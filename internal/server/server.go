// Package server implements the Homeplane control plane: enrolment, the grant
// lifecycle, the append-only audit trail, and server-component health.
//
// Two rules shape everything here:
//
//   - Tailnet reachability is never authorization. Every request resolves its
//     caller via WhoIs (observed identity) AND, for machine-scoped endpoints,
//     verifies a machine credential (authenticated identity). Both must agree
//     on the same machine record.
//   - The client never names the machine it acts as. There is no caller-supplied
//     machine_id anywhere in this API; the acting machine is always derived from
//     the WhoIs-resolved node.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/health"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// Store is the persistence surface the control plane needs. It is an interface
// so handler tests can drive failure paths (store down, audit-write failure)
// that a real database will not produce on demand.
// Every mutating method takes an audit callback whose events are written in
// the same transaction as the mutation, so a lifecycle change and the record of
// it either both land or neither does.
type Store interface {
	Enrol(ctx context.Context, id store.Identity, name, osName, credentialHash string,
		audit func(m store.Machine, rotated bool) []store.AuditEvent) (store.Machine, bool, error)
	MachineByNodeID(ctx context.Context, nodeID string) (store.Machine, error)
	MachineByCredentialHash(ctx context.Context, credentialHash string) (store.Machine, error)
	IssueGrant(ctx context.Context, machineID, harness string, capabilities []string, tokenHash string,
		audit func(g store.Grant, superseded *store.Grant) []store.AuditEvent) (store.Grant, *store.Grant, error)
	GrantByID(ctx context.Context, id string) (store.Grant, error)
	RevokeGrant(ctx context.Context, id, reason string,
		audit func(g store.Grant) []store.AuditEvent) (store.Grant, bool, error)
	ListGrants(ctx context.Context, machineID string) ([]store.Grant, error)
	AppendAudit(ctx context.Context, e store.AuditEvent) error
}

// IdentityResolver turns a connection's remote address into the tailnet
// identity of the peer. The production implementation is tsnet's WhoIs
// (internal/tsnetid); tests substitute a table.
type IdentityResolver interface {
	Resolve(ctx context.Context, remoteAddr string) (store.Identity, error)
}

// Config carries the server's non-secret settings.
type Config struct {
	// ConnectorEndpointURL is the URL handed to a harness alongside a fresh
	// grant token — the address of the Homeplane connector edge (task .16).
	ConnectorEndpointURL string
	// Policy is the server-side per-harness capability policy.
	Policy policy.Policy
	// MaxRequestBytes bounds any request body. Zero uses DefaultMaxRequestBytes.
	MaxRequestBytes int64
	// Logger receives operational logs. Nil uses slog.Default().
	Logger *slog.Logger
}

// DefaultMaxRequestBytes bounds request bodies; every body in this API is a
// handful of short fields.
const DefaultMaxRequestBytes = 64 << 10

// Server is the control-plane HTTP application.
type Server struct {
	store    Store
	identity IdentityResolver
	health   *health.Checker
	cfg      Config
	log      *slog.Logger
}

// New builds a Server. It returns an error when the capability policy is
// internally inconsistent — a bad policy must fail at startup, not at the first
// grant request.
func New(st Store, resolver IdentityResolver, checker *health.Checker, cfg Config) (*Server, error) {
	if err := cfg.Policy.Validate(); err != nil {
		return nil, err
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = DefaultMaxRequestBytes
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Server{store: st, identity: resolver, health: checker, cfg: cfg, log: log}, nil
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enrol", s.handleEnrol)
	mux.HandleFunc("POST /grants", s.handleIssueGrant)
	mux.HandleFunc("GET /grants", s.handleListGrants)
	mux.HandleFunc("DELETE /grants/{id}", s.handleRevokeGrant)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	return mux
}

// errorCode is a stable machine-readable error identifier returned to clients.
type errorCode string

const (
	codeInvalidRequest  errorCode = "invalid_request"
	codeUnauthenticated errorCode = "unauthenticated"
	codeForbidden       errorCode = "forbidden"
	codeNotFound        errorCode = "not_found"
	codeInternal        errorCode = "internal"
)

type errorBody struct {
	Error   errorCode `json:"error"`
	Message string    `json:"message"`
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.log.Error("write response", "error", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, code errorCode, message string) {
	s.writeJSON(w, status, errorBody{Error: code, Message: message})
}

// decodeJSON reads a bounded, strictly-typed JSON body.
func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// audit appends a STANDALONE audit row — one with no accompanying state change,
// which in this package means a rejected call. Events that accompany a mutation
// are written by that mutation's transaction instead (see Store), so they can
// never diverge from it.
//
// Here, and only here, a failed write is logged rather than propagated: the
// request is already being denied, so nothing privileged happened that could go
// unrecorded, and turning a broken log into a different error code would just
// mislead the caller. The store failure surfaces through /healthz.
func (s *Server) audit(ctx context.Context, e store.AuditEvent) {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	if err := s.store.AppendAudit(ctx, e); err != nil {
		s.log.Error("audit append failed", "event", e.Event, "error", err)
	}
}
