// Package edge is Homeplane's connector edge: the streamable-HTTP MCP endpoint
// a harness connects to over the tailnet, in front of the composed gateway.
//
// It is the network half of the connector plane. The decision half — the
// manifest, the policy engine, the authoritative audit rows — lives in
// internal/server/connectors and is reached here through its broker, unchanged.
// This package adds exactly three things, and deliberately nothing else:
//
//   - Authentication: a grant token proves WHICH grant is calling, and it is
//     resolved from the store on EVERY request. There is no token cache, which
//     is what makes revocation take effect on the next call rather than at the
//     end of some TTL.
//   - Machine binding: the tailnet node the request actually came from (WhoIs,
//     the observed identity) must be the node the grant's machine is enrolled
//     as. A token replayed from another node is refused and audited against the
//     OBSERVED node — never attributed to the machine that legitimately owns it.
//   - Isolation: the composed gateway is reachable only over loopback (checked
//     at construction), so the sole route to it from another tailnet node runs
//     through this file, where the two rules above apply.
//
// Everything about the MCP protocol itself — sessions, initialize, tools/list,
// SSE streams — stays with the gateway: those frames are forwarded verbatim
// with the Homeplane grant token stripped. Only `tools/call` is intercepted,
// because that is the only frame that has an effect worth authorizing.
package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/cred"
	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// Store is the persistence surface the edge needs. It is intentionally
// read-mostly: the edge issues nothing and revokes nothing, it only resolves
// what the control plane already decided, and appends audit rows.
type Store interface {
	// ActiveGrantByTokenHash returns the ACTIVE grant for a token hash, or
	// store.ErrNotFound. A revoked grant is not active, which is the entire
	// revocation mechanism at this layer.
	ActiveGrantByTokenHash(ctx context.Context, tokenHash string) (store.Grant, error)
	MachineByID(ctx context.Context, id string) (store.Machine, error)
	AppendAudit(ctx context.Context, e store.AuditEvent) error
}

// IdentityResolver turns a connection's remote address into the tailnet
// identity of the peer. Production is tsnet's in-process WhoIs
// (internal/tsnetid); tests substitute a table.
type IdentityResolver interface {
	Resolve(ctx context.Context, remoteAddr string) (store.Identity, error)
}

// Config wires the edge.
type Config struct {
	// Store resolves grants and machines and receives audit rows.
	Store Store
	// Identity resolves the observed tailnet node of each caller.
	Identity IdentityResolver
	// Broker is the task .3 policy/audit engine bound to a ToolRuntime. In
	// production that runtime is NewHTTPRuntime over Upstream.
	Broker *connectors.Broker
	// Upstream is the composed gateway's MCP endpoint. It MUST be loopback
	// (see ParseUpstream) and is used for the frames the edge forwards
	// verbatim.
	Upstream *url.URL
	// UpstreamTransport optionally overrides the transport used for forwarded
	// (non-tool-call) frames.
	UpstreamTransport http.RoundTripper
	// MaxRequestBytes bounds a client request body. Zero uses the default.
	MaxRequestBytes int64
	// Logger receives operational logs. Nil uses slog.Default().
	Logger *slog.Logger
}

// DefaultMaxRequestBytes bounds a client MCP frame. Tool arguments are
// structured parameters, not uploads.
const DefaultMaxRequestBytes = 4 << 20

// Edge is the connector edge HTTP application.
type Edge struct {
	cfg    Config
	router *toolRouter
	proxy  *httputil.ReverseProxy
	log    *slog.Logger
}

// New builds an Edge, refusing any configuration that would weaken the
// boundary it exists to hold: a missing dependency, a non-loopback gateway, or
// a manifest the edge cannot route deterministically.
func New(cfg Config) (*Edge, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("edge: a store is required")
	case cfg.Identity == nil:
		return nil, errors.New("edge: an identity resolver is required")
	case cfg.Broker == nil:
		return nil, errors.New("edge: a connector broker is required")
	case cfg.Upstream == nil:
		return nil, errors.New("edge: a gateway upstream is required")
	}
	if !IsLoopbackHost(cfg.Upstream.Hostname()) {
		return nil, fmt.Errorf("%w: %q", ErrUpstreamNotLoopback, cfg.Upstream.String())
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = DefaultMaxRequestBytes
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	router, err := newToolRouter(cfg.Broker.Engine().Manifest())
	if err != nil {
		return nil, err
	}

	upstream := *cfg.Upstream
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// The outbound URL is the gateway's endpoint EXACTLY, not the
			// endpoint joined with the inbound path: both sides name the same
			// single streamable-HTTP endpoint, so joining them would ask the
			// gateway for /mcp/mcp. Streamable HTTP has no sub-resources; the
			// only thing carried over from the client's URL is its query.
			pr.Out.URL.Scheme = upstream.Scheme
			pr.Out.URL.Host = upstream.Host
			pr.Out.URL.Path = upstream.Path
			pr.Out.URL.RawPath = upstream.RawPath
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.Host = upstream.Host

			// The grant token is a Homeplane credential and has no meaning
			// past this point; the gateway must never see it.
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("X-Forwarded-For")
			if pr.Out.Header.Get(HeaderProtocolVersion) == "" {
				pr.Out.Header.Set(HeaderProtocolVersion, ProtocolVersion)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Error("gateway forward failed", "error", err)
			writeErrorJSON(w, http.StatusBadGateway, "gateway_unreachable", "the connector gateway is unreachable")
		},
	}
	if cfg.UpstreamTransport != nil {
		proxy.Transport = cfg.UpstreamTransport
	}

	return &Edge{cfg: cfg, router: router, proxy: proxy, log: log}, nil
}

// Handler returns the edge's HTTP handler. Mount it at the MCP endpoint path
// the grant's endpoint_url advertises (`/mcp`).
func (e *Edge) Handler() http.Handler { return e }

// ServeHTTP authenticates every request before anything else looks at it, then
// either authorizes a tool call or forwards a transport frame.
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, ok := e.authenticate(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		e.handlePost(w, r, c)
		return
	}
	// GET (SSE stream) and DELETE (session teardown) carry no tool call. They
	// are session transport and belong to the gateway.
	e.forward(w, r)
}

// authenticate resolves the caller's OBSERVED tailnet identity, resolves the
// presented grant token to an ACTIVE grant, and requires the two to describe
// the same machine.
//
// The failure shapes are distinct on purpose, and mirror the control plane's
// (internal/server/auth.go):
//
//   - unresolvable peer -> 403; nothing can be authorized for a caller the
//     tailnet cannot name.
//   - missing / unknown / REVOKED token -> 401, audited with a token
//     fingerprint only, never with an identity the token did not prove.
//   - a valid token presented from a node other than the grant's machine ->
//     403 machine_mismatch, audited against the OBSERVED node with the bound
//     machine recorded as metadata. A stolen token therefore cannot act as its
//     owner from anywhere else, and the log never blames the owner for it.
func (e *Edge) authenticate(w http.ResponseWriter, r *http.Request) (connectors.Caller, bool) {
	ctx := r.Context()

	observed, err := e.cfg.Identity.Resolve(ctx, r.RemoteAddr)
	if err != nil || observed.NodeID == "" {
		reason := "identity_unresolvable"
		if err == nil {
			reason = "identity_empty"
		}
		e.log.Warn("peer identity unresolvable", "remote", r.RemoteAddr, "error", err)
		e.deny(w, r, store.AuditEvent{
			Event:     store.EventAuthDenied,
			ActorKind: store.ActorMachine,
			Outcome:   store.OutcomeDenied,
			Reason:    reason,
			Detail:    requestDetail(r),
		}, http.StatusForbidden, "forbidden", "peer tailnet identity could not be resolved")
		return connectors.Caller{}, false
	}

	tok, ok := bearer(r)
	if !ok {
		e.denyAuth(w, r, observed, "", "missing_grant_token", nil,
			http.StatusUnauthorized, "unauthenticated", "missing grant token")
		return connectors.Caller{}, false
	}

	// Resolved per request, with no cache: this single lookup is what makes
	// revocation take effect on the next call instead of at a TTL boundary.
	g, err := e.cfg.Store.ActiveGrantByTokenHash(ctx, cred.Hash(tok))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// One reason for two cases on purpose: a revoked token and a token
			// that never existed are indistinguishable to the caller, and the
			// operator learns which it was from the grant's own lifecycle rows.
			e.denyAuth(w, r, observed, tok, "invalid_or_revoked_grant", nil,
				http.StatusUnauthorized, "unauthenticated", "invalid or revoked grant token")
			return connectors.Caller{}, false
		}
		e.log.Error("grant lookup", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "internal", "grant lookup failed")
		return connectors.Caller{}, false
	}

	m, err := e.cfg.Store.MachineByID(ctx, g.MachineID)
	if err != nil {
		// A grant whose machine cannot be resolved is not a caller error and is
		// never admitted: without the machine record there is no node to bind
		// the token to.
		e.log.Error("machine lookup", "grant", g.ID, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "internal", "machine lookup failed")
		return connectors.Caller{}, false
	}

	if m.NodeID != observed.NodeID {
		e.denyAuth(w, r, observed, tok, "machine_mismatch",
			mergeDetail(requestDetail(r), map[string]string{"bound_machine_id": m.ID}),
			http.StatusForbidden, "forbidden", "grant token is not valid from this machine")
		return connectors.Caller{}, false
	}

	return connectors.Caller{
		Actor:            store.ActorMachine,
		ObservedNodeID:   observed.NodeID,
		ObservedNodeName: observed.NodeName,
		MachineID:        m.ID,
		Harness:          g.Harness,
		GrantID:          g.ID,
		Capabilities:     g.Capabilities,
	}, true
}

// handlePost either authorizes a tool call through the broker or forwards the
// frame. A body that is not a well-formed `tools/call` is forwarded unchanged:
// initialize, tools/list, ping and notifications are the gateway's business.
func (e *Edge) handlePost(w http.ResponseWriter, r *http.Request, c connectors.Caller) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, e.cfg.MaxRequestBytes))
	if err != nil {
		writeErrorJSON(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body is too large or unreadable")
		return
	}

	// A JSON-RPC BATCH is refused rather than forwarded. A batch is an array of
	// frames, so the single-frame parse below would not see the `tools/call`
	// inside it and would forward the whole array to the gateway unauthorized —
	// a policy bypass. MCP dropped batching in the 2025-06-18 revision, so
	// refusing costs nothing and closes the hole for older clients.
	if isJSONArray(body) {
		writeRPCError(w, http.StatusBadRequest, nil, codeInvalidRequest,
			"batched JSON-RPC requests are not supported")
		return
	}

	var req rpcRequest
	if json.Unmarshal(body, &req) != nil || req.Method != methodToolsCall {
		e.forwardBody(w, r, body)
		return
	}
	var params toolCallParams
	if len(req.Params) > 0 && json.Unmarshal(req.Params, &params) != nil {
		writeRPCError(w, http.StatusBadRequest, req.ID, codeInvalidParams, "malformed tools/call parameters")
		return
	}

	provider, tool := e.router.route(params.Name)
	state := &callState{
		sessionID:       r.Header.Get(HeaderSessionID),
		wireTool:        params.Name,
		protocolVersion: r.Header.Get(HeaderProtocolVersion),
	}
	ctx := withCallState(r.Context(), state)

	// From here the decision, the audit row and the forward are the broker's:
	// the edge contributes the identity it proved and nothing else.
	result, err := e.cfg.Broker.Invoke(ctx, connectors.Request{
		Provider: provider,
		Tool:     tool,
		Args:     params.Arguments,
		Caller:   c,
	})
	switch {
	case err == nil:
		e.writeRPCResult(w, req.ID, result)

	case errors.Is(err, connectors.ErrDenied):
		// The refusal is already on the record (the broker writes the row
		// before it returns); the client is told what was refused.
		e.log.Info("connector call denied", "grant", c.GrantID, "tool", params.Name, "error", err)
		writeRPCError(w, http.StatusForbidden, req.ID, codeForbidden, err.Error())

	case errors.Is(err, connectors.ErrAuditUnavailable):
		// The authoritative log could not record the call, so the call does not
		// happen. Availability is the thing that gives way, never the record.
		e.log.Error("connector call refused: audit unavailable", "tool", params.Name, "error", err)
		writeRPCError(w, http.StatusServiceUnavailable, req.ID, codeAuditFailure,
			"call refused: the audit log is unavailable")

	default:
		if state.toolError != nil {
			// The gateway (or the provider behind it) answered with its own
			// JSON-RPC error. The call was admitted and is audited as such
			// (`tool_failed`); the client gets the real error rather than a
			// synthesized one.
			e.writeRPCFailure(w, req.ID, state.toolError)
			return
		}
		e.log.Error("connector call failed", "tool", params.Name, "error", err)
		writeRPCError(w, http.StatusBadGateway, req.ID, codeGatewayFailure, "the connector gateway call failed")
	}
}

// forward proxies a transport frame to the gateway with the grant token
// stripped.
func (e *Edge) forward(w http.ResponseWriter, r *http.Request) {
	e.proxy.ServeHTTP(w, r)
}

// forwardBody proxies a POST whose body has already been read.
func (e *Edge) forwardBody(w http.ResponseWriter, r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	e.proxy.ServeHTTP(w, r)
}

func (e *Edge) writeRPCResult(w http.ResponseWriter, id json.RawMessage, result json.RawMessage) {
	writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: jsonRPCVersion, ID: id, Result: result})
}

func (e *Edge) writeRPCFailure(w http.ResponseWriter, id json.RawMessage, rpcErr *RPCError) {
	writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: jsonRPCVersion, ID: id, Error: rpcErr})
}

// denyAuth records an authentication rejection and refuses the request.
//
// What the row does NOT contain is the point: no AuthMachineID, no GrantID. A
// rejected credential is reduced to a non-reversible fingerprint, so repeated
// attempts correlate with each other without ever being attributable to the
// machine that legitimately owns the token.
func (e *Edge) denyAuth(w http.ResponseWriter, r *http.Request, observed store.Identity,
	presentedToken, reason string, detail map[string]string, status int, code, message string) {
	if detail == nil {
		detail = requestDetail(r)
	}
	ev := store.AuditEvent{
		Event:            store.EventAuthDenied,
		ActorKind:        store.ActorMachine,
		ObservedNodeID:   observed.NodeID,
		ObservedNodeName: observed.NodeName,
		Outcome:          store.OutcomeDenied,
		Reason:           reason,
		Detail:           detail,
	}
	if presentedToken != "" {
		ev.TokenFingerprint = cred.Fingerprint(presentedToken)
	}
	e.deny(w, r, ev, status, code, message)
}

// deny records a rejected call and then refuses it.
//
// If the record cannot be written the caller gets 503 instead of 401/403: a
// rejected call — a revoked token, a replay from the wrong node — is exactly
// what an operator most needs to see, so answering "denied" while quietly
// failing to write it down would make an attacker's probing invisible. The
// request is refused either way; only the status differs.
func (e *Edge) deny(w http.ResponseWriter, r *http.Request, ev store.AuditEvent,
	status int, code, message string) {
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}
	if err := e.cfg.Store.AppendAudit(r.Context(), ev); err != nil {
		e.log.Error("audit append failed", "event", ev.Event, "reason", ev.Reason, "error", err)
		writeErrorJSON(w, http.StatusServiceUnavailable, "unavailable",
			"request refused, but the refusal could not be recorded: audit log unavailable")
		return
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	writeErrorJSON(w, status, code, message)
}

// isJSONArray reports whether a body is a JSON array (a JSON-RPC batch).
func isJSONArray(body []byte) bool {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '['
}

// bearer extracts an `Authorization: Bearer <token>` credential.
func bearer(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	return tok, tok != ""
}

// requestDetail is the bounded metadata every edge denial carries. The keys are
// from the store's closed Detail vocabulary; nothing request-derived beyond
// method and path can enter the log.
func requestDetail(r *http.Request) map[string]string {
	return map[string]string{"path": truncateDetail(r.URL.Path), "method": r.Method}
}

func mergeDetail(base, extra map[string]string) map[string]string {
	for k, v := range extra {
		base[k] = v
	}
	return base
}

func truncateDetail(s string) string {
	if len(s) <= store.MaxDetailValueLen {
		return s
	}
	return s[:store.MaxDetailValueLen]
}

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeErrorJSON(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: code, Message: message})
}

func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string) {
	writeJSON(w, status, rpcResponse{
		JSONRPC: jsonRPCVersion,
		ID:      id,
		Error:   &RPCError{Code: code, Message: message},
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
