package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/DanielKillenberger/homeplane/internal/cred"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// Field bounds. Every field on this API is a short label; bounding them keeps
// oversized values out of the database and out of the audit log.
const (
	maxMachineNameLen = 128
	maxOSLen          = 64
	maxHarnessLen     = 64
	maxCapabilities   = 32
)

type enrolRequest struct {
	MachineName string `json:"machine_name"`
	OS          string `json:"os"`
}

type enrolResponse struct {
	MachineID         string `json:"machine_id"`
	MachineCredential string `json:"machine_credential"`
	// Rotated is true when this call rotated an existing machine's credential
	// rather than enrolling a new machine. The agent uses it to know the old
	// credential is now dead.
	Rotated           bool  `json:"rotated"`
	CredentialVersion int64 `json:"credential_version"`
}

// handleEnrol registers the calling tailnet node, or rotates its credential.
//
// D12: enrolment is auto-approved — any node that can reach this server over
// the tailnet is Daniel's. What is NOT auto-approved is identity: the machine
// record is keyed on the WhoIs node id, so re-enrolling from the same node
// always lands on the same record (rotation), and enrolling from a different
// node can never take over an existing record.
func (s *Server) handleEnrol(w http.ResponseWriter, r *http.Request) {
	observed, ok := s.observe(w, r)
	if !ok {
		return
	}

	var req enrolRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, codeInvalidRequest, "malformed request body: "+err.Error())
		return
	}
	name := strings.TrimSpace(req.MachineName)
	osName := strings.TrimSpace(req.OS)
	if msg, ok := validLabel(name, maxMachineNameLen); !ok {
		s.writeError(w, http.StatusBadRequest, codeInvalidRequest, "machine_name "+msg)
		return
	}
	if msg, ok := validLabel(osName, maxOSLen); !ok {
		s.writeError(w, http.StatusBadRequest, codeInvalidRequest, "os "+msg)
		return
	}

	// The plaintext credential exists only in this function's scope and in the
	// response; the store receives a hash. That is precisely why re-enrolment
	// cannot be a silent no-op returning the original secret.
	plaintext, hash, err := cred.New()
	if err != nil {
		s.log.Error("mint machine credential", "error", err)
		s.writeError(w, http.StatusInternalServerError, codeInternal, "could not mint credential")
		return
	}

	// The enrolment and its audit record commit together: a machine credential
	// that exists with no record of having been issued is exactly the state an
	// audit log exists to make impossible.
	m, rotated, err := s.store.Enrol(r.Context(), observed, name, osName, hash,
		func(m store.Machine, rotated bool) []store.AuditEvent {
			event := store.EventEnrolment
			if rotated {
				event = store.EventCredentialRotation
			}
			// AuthMachineID is populated here even though no bearer credential
			// was presented, and that is not a misattribution: for enrolment the
			// authenticating factor IS the tailnet node identity (D12), and the
			// machine record is by construction the one that node owns. Observed
			// and authenticated identity are the same fact on this endpoint.
			return []store.AuditEvent{{
				Event:            event,
				ActorKind:        store.ActorMachine,
				ObservedNodeID:   observed.NodeID,
				ObservedNodeName: observed.NodeName,
				AuthMachineID:    m.ID,
				Outcome:          store.OutcomeAllowed,
				Detail: map[string]string{
					"machine_name":       m.Name,
					"os":                 m.OS,
					"credential_version": strconv.FormatInt(m.CredentialVersion, 10),
				},
			}}
		})
	if err != nil {
		s.log.Error("enrol", "error", err)
		s.writeError(w, http.StatusInternalServerError, codeInternal, "enrolment failed")
		return
	}

	status := http.StatusCreated
	if rotated {
		status = http.StatusOK
	}
	s.writeJSON(w, status, enrolResponse{
		MachineID:         m.ID,
		MachineCredential: plaintext,
		Rotated:           rotated,
		CredentialVersion: m.CredentialVersion,
	})
}

type issueGrantRequest struct {
	Harness      string   `json:"harness"`
	Capabilities []string `json:"capabilities"`
}

type issueGrantResponse struct {
	GrantID           string   `json:"grant_id"`
	Harness           string   `json:"harness"`
	Capabilities      []string `json:"capabilities"`
	EndpointURL       string   `json:"endpoint_url"`
	GrantToken        string   `json:"grant_token"`
	SupersededGrantID string   `json:"superseded_grant_id,omitempty"`
}

// handleIssueGrant issues an active grant for (calling machine, harness).
//
// Note the absence of a machine_id field in the request: the grant is always
// for the caller. Capabilities are decided by server-side policy, so a client
// asking for more than its harness may hold is refused outright rather than
// quietly handed a different authority than it asked for.
func (s *Server) handleIssueGrant(w http.ResponseWriter, r *http.Request) {
	c, ok := s.authenticate(w, r)
	if !ok {
		return
	}

	var req issueGrantRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, codeInvalidRequest, "malformed request body: "+err.Error())
		return
	}
	harness := strings.ToLower(strings.TrimSpace(req.Harness))
	if msg, ok := validLabel(harness, maxHarnessLen); !ok {
		s.writeError(w, http.StatusBadRequest, codeInvalidRequest, "harness "+msg)
		return
	}
	if len(req.Capabilities) > maxCapabilities {
		s.writeError(w, http.StatusBadRequest, codeInvalidRequest, "too many capabilities requested")
		return
	}

	capabilities, err := s.cfg.Policy.Resolve(harness, req.Capabilities)
	if err != nil {
		s.deny(w, r, store.AuditEvent{
			Event:            store.EventGrantIssued,
			ActorKind:        store.ActorMachine,
			ObservedNodeID:   c.Observed.NodeID,
			ObservedNodeName: c.Observed.NodeName,
			AuthMachineID:    c.Machine.ID,
			Harness:          harness,
			Outcome:          store.OutcomeDenied,
			Reason:           denialReason(err),
			Detail: map[string]string{
				"requested_capabilities": truncate(strings.Join(req.Capabilities, ","), store.MaxDetailValueLen),
			},
		}, http.StatusForbidden, codeForbidden, err.Error())
		return
	}

	plaintext, hash, err := cred.New()
	if err != nil {
		s.log.Error("mint grant token", "error", err)
		s.writeError(w, http.StatusInternalServerError, codeInternal, "could not mint grant token")
		return
	}

	// Issuance, supersession, and their audit rows commit as one unit.
	g, superseded, err := s.store.IssueGrant(r.Context(), c.Machine.ID, harness, capabilities, hash,
		func(g store.Grant, superseded *store.Grant) []store.AuditEvent {
			events := make([]store.AuditEvent, 0, 2)
			if superseded != nil {
				// Supersession is a system-caused revocation, not an operator or
				// machine action: the machine asked for a grant, the SERVER
				// decided the old one dies. ActorSystem keeps that honest.
				events = append(events, store.AuditEvent{
					Event:            store.EventGrantSuperseded,
					ActorKind:        store.ActorSystem,
					ObservedNodeID:   c.Observed.NodeID,
					ObservedNodeName: c.Observed.NodeName,
					AuthMachineID:    c.Machine.ID,
					Harness:          harness,
					GrantID:          superseded.ID,
					Outcome:          store.OutcomeAllowed,
					Reason:           "superseded",
					Detail:           map[string]string{"superseded_by_grant_id": g.ID},
				})
			}
			return append(events, store.AuditEvent{
				Event:            store.EventGrantIssued,
				ActorKind:        store.ActorMachine,
				ObservedNodeID:   c.Observed.NodeID,
				ObservedNodeName: c.Observed.NodeName,
				AuthMachineID:    c.Machine.ID,
				Harness:          harness,
				GrantID:          g.ID,
				Outcome:          store.OutcomeAllowed,
				Detail:           map[string]string{"capabilities": truncate(strings.Join(capabilities, ","), store.MaxDetailValueLen)},
			})
		})
	if err != nil {
		s.log.Error("issue grant", "error", err)
		s.writeError(w, http.StatusInternalServerError, codeInternal, "grant issuance failed")
		return
	}

	resp := issueGrantResponse{
		GrantID:      g.ID,
		Harness:      g.Harness,
		Capabilities: g.Capabilities,
		EndpointURL:  s.cfg.ConnectorEndpointURL,
		GrantToken:   plaintext,
	}
	if superseded != nil {
		resp.SupersededGrantID = superseded.ID
	}
	s.writeJSON(w, http.StatusCreated, resp)
}

// grantView is the non-secret projection of a grant. There is no token field
// and no token-hash field: `GET /grants` is metadata only, and a grant token is
// returned exactly once, at issuance.
type grantView struct {
	GrantID      string   `json:"grant_id"`
	Harness      string   `json:"harness"`
	Capabilities []string `json:"capabilities"`
	State        string   `json:"state"`
	CreatedAt    string   `json:"created_at"`
	RevokedAt    string   `json:"revoked_at,omitempty"`
}

type listGrantsResponse struct {
	Grants []grantView `json:"grants"`
}

// handleListGrants returns the calling machine's grants — and only those. The
// machine id is never taken from the request, so there is no parameter to
// tamper with in order to read another machine's grants.
func (s *Server) handleListGrants(w http.ResponseWriter, r *http.Request) {
	c, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	grants, err := s.store.ListGrants(r.Context(), c.Machine.ID)
	if err != nil {
		s.log.Error("list grants", "error", err)
		s.writeError(w, http.StatusInternalServerError, codeInternal, "could not list grants")
		return
	}
	views := make([]grantView, 0, len(grants))
	for _, g := range grants {
		v := grantView{
			GrantID:      g.ID,
			Harness:      g.Harness,
			Capabilities: g.Capabilities,
			State:        string(g.State),
			CreatedAt:    g.CreatedAt.UTC().Format(timeLayout),
		}
		if g.RevokedAt != nil {
			v.RevokedAt = g.RevokedAt.UTC().Format(timeLayout)
		}
		views = append(views, v)
	}
	s.writeJSON(w, http.StatusOK, listGrantsResponse{Grants: views})
}

type revokeGrantResponse struct {
	GrantID string `json:"grant_id"`
	State   string `json:"state"`
	// Revoked is true when this call performed the revocation, false when the
	// grant was already revoked. The endpoint is idempotent either way.
	Revoked   bool   `json:"revoked"`
	RevokedAt string `json:"revoked_at,omitempty"`
}

// handleRevokeGrant revokes one of the calling machine's grants.
//
// Ownership is checked before anything else happens, and a grant belonging to
// another machine is refused with 403 — cross-machine revocation exists only on
// the server-local admin CLI, where the operator identity is shell access to
// the server itself.
func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	c, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		s.writeError(w, http.StatusBadRequest, codeInvalidRequest, "grant id is required")
		return
	}

	g, err := s.store.GrantByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.deny(w, r, store.AuditEvent{
				Event:            store.EventGrantRevoked,
				ActorKind:        store.ActorMachine,
				ObservedNodeID:   c.Observed.NodeID,
				ObservedNodeName: c.Observed.NodeName,
				AuthMachineID:    c.Machine.ID,
				GrantID:          id,
				Outcome:          store.OutcomeDenied,
				Reason:           "unknown_grant",
			}, http.StatusNotFound, codeNotFound, "unknown grant")
			return
		}
		s.log.Error("grant lookup", "error", err)
		s.writeError(w, http.StatusInternalServerError, codeInternal, "grant lookup failed")
		return
	}
	if g.MachineID != c.Machine.ID {
		s.deny(w, r, store.AuditEvent{
			Event:            store.EventGrantRevoked,
			ActorKind:        store.ActorMachine,
			ObservedNodeID:   c.Observed.NodeID,
			ObservedNodeName: c.Observed.NodeName,
			AuthMachineID:    c.Machine.ID,
			GrantID:          g.ID,
			Harness:          g.Harness,
			Outcome:          store.OutcomeDenied,
			Reason:           "cross_machine_revocation",
		}, http.StatusForbidden, codeForbidden, "grant belongs to another machine")
		return
	}

	// Only a real state transition is audited (the callback is not invoked on a
	// repeat call): logging a second revocation would put a fictional event in
	// an append-only record. The transition and its record commit together, so
	// a token cannot stop working without the log saying why.
	revoked, changed, err := s.store.RevokeGrant(r.Context(), id, "revoked_by_machine",
		func(g store.Grant) []store.AuditEvent {
			return []store.AuditEvent{{
				Event:            store.EventGrantRevoked,
				ActorKind:        store.ActorMachine,
				ObservedNodeID:   c.Observed.NodeID,
				ObservedNodeName: c.Observed.NodeName,
				AuthMachineID:    c.Machine.ID,
				Harness:          g.Harness,
				GrantID:          g.ID,
				Outcome:          store.OutcomeAllowed,
				Reason:           "revoked_by_machine",
			}}
		})
	if err != nil {
		s.log.Error("revoke grant", "error", err)
		s.writeError(w, http.StatusInternalServerError, codeInternal, "revocation failed")
		return
	}

	resp := revokeGrantResponse{GrantID: revoked.ID, State: string(revoked.State), Revoked: changed}
	if revoked.RevokedAt != nil {
		resp.RevokedAt = revoked.RevokedAt.UTC().Format(timeLayout)
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleHealthz reports SERVER-side components only.
//
// A degraded result returns BOTH a non-2xx status and a payload naming the
// degraded component: `curl -sf .../healthz` must fail, and a human reading the
// body must learn which component broke without grepping logs.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	report := s.health.Check(r.Context())
	status := http.StatusOK
	if report.Degraded() {
		status = http.StatusServiceUnavailable
	}
	s.writeJSON(w, status, report)
}

// timeLayout is the wire format for timestamps in API responses.
const timeLayout = time.RFC3339Nano

// validLabel bounds a short user-supplied label and rejects control characters,
// which have no business in a machine name and would corrupt log output.
func validLabel(v string, max int) (string, bool) {
	if v == "" {
		return "is required", false
	}
	if len(v) > max {
		return "is too long", false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return "contains control characters", false
		}
	}
	return "", true
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// denialReason maps a policy error onto a stable audit reason code.
func denialReason(err error) string {
	switch {
	case errors.Is(err, policy.ErrUnknownHarness):
		return "unknown_harness"
	case errors.Is(err, policy.ErrNotPermitted):
		return "capability_not_permitted"
	default:
		return "policy_error"
	}
}
