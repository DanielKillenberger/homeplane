package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/DanielKillenberger/homeplane/internal/cred"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// caller is a fully resolved request principal: what the network observed plus,
// for machine-scoped endpoints, what the presented credential proved.
type caller struct {
	Observed store.Identity
	Machine  store.Machine
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

// observe resolves the caller's tailnet identity. Failure is fatal to the
// request: an unidentifiable peer can never be authorized, because every
// authorization decision in this API is anchored on the observed node.
func (s *Server) observe(w http.ResponseWriter, r *http.Request) (store.Identity, bool) {
	id, err := s.identity.Resolve(r.Context(), r.RemoteAddr)
	if err != nil || id.NodeID == "" {
		reason := "identity_unresolvable"
		if err == nil {
			reason = "identity_empty"
		}
		s.audit(r.Context(), store.AuditEvent{
			Event:     store.EventAuthDenied,
			ActorKind: store.ActorMachine,
			Outcome:   store.OutcomeDenied,
			Reason:    reason,
			Detail:    map[string]string{"path": r.URL.Path, "method": r.Method},
		})
		s.log.Warn("peer identity unresolvable", "remote", r.RemoteAddr, "error", err)
		s.writeError(w, http.StatusForbidden, codeForbidden, "peer tailnet identity could not be resolved")
		return store.Identity{}, false
	}
	return id, true
}

// authenticate resolves the observed identity AND verifies a machine
// credential against the machine enrolled for that node.
//
// The three failure shapes are deliberately distinct:
//
//   - no credential / no machine enrolled for this node / credential matches
//     nothing at all -> 401, audited with a token fingerprint only.
//   - credential belongs to a DIFFERENT machine (a credential exfiltrated to
//     another node and replayed) -> 403, audited against the OBSERVED node with
//     the bound machine recorded as metadata, never as the acting identity.
//
// A caller therefore cannot act as another machine by holding its credential,
// and cannot act as itself without one.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (caller, bool) {
	observed, ok := s.observe(w, r)
	if !ok {
		return caller{}, false
	}

	tok, ok := bearer(r)
	if !ok {
		s.auditDenied(r, observed, "", "missing_machine_credential")
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.writeError(w, http.StatusUnauthorized, codeUnauthenticated, "missing machine credential")
		return caller{}, false
	}

	m, err := s.store.MachineByNodeID(r.Context(), observed.NodeID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.auditDenied(r, observed, tok, "machine_not_enrolled")
			s.writeError(w, http.StatusUnauthorized, codeUnauthenticated, "machine is not enrolled")
			return caller{}, false
		}
		s.log.Error("machine lookup", "error", err)
		s.writeError(w, http.StatusInternalServerError, codeInternal, "machine lookup failed")
		return caller{}, false
	}

	if !cred.Verify(tok, m.CredentialHash) {
		// Is this a valid credential for some OTHER machine — i.e. a replay
		// from the wrong node — or simply an invalid credential?
		if other, err := s.store.MachineByCredentialHash(r.Context(), cred.Hash(tok)); err == nil {
			s.auditDeniedDetail(r, observed, tok, "machine_mismatch", map[string]string{
				"bound_machine_id": other.ID,
				"path":             r.URL.Path,
				"method":           r.Method,
			})
			s.writeError(w, http.StatusForbidden, codeForbidden, "credential is not valid from this machine")
			return caller{}, false
		} else if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("credential lookup", "error", err)
			s.writeError(w, http.StatusInternalServerError, codeInternal, "credential lookup failed")
			return caller{}, false
		}
		s.auditDenied(r, observed, tok, "invalid_machine_credential")
		s.writeError(w, http.StatusUnauthorized, codeUnauthenticated, "invalid machine credential")
		return caller{}, false
	}

	return caller{Observed: observed, Machine: m}, true
}

// auditDenied records a rejected call. Note what it does NOT do: it never sets
// AuthMachineID, because nothing authenticated. The presented credential is
// reduced to a non-reversible fingerprint so repeated attempts correlate with
// each other without being attributable to whichever machine owns the token.
func (s *Server) auditDenied(r *http.Request, observed store.Identity, presentedToken, reason string) {
	s.auditDeniedDetail(r, observed, presentedToken, reason, map[string]string{
		"path": r.URL.Path, "method": r.Method,
	})
}

func (s *Server) auditDeniedDetail(r *http.Request, observed store.Identity, presentedToken, reason string, detail map[string]string) {
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
	s.audit(r.Context(), ev)
}
