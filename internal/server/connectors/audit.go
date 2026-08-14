package connectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"

	"github.com/DanielKillenberger/homeplane/internal/store"
)

// Audit derivation. Everything an audit row says about a connector call comes
// from the manifest (action class, artifact identity) or from a one-way digest
// of the request arguments — never from inspecting a payload for meaning. That
// is what keeps the audit trail generic across arbitrary MCP tools without any
// connector-specific code, and structurally incapable of holding a body.
//
// One subtlety governs the whole file: on a DENIED call the provider and tool
// names are attacker-chosen strings that matched nothing in the manifest. They
// are still worth recording — an operator needs to see what was attempted — but
// they are sanitized first (see safeName). An unbounded name would otherwise be
// a payload channel, and, worse, would make the store reject the row and leave
// the denial unrecorded.

// safeNameRe is the shape a name may have to be recorded verbatim. It is the
// union of the provider and tool identifier shapes; anything else is replaced.
var safeNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@/-]*$`)

// UnnamedMarker is recorded when a call named nothing at all.
const UnnamedMarker = "unnamed"

// unrecognizedPrefix labels a name that could not be recorded verbatim. The
// digest that follows keeps repeated probes correlated with each other without
// letting their content into the log.
const unrecognizedPrefix = "unrecognized-"

const nameDigestDomain = "homeplane/connector-name\x00"

// nameDigestLen is the hex length of the digest appended to an unrecognized
// name. Twelve characters is ample to correlate probes and keeps the recorded
// value fixed-width.
const nameDigestLen = 12

// safeName renders a caller-supplied provider or tool name for an audit row:
// verbatim when it is a bounded, well-formed identifier, and otherwise a fixed
// marker plus a digest of what was actually sent.
func safeName(raw string) string {
	switch {
	case raw == "":
		return UnnamedMarker
	case len(raw) <= MaxIdentifierLen && safeNameRe.MatchString(raw):
		return raw
	default:
		sum := sha256.Sum256(append([]byte(nameDigestDomain), []byte(raw)...))
		return unrecognizedPrefix + hex.EncodeToString(sum[:])[:nameDigestLen]
	}
}

// CallEvent builds the row recorded for an authorization decision, before the
// tool runs. For an admitted call this row is the authoritative record that the
// call was made: it exists whether or not the tool later succeeds.
func (e *Engine) CallEvent(req Request, d Decision, callID string) store.AuditEvent {
	ev := store.AuditEvent{
		ActorKind:        req.Caller.actorKind(),
		ObservedNodeID:   req.Caller.ObservedNodeID,
		ObservedNodeName: req.Caller.ObservedNodeName,
		AuthMachineID:    req.Caller.MachineID,
		Harness:          req.Caller.Harness,
		GrantID:          req.Caller.GrantID,
		ActionClass:      string(d.ActionClass),
		Tool:             safeName(req.Tool),
		Detail: map[string]string{
			"provider": safeName(req.Provider),
			"call_id":  callID,
		},
	}

	// A refused call is never attributed as if it had acted: the grant identity
	// is what the credential proved, and it stays, but the row's outcome and
	// reason say plainly that nothing was forwarded.
	switch {
	case d.Allowed:
		ev.Event = store.EventConnectorToolCall
		ev.Outcome = store.OutcomeAllowed
	case d.PolicyViolation():
		ev.Event = store.EventPolicyViolation
		ev.Outcome = store.OutcomeDenied
		ev.Reason = d.Reason
	default:
		ev.Event = store.EventConnectorDenied
		ev.Outcome = store.OutcomeDenied
		ev.Reason = d.Reason
	}

	if d.RequiredCapability != "" {
		ev.Detail["required_capability"] = string(d.RequiredCapability)
	}
	if d.ExclusionReason != "" {
		ev.Detail["exclusion_reason"] = truncateDetail(d.ExclusionReason)
	}

	// Artifact identity, from the manifest's declared extractor when it reads
	// the request. The args digest is the FALLBACK, not a companion: when the
	// artifact is identified there is nothing for a digest to stand in for, and
	// a digest of the arguments is one more thing about the request in the log
	// than the record needs.
	ev.ArtifactID = ArtifactUnknown
	for _, ex := range d.Mapping.ArtifactID {
		if ex.Source != FromRequest {
			continue
		}
		if id, ok := Extract(ex, req.Args); ok {
			ev.ArtifactID = id
			break
		}
	}
	if ev.ArtifactID == ArtifactUnknown {
		ev.Detail["args_digest"] = ArgsDigest(req.Args)
	}
	return ev
}

// ResultEvent builds the row recorded once an admitted call has run. It exists
// for two reasons: to resolve artifact identities that only the response
// reveals (a created calendar event's id), and to record that the call ended.
//
// Outcome on this row repeats the AUTHORIZATION outcome — the call was
// permitted — while Reason distinguishes a tool that failed. A transport
// failure is not a policy denial and must not be logged as one.
func (e *Engine) ResultEvent(req Request, d Decision, callID string, resp json.RawMessage, callErr error) store.AuditEvent {
	ev := e.CallEvent(req, d, callID)
	ev.Event = store.EventConnectorToolResult
	if callErr != nil {
		// The error's text is not recorded: it originates in a remote provider
		// and can quote the request. That the call failed is the auditable fact.
		ev.Reason = "tool_failed"
		return ev
	}
	// Candidates are tried in the manifest's order, and a request-side one that
	// already identified the artifact wins: an id the CALLER named is the one an
	// auditor can correlate the call row with.
	if ev.ArtifactID == ArtifactUnknown {
		for _, ex := range d.Mapping.ArtifactID {
			if ex.Source != FromResponse {
				continue
			}
			if id, ok := Extract(ex, resp); ok {
				ev.ArtifactID = id
				// The artifact is now identified, so the digest has nothing
				// left to stand in for.
				delete(ev.Detail, "args_digest")
				break
			}
		}
	}
	return ev
}

func truncateDetail(s string) string {
	if len(s) <= store.MaxDetailValueLen {
		return s
	}
	return s[:store.MaxDetailValueLen]
}
