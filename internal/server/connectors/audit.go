package connectors

import (
	"encoding/json"

	"github.com/DanielKillenberger/homeplane/internal/store"
)

// Audit derivation. Everything an audit row says about a connector call comes
// from the manifest (action class, artifact identity) or from a one-way digest
// of the request arguments — never from inspecting a payload for meaning. That
// is what keeps the audit trail generic across arbitrary MCP tools without any
// connector-specific code, and structurally incapable of holding a body.

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
		Tool:             req.Tool,
		Detail: map[string]string{
			"provider":    req.Provider,
			"args_digest": ArgsDigest(req.Args),
			"call_id":     callID,
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
	// the request; otherwise the args digest above stands in for it and the
	// artifact is recorded as unknown.
	ev.ArtifactID = ArtifactUnknown
	if ex := d.Mapping.ArtifactID; ex != nil && ex.Source == FromRequest {
		if id, ok := Extract(*ex, req.Args); ok {
			ev.ArtifactID = id
		}
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
	if ex := d.Mapping.ArtifactID; ex != nil && ex.Source == FromResponse {
		if id, ok := Extract(*ex, resp); ok {
			ev.ArtifactID = id
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
