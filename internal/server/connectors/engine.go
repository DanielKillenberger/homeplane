package connectors

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// Denial reasons. They are stable strings because they are written into audit
// rows and read back by operators and by the acceptance gates.
const (
	// ReasonUnknownProvider — the call named a connector that is not in the
	// manifest at all.
	ReasonUnknownProvider = "unknown_provider"
	// ReasonUnmappedTool — the connector exists, the tool has no mapping. This
	// is the fail-closed case a connector upgrade lands in.
	ReasonUnmappedTool = "unmapped_tool"
	// ReasonExcludedTool — the tool is explicitly out of scope (D18 keeps
	// Drive's write tools here).
	ReasonExcludedTool = "excluded_tool"
	// ReasonUnresolvedAction — the tool is mapped by an action selector and the
	// call's discriminating argument named no declared case. The call cannot be
	// classified, so it is neither authorized nor forwarded.
	ReasonUnresolvedAction = "unresolved_action"
	// ReasonCapabilityMissing — the tool is mapped, but the calling grant does
	// not carry the capability its action class requires.
	ReasonCapabilityMissing = "capability_missing"
	// ReasonUnauthenticated — a machine-actor call arrived without a resolved
	// grant identity. Never forwarded.
	ReasonUnauthenticated = "unauthenticated"
	// ReasonInvalidActor — the call declared an actor kind outside the model.
	ReasonInvalidActor = "invalid_actor"
)

// ErrDenied is returned by Broker.Invoke for every refusal; the Decision on the
// error carries the reason and the audited row's classification.
var ErrDenied = errors.New("connectors: denied")

// Caller is the resolved identity behind a tool call. It mirrors the control
// plane's attribution model: observed (WhoIs) identity is separate from
// authenticated (credential-proved) identity, and the capability set is the one
// the SERVER issued to the grant — never a set the caller names for itself.
type Caller struct {
	// Actor is the actor model of the caller. Empty means store.ActorMachine.
	Actor store.ActorKind

	// Observed identity, from WhoIs. Absent for operator/system actors.
	ObservedNodeID   string
	ObservedNodeName string

	// Authenticated identity, from the presented grant token.
	MachineID string
	Harness   string
	GrantID   string

	// Capabilities is the grant's issued capability set.
	Capabilities []string
}

func (c Caller) actorKind() store.ActorKind {
	if c.Actor == "" {
		return store.ActorMachine
	}
	return c.Actor
}

func (c Caller) hasCapability(want policy.Capability) bool {
	for _, got := range c.Capabilities {
		if policy.Capability(strings.ToLower(strings.TrimSpace(got))) == want {
			return true
		}
	}
	return false
}

// Request is one tool invocation presented for authorization.
type Request struct {
	Provider string
	Tool     string
	// Args are the tool's request arguments. They are used for the argument
	// digest and for request-source artifact extraction, and are never stored.
	Args   json.RawMessage
	Caller Caller
}

// Decision is the manifest's verdict on a Request.
type Decision struct {
	Allowed bool
	// Reason is one of the Reason* constants; empty when allowed.
	Reason string
	// ActionClass is the manifest-declared class, or ActionUnknown when the
	// call was refused before a class could be established.
	ActionClass ActionClass
	// RequiredCapability is the capability the mapping demands; empty when the
	// tool is not mapped.
	RequiredCapability policy.Capability
	// Mapping is the matched mapping; the zero value when unmapped.
	Mapping ToolMapping
	// ExclusionReason is the manifest's recorded reason when Reason is
	// ReasonExcludedTool.
	ExclusionReason string
}

// PolicyViolation reports whether the refusal is a manifest-level violation
// (unknown connector, unclassified or excluded tool) rather than an
// authorization failure of an otherwise well-formed call.
func (d Decision) PolicyViolation() bool {
	switch d.Reason {
	case ReasonUnknownProvider, ReasonUnmappedTool, ReasonExcludedTool, ReasonUnresolvedAction:
		return true
	}
	return false
}

// Engine is a registered manifest: an immutable, indexed authorization input.
type Engine struct {
	manifest   Manifest
	connectors map[string]*registration
}

type registration struct {
	connector Connector
	tools     map[string]ToolMapping
	excluded  map[string]string
}

// Register validates a manifest and indexes it for authorization. A manifest
// that does not validate is REFUSED — there is no partial registration, so a
// half-declared connector can never serve traffic.
func Register(m Manifest) (*Engine, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	e := &Engine{manifest: m, connectors: make(map[string]*registration, len(m.Connectors))}
	for _, c := range m.Connectors {
		reg := &registration{
			connector: c,
			tools:     make(map[string]ToolMapping, len(c.Tools)),
			excluded:  make(map[string]string, len(c.Excluded)),
		}
		for _, t := range c.Tools {
			reg.tools[t.Tool] = t
		}
		for _, x := range c.Excluded {
			reg.excluded[x.Tool] = x.Reason
		}
		e.connectors[c.Provider] = reg
	}
	return e, nil
}

// Manifest returns the registered manifest.
func (e *Engine) Manifest() Manifest { return e.manifest }

// Providers lists the registered providers, sorted.
func (e *Engine) Providers() []string { return e.manifest.Providers() }

// Connector returns a registered connector's declaration.
func (e *Engine) Connector(provider string) (Connector, bool) {
	reg, ok := e.connectors[provider]
	if !ok {
		return Connector{}, false
	}
	return reg.connector, true
}

// CredentialRefs maps each provider to the secret reference its credential
// lives under. The edge uses it to fetch credentials without knowing anything
// provider-specific.
func (e *Engine) CredentialRefs() map[string]string {
	out := make(map[string]string, len(e.connectors))
	for p, reg := range e.connectors {
		out[p] = reg.connector.CredentialRef
	}
	return out
}

// Authorize is the whole authorization decision, and it is a pure function of
// the manifest and the caller's issued capabilities. There is no provider
// name, no tool name and no special case in this function: that is what makes
// a new connector a manifest entry rather than a code change (R12).
func (e *Engine) Authorize(req Request) Decision {
	switch req.Caller.actorKind() {
	case store.ActorMachine:
		// A machine-actor call must be fully attributed before it can be
		// authorized: without a grant there is no capability set to check, and
		// an unattributable call is never forwarded.
		if req.Caller.MachineID == "" || req.Caller.GrantID == "" || req.Caller.Harness == "" {
			return Decision{Reason: ReasonUnauthenticated, ActionClass: ActionUnknown}
		}
	case store.ActorOperator, store.ActorSystem:
	default:
		return Decision{Reason: ReasonInvalidActor, ActionClass: ActionUnknown}
	}

	reg, ok := e.connectors[req.Provider]
	if !ok {
		return Decision{Reason: ReasonUnknownProvider, ActionClass: ActionUnknown}
	}

	mapping, mapped := reg.tools[req.Tool]
	if !mapped {
		if why, excluded := reg.excluded[req.Tool]; excluded {
			return Decision{Reason: ReasonExcludedTool, ActionClass: ActionUnknown, ExclusionReason: why}
		}
		return Decision{Reason: ReasonUnmappedTool, ActionClass: ActionUnknown}
	}

	// The class is resolved per call, because a polymorphic tool's class is a
	// property of the CALL, not of the tool (see ActionSelector). A call whose
	// class cannot be established is refused: an unclassifiable call has no
	// capability to check and nothing truthful to audit.
	class, resolved := mapping.ResolveActionClass(req.Args)
	if !resolved {
		return Decision{Reason: ReasonUnresolvedAction, ActionClass: ActionUnknown, Mapping: mapping}
	}

	need := classCapability[class]
	if !req.Caller.hasCapability(need) {
		return Decision{
			Reason:             ReasonCapabilityMissing,
			ActionClass:        class,
			RequiredCapability: need,
			Mapping:            mapping,
		}
	}

	return Decision{
		Allowed:            true,
		ActionClass:        class,
		RequiredCapability: need,
		Mapping:            mapping,
	}
}

// DeniedError renders a decision as a caller-facing error. It names what was
// refused and why, and never leaks the manifest's shape beyond the tool asked
// for.
func (d Decision) DeniedError(req Request) error {
	switch d.Reason {
	case ReasonUnknownProvider:
		return fmt.Errorf("%w: unknown connector %q", ErrDenied, req.Provider)
	case ReasonUnmappedTool:
		return fmt.Errorf("%w: tool %q is not authorized by the connector manifest", ErrDenied, req.Tool)
	case ReasonExcludedTool:
		return fmt.Errorf("%w: tool %q is excluded by connector policy (%s)", ErrDenied, req.Tool, d.ExclusionReason)
	case ReasonUnresolvedAction:
		return fmt.Errorf("%w: tool %q does not say which action it performs, so the connector manifest "+
			"cannot classify the call", ErrDenied, req.Tool)
	case ReasonCapabilityMissing:
		return fmt.Errorf("%w: tool %q is %s-class and requires capability %q",
			ErrDenied, req.Tool, d.ActionClass, d.RequiredCapability)
	case ReasonUnauthenticated:
		return fmt.Errorf("%w: connector calls require an authenticated grant", ErrDenied)
	case ReasonInvalidActor:
		return fmt.Errorf("%w: unsupported actor kind", ErrDenied)
	default:
		return fmt.Errorf("%w: %s", ErrDenied, d.Reason)
	}
}

// UnmappedTools reports which of the supplied gateway-advertised tools a
// connector does not authorize. The edge uses it at connect time to log (and a
// gate to assert) exactly what a connector upgrade added. Result is sorted.
func (e *Engine) UnmappedTools(provider string, advertised []string) []string {
	reg, ok := e.connectors[provider]
	if !ok {
		out := append([]string(nil), advertised...)
		sort.Strings(out)
		return out
	}
	var out []string
	for _, t := range advertised {
		if _, mapped := reg.tools[t]; !mapped {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}
