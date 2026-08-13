package connectors

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/DanielKillenberger/homeplane/internal/store"
)

// ToolRuntime is the MCP tool surface the broker forwards admitted calls to.
// In production it is the composed gateway (D6: ToolHive over loopback); in
// tests it is an in-process stub. The broker knows nothing else about it —
// which is why the policy and audit logic can be proven without a gateway.
type ToolRuntime interface {
	CallTool(ctx context.Context, provider, tool string, args json.RawMessage) (json.RawMessage, error)
}

// AuditSink is where audit rows go. The store's append-only audit log
// implements it; tests substitute a sink that can fail on demand.
// It is satisfied as-is by *store.SQLite.
type AuditSink interface {
	AppendAudit(ctx context.Context, e store.AuditEvent) error
}

// ErrAuditUnavailable means a call could not be recorded. It is returned
// INSTEAD of forwarding the call: with an authoritative audit log, an
// unrecorded action is worse than a refused one.
var ErrAuditUnavailable = errors.New("connectors: audit log unavailable")

// ErrToolFailed wraps a runtime failure of an admitted call.
var ErrToolFailed = errors.New("connectors: tool call failed")

// Broker is the in-process invocation path: authorize against the manifest,
// record, forward, record the result. The edge (task .16) is a transport in
// front of this; every rule that matters is decided here, which is why it can
// be tested end to end with no network.
type Broker struct {
	engine  *Engine
	runtime ToolRuntime
	audit   AuditSink
	newID   func() string
}

// NewBroker wires an engine to a runtime and an audit sink.
func NewBroker(e *Engine, rt ToolRuntime, sink AuditSink) *Broker {
	return &Broker{engine: e, runtime: rt, audit: sink, newID: newCallID}
}

// Engine exposes the registered manifest for callers that only need decisions.
func (b *Broker) Engine() *Engine { return b.engine }

// Invoke authorizes and (if admitted) performs one tool call.
//
// Ordering is the security property: the decision is recorded BEFORE the tool
// runs, and if that record cannot be written the call is refused rather than
// forwarded unlogged. A denial is likewise refused only after its policy
// violation is on the record.
func (b *Broker) Invoke(ctx context.Context, req Request) (json.RawMessage, error) {
	decision := b.engine.Authorize(req)
	callID := b.newID()

	if err := b.audit.AppendAudit(ctx, b.engine.CallEvent(req, decision, callID)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	if !decision.Allowed {
		return nil, decision.DeniedError(req)
	}

	resp, callErr := b.runtime.CallTool(ctx, req.Provider, req.Tool, req.Args)

	// The call has now had its effect, so the result row cannot gate it — but a
	// missing result row still means the trail is incomplete, and the caller is
	// told so rather than being handed a response that nothing recorded.
	if err := b.audit.AppendAudit(ctx, b.engine.ResultEvent(req, decision, callID, resp, callErr)); err != nil {
		return nil, fmt.Errorf("%w: call %s completed but its result could not be recorded: %v",
			ErrAuditUnavailable, callID, err)
	}
	if callErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrToolFailed, callErr)
	}
	return resp, nil
}

func newCallID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// A call id only correlates two rows of the same call; if the CSPRNG is
		// unavailable the rows must still be written.
		return "unavailable"
	}
	return hex.EncodeToString(buf[:])
}
