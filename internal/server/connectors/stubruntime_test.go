package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// The stub tool runtime. It stands in for the composed MCP gateway so that the
// manifest, the policy engine and the audit derivation can be proven with no
// network, no container and no provider — which is the whole point of this
// task: the declarative core is acceptable before any integration risk.

type stubCall struct {
	Provider string
	Tool     string
	Args     string
}

type stubRuntime struct {
	calls     []stubCall
	responses map[string]json.RawMessage
	failures  map[string]error
}

func newStubRuntime() *stubRuntime {
	return &stubRuntime{
		responses: map[string]json.RawMessage{},
		failures:  map[string]error{},
	}
}

func (s *stubRuntime) respond(tool string, body string) *stubRuntime {
	s.responses[tool] = json.RawMessage(body)
	return s
}

func (s *stubRuntime) fail(tool string, err error) *stubRuntime {
	s.failures[tool] = err
	return s
}

func (s *stubRuntime) CallTool(_ context.Context, provider, tool string, args json.RawMessage) (json.RawMessage, error) {
	s.calls = append(s.calls, stubCall{Provider: provider, Tool: tool, Args: string(args)})
	if err, ok := s.failures[tool]; ok {
		return nil, err
	}
	if resp, ok := s.responses[tool]; ok {
		return resp, nil
	}
	return json.RawMessage(`{"ok":true}`), nil
}

// recordingSink is the audit log under test control: it captures every row and
// can be made to fail at a chosen row, which is how the fail-closed ordering is
// proven (a passing suite says nothing about a path that only runs when the log
// is broken).
type recordingSink struct {
	events  []store.AuditEvent
	failAt  int // 1-based index of the append that fails; 0 = never
	appends int
}

var errSinkDown = errors.New("audit log is down")

func (r *recordingSink) AppendAudit(_ context.Context, e store.AuditEvent) error {
	r.appends++
	if r.failAt != 0 && r.appends == r.failAt {
		return errSinkDown
	}
	// The real store rejects any row outside the metadata vocabulary; applying
	// the same check here means a test row that the production log would refuse
	// cannot pass silently.
	if err := store.ValidateDetail(e.Detail); err != nil {
		return err
	}
	r.events = append(r.events, e)
	return nil
}

func (r *recordingSink) last() store.AuditEvent {
	if len(r.events) == 0 {
		return store.AuditEvent{}
	}
	return r.events[len(r.events)-1]
}

func (r *recordingSink) only(t *testing.T) store.AuditEvent {
	t.Helper()
	if len(r.events) != 1 {
		t.Fatalf("want exactly 1 audit row, got %d: %+v", len(r.events), r.events)
	}
	return r.events[0]
}

// --- fixtures ---------------------------------------------------------------

func loadManifest(t *testing.T, name string) Manifest {
	t.Helper()
	m, err := LoadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return m
}

func stubEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := Register(loadManifest(t, "stub.json"))
	if err != nil {
		t.Fatalf("register stub manifest: %v", err)
	}
	return e
}

func googleEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := Register(loadManifest(t, "google.json"))
	if err != nil {
		t.Fatalf("register google manifest: %v", err)
	}
	return e
}

// machineCaller is a fully attributed harness caller holding caps.
func machineCaller(caps ...policy.Capability) Caller {
	c := Caller{
		ObservedNodeID:   "nodeid-abc",
		ObservedNodeName: "danis-mac",
		MachineID:        "machine-1",
		Harness:          policy.HarnessClaudeCode,
		GrantID:          "grant-1",
	}
	for _, cap := range caps {
		c.Capabilities = append(c.Capabilities, string(cap))
	}
	return c
}

func readOnlyCaller() Caller  { return machineCaller(policy.ConnectorRead) }
func readWriteCaller() Caller { return machineCaller(policy.ConnectorRead, policy.ConnectorWrite) }
func fullCaller() Caller {
	return machineCaller(policy.ConnectorRead, policy.ConnectorWrite, policy.ConnectorDelete)
}

func req(provider, tool, args string, c Caller) Request {
	return Request{Provider: provider, Tool: tool, Args: json.RawMessage(args), Caller: c}
}

// assertNoPayload fails if any audited value carries a fragment of the request
// or response bodies. The audit log is metadata only, and that is a property of
// every row, not of the fields we remembered to check.
func assertNoPayload(t *testing.T, events []store.AuditEvent, fragments ...string) {
	t.Helper()
	for i, e := range events {
		values := []string{
			e.Event, string(e.ActorKind), e.ObservedNodeID, e.ObservedNodeName,
			e.AuthMachineID, e.Harness, e.GrantID, e.ActionClass, e.Tool,
			e.ArtifactID, string(e.Outcome), e.Reason, e.TokenFingerprint,
		}
		for k, v := range e.Detail {
			values = append(values, fmt.Sprintf("%s=%s", k, v))
		}
		for _, frag := range fragments {
			for _, v := range values {
				if containsFold(v, frag) {
					t.Fatalf("audit row %d leaked payload fragment %q in %q", i, frag, v)
				}
			}
		}
	}
}

func containsFold(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
