package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// End to end against the stub runtime: authorize, record, forward, record the
// result — with no gateway, no container and no provider anywhere in the path.

const secretBody = "the quarterly plan nobody outside should read"

func newHarness(t *testing.T) (*Broker, *stubRuntime, *recordingSink) {
	t.Helper()
	rt := newStubRuntime()
	sink := &recordingSink{}
	return NewBroker(stubEngine(t), rt, sink), rt, sink
}

func TestAllowedCallIsForwardedAndAuditedFromTheManifest(t *testing.T) {
	b, rt, sink := newHarness(t)
	rt.respond("get_note", `{"note":{"id":"n-1","body":"`+secretBody+`"}}`)

	resp, err := b.Invoke(context.Background(),
		req("stub-notes", "get_note", `{"note_id":"n-1"}`, readOnlyCaller()))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !strings.Contains(string(resp), "n-1") {
		t.Fatalf("response not returned to the caller: %s", resp)
	}
	if len(rt.calls) != 1 || rt.calls[0].Tool != "get_note" {
		t.Fatalf("runtime calls = %+v", rt.calls)
	}

	if len(sink.events) != 2 {
		t.Fatalf("want a call row and a result row, got %d: %+v", len(sink.events), sink.events)
	}
	call, result := sink.events[0], sink.events[1]

	if call.Event != store.EventConnectorToolCall || call.Outcome != store.OutcomeAllowed {
		t.Errorf("call row = %s/%s", call.Event, call.Outcome)
	}
	if call.ActionClass != string(ActionRead) || call.Tool != "get_note" {
		t.Errorf("call row class/tool = %s/%s", call.ActionClass, call.Tool)
	}
	if call.ArtifactID != "n-1" {
		t.Errorf("artifact id = %q, want the extractor's value n-1", call.ArtifactID)
	}
	if call.ActorKind != store.ActorMachine || call.AuthMachineID != "machine-1" ||
		call.GrantID != "grant-1" || call.Harness != policy.HarnessClaudeCode {
		t.Errorf("attribution wrong: %+v", call)
	}
	if call.ObservedNodeID != "nodeid-abc" || call.ObservedNodeName != "danis-mac" {
		t.Errorf("observed identity wrong: %+v", call)
	}
	if call.Detail["provider"] != "stub-notes" {
		t.Errorf("detail = %v", call.Detail)
	}
	// The artifact was identified from the manifest's extractor, so the digest
	// — which exists only to stand in for an identity — must NOT be recorded.
	if _, ok := call.Detail["args_digest"]; ok {
		t.Errorf("args digest recorded alongside a known artifact id: %v", call.Detail)
	}
	if call.Detail["required_capability"] != string(policy.ConnectorRead) {
		t.Errorf("required capability = %q", call.Detail["required_capability"])
	}
	if result.Event != store.EventConnectorToolResult || result.Reason != "" {
		t.Errorf("result row = %s reason %q", result.Event, result.Reason)
	}
	if result.Detail["call_id"] == "" || result.Detail["call_id"] != call.Detail["call_id"] {
		t.Errorf("call id does not correlate the two rows: %q vs %q",
			call.Detail["call_id"], result.Detail["call_id"])
	}

	assertNoPayload(t, sink.events, secretBody, "quarterly")
}

// The artifact identity of a created object exists only in the response; the
// manifest says so declaratively and the result row picks it up.
func TestResponseExtractorRecordsTheCreatedArtifact(t *testing.T) {
	b, rt, sink := newHarness(t)
	rt.respond("create_note", `{"note":{"id":"n-created","body":"`+secretBody+`"}}`)

	if _, err := b.Invoke(context.Background(),
		req("stub-notes", "create_note", `{"title":"weekly","body":"`+secretBody+`"}`, readWriteCaller())); err != nil {
		t.Fatalf("invoke: %v", err)
	}

	call, result := sink.events[0], sink.events[1]
	if call.ArtifactID != ArtifactUnknown {
		t.Errorf("pre-call artifact id = %q, want %q (the id does not exist yet)", call.ArtifactID, ArtifactUnknown)
	}
	if call.Detail["args_digest"] == "" {
		t.Error("a call with no request-side identity must still carry an args digest")
	}
	if result.ArtifactID != "n-created" {
		t.Errorf("result artifact id = %q, want n-created", result.ArtifactID)
	}
	if _, ok := result.Detail["args_digest"]; ok {
		t.Errorf("the result row kept an args digest after identifying the artifact: %v", result.Detail)
	}
	assertNoPayload(t, sink.events, secretBody, "weekly")
}

// A tool with no extractor records the digest and says `unknown` rather than
// guessing at an identity.
func TestToolWithoutAnExtractorRecordsDigestAndUnknown(t *testing.T) {
	b, _, sink := newHarness(t)

	if _, err := b.Invoke(context.Background(),
		req("stub-notes", "list_notes", `{"query":"`+secretBody+`"}`, readOnlyCaller())); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	for _, e := range sink.events {
		if e.ArtifactID != ArtifactUnknown {
			t.Errorf("artifact id = %q, want %q", e.ArtifactID, ArtifactUnknown)
		}
		if e.Detail["args_digest"] != ArgsDigest(json.RawMessage(`{"query":"`+secretBody+`"}`)) {
			t.Errorf("args digest = %q, want the digest of the request arguments", e.Detail["args_digest"])
		}
	}
	assertNoPayload(t, sink.events, secretBody)
}

func TestCapabilityDenialIsAuditedAndNeverForwarded(t *testing.T) {
	b, rt, sink := newHarness(t)

	_, err := b.Invoke(context.Background(),
		req("stub-notes", "create_note", `{"body":"`+secretBody+`"}`, readOnlyCaller()))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	if len(rt.calls) != 0 {
		t.Fatalf("a denied call reached the runtime: %+v", rt.calls)
	}

	e := sink.only(t)
	if e.Event != store.EventConnectorDenied || e.Outcome != store.OutcomeDenied {
		t.Errorf("row = %s/%s, want connector_denied/denied", e.Event, e.Outcome)
	}
	if e.Reason != ReasonCapabilityMissing {
		t.Errorf("reason = %q", e.Reason)
	}
	if e.ActionClass != string(ActionWrite) {
		t.Errorf("action class = %q, want write — the class is known even when the call is refused", e.ActionClass)
	}
	if e.Detail["required_capability"] != string(policy.ConnectorWrite) {
		t.Errorf("required capability = %q", e.Detail["required_capability"])
	}
	assertNoPayload(t, sink.events, secretBody)
}

func TestUnmappedToolIsDeniedAndAuditedAsAPolicyViolation(t *testing.T) {
	b, rt, sink := newHarness(t)

	_, err := b.Invoke(context.Background(),
		req("stub-notes", "summarize_notes", `{"body":"`+secretBody+`"}`, fullCaller()))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	if len(rt.calls) != 0 {
		t.Fatalf("an unmapped tool reached the runtime: %+v", rt.calls)
	}

	e := sink.only(t)
	if e.Event != store.EventPolicyViolation || e.Outcome != store.OutcomeDenied {
		t.Errorf("row = %s/%s, want policy_violation/denied", e.Event, e.Outcome)
	}
	if e.Reason != ReasonUnmappedTool {
		t.Errorf("reason = %q", e.Reason)
	}
	if e.ActionClass != string(ActionUnknown) {
		t.Errorf("action class = %q, want unknown", e.ActionClass)
	}
	if e.Tool != "summarize_notes" {
		t.Errorf("tool = %q", e.Tool)
	}
	assertNoPayload(t, sink.events, secretBody)
}

func TestExcludedToolRecordsWhyItWasExcluded(t *testing.T) {
	b, rt, sink := newHarness(t)

	if _, err := b.Invoke(context.Background(),
		req("stub-notes", "export_archive", `{}`, fullCaller())); !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	if len(rt.calls) != 0 {
		t.Fatalf("an excluded tool reached the runtime: %+v", rt.calls)
	}
	e := sink.only(t)
	if e.Event != store.EventPolicyViolation || e.Reason != ReasonExcludedTool {
		t.Fatalf("row = %s reason %q", e.Event, e.Reason)
	}
	if !strings.Contains(e.Detail["exclusion_reason"], "bulk export") {
		t.Fatalf("exclusion reason = %q", e.Detail["exclusion_reason"])
	}
}

func TestUnknownConnectorIsDeniedAndAudited(t *testing.T) {
	b, rt, sink := newHarness(t)

	if _, err := b.Invoke(context.Background(),
		req("gmail", "send_message", `{}`, fullCaller())); !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	if len(rt.calls) != 0 {
		t.Fatal("an unknown connector reached the runtime")
	}
	if e := sink.only(t); e.Event != store.EventPolicyViolation || e.Reason != ReasonUnknownProvider {
		t.Fatalf("row = %s reason %q", e.Event, e.Reason)
	}
}

// Fail-closed ordering: when the audit log cannot take the decision row, the
// call is refused rather than forwarded unrecorded. This is the path a green
// suite would otherwise never execute.
func TestCallIsNotForwardedWhenItCannotBeAudited(t *testing.T) {
	rt := newStubRuntime()
	sink := &recordingSink{failAt: 1}
	b := NewBroker(stubEngine(t), rt, sink)

	_, err := b.Invoke(context.Background(), req("stub-notes", "get_note", `{"note_id":"n-1"}`, readOnlyCaller()))
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("error = %v, want ErrAuditUnavailable", err)
	}
	if len(rt.calls) != 0 {
		t.Fatalf("the call was forwarded although it could not be recorded: %+v", rt.calls)
	}
}

func TestDenialIsRefusedLoudlyWhenItCannotBeAudited(t *testing.T) {
	rt := newStubRuntime()
	sink := &recordingSink{failAt: 1}
	b := NewBroker(stubEngine(t), rt, sink)

	_, err := b.Invoke(context.Background(), req("stub-notes", "summarize_notes", `{}`, fullCaller()))
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("error = %v, want ErrAuditUnavailable (a denial nobody can see is not a denial)", err)
	}
	if len(rt.calls) != 0 {
		t.Fatal("the runtime was reached")
	}
}

// The result row cannot gate a call that already ran, but its loss must still
// surface: the caller gets an error rather than a response nothing recorded.
func TestUnrecordableResultSurfacesToTheCaller(t *testing.T) {
	rt := newStubRuntime()
	rt.respond("create_note", `{"note":{"id":"n-created"}}`)
	sink := &recordingSink{failAt: 2}
	b := NewBroker(stubEngine(t), rt, sink)

	_, err := b.Invoke(context.Background(), req("stub-notes", "create_note", `{"title":"x"}`, readWriteCaller()))
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("error = %v, want ErrAuditUnavailable", err)
	}
	if len(rt.calls) != 1 {
		t.Fatalf("runtime calls = %+v", rt.calls)
	}
	if len(sink.events) != 1 || sink.events[0].Event != store.EventConnectorToolCall {
		t.Fatalf("the pre-call row must survive: %+v", sink.events)
	}
}

// A provider-side failure is not a policy denial and must not be logged as one,
// and the provider's error text never reaches the audit log.
func TestToolFailureIsAuditedAsAFailureNotADenial(t *testing.T) {
	rt := newStubRuntime()
	rt.fail("update_note", errors.New("upstream said: "+secretBody))
	sink := &recordingSink{}
	b := NewBroker(stubEngine(t), rt, sink)

	_, err := b.Invoke(context.Background(),
		req("stub-notes", "update_note", `{"note_id":"n-1"}`, readWriteCaller()))
	if !errors.Is(err, ErrToolFailed) {
		t.Fatalf("error = %v, want ErrToolFailed", err)
	}
	result := sink.last()
	if result.Event != store.EventConnectorToolResult {
		t.Fatalf("result row = %s", result.Event)
	}
	if result.Outcome != store.OutcomeAllowed {
		t.Errorf("outcome = %q: the call was permitted; only the tool failed", result.Outcome)
	}
	if result.Reason != "tool_failed" {
		t.Errorf("reason = %q", result.Reason)
	}
	assertNoPayload(t, sink.events, secretBody, "upstream said")
}

// Every row this package produces must be acceptable to the real audit log's
// metadata vocabulary — the sink applies store.ValidateDetail, so this walks
// the whole tool surface through it.
func TestEveryProducedRowSatisfiesTheAuditMetadataVocabulary(t *testing.T) {
	b, rt, sink := newHarness(t)
	rt.respond("create_note", `{"note":{"id":"n-1"}}`)

	calls := []struct {
		tool   string
		caller Caller
	}{
		{"list_notes", readOnlyCaller()},
		{"get_note", readOnlyCaller()},
		{"create_note", readWriteCaller()},
		{"update_note", readWriteCaller()},
		{"delete_note", fullCaller()},
		{"share_note", fullCaller()},
		{"export_archive", fullCaller()},
		{"summarize_notes", fullCaller()},
	}
	for _, c := range calls {
		_, _ = b.Invoke(context.Background(), req("stub-notes", c.tool, `{"note_id":"n-1"}`, c.caller))
	}
	if len(sink.events) == 0 {
		t.Fatal("no rows recorded")
	}
	for _, e := range sink.events {
		if err := store.ValidateDetail(e.Detail); err != nil {
			t.Errorf("row %s: %v", e.Event, err)
		}
		if e.Tool == "" || e.ActionClass == "" || e.ArtifactID == "" || e.Outcome == "" {
			t.Errorf("row %s is missing a required audit field: %+v", e.Event, e)
		}
		if e.TokenFingerprint != "" {
			t.Errorf("row %s carries a token fingerprint; connector calls are attributed by grant", e.Event)
		}
	}
}
