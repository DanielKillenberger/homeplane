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

// --- capability may never diverge from the action class ----------------------

// A manifest edit must not be able to hand a read-only grant write or delete
// authority by declaring a weaker required capability than the tool's class.
func TestCapabilityMayNotDivergeFromTheActionClass(t *testing.T) {
	base := string(mustReadFixture(t, "stub.json"))

	weakened := strings.Replace(base,
		`"tool": "delete_note",
          "action_class": "delete",`,
		`"tool": "delete_note",
          "action_class": "delete",
          "capability": "connector.read",`, 1)
	if weakened == base {
		t.Fatal("fixture mutation failed")
	}

	_, err := Parse([]byte(weakened))
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("error = %v, want ErrInvalidManifest — a delete tool must not be able to require connector.read", err)
	}
	if !strings.Contains(err.Error(), "connector.delete") {
		t.Fatalf("error %q does not say what the tool must require", err)
	}

	// Strengthening is refused for the same reason: the capability is a
	// function of the class, not an independent knob.
	strengthened := strings.Replace(base,
		`{ "tool": "list_notes", "action_class": "read" },`,
		`{ "tool": "list_notes", "action_class": "read", "capability": "connector.delete" },`, 1)
	if _, err := Parse([]byte(strengthened)); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("error = %v, want ErrInvalidManifest", err)
	}

	// Restating the class's own capability is fine — manifests may be explicit.
	restated := strings.Replace(base,
		`{ "tool": "list_notes", "action_class": "read" },`,
		`{ "tool": "list_notes", "action_class": "read", "capability": "connector.read" },`, 1)
	m, err := Parse([]byte(restated))
	if err != nil {
		t.Fatalf("restating the class capability must be accepted: %v", err)
	}
	e, err := Register(m)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if d := e.Authorize(req("stub-notes", "list_notes", `{}`, readOnlyCaller())); !d.Allowed {
		t.Fatalf("decision = %+v, want allowed", d)
	}
}

// The engine's authority check must read the class, not a mapping field: even a
// hand-built mapping that names a weaker capability cannot admit a read-only
// grant to a delete tool.
func TestAuthorizeDerivesAuthorityFromTheClassNotTheMappingField(t *testing.T) {
	m := loadManifest(t, "stub.json")
	for i := range m.Connectors[0].Tools {
		if m.Connectors[0].Tools[i].Tool == "delete_note" {
			m.Connectors[0].Tools[i].Capability = policy.ConnectorRead
		}
	}
	// Register would refuse this manifest; index it directly to prove the
	// decision path itself does not trust the field.
	e := &Engine{manifest: m, connectors: map[string]*registration{}}
	reg := &registration{connector: m.Connectors[0], tools: map[string]ToolMapping{}, excluded: map[string]string{}}
	for _, tool := range m.Connectors[0].Tools {
		reg.tools[tool.Tool] = tool
	}
	e.connectors[m.Connectors[0].Provider] = reg

	d := e.Authorize(req("stub-notes", "delete_note", `{"note_id":"n-1"}`, readOnlyCaller()))
	if d.Allowed {
		t.Fatal("a read-only grant was admitted to a delete-class tool")
	}
	if d.RequiredCapability != policy.ConnectorDelete {
		t.Fatalf("required capability = %q, want connector.delete", d.RequiredCapability)
	}

	if _, err := Register(m); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("Register error = %v, want ErrInvalidManifest", err)
	}
}

// --- caller-supplied names are bounded before they reach the log -------------

func TestManifestRefusesUnboundedOrMalformedToolNames(t *testing.T) {
	base := string(mustReadFixture(t, "stub.json"))

	long := strings.Repeat("t", MaxIdentifierLen+1)
	cases := map[string]string{
		"oversized tool name":       strings.Replace(base, `"list_notes"`, `"`+long+`"`, -1),
		"tool name with whitespace": strings.Replace(base, `"list_notes"`, `"list notes"`, -1),
		"tool name with newline":    strings.Replace(base, `"list_notes"`, `"list\nnotes"`, -1),
	}
	for name, mutated := range cases {
		t.Run(name, func(t *testing.T) {
			if mutated == base {
				t.Fatal("fixture mutation failed")
			}
			if _, err := Parse([]byte(mutated)); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("error = %v, want ErrInvalidManifest", err)
			}
		})
	}

	oversizedProvider := strings.Replace(base, `"provider": "stub-notes"`,
		`"provider": "`+strings.Repeat("p", MaxIdentifierLen+1)+`"`, 1)
	if _, err := Parse([]byte(oversizedProvider)); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("error = %v, want ErrInvalidManifest", err)
	}
}

// A denial must stay recordable no matter what the caller sent. An unbounded or
// malformed name is reduced to a fixed marker plus a digest — which keeps the
// row inside the store's metadata vocabulary, so the denial is never lost
// because the attacker chose a long enough tool name.
func TestOversizedCallerSuppliedNamesAreReducedAndStillAudited(t *testing.T) {
	rt := newStubRuntime()
	sink := &recordingSink{}
	b := NewBroker(stubEngine(t), rt, sink)

	hugeTool := strings.Repeat("A", 4096)
	hugeProvider := strings.Repeat("B", 4096) + secretBody

	_, err := b.Invoke(context.Background(), req(hugeProvider, hugeTool, `{}`, fullCaller()))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	if len(rt.calls) != 0 {
		t.Fatal("the runtime was reached")
	}

	e := sink.only(t) // the sink applies store.ValidateDetail: the row is storable
	if len(e.Tool) > MaxIdentifierLen || !strings.HasPrefix(e.Tool, unrecognizedPrefix) {
		t.Fatalf("tool recorded as %q (%d bytes)", e.Tool, len(e.Tool))
	}
	if p := e.Detail["provider"]; len(p) > store.MaxDetailValueLen || !strings.HasPrefix(p, unrecognizedPrefix) {
		t.Fatalf("provider recorded as %q (%d bytes)", p, len(p))
	}
	if e.Event != store.EventPolicyViolation || e.Reason != ReasonUnknownProvider {
		t.Fatalf("row = %s reason %q", e.Event, e.Reason)
	}
	assertNoPayload(t, sink.events, secretBody)

	// Repeated probes with the same name correlate; different names do not.
	if safeName(hugeTool) != safeName(hugeTool) {
		t.Fatal("the same name digested differently")
	}
	if safeName(hugeTool) == safeName(hugeTool+"x") {
		t.Fatal("distinct names collided")
	}
	if safeName("") != UnnamedMarker {
		t.Fatalf("empty name = %q", safeName(""))
	}
	if got := safeName("google-calendar"); got != "google-calendar" {
		t.Fatalf("a well-formed name must be recorded verbatim, got %q", got)
	}
}

// The same reduction must also hold through the REAL store, which is where an
// unbounded value would actually have been refused.
func TestAMalformedNameDoesNotPreventPersistingTheDenial(t *testing.T) {
	db := newRealStore(t)
	b := NewBroker(stubEngine(t), newStubRuntime(), db)

	_, err := b.Invoke(context.Background(),
		req("stub-notes", strings.Repeat("x", 9000), `{}`, fullCaller()))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	rows, err := db.QueryAudit(context.Background(), store.AuditQuery{Limit: 10})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(rows) != 1 || rows[0].Event != store.EventPolicyViolation {
		t.Fatalf("the denial was not persisted: %+v", rows)
	}
}

// --- numeric identities survive at full precision ---------------------------

func TestLargeIntegerIdentitiesAreNotRoundedByJSONDecoding(t *testing.T) {
	// Above 2^53 float64 cannot represent consecutive integers: decoding into
	// float64 turns ...993 into ...992 — a different object's id.
	const big = "9007199254740993"
	doc := json.RawMessage(`{"event":{"id":` + big + `}}`)

	got, ok := Extract(Extractor{Source: FromResponse, Pointer: "$.event.id"}, doc)
	if !ok {
		t.Fatal("extraction failed")
	}
	if got != big {
		t.Fatalf("artifact id = %q, want %q", got, big)
	}

	// And the digest must distinguish two ids that float64 would merge.
	a := ArgsDigest(json.RawMessage(`{"id":9007199254740993}`))
	bb := ArgsDigest(json.RawMessage(`{"id":9007199254740992}`))
	if a == bb {
		t.Fatal("two distinct 64-bit ids produced the same args digest")
	}
	// Fractions keep their literal form too.
	if got, _ := Extract(Extractor{Source: FromRequest, Pointer: "$.v"}, json.RawMessage(`{"v":1.500}`)); got != "1.500" {
		t.Fatalf("fractional value = %q, want the literal 1.500", got)
	}
}

// --- the args digest is a fallback, not a companion --------------------------

func TestArgsDigestIsRecordedOnlyWhenTheArtifactStaysUnknown(t *testing.T) {
	b, rt, sink := newHarness(t)
	rt.respond("create_note", `{"note":{"id":"n-created"}}`)

	// Request-side extractor hits: no digest.
	if _, err := b.Invoke(context.Background(),
		req("stub-notes", "update_note", `{"note_id":"n-7"}`, readWriteCaller())); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	for _, e := range sink.events {
		if e.ArtifactID != "n-7" {
			t.Fatalf("artifact id = %q", e.ArtifactID)
		}
		if _, ok := e.Detail["args_digest"]; ok {
			t.Fatalf("row %s recorded a digest beside a known artifact", e.Event)
		}
	}

	// Request-side extractor misses (the argument is absent): digest stands in.
	sink.events = nil
	if _, err := b.Invoke(context.Background(),
		req("stub-notes", "update_note", `{"other":"x"}`, readWriteCaller())); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	for _, e := range sink.events {
		if e.ArtifactID != ArtifactUnknown || e.Detail["args_digest"] == "" {
			t.Fatalf("row %s = artifact %q digest %q", e.Event, e.ArtifactID, e.Detail["args_digest"])
		}
	}

	// Response-side extractor: the pre-call row cannot know the id, so it
	// carries the digest; the result row identifies it and drops the digest.
	sink.events = nil
	if _, err := b.Invoke(context.Background(),
		req("stub-notes", "create_note", `{"title":"x"}`, readWriteCaller())); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if sink.events[0].Detail["args_digest"] == "" {
		t.Fatal("the pre-call row must carry a digest while the artifact is unknown")
	}
	if _, ok := sink.events[1].Detail["args_digest"]; ok {
		t.Fatal("the result row kept a digest after identifying the artifact")
	}
}

// --- the result row outlives the caller's context ---------------------------

// A harness that hangs up while the provider is working must not be able to
// cancel the record of a call that already had its effect.
func TestResultRowSurvivesCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	rt := newStubRuntime()
	rt.respond("create_note", `{"note":{"id":"n-created"}}`)
	// The client disconnects while the provider is executing.
	rt.before = func() { cancel() }

	sink := &ctxSensitiveSink{}
	b := NewBroker(stubEngine(t), rt, sink)

	_, err := b.Invoke(ctx, req("stub-notes", "create_note", `{"title":"x"}`, readWriteCaller()))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if len(sink.events) != 2 {
		t.Fatalf("want the call row and the result row, got %d", len(sink.events))
	}
	if sink.events[1].Event != store.EventConnectorToolResult || sink.events[1].ArtifactID != "n-created" {
		t.Fatalf("result row = %+v", sink.events[1])
	}
	if !sink.lastHadDeadline {
		t.Fatal("the detached result write must still be time-bounded")
	}
}

// ctxSensitiveSink refuses a write whose context is already cancelled, exactly
// as a database driver does.
type ctxSensitiveSink struct {
	events          []store.AuditEvent
	lastHadDeadline bool
}

func (s *ctxSensitiveSink) AppendAudit(ctx context.Context, e store.AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := store.ValidateDetail(e.Detail); err != nil {
		return err
	}
	_, s.lastHadDeadline = ctx.Deadline()
	s.events = append(s.events, e)
	return nil
}
