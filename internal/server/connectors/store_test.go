package connectors

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/store"
)

// The rows this package derives have to survive the REAL audit log, not just a
// test double: the store validates the metadata vocabulary and persists into
// fixed columns. Wiring the broker straight to *store.SQLite proves the two
// halves agree, in process, with no server and no gateway.
func TestConnectorRowsPersistThroughTheRealAuditLog(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "homeplane.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	rt := newStubRuntime()
	rt.respond("create_note", `{"note":{"id":"n-created","body":"`+secretBody+`"}}`)
	b := NewBroker(stubEngine(t), rt, db)

	if _, err := b.Invoke(context.Background(),
		req("stub-notes", "create_note", `{"title":"weekly","body":"`+secretBody+`"}`, readWriteCaller())); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if _, err := b.Invoke(context.Background(),
		req("stub-notes", "summarize_notes", `{"body":"`+secretBody+`"}`, readWriteCaller())); err == nil {
		t.Fatal("unmapped tool was allowed")
	}

	rows, err := db.QueryAudit(context.Background(), store.AuditQuery{Limit: 100})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 persisted rows (call, result, policy violation), got %d: %+v", len(rows), rows)
	}

	byEvent := map[string]store.AuditEvent{}
	for _, r := range rows {
		byEvent[r.Event] = r
		if r.TS.IsZero() {
			t.Errorf("row %s has no timestamp", r.Event)
		}
	}
	if got := byEvent[store.EventConnectorToolCall]; got.ActionClass != string(ActionWrite) ||
		got.Tool != "create_note" || got.ArtifactID != ArtifactUnknown {
		t.Errorf("call row round-tripped wrong: %+v", got)
	}
	if got := byEvent[store.EventConnectorToolResult]; got.ArtifactID != "n-created" {
		t.Errorf("result row artifact id = %q", got.ArtifactID)
	}
	if got := byEvent[store.EventPolicyViolation]; got.Reason != ReasonUnmappedTool ||
		got.Outcome != store.OutcomeDenied {
		t.Errorf("policy violation row round-tripped wrong: %+v", got)
	}
	if got := byEvent[store.EventConnectorToolCall].Detail["args_digest"]; len(got) != 64 {
		t.Errorf("args digest did not survive persistence: %q", got)
	}
	assertNoPayload(t, rows, secretBody, "weekly")
}

// A connector must not be able to widen the audit vocabulary by hand: the
// store refuses anything outside the allow-list, which is what keeps a body
// from ever reaching the log through a creative key.
func TestTheAuditVocabularyStaysClosed(t *testing.T) {
	if err := store.ValidateDetail(map[string]string{"request_body": "…"}); err == nil {
		t.Fatal("store accepted a free-form detail key")
	}
	for _, k := range []string{"provider", "args_digest", "call_id", "required_capability", "exclusion_reason"} {
		if err := store.ValidateDetail(map[string]string{k: "x"}); err != nil {
			t.Errorf("connector detail key %q rejected by the store: %v", k, err)
		}
	}
	long := strings.Repeat("x", store.MaxDetailValueLen+1)
	if err := store.ValidateDetail(map[string]string{"exclusion_reason": long}); err == nil {
		t.Fatal("store accepted an unbounded detail value")
	}
}
