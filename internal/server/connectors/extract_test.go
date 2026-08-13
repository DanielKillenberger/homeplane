package connectors

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractReadsDeclaredScalarIdentities(t *testing.T) {
	doc := json.RawMessage(`{
		"event": {"id": "evt-42", "attendees": [{"email": "a@example.test"}]},
		"count": 7,
		"ok": true,
		"nested": {"list": [{"id": "first"}, {"id": "second"}]},
		"empty": "",
		"obj": {"a": 1},
		"arr": [1,2],
		"null": null
	}`)

	tests := []struct {
		pointer string
		want    string
		ok      bool
	}{
		{pointer: "$.event.id", want: "evt-42", ok: true},
		{pointer: "$.count", want: "7", ok: true},
		{pointer: "$.ok", want: "true", ok: true},
		{pointer: "$.nested.list[1].id", want: "second", ok: true},
		{pointer: "$.event.attendees[0].email", want: "a@example.test", ok: true},
		{pointer: "$.missing"},
		{pointer: "$.nested.list[9].id"},
		{pointer: "$.event.id.deeper"},
		{pointer: "$.empty"},
		{pointer: "$.obj"},
		{pointer: "$.arr"},
		{pointer: "$.null"},
	}

	for _, tc := range tests {
		t.Run(tc.pointer, func(t *testing.T) {
			got, ok := Extract(Extractor{Source: FromResponse, Pointer: tc.pointer}, doc)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("Extract(%q) = (%q, %v), want (%q, %v)", tc.pointer, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestExtractIsTotalOnBadInput(t *testing.T) {
	cases := []struct {
		name    string
		pointer string
		doc     string
	}{
		{name: "malformed document", pointer: "$.id", doc: `{"id":`},
		{name: "empty document", pointer: "$.id", doc: ``},
		{name: "unparseable pointer", pointer: "id", doc: `{"id":"x"}`},
		{name: "negative index", pointer: "$.a[-1]", doc: `{"a":["x"]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := Extract(Extractor{Source: FromRequest, Pointer: tc.pointer}, json.RawMessage(tc.doc)); ok {
				t.Fatalf("Extract returned (%q, true); audit derivation must never assert an identity it did not find", got)
			}
		})
	}
}

// An oversized value is not an identity — it is payload wearing an id's name.
func TestExtractRefusesOversizedValues(t *testing.T) {
	long := strings.Repeat("x", MaxArtifactIDLen+1)
	doc := json.RawMessage(`{"id":"` + long + `"}`)
	if got, ok := Extract(Extractor{Source: FromResponse, Pointer: "$.id"}, doc); ok {
		t.Fatalf("Extract accepted a %d-char value: %q", len(got), got)
	}
}

func TestArgsDigestIsStableCanonicalAndOneWay(t *testing.T) {
	a := json.RawMessage(`{"note_id":"n-1","body":"my private note text"}`)
	reordered := json.RawMessage(`{  "body" : "my private note text",  "note_id":"n-1" }`)
	different := json.RawMessage(`{"note_id":"n-2","body":"my private note text"}`)

	da, db, dc := ArgsDigest(a), ArgsDigest(reordered), ArgsDigest(different)
	if da != db {
		t.Fatalf("semantically identical arguments digest differently:\n%s\n%s", da, db)
	}
	if da == dc {
		t.Fatal("different arguments produced the same digest")
	}
	if len(da) != 64 {
		t.Fatalf("digest = %q, want 64 hex chars", da)
	}
	if strings.Contains(da, "private") || strings.Contains(da, "n-1") {
		t.Fatalf("digest %q carries argument content", da)
	}
	// Absent arguments still digest, so the field is never empty.
	if ArgsDigest(nil) == "" {
		t.Fatal("nil arguments produced an empty digest")
	}
	// Non-JSON arguments are digested as bytes rather than guessed at.
	if ArgsDigest(json.RawMessage(`not json`)) == ArgsDigest(json.RawMessage(`also not json`)) {
		t.Fatal("distinct non-JSON arguments collided")
	}
}
