package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/store"
)

// R12: adding a connector is a manifest entry plus its credentials — no code.
//
// The test is built to make that claim falsifiable rather than asserted: it
// takes the SAME registered engine, appends a connector entry read from a JSON
// document (a fake provider with its own fake OAuth endpoints, scopes and
// client refs), and drives the second connector through the identical
// authorization and audit path. Nothing below names the new provider outside
// the fixture it came from, and no production file changes to make it work.
func TestSecondConnectorRegistersFromAManifestEntryAlone(t *testing.T) {
	base := loadManifest(t, "stub.json")

	entry, err := os.ReadFile(filepath.Join("testdata", "second-connector-entry.json"))
	if err != nil {
		t.Fatalf("read connector entry: %v", err)
	}
	var second Connector
	if err := json.Unmarshal(entry, &second); err != nil {
		t.Fatalf("decode connector entry: %v", err)
	}

	extended := Manifest{Version: base.Version, Connectors: append(append([]Connector{}, base.Connectors...), second)}
	e, err := Register(extended)
	if err != nil {
		t.Fatalf("registering a second connector required more than a manifest entry: %v", err)
	}

	if got := e.Providers(); len(got) != 2 {
		t.Fatalf("providers = %v, want both connectors", got)
	}

	// Its credential-acquisition metadata — a different OAuth provider, its own
	// endpoints, scopes and client refs — is carried declaratively.
	c, ok := e.Connector(second.Provider)
	if !ok {
		t.Fatalf("%s not registered", second.Provider)
	}
	if c.Credential.Driver != DriverOAuth2AuthCode {
		t.Fatalf("driver = %q", c.Credential.Driver)
	}
	if c.Credential.Params["auth_endpoint"] == base.Connectors[0].Credential.Params["auth_endpoint"] {
		t.Fatal("the second connector must carry its own authorization endpoint")
	}
	if len(c.Credential.Scopes) == 0 || c.CredentialRef == base.Connectors[0].CredentialRef {
		t.Fatalf("the second connector must carry its own scopes and credential ref: %+v", c.Credential)
	}

	// And it authorizes and audits through the same engine, with the same
	// rules, decided from its own entry.
	rt := newStubRuntime()
	rt.respond("create_task", `{"task":{"id":"t-99"}}`)
	sink := &recordingSink{}
	b := NewBroker(e, rt, sink)

	if _, err := b.Invoke(context.Background(),
		req(second.Provider, "list_tasks", `{}`, readOnlyCaller())); err != nil {
		t.Fatalf("read on the second connector: %v", err)
	}
	if _, err := b.Invoke(context.Background(),
		req(second.Provider, "create_task", `{"title":"x"}`, readOnlyCaller())); !errors.Is(err, ErrDenied) {
		t.Fatalf("write with a read-only grant = %v, want ErrDenied", err)
	}
	if _, err := b.Invoke(context.Background(),
		req(second.Provider, "create_task", `{"title":"x"}`, readWriteCaller())); err != nil {
		t.Fatalf("write with a matching grant: %v", err)
	}
	if _, err := b.Invoke(context.Background(),
		req(second.Provider, "purge_tasks", `{}`, fullCaller())); !errors.Is(err, ErrDenied) {
		t.Fatalf("excluded tool = %v, want ErrDenied", err)
	}
	if _, err := b.Invoke(context.Background(),
		req(second.Provider, "invent_tool", `{}`, fullCaller())); !errors.Is(err, ErrDenied) {
		t.Fatalf("unmapped tool = %v, want ErrDenied", err)
	}

	// The response-side extractor declared in the new entry produced the
	// created artifact's identity, with no code that knows what a task is.
	var sawArtifact bool
	for _, ev := range sink.events {
		if ev.Event == store.EventConnectorToolResult && ev.ArtifactID == "t-99" {
			sawArtifact = true
		}
		if ev.Detail["provider"] == "" {
			t.Errorf("row %s did not record its provider", ev.Event)
		}
	}
	if !sawArtifact {
		t.Fatalf("no result row carried the extracted artifact id: %+v", sink.events)
	}

	// The first connector is untouched by the addition.
	if _, err := b.Invoke(context.Background(),
		req("stub-notes", "get_note", `{"note_id":"n-1"}`, readOnlyCaller())); err != nil {
		t.Fatalf("the pre-existing connector broke when a second one was added: %v", err)
	}
}

// The decision path must be free of provider-specific behaviour: two connectors
// with the same declared shape must produce identical decisions.
func TestDecisionsDependOnlyOnTheManifestShape(t *testing.T) {
	base := loadManifest(t, "stub.json")
	twin := base.Connectors[0]
	twin.Provider = "stub-notes-twin"
	twin.CredentialRef = "twin/oauth-session"
	twin.Server.Name = "stub-notes-twin"

	e, err := Register(Manifest{Version: base.Version, Connectors: append(append([]Connector{}, base.Connectors...), twin)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	tools := []string{"list_notes", "get_note", "create_note", "delete_note", "share_note", "export_archive", "nope"}
	for _, caller := range []Caller{readOnlyCaller(), readWriteCaller(), fullCaller()} {
		for _, tool := range tools {
			a := e.Authorize(req("stub-notes", tool, `{"note_id":"n"}`, caller))
			bb := e.Authorize(req("stub-notes-twin", tool, `{"note_id":"n"}`, caller))
			if a.Allowed != bb.Allowed || a.Reason != bb.Reason || a.ActionClass != bb.ActionClass {
				t.Fatalf("tool %q decided differently per provider: %+v vs %+v", tool, a, bb)
			}
		}
	}
}
