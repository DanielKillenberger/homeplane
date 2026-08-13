package edge

import (
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
)

func manifestFor(t *testing.T, body string) connectors.Manifest {
	t.Helper()
	m, err := connectors.Parse([]byte(body))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return m
}

func TestRoutingResolvesToolsToTheirConnector(t *testing.T) {
	r, err := newToolRouter(manifestFor(t, testManifest))
	if err != nil {
		t.Fatalf("newToolRouter: %v", err)
	}

	cases := []struct {
		wire         string
		wantProvider string
		wantTool     string
	}{
		{"list_notes", "stub-notes", "list_notes"},
		{"stub-notes__create_note", "stub-notes", "create_note"},
		// An excluded tool routes to its OWN connector, so the refusal is
		// audited as the deliberate exclusion it is rather than as an unknown
		// connector.
		{"export_archive", "stub-notes", "export_archive"},
		// Nothing in the manifest claims these: they belong to no connector,
		// and the engine refuses them as such.
		{"summarize_notes", UnroutedProvider, "summarize_notes"},
		{"other__do_thing", UnroutedProvider, "other__do_thing"},
		{"", UnroutedProvider, ""},
	}
	for _, tc := range cases {
		provider, tool := r.route(tc.wire)
		if provider != tc.wantProvider || tool != tc.wantTool {
			t.Errorf("route(%q) = (%q, %q), want (%q, %q)",
				tc.wire, provider, tool, tc.wantProvider, tc.wantTool)
		}
	}
}

// Two connectors sharing a bare tool name is a NORMAL multi-connector
// composition, not a startup failure: the gateway namespaces such tools, and
// refusing the manifest would mean the deployment could not run at all (R12).
// Only the unqualified form is denied — guessing whose policy applies is how
// one connector's read-only rules end up applied to another's delete tool.
func TestSharedToolNamesStayRoutableWhenQualified(t *testing.T) {
	shared := `{"version":1,"connectors":[` +
		connectorJSON("notes-a") + `,` + connectorJSON("notes-b") + `]}`
	r, err := newToolRouter(manifestFor(t, shared))
	if err != nil {
		t.Fatalf("a qualifiable composition was refused: %v", err)
	}

	if provider, tool := r.route("list_notes"); provider != AmbiguousProvider || tool != "list_notes" {
		t.Errorf("bare ambiguous name routed to (%q, %q), want the ambiguous marker", provider, tool)
	}
	for _, want := range []string{"notes-a", "notes-b"} {
		provider, tool := r.route(want + QualifierSeparator + "list_notes")
		if provider != want || tool != "list_notes" {
			t.Errorf("qualified name routed to (%q, %q), want (%q, list_notes)", provider, tool, want)
		}
	}
	if got := r.ambiguousTools(); len(got) != 1 || got[0] != "list_notes" {
		t.Errorf("ambiguousTools() = %v, want [list_notes]", got)
	}

	// A third connector claiming the same name keeps it ambiguous rather than
	// letting the last one declared win it back.
	three := `{"version":1,"connectors":[` +
		connectorJSON("notes-a") + `,` + connectorJSON("notes-b") + `,` + connectorJSON("notes-c") + `]}`
	r, err = newToolRouter(manifestFor(t, three))
	if err != nil {
		t.Fatalf("newToolRouter: %v", err)
	}
	if provider, _ := r.route("list_notes"); provider != AmbiguousProvider {
		t.Errorf("a thrice-claimed name routed to %q", provider)
	}
}

// The markers are not connector names: a manifest may not claim one, or
// "belongs to no connector" would become a reachable connector.
func TestReservedProviderNamesAreRefused(t *testing.T) {
	for _, name := range []string{UnroutedProvider, AmbiguousProvider} {
		reserved := `{"version":1,"connectors":[` + connectorJSON(name) + `]}`
		if _, err := newToolRouter(manifestFor(t, reserved)); err == nil {
			t.Errorf("a connector named %q was accepted", name)
		} else if !strings.Contains(err.Error(), name) {
			t.Errorf("error does not name the connector: %v", err)
		}
	}
}

// connectorJSON is a minimal valid connector declaration under a chosen
// provider name. Two of them collide on `list_notes`, which is the point.
func connectorJSON(provider string) string {
	return `{
      "provider": "` + provider + `",
      "credential_ref": "` + provider + `/oauth-session",
      "credential_acquisition": {
        "driver": "oauth2-authcode",
        "params": {
          "auth_endpoint": "https://auth.stub.test/authorize",
          "token_endpoint": "https://auth.stub.test/token",
          "client_id_ref": "stub/client-id",
          "client_secret_ref": "stub/client-secret"
        },
        "scopes": ["notes.read"]
      },
      "mcp_server": { "name": "` + provider + `", "transport": "streamable-http", "source": "stub://in-process" },
      "tools": [ { "tool": "list_notes", "action_class": "read" } ]
    }`
}
