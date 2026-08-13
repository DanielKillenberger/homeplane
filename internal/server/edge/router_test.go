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

// A gateway composition the edge cannot route deterministically must not serve
// traffic: guessing whose policy applies to an ambiguous tool name is exactly
// how a read-only connector's rules end up applied to another connector's
// delete tool.
func TestAmbiguousAndReservedCompositionsAreRefused(t *testing.T) {
	ambiguous := `{"version":1,"connectors":[` +
		connectorJSON("notes-a") + `,` + connectorJSON("notes-b") + `]}`
	if _, err := newToolRouter(manifestFor(t, ambiguous)); err == nil {
		t.Error("two connectors declaring the same tool name were accepted")
	} else if !strings.Contains(err.Error(), "list_notes") {
		t.Errorf("error does not name the colliding tool: %v", err)
	}

	reserved := `{"version":1,"connectors":[` + connectorJSON(UnroutedProvider) + `]}`
	if _, err := newToolRouter(manifestFor(t, reserved)); err == nil {
		t.Error("a connector using the reserved provider name was accepted")
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
