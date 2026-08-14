package server_test

import (
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/health"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/secrets"
	"github.com/DanielKillenberger/homeplane/internal/server"
	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
	"github.com/DanielKillenberger/homeplane/internal/server/credflow"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// The credential broker's own state machine is tested in its package. What
// belongs HERE is the wiring: that its endpoints are machine-authenticated by
// the same code path as every other machine-scoped endpoint, and that they do
// not exist at all on a server with no connector manifest.

// credentialManifest is a syntactically real manifest whose provider is never
// actually contacted — every case below is decided before any provider call.
const credentialManifest = `{"version":1,"connectors":[{
	"provider":"testprovider",
	"credential_ref":"testprovider/oauth-session",
	"credential_acquisition":{
		"driver":"oauth2-authcode",
		"params":{
			"auth_endpoint":"https://auth.invalid/authorize",
			"token_endpoint":"https://auth.invalid/token",
			"client_id_ref":"testprovider/client-id",
			"client_secret_ref":"testprovider/client-secret"
		},
		"scopes":["things.read"]
	},
	"mcp_server":{"name":"testprovider","transport":"streamable-http","source":"stub://in-process"},
	"tool_inventory":["list_things"],
	"tools":[{"tool":"list_things","action_class":"read"}]}]}`

func newCredentialHarness(t *testing.T) *harness {
	t.Helper()
	st := newStore(t)
	keyring, err := secrets.GenerateKeyFile(filepath.Join(t.TempDir(), "secrets.age-key"))
	if err != nil {
		t.Fatalf("secrets.GenerateKeyFile: %v", err)
	}
	manifest, err := connectors.Parse([]byte(credentialManifest))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	engine, err := connectors.Register(manifest)
	if err != nil {
		t.Fatalf("register manifest: %v", err)
	}
	broker, err := credflow.New(engine, st, keyring, st, credflow.Config{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("credflow.New: %v", err)
	}
	checker := health.New(health.Component{Name: health.ComponentStore, Probe: health.StoreProbe(st)})
	srv, err := server.New(st, fakeResolver{byAddr: map[string]store.Identity{
		addrA: machineA,
		addrB: machineB,
	}}, checker, server.Config{
		Policy:      policy.Default(),
		Credentials: broker,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &harness{t: t, st: st, handler: srv.Handler()}
}

func TestCredentialFlowEndpointsRequireAMachineCredential(t *testing.T) {
	h := newCredentialHarness(t)
	_, credential, _ := h.enrol(addrA, "mac-a", "darwin")
	// Machine B is enrolled too, so replaying A's credential from B's node
	// exercises the machine-mismatch refusal rather than "not enrolled".
	h.enrol(addrB, "linux-b", "linux")

	body := map[string]any{"provider": "testprovider", "replace": false, "redirect_uri": "http://127.0.0.1:53682"}

	cases := []struct {
		name       string
		method     string
		path       string
		addr       string
		token      string
		body       any
		wantStatus int
	}{
		{"start without a credential", http.MethodPost, "/credentials/flows", addrA, "", body, http.StatusUnauthorized},
		{"start with a bogus credential", http.MethodPost, "/credentials/flows", addrA, "not-a-credential", body, http.StatusUnauthorized},
		{"start from an unidentifiable node", http.MethodPost, "/credentials/flows", addrC, credential, body, http.StatusForbidden},
		{"start with another machine's credential", http.MethodPost, "/credentials/flows", addrB, credential, body, http.StatusForbidden},
		{"poll without a credential", http.MethodGet, "/credentials/flows/flow-x", addrA, "", nil, http.StatusUnauthorized},
		{"relay without a credential", http.MethodPost, "/credentials/flows/flow-x/code", addrA, "",
			map[string]string{"code": "c", "state": "s"}, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := h.do(tc.method, tc.path, tc.addr, tc.token, tc.body)
			if res.status != tc.wantStatus {
				t.Fatalf("status %d, want %d (body %s)", res.status, tc.wantStatus, res.raw)
			}
		})
	}

	// An authenticated call reaches the broker: an unknown flow is a 404 from
	// the broker, not a 401 from the front door.
	res := h.do(http.MethodGet, "/credentials/flows/flow-nonesuch", addrA, credential, nil)
	if res.status != http.StatusNotFound {
		t.Fatalf("authenticated poll of an unknown flow: status %d, want 404 (body %s)", res.status, res.raw)
	}
}

// TestRejectedCredentialFlowCallsAreAudited — a probe against the credential
// broker is exactly the kind of denial an operator opens the log to find.
func TestRejectedCredentialFlowCallsAreAudited(t *testing.T) {
	h := newCredentialHarness(t)
	h.enrol(addrA, "mac-a", "darwin")

	before := len(h.auditEvents())
	res := h.do(http.MethodPost, "/credentials/flows", addrA, "stolen-looking-token",
		map[string]any{"provider": "testprovider", "redirect_uri": "http://127.0.0.1:53682"})
	if res.status != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", res.status)
	}
	events := h.auditEvents()
	if len(events) <= before {
		t.Fatal("a rejected credential-flow call was not audited")
	}
	last := events[len(events)-1]
	if last.Event != store.EventAuthDenied || last.Outcome != store.OutcomeDenied {
		t.Fatalf("last audit row = %+v, want an auth denial", last)
	}
	if last.TokenFingerprint == "" {
		t.Error("denial has no token fingerprint to correlate repeated attempts with")
	}
}

// TestCredentialEndpointsAreAbsentWithoutAManifest — a server with no connector
// manifest has no provider to broker a credential for, and says so by not
// routing the endpoint at all.
func TestCredentialEndpointsAreAbsentWithoutAManifest(t *testing.T) {
	h := newHarness(t) // the standard harness configures no credential broker
	_, credential, _ := h.enrol(addrA, "mac-a", "darwin")

	res := h.do(http.MethodPost, "/credentials/flows", addrA, credential,
		map[string]any{"provider": "testprovider", "redirect_uri": "http://127.0.0.1:53682"})
	if res.status != http.StatusNotFound {
		t.Fatalf("status %d, want 404 on a server with no credential broker (body %s)", res.status, res.raw)
	}
}
