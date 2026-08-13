package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/health"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/secrets"
	"github.com/DanielKillenberger/homeplane/internal/server"
	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
	"github.com/DanielKillenberger/homeplane/internal/server/credflow"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// A control plane WITH a credential broker, so the CLI's add-credentials path
// can be driven end to end: real enrolment, real machine credential, real
// broker. The provider's endpoints are never contacted — the flow below ends
// in a denial, which the server decides on its own.
const cliManifest = `{"version":1,"connectors":[{
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

func newControlPlaneWithBroker(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "homeplane.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keyring, err := secrets.GenerateKeyFile(filepath.Join(dir, "secrets.age-key"))
	if err != nil {
		t.Fatalf("secrets.GenerateKeyFile: %v", err)
	}
	for ref, value := range map[string]string{
		"testprovider/client-id":     "client-id-value",
		"testprovider/client-secret": "client-secret-value",
	} {
		ciphertext, err := keyring.Encrypt([]byte(value))
		if err != nil {
			t.Fatalf("encrypt %s: %v", ref, err)
		}
		if _, err := st.PutSecret(context.Background(), ref, ciphertext, func(int64) []store.AuditEvent {
			return []store.AuditEvent{{Event: store.EventSecretImported, ActorKind: store.ActorOperator,
				Outcome: store.OutcomeAllowed, Detail: map[string]string{"secret_ref": ref, "source": "test"}}}
		}); err != nil {
			t.Fatalf("import %s: %v", ref, err)
		}
	}

	manifest, err := connectors.Parse([]byte(cliManifest))
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
	srv, err := server.New(st, fakeResolver{id: store.Identity{NodeID: "node-cli", NodeName: "cli"}}, checker,
		server.Config{Policy: policy.Default(), Credentials: broker})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

// declineInBrowser stands in for the human: it reads the redirect URI and state
// out of the authorization URL and reports a denial straight to the agent's
// loopback listener.
func declineInBrowser(t *testing.T) func(context.Context, string) error {
	t.Helper()
	return func(ctx context.Context, authURL string) error {
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		callback, err := url.Parse(u.Query().Get("redirect_uri"))
		if err != nil {
			return err
		}
		q := callback.Query()
		q.Set("error", "access_denied")
		q.Set("state", u.Query().Get("state"))
		callback.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, callback.String(), nil)
		if err != nil {
			return err
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, res.Body)
		return res.Body.Close()
	}
}

// TestAddCredentialsJSONModeEmitsOneJSONValueOnStdout — `-json` exists to be
// piped into something. Progress lines (including the authorization URL, which
// a human may still need) belong on stderr, where they cannot corrupt it.
func TestAddCredentialsJSONModeEmitsOneJSONValueOnStdout(t *testing.T) {
	cp := newControlPlaneWithBroker(t)
	dir := filepath.Join(t.TempDir(), "state")
	if enrolled := invoke(t, "enrol", "-server", cp.URL, "-name", "cli-machine", "-state-dir", dir); enrolled.code != 0 {
		t.Fatalf("enrol: exit %d (stderr %q)", enrolled.code, enrolled.stderr)
	}

	original := openBrowser
	openBrowser = declineInBrowser(t)
	t.Cleanup(func() { openBrowser = original })

	res := invoke(t, "add-credentials", "testprovider", "-state-dir", dir, "-json",
		"-poll-interval", "20ms", "-timeout", "20s")
	if res.code != 1 {
		t.Fatalf("exit %d, want 1 for a declined flow (stderr %q)", res.code, res.stderr)
	}

	var outcome struct {
		Provider  string `json:"provider"`
		State     string `json:"state"`
		ErrorCode string `json:"error_code"`
		Retryable bool   `json:"retryable"`
	}
	dec := json.NewDecoder(strings.NewReader(res.stdout))
	if err := dec.Decode(&outcome); err != nil {
		t.Fatalf("stdout is not valid JSON (%v): %q", err, res.stdout)
	}
	if dec.More() {
		t.Fatalf("stdout carries more than one JSON value: %q", res.stdout)
	}
	if outcome.State != "denied" || outcome.ErrorCode != "provider_denied" || !outcome.Retryable {
		t.Fatalf("outcome = %+v, want a retryable provider_denied", outcome)
	}
	// The human-readable half still happened — on stderr.
	if !strings.Contains(res.stderr, "authorize Homeplane") {
		t.Errorf("progress was not written to stderr: %q", res.stderr)
	}
}

// TestAddCredentialsHumanModeReportsTheDenial covers the default output path.
func TestAddCredentialsHumanModeReportsTheDenial(t *testing.T) {
	cp := newControlPlaneWithBroker(t)
	dir := filepath.Join(t.TempDir(), "state")
	if enrolled := invoke(t, "enrol", "-server", cp.URL, "-name", "cli-machine", "-state-dir", dir); enrolled.code != 0 {
		t.Fatalf("enrol: exit %d (stderr %q)", enrolled.code, enrolled.stderr)
	}

	original := openBrowser
	openBrowser = declineInBrowser(t)
	t.Cleanup(func() { openBrowser = original })

	res := invoke(t, "add-credentials", "testprovider", "-state-dir", dir,
		"-poll-interval", "20ms", "-timeout", "20s")
	if res.code != 1 {
		t.Fatalf("exit %d, want 1 (stderr %q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "provider_denied") || !strings.Contains(res.stderr, "nothing was changed") {
		t.Errorf("stderr does not explain the denial: %q", res.stderr)
	}
}

// TestAddCredentialsUnknownProviderListsTheKnownOnes — the server's guidance
// has to survive all the way to the operator's terminal.
func TestAddCredentialsUnknownProviderListsTheKnownOnes(t *testing.T) {
	cp := newControlPlaneWithBroker(t)
	dir := filepath.Join(t.TempDir(), "state")
	if enrolled := invoke(t, "enrol", "-server", cp.URL, "-name", "cli-machine", "-state-dir", dir); enrolled.code != 0 {
		t.Fatalf("enrol: exit %d (stderr %q)", enrolled.code, enrolled.stderr)
	}

	res := invoke(t, "add-credentials", "nonesuch", "-state-dir", dir, "-no-browser")
	if res.code != 1 {
		t.Fatalf("exit %d, want 1 (stderr %q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "testprovider") {
		t.Fatalf("the refusal does not list the known providers: %q", res.stderr)
	}
}
