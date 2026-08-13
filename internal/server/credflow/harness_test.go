package credflow_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/secrets"
	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
	"github.com/DanielKillenberger/homeplane/internal/server/credflow"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// Two simulated machines. The credential broker is a per-machine surface: a
// flow belongs to the machine that started it, and the race that R13 has to
// survive is two MACHINES authorizing the same provider at once.
const (
	machineA = "machine-aaaa"
	machineB = "machine-bbbb"
)

// testMachineHeader is how this test injects an already-authenticated machine.
// Authentication itself is the control plane's (internal/server's) job and is
// tested there; mixing it in here would only test that package twice.
const testMachineHeader = "X-Test-Machine"

type harness struct {
	t       *testing.T
	svc     *credflow.Service
	st      *store.SQLite
	keyring *secrets.Keyring
	handler http.Handler
	client  *http.Client
	clock   *testClock
}

// testClock makes expiry testable without sleeping through it.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *testClock { return &testClock{t: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)} }

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// advance moves the harness's clock forward. It is only meaningful when the
// harness was built with a clock.
func (h *harness) advance(d time.Duration) {
	h.t.Helper()
	if h.clock == nil {
		h.t.Fatal("harness has no injected clock")
	}
	h.clock.advance(d)
}

// oauthStateFrom reads the state parameter the server put in an authorization
// URL — what the provider will echo back to the loopback listener.
func oauthStateFrom(t *testing.T, authURL string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	return u.Query().Get("state")
}

type harnessOptions struct {
	providers []*fakeProvider
	// secretStore overrides the credential store (for failure injection).
	secretStore credflow.SecretStore
	sealer      credflow.Sealer
	audit       credflow.AuditSink
	// clock, when set, replaces the broker's wall clock so expiry is testable.
	clock             *testClock
	ttl               time.Duration
	terminalRetention time.Duration
	maxActiveFlows    int
	// manifestJSON overrides the generated manifest entirely.
	manifestJSON string
	// skipClientSecrets leaves the provider's client credentials unimported.
	skipClientSecrets bool
}

func newHarness(t *testing.T, opts harnessOptions) *harness {
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

	manifestJSON := opts.manifestJSON
	if manifestJSON == "" {
		manifestJSON = manifestFor(opts.providers...)
	}
	manifest, err := connectors.Parse([]byte(manifestJSON))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	engine, err := connectors.Register(manifest)
	if err != nil {
		t.Fatalf("register manifest: %v", err)
	}

	h := &harness{t: t, st: st, keyring: keyring, client: providerClient(opts.providers...)}
	if !opts.skipClientSecrets {
		for _, p := range opts.providers {
			h.importSecret(p.name+"/client-id", []byte(p.clientID))
			h.importSecret(p.name+"/client-secret", []byte(p.secret))
		}
	}

	var secretStore credflow.SecretStore = st
	if opts.secretStore != nil {
		secretStore = opts.secretStore
	}
	var sealer credflow.Sealer = keyring
	if opts.sealer != nil {
		sealer = opts.sealer
	}
	var audit credflow.AuditSink = st
	if opts.audit != nil {
		audit = opts.audit
	}

	var now func() time.Time
	if opts.clock != nil {
		h.clock = opts.clock
		now = opts.clock.now
	}
	svc, err := credflow.New(engine, secretStore, sealer, audit, credflow.Config{
		TTL:                      opts.ttl,
		TerminalRetention:        opts.terminalRetention,
		MaxActiveFlowsPerMachine: opts.maxActiveFlows,
		HTTPClient:               h.client,
		Now:                      now,
		Logger:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("credflow.New: %v", err)
	}
	h.svc = svc

	mux := http.NewServeMux()
	mux.HandleFunc("POST /credentials/flows", func(w http.ResponseWriter, r *http.Request) {
		svc.HandleStart(w, r, callerMachine(r))
	})
	mux.HandleFunc("POST /credentials/flows/{flow_id}/code", func(w http.ResponseWriter, r *http.Request) {
		svc.HandleRelay(w, r, callerMachine(r))
	})
	mux.HandleFunc("GET /credentials/flows/{flow_id}", func(w http.ResponseWriter, r *http.Request) {
		svc.HandlePoll(w, r, callerMachine(r))
	})
	h.handler = mux
	// Exchange jobs outlive their request by design, so every test waits for
	// them rather than leaving goroutines to trip the race detector.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := svc.Shutdown(ctx); err != nil {
			t.Errorf("credential exchange jobs still running at test end: %v", err)
		}
	})
	return h
}

func callerMachine(r *http.Request) string {
	if m := r.Header.Get(testMachineHeader); m != "" {
		return m
	}
	return machineA
}

// manifestFor renders a connector manifest for the given fake providers. Note
// what is provider-specific about it: endpoints, scopes and secret refs, and
// nothing else. That is the R12 claim in concrete form — a new provider is this
// JSON, not a code path.
func manifestFor(providers ...*fakeProvider) string {
	entries := make([]string, 0, len(providers))
	for _, p := range providers {
		entries = append(entries, fmt.Sprintf(`{
      "provider": %q,
      "credential_ref": %q,
      "credential_acquisition": {
        "driver": "oauth2-authcode",
        "params": {
          "auth_endpoint": %q,
          "token_endpoint": %q,
          "client_id_ref": %q,
          "client_secret_ref": %q,
          "access_type": "offline",
          "prompt": "consent"
        },
        "scopes": ["things.read", "things.write"]
      },
      "mcp_server": {"name": %q, "transport": "streamable-http", "source": "stub://in-process"},
      "tool_inventory": ["list_things"],
      "tools": [{"tool": "list_things", "action_class": "read"}]
    }`,
			p.name, p.name+"/oauth-session",
			p.authEndpoint(), p.tokenEndpoint(),
			p.name+"/client-id", p.name+"/client-secret",
			p.name))
	}
	return fmt.Sprintf(`{"version": 1, "connectors": [%s]}`, strings.Join(entries, ","))
}

// parseManifestErr reports whether a manifest is acceptable to the connector
// plane at all.
func parseManifestErr(manifestJSON string) error {
	_, err := connectors.Parse([]byte(manifestJSON))
	return err
}

func (h *harness) importSecret(ref string, value []byte) int64 {
	h.t.Helper()
	ciphertext, err := h.keyring.Encrypt(value)
	if err != nil {
		h.t.Fatalf("encrypt %s: %v", ref, err)
	}
	generation, err := h.st.PutSecret(context.Background(), ref, ciphertext, func(generation int64) []store.AuditEvent {
		return []store.AuditEvent{{
			Event:     store.EventSecretImported,
			ActorKind: store.ActorOperator,
			Outcome:   store.OutcomeAllowed,
			Detail:    map[string]string{"secret_ref": ref, "source": "test"},
		}}
	})
	if err != nil {
		h.t.Fatalf("import %s: %v", ref, err)
	}
	return generation
}

// seedCredential plants an existing provider credential, as though a previous
// add-credentials run (or an operator import) had stored one.
func (h *harness) seedCredential(provider, accessToken string) {
	h.t.Helper()
	payload, err := json.Marshal(credflow.Credential{Provider: provider, Access: accessToken, ObtainedAt: time.Now().UTC()})
	if err != nil {
		h.t.Fatalf("marshal credential: %v", err)
	}
	h.importSecret(provider+"/oauth-session", payload)
}

type response struct {
	status int
	body   map[string]any
	raw    string
}

func (r response) str(key string) string {
	v, _ := r.body[key].(string)
	return v
}

func (r response) diagnostic() map[string]any {
	d, _ := r.body["diagnostic"].(map[string]any)
	return d
}

func (h *harness) do(method, path, machine string, body any) response {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal request: %v", err)
		}
		reader = strings.NewReader(string(encoded))
	}
	req := httptest.NewRequest(method, path, reader)
	if machine != "" {
		req.Header.Set(testMachineHeader, machine)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	res := response{status: rec.Code, raw: rec.Body.String()}
	if res.raw != "" {
		_ = json.Unmarshal([]byte(res.raw), &res.body)
	}
	return res
}

const loopbackRedirect = "http://127.0.0.1:53682"

func (h *harness) start(machine, provider string, replace bool) response {
	h.t.Helper()
	return h.startWithRedirect(machine, provider, loopbackRedirect, replace)
}

func (h *harness) startWithRedirect(machine, provider, redirect string, replace bool) response {
	h.t.Helper()
	return h.do(http.MethodPost, "/credentials/flows", machine,
		map[string]any{"provider": provider, "replace": replace, "redirect_uri": redirect})
}

func (h *harness) relay(machine, flowID string, body map[string]string) response {
	h.t.Helper()
	return h.do(http.MethodPost, "/credentials/flows/"+flowID+"/code", machine, body)
}

func (h *harness) poll(machine, flowID string) response {
	h.t.Helper()
	return h.do(http.MethodGet, "/credentials/flows/"+flowID, machine, nil)
}

// runFlow drives a whole flow: start, consent in the "browser", relay the
// outcome, then wait for the server's exchange job to reach a terminal state.
// It returns the flow id and the TERMINAL poll response — the relay's own
// answer says only that the outcome was received.
func (h *harness) runFlow(machine string, p *fakeProvider, replace bool) (string, response) {
	h.t.Helper()
	flowID, relay := h.relayFlow(machine, p, replace)
	if relay.status != http.StatusAccepted {
		h.t.Fatalf("relay: status %d body %s", relay.status, relay.raw)
	}
	return flowID, h.awaitTerminal(machine, flowID)
}

// relayFlow runs a flow up to and including the relay, without waiting.
func (h *harness) relayFlow(machine string, p *fakeProvider, replace bool) (string, response) {
	h.t.Helper()
	start := h.start(machine, p.name, replace)
	if start.status != http.StatusCreated {
		h.t.Fatalf("start flow: status %d body %s", start.status, start.raw)
	}
	flowID := start.str("flow_id")
	code, providerErr, state := p.consent(h.t, h.client, start.str("authorization_url"))
	body := map[string]string{"state": state}
	if code != "" {
		body["code"] = code
	}
	if providerErr != "" {
		body["error"] = providerErr
	}
	return flowID, h.relay(machine, flowID, body)
}

// awaitTerminal polls until the flow finishes, exactly as the agent does. The
// exchange is a server-owned job now, so a terminal state is something a test
// waits for rather than something a response hands it.
func (h *harness) awaitTerminal(machine, flowID string) response {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		res := h.poll(machine, flowID)
		if res.status == http.StatusOK && res.str("state") != string(credflow.StatePending) {
			return res
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("flow %s never reached a terminal state (last: status %d body %s)", flowID, res.status, res.raw)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// credential reads what the broker stored, the way a grant-holding connector
// call would.
func (h *harness) credential(provider string) (credflow.Credential, int64, error) {
	h.t.Helper()
	return h.svc.Credential(context.Background(), provider)
}

func (h *harness) auditEvents() []store.AuditEvent {
	h.t.Helper()
	events, err := h.st.QueryAudit(context.Background(), store.AuditQuery{})
	if err != nil {
		h.t.Fatalf("query audit: %v", err)
	}
	return events
}
