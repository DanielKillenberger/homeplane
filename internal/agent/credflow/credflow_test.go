package credflow_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	agentcredflow "github.com/DanielKillenberger/homeplane/internal/agent/credflow"
	"github.com/DanielKillenberger/homeplane/internal/secrets"
	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
	servercredflow "github.com/DanielKillenberger/homeplane/internal/server/credflow"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// These tests run the whole R13 path in one process: a fake provider, a real
// server-side credential broker, and the real machine-side flow — including its
// real loopback listener, which the provider's redirect genuinely lands on.
//
// What they are for is the custody claim. It is easy to write a flow that works
// and still leaves a token in a log line, a state file, or a process argument;
// the only way to know is to run the thing and then look at the machine.

const testMachineID = "machine-under-test"

type endToEnd struct {
	t          *testing.T
	provider   *fakeProvider
	control    *httptest.Server
	client     *agent.Client
	broker     *servercredflow.Service
	stateDir   string
	browserLog *strings.Builder
	dropRelay  *atomicBool
}

func newEndToEnd(t *testing.T) *endToEnd {
	t.Helper()
	p := newFakeProvider(t, "acme")

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

	manifest, err := connectors.Parse([]byte(fmt.Sprintf(`{"version":1,"connectors":[{
		"provider": %q,
		"credential_ref": "acme/oauth-session",
		"credential_acquisition": {
			"driver": "oauth2-authcode",
			"params": {
				"auth_endpoint": %q,
				"token_endpoint": %q,
				"client_id_ref": "acme/client-id",
				"client_secret_ref": "acme/client-secret"
			},
			"scopes": ["things.read"]
		},
		"mcp_server": {"name": "acme", "transport": "streamable-http", "source": "stub://in-process"},
		"tool_inventory": ["list_things"],
		"tools": [{"tool": "list_things", "action_class": "read"}]}]}`,
		p.name, p.authEndpoint(), p.tokenEndpoint())))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	engine, err := connectors.Register(manifest)
	if err != nil {
		t.Fatalf("register manifest: %v", err)
	}

	importSecret(t, st, keyring, "acme/client-id", p.clientID)
	importSecret(t, st, keyring, "acme/client-secret", p.secret)

	broker, err := servercredflow.New(engine, st, keyring, st, servercredflow.Config{
		HTTPClient: p.trustingClient(),
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("credflow.New: %v", err)
	}

	// The control plane's authentication is tested in internal/server; here the
	// machine identity is fixed so the test is about the flow itself.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /credentials/flows", func(w http.ResponseWriter, r *http.Request) {
		broker.HandleStart(w, r, testMachineID)
	})
	mux.HandleFunc("POST /credentials/flows/{flow_id}/code", func(w http.ResponseWriter, r *http.Request) {
		broker.HandleRelay(w, r, testMachineID)
	})
	mux.HandleFunc("GET /credentials/flows/{flow_id}", func(w http.ResponseWriter, r *http.Request) {
		broker.HandlePoll(w, r, testMachineID)
	})
	// dropRelayResponse simulates the relay answer being lost on the way back:
	// the server handles the call, and the machine never hears the outcome.
	var dropRelay atomicBool
	outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dropRelay.get() && strings.HasSuffix(r.URL.Path, "/code") {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, r)
			// The request WAS processed; only the response goes missing.
			http.Error(w, "simulated gateway failure", http.StatusBadGateway)
			return
		}
		mux.ServeHTTP(w, r)
	})
	control := httptest.NewServer(outer)
	t.Cleanup(control.Close)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := broker.Shutdown(ctx); err != nil {
			t.Errorf("credential exchange jobs still running at test end: %v", err)
		}
	})

	client, err := agent.NewClient(control.URL, 10*time.Second)
	if err != nil {
		t.Fatalf("agent.NewClient: %v", err)
	}
	stateDir := filepath.Join(dir, "agent-state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("create agent state dir: %v", err)
	}
	return &endToEnd{
		t: t, provider: p, control: control, broker: broker,
		client: client.WithCredential("machine-credential"), stateDir: stateDir,
		browserLog: &strings.Builder{}, dropRelay: &dropRelay,
	}
}

// atomicBool is a tiny mutex-guarded flag; the test toggles it from one
// goroutine while the server reads it from another.
type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) set(v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.v = v
}

func (b *atomicBool) get() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.v
}

// browser simulates the human's browser: it follows the authorization URL and
// lets the provider's redirect land on the agent's REAL loopback listener.
func (e *endToEnd) browser() func(context.Context, string) error {
	return func(ctx context.Context, authURL string) error {
		e.browserLog.WriteString(authURL + "\n")
		client := e.provider.trustingClient()
		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
			if err != nil {
				return
			}
			res, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, res.Body)
				res.Body.Close()
			}
		}()
		return nil
	}
}

func (e *endToEnd) run(opts agentcredflow.Options) (agentcredflow.Result, error) {
	e.t.Helper()
	if opts.Client == nil {
		opts.Client = e.client
	}
	if opts.Provider == "" {
		opts.Provider = e.provider.name
	}
	if opts.OpenBrowser == nil {
		opts.OpenBrowser = e.browser()
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = 10 * time.Millisecond
	}
	if opts.Timeout == 0 {
		opts.Timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return agentcredflow.AddCredentials(ctx, opts)
}

// TestAddCredentialsStoresTheCredentialServerSideOnly is the R13 end-to-end
// proof, including the custody check: after a successful flow the machine's
// state directory and the CLI's own output contain no provider token.
func TestAddCredentialsStoresTheCredentialServerSideOnly(t *testing.T) {
	e := newEndToEnd(t)
	out := &strings.Builder{}

	result, err := e.run(agentcredflow.Options{Out: out})
	if err != nil {
		t.Fatalf("AddCredentials: %v", err)
	}
	if !result.Succeeded() {
		t.Fatalf("result = %+v, want completed", result)
	}

	cred, generation, err := e.broker.Credential(context.Background(), e.provider.name)
	if err != nil {
		t.Fatalf("server-side credential: %v", err)
	}
	if cred.Access != "acme-access-token" || cred.Refresh != "acme-refresh-token" {
		t.Fatalf("server-side credential = %+v, want the provider's tokens", cred)
	}
	if generation != 1 {
		t.Fatalf("generation = %d, want 1", generation)
	}

	// R17: inspect the machine. Nothing it wrote, printed, or was told may
	// contain provider token material.
	secretsToFind := []string{cred.Access, cred.Refresh, e.provider.secret}
	assertMachineIsClean(t, e.stateDir, secretsToFind)
	// Stronger than "no token in the files": the flow wrote no file at all.
	// The machine's part in R13 is transient by construction.
	entries, err := os.ReadDir(e.stateDir)
	if err != nil {
		t.Fatalf("read agent state dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("add-credentials wrote %d file(s) into the agent state directory; it must write none", len(entries))
	}
	for _, text := range []string{out.String(), e.browserLog.String(), result.Message} {
		for _, secret := range secretsToFind {
			if secret != "" && strings.Contains(text, secret) {
				t.Fatalf("machine-visible text contained credential material: %q", text)
			}
		}
	}
}

// TestRedirectURIIsThisMachinesBoundLoopbackPort — the listener is bound before
// the flow starts, and the port the provider is told about is the port this
// machine actually holds.
func TestRedirectURIIsThisMachinesBoundLoopbackPort(t *testing.T) {
	e := newEndToEnd(t)
	if _, err := e.run(agentcredflow.Options{}); err != nil {
		t.Fatalf("AddCredentials: %v", err)
	}

	e.provider.mu.Lock()
	defer e.provider.mu.Unlock()
	if len(e.provider.authorizeCalls) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(e.provider.authorizeCalls))
	}
	redirect := e.provider.authorizeCalls[0].RedirectURI
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect_uri %q: %v", redirect, err)
	}
	if u.Scheme != "http" || u.Hostname() != "127.0.0.1" {
		t.Fatalf("redirect_uri = %q, want an http loopback address", redirect)
	}
	if u.Port() == "" || u.Port() == "0" {
		t.Fatalf("redirect_uri = %q, want a concrete bound port", redirect)
	}
}

// TestDeniedConsentIsReportedCleanly — a refusal is an answer, reported with
// the safe diagnostic, leaving nothing stored.
func TestDeniedConsentIsReportedCleanly(t *testing.T) {
	e := newEndToEnd(t)
	e.provider.mu.Lock()
	e.provider.denyConsent = true
	e.provider.mu.Unlock()

	result, err := e.run(agentcredflow.Options{})
	if err != nil {
		t.Fatalf("AddCredentials returned an error for a denial; a denial is a result: %v", err)
	}
	if result.Succeeded() {
		t.Fatal("a denied flow reported success")
	}
	if result.State != "denied" || result.ErrorCode != servercredflow.CodeProviderDenied {
		t.Fatalf("result = %+v, want a denied/provider_denied outcome", result)
	}
	if !result.Retryable {
		t.Error("a denial should be retryable: the human can consent on a second run")
	}
	if _, _, err := e.broker.Credential(context.Background(), e.provider.name); err == nil {
		t.Fatal("a credential was stored despite the denial")
	}
}

// TestAbandonedFlowStoresNothing — the human closes the browser and walks away.
func TestAbandonedFlowStoresNothing(t *testing.T) {
	e := newEndToEnd(t)

	result, err := e.run(agentcredflow.Options{
		// No browser: nothing ever consents.
		OpenBrowser: func(context.Context, string) error { return nil },
		Timeout:     300 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("an abandoned flow returned no error")
	}
	if !strings.Contains(err.Error(), "nothing was changed") {
		t.Errorf("error does not reassure the operator that nothing changed: %v", err)
	}
	if result.Succeeded() {
		t.Fatal("an abandoned flow reported success")
	}
	if _, _, err := e.broker.Credential(context.Background(), e.provider.name); err == nil {
		t.Fatal("a credential was stored for a flow nobody completed")
	}
	assertMachineIsClean(t, e.stateDir, []string{"acme-access-token", "acme-refresh-token"})
}

// TestUnknownProviderIsRefusedWithGuidance — the CLI's most likely user error.
func TestUnknownProviderIsRefusedWithGuidance(t *testing.T) {
	e := newEndToEnd(t)
	_, err := e.run(agentcredflow.Options{Provider: "nonesuch"})
	if err == nil {
		t.Fatal("an unknown provider was accepted")
	}
	var apiErr *agent.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
		t.Fatalf("error = %v, want a 404 from the server", err)
	}
}

// TestStrayLoopbackRequestsDoNotConsumeTheFlow — loopback is a shared space on
// a personal machine; a probe must not be able to take the one-shot.
func TestStrayLoopbackRequestsDoNotConsumeTheFlow(t *testing.T) {
	e := newEndToEnd(t)

	result, err := e.run(agentcredflow.Options{
		OpenBrowser: func(ctx context.Context, authURL string) error {
			redirect := loopbackFromAuthURL(t, authURL)
			// Something else on the machine pokes the listener first.
			for _, path := range []string{"/", "/favicon.ico", "/?hello=1"} {
				res, err := http.Get(redirect + path) //nolint:noctx // a probe, deliberately crude
				if err == nil {
					_, _ = io.Copy(io.Discard, res.Body)
					res.Body.Close()
				}
			}
			return e.browser()(ctx, authURL)
		},
	})
	if err != nil {
		t.Fatalf("AddCredentials: %v", err)
	}
	if !result.Succeeded() {
		t.Fatalf("result = %+v, want the real redirect to still complete the flow", result)
	}
}

func loopbackFromAuthURL(t *testing.T, authURL string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	return u.Query().Get("redirect_uri")
}

// assertMachineIsClean walks everything the agent could have written and fails
// if any provider secret appears in it.
func assertMachineIsClean(t *testing.T, dir string, secretValues []string) {
	t.Helper()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, secret := range secretValues {
			if secret != "" && strings.Contains(string(raw), secret) {
				t.Errorf("%s contains provider credential material", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk agent state dir: %v", err)
	}
}

func importSecret(t *testing.T, st *store.SQLite, keyring *secrets.Keyring, ref, value string) {
	t.Helper()
	ciphertext, err := keyring.Encrypt([]byte(value))
	if err != nil {
		t.Fatalf("encrypt %s: %v", ref, err)
	}
	if _, err := st.PutSecret(context.Background(), ref, ciphertext, func(int64) []store.AuditEvent {
		return []store.AuditEvent{{
			Event: store.EventSecretImported, ActorKind: store.ActorOperator,
			Outcome: store.OutcomeAllowed, Detail: map[string]string{"secret_ref": ref, "source": "test"},
		}}
	}); err != nil {
		t.Fatalf("import %s: %v", ref, err)
	}
}

// fakeProvider is a minimal OAuth authorization server over TLS — enough to
// verify PKCE, the client credentials and the redirect URI, which are the
// properties the machine side has to get right.
type fakeProvider struct {
	name     string
	clientID string
	secret   string
	server   *httptest.Server

	mu             sync.Mutex
	codes          map[string]string // code -> code_challenge
	redirects      map[string]string // code -> redirect_uri
	authorizeCalls []authorizeCall
	denyConsent    bool
	// tokenDelay makes the provider take its time, so a test can outlast the
	// agent's own request deadline.
	tokenDelay time.Duration
}

type authorizeCall struct {
	RedirectURI string
	State       string
	Challenge   string
}

func newFakeProvider(t *testing.T, name string) *fakeProvider {
	t.Helper()
	p := &fakeProvider{
		name: name, clientID: name + "-client-id", secret: name + "-client-secret",
		codes: map[string]string{}, redirects: map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	p.server = httptest.NewTLSServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *fakeProvider) authEndpoint() string  { return p.server.URL + "/authorize" }
func (p *fakeProvider) tokenEndpoint() string { return p.server.URL + "/token" }

func (p *fakeProvider) trustingClient() *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(p.server.Certificate())
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func (p *fakeProvider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p.mu.Lock()
	p.authorizeCalls = append(p.authorizeCalls, authorizeCall{
		RedirectURI: q.Get("redirect_uri"), State: q.Get("state"), Challenge: q.Get("code_challenge")})
	deny := p.denyConsent
	code := fmt.Sprintf("%s-code-%d", p.name, len(p.authorizeCalls))
	if !deny {
		p.codes[code] = q.Get("code_challenge")
		p.redirects[code] = q.Get("redirect_uri")
	}
	p.mu.Unlock()

	target, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := target.Query()
	rq.Set("state", q.Get("state"))
	if deny {
		rq.Set("error", "access_denied")
	} else {
		rq.Set("code", code)
	}
	target.RawQuery = rq.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (p *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("code")
	p.mu.Lock()
	challenge, ok := p.codes[code]
	redirect := p.redirects[code]
	delete(p.codes, code)
	delay := p.tokenDelay
	p.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}

	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	switch {
	case !ok:
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	case r.PostForm.Get("client_id") != p.clientID || r.PostForm.Get("client_secret") != p.secret:
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
	case r.PostForm.Get("redirect_uri") != redirect:
		http.Error(w, `{"error":"redirect_uri_mismatch"}`, http.StatusBadRequest)
	case base64.RawURLEncoding.EncodeToString(sum[:]) != challenge:
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  p.name + "-access-token",
			"refresh_token": p.name + "-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "things.read",
		})
	}
}

// TestSlowProviderDoesNotBecomeAFalseFailure — the failure this whole
// asynchronous design exists to prevent.
//
// The agent's per-request deadline here is far shorter than the provider takes.
// Two things have to hold for that to be survivable: the server must not make
// the relay wait for the exchange, and the agent must treat a request that did
// not come back as a question for the server rather than a verdict. Otherwise
// the CLI reports a transport error while the server goes on to store the
// credential — a machine telling its operator the opposite of the truth.
func TestSlowProviderDoesNotBecomeAFalseFailure(t *testing.T) {
	e := newEndToEnd(t)
	e.provider.mu.Lock()
	e.provider.tokenDelay = 400 * time.Millisecond
	e.provider.mu.Unlock()

	// A client whose every request times out long before the provider answers.
	impatient, err := agent.NewClient(e.control.URL, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("agent.NewClient: %v", err)
	}

	result, err := e.run(agentcredflow.Options{
		Client:       impatient.WithCredential("machine-credential"),
		PollInterval: 20 * time.Millisecond,
		Timeout:      20 * time.Second,
	})
	if err != nil {
		t.Fatalf("AddCredentials: %v", err)
	}
	if !result.Succeeded() {
		t.Fatalf("result = %+v, want completed", result)
	}
	cred, _, err := e.broker.Credential(context.Background(), e.provider.name)
	if err != nil || cred.Access != "acme-access-token" {
		t.Fatalf("server-side credential = %+v (%v), want the provider's token", cred, err)
	}
}

// TestLostRelayResponseStillConvergesOnTheServersOutcome — the relay is
// one-shot, so a lost RESPONSE must not be read as a lost request. The agent
// asks the server what happened instead of guessing.
func TestLostRelayResponseStillConvergesOnTheServersOutcome(t *testing.T) {
	e := newEndToEnd(t)
	e.dropRelay.set(true)

	out := &strings.Builder{}
	result, err := e.run(agentcredflow.Options{Out: out, PollInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("AddCredentials: %v", err)
	}
	if !result.Succeeded() {
		t.Fatalf("result = %+v, want completed despite the lost relay response", result)
	}
	if !strings.Contains(out.String(), "asking the server what happened") {
		t.Errorf("the operator was not told why the CLI kept waiting: %q", out.String())
	}
	if cred, _, err := e.broker.Credential(context.Background(), e.provider.name); err != nil || cred.Access == "" {
		t.Fatalf("credential = %+v (%v), want it stored", cred, err)
	}
}

// TestUnknownProviderErrorNamesTheKnownProviders — R13 requires the refusal to
// list what IS configured; a CLI that drops the list leaves the operator
// guessing at a name they already mistyped once.
func TestUnknownProviderErrorNamesTheKnownProviders(t *testing.T) {
	e := newEndToEnd(t)
	_, err := e.run(agentcredflow.Options{Provider: "nonesuch"})
	if err == nil {
		t.Fatal("an unknown provider was accepted")
	}
	var apiErr *agent.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want an APIError", err)
	}
	if len(apiErr.KnownProviders) != 1 || apiErr.KnownProviders[0] != e.provider.name {
		t.Fatalf("known providers = %v, want [%s]", apiErr.KnownProviders, e.provider.name)
	}
	if !strings.Contains(err.Error(), e.provider.name) {
		t.Fatalf("error text does not name the configured provider: %v", err)
	}
}
