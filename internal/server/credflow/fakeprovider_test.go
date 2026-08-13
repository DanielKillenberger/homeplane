package credflow_test

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

// fakeProvider is a stand-in OAuth 2.0 authorization server: an authorization
// endpoint that redirects back with a code, and a token endpoint that redeems
// it. It verifies the things a real provider verifies — PKCE, the client
// credentials, and that the redirect URI presented at exchange is byte-identical
// to the one the authorization request carried — because those are exactly the
// properties this package claims to uphold.
//
// It is served over TLS because the manifest refuses a non-https endpoint, and
// that refusal is load-bearing: the test must not be able to prove the flow
// against a manifest the real validator would reject.
type fakeProvider struct {
	t        *testing.T
	name     string
	server   *httptest.Server
	clientID string
	secret   string

	mu sync.Mutex
	// codes maps an issued authorization code to the authorization request it
	// came from.
	codes map[string]authRequest
	// authorizeCalls records every authorization request, so a test can assert
	// what the server put in the URL.
	authorizeCalls []authRequest

	// Failure switches, all off by default.
	denyConsent   bool
	tokenStatus   int
	tokenBody     string
	dropRefresh   bool
	issuedRefresh string
}

type authRequest struct {
	ClientID    string
	RedirectURI string
	Scope       string
	State       string
	Challenge   string
	Method      string
	AccessType  string
	Prompt      string
}

func newFakeProvider(t *testing.T, name string) *fakeProvider {
	t.Helper()
	p := &fakeProvider{
		t:             t,
		name:          name,
		clientID:      name + "-client-id",
		secret:        name + "-client-secret",
		codes:         map[string]authRequest{},
		issuedRefresh: name + "-refresh-token",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", p.handleAuthorize)
	mux.HandleFunc("/token", p.handleToken)
	p.server = httptest.NewTLSServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *fakeProvider) authEndpoint() string  { return p.server.URL + "/authorize" }
func (p *fakeProvider) tokenEndpoint() string { return p.server.URL + "/token" }

func (p *fakeProvider) certificate() *x509.Certificate { return p.server.Certificate() }

func (p *fakeProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := authRequest{
		ClientID:    q.Get("client_id"),
		RedirectURI: q.Get("redirect_uri"),
		Scope:       q.Get("scope"),
		State:       q.Get("state"),
		Challenge:   q.Get("code_challenge"),
		Method:      q.Get("code_challenge_method"),
		AccessType:  q.Get("access_type"),
		Prompt:      q.Get("prompt"),
	}
	p.mu.Lock()
	p.authorizeCalls = append(p.authorizeCalls, req)
	deny := p.denyConsent
	code := fmt.Sprintf("%s-code-%d", p.name, len(p.authorizeCalls))
	if !deny {
		p.codes[code] = req
	}
	p.mu.Unlock()

	target, err := url.Parse(req.RedirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := target.Query()
	rq.Set("state", req.State)
	if deny {
		rq.Set("error", "access_denied")
	} else {
		rq.Set("code", code)
	}
	target.RawQuery = rq.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (p *fakeProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	status, body := p.tokenStatus, p.tokenBody
	p.mu.Unlock()
	if status != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("code")
	p.mu.Lock()
	authReq, ok := p.codes[code]
	if ok {
		// One-shot at the provider too: a replayed code is not redeemable.
		delete(p.codes, code)
	}
	dropRefresh, refresh := p.dropRefresh, p.issuedRefresh
	p.mu.Unlock()

	switch {
	case !ok:
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	case r.PostForm.Get("grant_type") != "authorization_code":
		http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
		return
	case r.PostForm.Get("client_id") != p.clientID || r.PostForm.Get("client_secret") != p.secret:
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	case r.PostForm.Get("redirect_uri") != authReq.RedirectURI:
		// The requirement that makes the client's loopback address travel all
		// the way through the server's flow.
		http.Error(w, `{"error":"redirect_uri_mismatch"}`, http.StatusBadRequest)
		return
	case s256(r.PostForm.Get("code_verifier")) != authReq.Challenge:
		http.Error(w, `{"error":"invalid_grant","error_description":"pkce"}`, http.StatusBadRequest)
		return
	}

	out := map[string]any{
		"access_token": p.name + "-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        authReq.Scope,
	}
	if !dropRefresh {
		out["refresh_token"] = refresh
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// consent drives the browser half of the flow: it follows the authorization URL
// and returns what the provider redirected to the loopback listener with.
func (p *fakeProvider) consent(t *testing.T, client *http.Client, authURL string) (code, providerErr, state string) {
	t.Helper()
	// The redirect target is the agent's loopback listener, which does not
	// exist in a server-side test — so the redirect is caught rather than
	// followed, and its query string read directly.
	noFollow := *client
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := noFollow.Get(authURL)
	if err != nil {
		t.Fatalf("authorization request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("authorization request: status %d, want 302", res.StatusCode)
	}
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	q := loc.Query()
	return q.Get("code"), q.Get("error"), q.Get("state")
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// providerClient returns an HTTP client trusting every given fake provider —
// the credential broker holds ONE client, so a multi-provider test needs one
// pool covering them all.
func providerClient(providers ...*fakeProvider) *http.Client {
	pool := x509.NewCertPool()
	for _, p := range providers {
		pool.AddCert(p.certificate())
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport}
}
