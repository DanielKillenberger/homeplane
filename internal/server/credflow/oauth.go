package credflow

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
)

// This file is the whole of the `oauth2-authcode` credential driver. It reads
// its endpoints, scopes and client-credential references from the connector
// manifest and knows nothing about any particular provider — which is what
// makes R12 true for credentials as well as for tools: a second OAuth provider
// is a manifest entry, not a branch in here.

// maxTokenResponseBytes bounds a provider's token response. It is generous for
// a token payload and small enough that a misconfigured endpoint answering with
// a login page cannot stream into memory.
const maxTokenResponseBytes = 1 << 20

// authorizationURL builds the provider consent URL for a flow.
//
// redirectURI is the client's loopback address, already validated, and it is
// carried verbatim into the token exchange later: providers (Google among them)
// require the authorization request and the exchange to present the identical
// redirect URI, and any normalization here would break that silently.
func authorizationURL(conn connectors.Connector, clientID, redirectURI, state, verifier string) (string, error) {
	endpoint := conn.Credential.Params["auth_endpoint"]
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("credflow: provider %q has an unusable auth_endpoint: %w", conn.Provider, err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(conn.Credential.Scopes, " "))
	q.Set("state", state)
	// PKCE is not optional here even though this is a confidential client: the
	// authorization code travels back through a loopback listener on a machine
	// that may run other software as the same OS user (the spec's stated
	// same-OS-user limitation). The verifier never leaves this server, so a code
	// intercepted on that machine is not redeemable.
	q.Set("code_challenge", codeChallenge(verifier))
	q.Set("code_challenge_method", "S256")
	// Optional, manifest-declared provider knobs.
	if v := conn.Credential.Params["access_type"]; v != "" {
		q.Set("access_type", v)
	}
	if v := conn.Credential.Params["prompt"]; v != "" {
		q.Set("prompt", v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// codeChallenge is RFC 7636's S256 transformation.
func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// tokenResponse is the subset of a token endpoint's answer Homeplane stores.
// Unknown fields are ignored rather than retained: whatever else a provider
// sends is not something this server has decided it is safe to keep.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
}

// errNoAccessToken means the endpoint answered 200 without a usable credential.
var errNoAccessToken = errors.New("token response contained no access_token")

// exchangeCode redeems an authorization code for provider tokens.
//
// Every error returned here is for the SERVER's log. The caller maps it to the
// fixed `exchange_failed` diagnostic, because a token endpoint's error body can
// contain anything at all — including credential material — and none of it may
// reach a machine.
func exchangeCode(ctx context.Context, client *http.Client, conn connectors.Connector,
	clientID, clientSecret, redirectURI, code, verifier string) (tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)

	endpoint := conn.Credential.Params["token_endpoint"]
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("token endpoint unreachable: %w", err)
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxTokenResponseBytes))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("read token response: %w", err)
	}
	if res.StatusCode/100 != 2 {
		// The body is NOT included: this error string reaches the server log,
		// and a token endpoint's error body is not something to copy around.
		return tokenResponse{}, fmt.Errorf("token endpoint returned %d", res.StatusCode)
	}
	var tokens tokenResponse
	if err := json.Unmarshal(raw, &tokens); err != nil {
		return tokenResponse{}, fmt.Errorf("malformed token response: %w", err)
	}
	if tokens.AccessToken == "" {
		return tokenResponse{}, errNoAccessToken
	}
	return tokens, nil
}

// sanitizeProviderError reduces a provider's OAuth error identifier to a short,
// character-restricted label. The standard values (`access_denied`,
// `consent_required`, …) survive intact; anything else becomes "unspecified",
// so a provider cannot use this field to push arbitrary text — or a token — into
// a diagnostic the agent prints.
func sanitizeProviderError(v string) string {
	if v == "" || len(v) > 64 {
		return "unspecified"
	}
	for _, r := range v {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '_' {
			return "unspecified"
		}
	}
	return v
}
