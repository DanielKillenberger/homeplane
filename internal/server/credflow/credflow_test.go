package credflow_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/server/credflow"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// TestCompletedFlowStoresCredentialServerSide is the R13 happy path: consent
// given on a machine ends with a provider credential encrypted in the server's
// store, immediately readable by the path a grant-holding call would take, and
// with no token material anywhere in what the machine was told.
func TestCompletedFlowStoresCredentialServerSide(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})

	flowID, poll := h.runFlow(machineA, p, false)
	if got := poll.str("state"); got != string(credflow.StateCompleted) {
		t.Fatalf("flow state = %q, want completed (body %s)", got, poll.raw)
	}
	_ = flowID

	cred, generation, err := h.credential(p.name)
	if err != nil {
		t.Fatalf("read stored credential: %v", err)
	}
	if cred.Access != "alpha-access-token" || cred.Refresh != "alpha-refresh-token" {
		t.Fatalf("stored credential = %+v, want the provider's issued tokens", cred)
	}
	if generation != 1 {
		t.Fatalf("credential generation = %d, want 1", generation)
	}
	if cred.ExpiresAt.IsZero() {
		t.Error("stored credential has no expiry; the provider reported expires_in")
	}

	// Custody: nothing the machine ever saw contains token material.
	for _, seen := range []string{poll.raw} {
		for _, secret := range []string{cred.Access, cred.Refresh, p.secret} {
			if strings.Contains(seen, secret) {
				t.Fatalf("a response returned to the machine contained credential material: %s", seen)
			}
		}
	}
}

// TestAuthorizationRequestUsesTheClientsRedirectURI pins the property Google
// requires and the loopback design depends on: the authorization URL is built
// with the machine's own redirect URI, and the exchange presents the identical
// one (the fake provider rejects a mismatch, so a completed flow proves it).
func TestAuthorizationRequestUsesTheClientsRedirectURI(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})

	const redirect = "http://127.0.0.1:41999"
	start := h.startWithRedirect(machineA, p.name, redirect, false)
	if start.status != http.StatusCreated {
		t.Fatalf("start: status %d body %s", start.status, start.raw)
	}
	code, _, state := p.consent(t, h.client, start.str("authorization_url"))
	if relay := h.relay(machineA, start.str("flow_id"), map[string]string{"code": code, "state": state}); relay.status != http.StatusAccepted {
		t.Fatalf("relay: status %d body %s", relay.status, relay.raw)
	}
	if final := h.awaitTerminal(machineA, start.str("flow_id")); final.str("state") != string(credflow.StateCompleted) {
		t.Fatalf("flow state = %q, want completed (body %s)", final.str("state"), final.raw)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.authorizeCalls) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(p.authorizeCalls))
	}
	call := p.authorizeCalls[0]
	if call.RedirectURI != redirect {
		t.Errorf("authorization redirect_uri = %q, want %q", call.RedirectURI, redirect)
	}
	if call.Method != "S256" || call.Challenge == "" {
		t.Errorf("authorization request lacks PKCE: challenge=%q method=%q", call.Challenge, call.Method)
	}
	if call.Scope != "things.read things.write" {
		t.Errorf("scope = %q, want the manifest's scopes", call.Scope)
	}
	// Manifest-declared optional driver knobs travel too.
	if call.AccessType != "offline" || call.Prompt != "consent" {
		t.Errorf("access_type/prompt = %q/%q, want the manifest's values", call.AccessType, call.Prompt)
	}
}

// TestRedirectURIValidation covers the check that decides where a provider will
// send an authorization code.
func TestRedirectURIValidation(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})

	accepted := []string{
		"http://127.0.0.1:53682",
		"http://127.0.0.1:1",
		"http://127.0.0.1:65535/",
		"http://[::1]:53682",
	}
	for _, redirect := range accepted {
		t.Run("accept "+redirect, func(t *testing.T) {
			res := h.startWithRedirect(machineA, p.name, redirect, true)
			if res.status != http.StatusCreated {
				t.Fatalf("status %d, want 201 (body %s)", res.status, res.raw)
			}
		})
	}

	rejected := []struct{ name, redirect string }{
		{"other host", "http://evil.example.com:53682"},
		{"loopback name", "http://localhost:53682"},
		{"https", "https://127.0.0.1:53682"},
		{"no port", "http://127.0.0.1"},
		{"path", "http://127.0.0.1:53682/callback"},
		{"path traversal", "http://127.0.0.1:53682/../x"},
		{"query", "http://127.0.0.1:53682?next=http://evil.example.com"},
		{"fragment", "http://127.0.0.1:53682#x"},
		{"userinfo host trick", "http://127.0.0.1:53682@evil.example.com:80"},
		{"decimal loopback", "http://2130706433:53682"},
		{"other loopback address", "http://127.0.0.2:53682"},
		{"custom scheme", "com.homeplane.app:/oauth"},
		{"empty", ""},
		{"whitespace", " http://127.0.0.1:53682 "},
		{"port out of range", "http://127.0.0.1:70000"},
	}
	for _, tc := range rejected {
		t.Run("reject "+tc.name, func(t *testing.T) {
			res := h.startWithRedirect(machineA, p.name, tc.redirect, true)
			if res.status != http.StatusBadRequest {
				t.Fatalf("status %d, want 400 (body %s)", res.status, res.raw)
			}
		})
	}
}

// TestUnknownProviderIsRefusedWithTheKnownList — being told "unknown" without
// being told what IS known is a dead end for whoever typed the name.
func TestUnknownProviderIsRefusedWithTheKnownList(t *testing.T) {
	alpha, beta := newFakeProvider(t, "alpha"), newFakeProvider(t, "beta")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{alpha, beta}})

	res := h.start(machineA, "nonesuch", false)
	if res.status != http.StatusNotFound {
		t.Fatalf("status %d, want 404 (body %s)", res.status, res.raw)
	}
	known, _ := res.body["known_providers"].([]any)
	if len(known) != 2 {
		t.Fatalf("known_providers = %v, want both configured providers", res.body["known_providers"])
	}
}

// TestAlreadyConfiguredProviderRequiresReplace — R13 forbids a silent overwrite.
func TestAlreadyConfiguredProviderRequiresReplace(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})
	h.seedCredential(p.name, "existing-access-token")

	refused := h.start(machineA, p.name, false)
	if refused.status != http.StatusConflict {
		t.Fatalf("status %d, want 409 (body %s)", refused.status, refused.raw)
	}
	if !strings.Contains(refused.str("message"), "replace") {
		t.Errorf("refusal does not say how to proceed: %q", refused.str("message"))
	}
	// The refusal changed nothing.
	if cred, _, err := h.credential(p.name); err != nil || cred.Access != "existing-access-token" {
		t.Fatalf("existing credential disturbed by a refused start: %+v (%v)", cred, err)
	}

	_, final := h.runFlow(machineA, p, true)
	if final.str("state") != string(credflow.StateCompleted) {
		t.Fatalf("replace flow state = %q, want completed (body %s)", final.str("state"), final.raw)
	}
	cred, generation, err := h.credential(p.name)
	if err != nil {
		t.Fatalf("read credential: %v", err)
	}
	if cred.Access != "alpha-access-token" {
		t.Errorf("credential after replace = %q, want the new token", cred.Access)
	}
	if generation != 2 {
		t.Errorf("generation after replace = %d, want 2", generation)
	}
}

// TestUnsuccessfulTerminalStatesPreserveTheExistingCredential is the atomic-swap
// claim, checked once per terminal failure state: the old credential must be
// exactly as it was, at the same generation, in every one of them.
func TestUnsuccessfulTerminalStatesPreserveTheExistingCredential(t *testing.T) {
	cases := []struct {
		name      string
		wantState credflow.State
		wantCode  string
		// run drives the flow to its terminal state and returns the flow id.
		run func(t *testing.T, h *harness, p *fakeProvider) string
	}{
		{
			name: "denied", wantState: credflow.StateDenied, wantCode: credflow.CodeProviderDenied,
			run: func(t *testing.T, h *harness, p *fakeProvider) string {
				p.mu.Lock()
				p.denyConsent = true
				p.mu.Unlock()
				flowID, _ := h.runFlow(machineA, p, true)
				return flowID
			},
		},
		{
			name: "expired", wantState: credflow.StateExpired, wantCode: credflow.CodeFlowExpired,
			run: func(t *testing.T, h *harness, p *fakeProvider) string {
				start := h.start(machineA, p.name, true)
				h.advance(2 * time.Hour)
				return start.str("flow_id")
			},
		},
		{
			name: "exchange failure", wantState: credflow.StateFailed, wantCode: credflow.CodeExchangeFailed,
			run: func(t *testing.T, h *harness, p *fakeProvider) string {
				start := h.start(machineA, p.name, true)
				code, _, state := p.consent(t, h.client, start.str("authorization_url"))
				p.mu.Lock()
				p.tokenStatus = http.StatusBadRequest
				p.tokenBody = `{"error":"invalid_grant"}`
				p.mu.Unlock()
				h.relay(machineA, start.str("flow_id"), map[string]string{"code": code, "state": state})
				return start.str("flow_id")
			},
		},
		{
			name: "abandoned", wantState: credflow.StatePending, wantCode: "",
			run: func(t *testing.T, h *harness, p *fakeProvider) string {
				// The human walks away: consent is never given, nothing is
				// relayed, and the flow simply sits there.
				return h.start(machineA, p.name, true).str("flow_id")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeProvider(t, "alpha")
			h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}, clock: newClock()})
			h.seedCredential(p.name, "existing-access-token")

			flowID := tc.run(t, h, p)
			poll := h.poll(machineA, flowID)
			if tc.wantState != credflow.StatePending {
				poll = h.awaitTerminal(machineA, flowID)
			}
			if got := poll.str("state"); got != string(tc.wantState) {
				t.Fatalf("state = %q, want %q (body %s)", got, tc.wantState, poll.raw)
			}
			if tc.wantCode != "" {
				diag := poll.diagnostic()
				if diag == nil {
					t.Fatalf("terminal failure has no diagnostic: %s", poll.raw)
				}
				if diag["error_code"] != tc.wantCode {
					t.Errorf("error_code = %v, want %q", diag["error_code"], tc.wantCode)
				}
				if diag["retryable"] != true {
					t.Errorf("retryable = %v, want true", diag["retryable"])
				}
			}

			cred, generation, err := h.credential(p.name)
			if err != nil {
				t.Fatalf("read credential: %v", err)
			}
			if cred.Access != "existing-access-token" {
				t.Errorf("credential = %q, want the untouched existing one", cred.Access)
			}
			if generation != 1 {
				t.Errorf("generation = %d, want 1 (nothing should have been written)", generation)
			}
		})
	}
}

// TestStoreFailureLeavesNothingPartial covers the terminal state that happens
// AFTER a valid code: the tokens existed, and storing them failed.
func TestStoreFailureLeavesNothingPartial(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	failing := &failingSecretStore{}
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}, secretStore: failing})
	h.seedCredential(p.name, "existing-access-token")
	failing.delegate = h.st
	failing.failWrites = true

	_, poll := h.runFlow(machineA, p, true)
	if poll.str("state") != string(credflow.StateFailed) {
		t.Fatalf("state = %q, want failed (body %s)", poll.str("state"), poll.raw)
	}
	diag := poll.diagnostic()
	if diag["error_code"] != credflow.CodeStoreFailed || diag["retryable"] != true {
		t.Fatalf("diagnostic = %v, want a retryable store_failed", diag)
	}

	// The old credential is intact, and a fresh flow still works — "retryable"
	// has to mean something.
	failing.failWrites = false
	if cred, generation, err := h.credential(p.name); err != nil || cred.Access != "existing-access-token" || generation != 1 {
		t.Fatalf("credential after store failure = %+v gen %d (%v)", cred, generation, err)
	}
	_, final := h.runFlow(machineA, p, true)
	if final.str("state") != string(credflow.StateCompleted) {
		t.Fatalf("retry after store failure = %q, want completed", final.str("state"))
	}
}

// TestCodeRelayIsOneShot — a replayed code must not start a second exchange.
func TestCodeRelayIsOneShot(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})

	start := h.start(machineA, p.name, false)
	code, _, state := p.consent(t, h.client, start.str("authorization_url"))
	flowID := start.str("flow_id")

	first := h.relay(machineA, flowID, map[string]string{"code": code, "state": state})
	if first.status != http.StatusAccepted {
		t.Fatalf("first relay: status %d body %s", first.status, first.raw)
	}
	if final := h.awaitTerminal(machineA, flowID); final.str("state") != string(credflow.StateCompleted) {
		t.Fatalf("first relay ended as %q, want completed", final.str("state"))
	}
	second := h.relay(machineA, flowID, map[string]string{"code": code, "state": state})
	if second.status != http.StatusConflict {
		t.Fatalf("replayed relay: status %d, want 409 (body %s)", second.status, second.raw)
	}
	if _, generation, err := h.credential(p.name); err != nil || generation != 1 {
		t.Fatalf("replay changed the stored credential: generation %d (%v)", generation, err)
	}
}

// TestStateMismatchIsRefusedWithoutBurningTheFlow — a forged or stale callback
// must not be able to kill a flow the human is still completing.
func TestStateMismatchIsRefusedWithoutBurningTheFlow(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})

	start := h.start(machineA, p.name, false)
	flowID := start.str("flow_id")
	bad := h.relay(machineA, flowID, map[string]string{"code": "attacker-code", "state": "not-the-state"})
	if bad.status != http.StatusBadRequest {
		t.Fatalf("mismatched state: status %d, want 400 (body %s)", bad.status, bad.raw)
	}
	if got := h.poll(machineA, flowID).str("state"); got != string(credflow.StatePending) {
		t.Fatalf("flow state after a rejected callback = %q, want pending", got)
	}

	code, _, state := p.consent(t, h.client, start.str("authorization_url"))
	if good := h.relay(machineA, flowID, map[string]string{"code": code, "state": state}); good.status != http.StatusAccepted {
		t.Fatalf("legitimate relay after a rejected one: status %d body %s", good.status, good.raw)
	}
	if final := h.awaitTerminal(machineA, flowID); final.str("state") != string(credflow.StateCompleted) {
		t.Fatalf("legitimate relay after a rejected one = %q, want completed (body %s)", final.str("state"), final.raw)
	}
}

// TestRelayRequiresExactlyOneOutcome guards the relay body's shape.
func TestRelayRequiresExactlyOneOutcome(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})
	flowID := h.start(machineA, p.name, false).str("flow_id")

	for _, body := range []map[string]string{
		{"state": "x"},
		{"code": "c", "error": "access_denied", "state": "x"},
		{"code": "c"},
	} {
		if res := h.relay(machineA, flowID, body); res.status != http.StatusBadRequest {
			t.Errorf("relay %v: status %d, want 400 (body %s)", body, res.status, res.raw)
		}
	}
}

// TestFlowsAreScopedToTheMachineThatStartedThem — another machine cannot poll,
// relay to, or even learn of a flow it did not start.
func TestFlowsAreScopedToTheMachineThatStartedThem(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})

	start := h.start(machineA, p.name, false)
	flowID := start.str("flow_id")
	code, _, state := p.consent(t, h.client, start.str("authorization_url"))

	if res := h.poll(machineB, flowID); res.status != http.StatusNotFound {
		t.Errorf("cross-machine poll: status %d, want 404 (body %s)", res.status, res.raw)
	}
	if res := h.relay(machineB, flowID, map[string]string{"code": code, "state": state}); res.status != http.StatusNotFound {
		t.Errorf("cross-machine relay: status %d, want 404 (body %s)", res.status, res.raw)
	}
	if res := h.poll(machineA, flowID); res.str("state") != string(credflow.StatePending) {
		t.Errorf("owner's flow disturbed by another machine: %s", res.raw)
	}
}

// TestConcurrentFlowsFromTwoMachinesCommitExactlyOnce is the race R13 has to
// survive: two machines authorizing the same provider at the same time. One
// commits; the other is told, in words, that nothing of its was written.
func TestConcurrentFlowsFromTwoMachinesCommitExactlyOnce(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})
	h.seedCredential(p.name, "existing-access-token")

	// Both flows start BEFORE either finishes: each observes generation 1, and
	// that shared observation is what the compare-and-swap resolves.
	startA := h.start(machineA, p.name, true)
	startB := h.start(machineB, p.name, true)
	if startA.status != http.StatusCreated || startB.status != http.StatusCreated {
		t.Fatalf("starts: %d / %d", startA.status, startB.status)
	}
	codeA, _, stateA := p.consent(t, h.client, startA.str("authorization_url"))
	codeB, _, stateB := p.consent(t, h.client, startB.str("authorization_url"))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		h.relay(machineA, startA.str("flow_id"), map[string]string{"code": codeA, "state": stateA})
	}()
	go func() {
		defer wg.Done()
		h.relay(machineB, startB.str("flow_id"), map[string]string{"code": codeB, "state": stateB})
	}()
	wg.Wait()

	results := []response{
		h.awaitTerminal(machineA, startA.str("flow_id")),
		h.awaitTerminal(machineB, startB.str("flow_id")),
	}

	var completed, lost int
	for _, res := range results {
		switch res.str("state") {
		case string(credflow.StateCompleted):
			completed++
		case string(credflow.StateFailed):
			lost++
			diag := res.diagnostic()
			if diag["error_code"] != credflow.CodeConcurrentReplacement {
				t.Errorf("loser error_code = %v, want %q", diag["error_code"], credflow.CodeConcurrentReplacement)
			}
			if diag["retryable"] != true {
				t.Errorf("loser retryable = %v, want true", diag["retryable"])
			}
			if msg, _ := diag["message"].(string); !strings.Contains(msg, "re-run") {
				t.Errorf("loser message does not tell the operator what to do: %q", msg)
			}
		default:
			t.Errorf("unexpected terminal state %q (body %s)", res.str("state"), res.raw)
		}
	}
	if completed != 1 || lost != 1 {
		t.Fatalf("completed=%d lost=%d, want exactly one of each", completed, lost)
	}

	// Exactly one commit happened: the credential moved one generation, and the
	// audit log agrees.
	_, generation, err := h.credential(p.name)
	if err != nil {
		t.Fatalf("read credential: %v", err)
	}
	if generation != 2 {
		t.Fatalf("generation = %d, want 2 (one commit on top of the seeded credential)", generation)
	}
	commits := 0
	for _, e := range h.auditEvents() {
		if e.Event == store.EventCredentialFlowCommitted {
			commits++
		}
	}
	if commits != 1 {
		t.Fatalf("credential_flow_committed rows = %d, want 1", commits)
	}
}

// TestDiagnosticsNeverCarryProviderBodies — the terminal diagnostic is the one
// thing a failed flow hands a machine, and a token endpoint's error body is the
// kind of place credential material shows up.
func TestDiagnosticsNeverCarryProviderBodies(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})

	const leak = "ya29.LEAKED-PROVIDER-TOKEN"
	start := h.start(machineA, p.name, false)
	code, _, state := p.consent(t, h.client, start.str("authorization_url"))
	p.mu.Lock()
	p.tokenStatus = http.StatusBadRequest
	p.tokenBody = `{"error":"invalid_grant","error_description":"stale token ` + leak + `","access_token":"` + leak + `"}`
	p.mu.Unlock()

	relay := h.relay(machineA, start.str("flow_id"), map[string]string{"code": code, "state": state})
	poll := h.awaitTerminal(machineA, start.str("flow_id"))
	for _, body := range []string{relay.raw, poll.raw} {
		if strings.Contains(body, leak) || strings.Contains(body, "invalid_grant") {
			t.Fatalf("provider response leaked into a machine-visible body: %s", body)
		}
	}
	if poll.diagnostic()["error_code"] != credflow.CodeExchangeFailed {
		t.Fatalf("diagnostic = %v, want exchange_failed", poll.diagnostic())
	}
}

// TestProviderDenialReasonIsSanitized — the provider's error identifier is
// echoed only when it is a plain OAuth error code.
func TestProviderDenialReasonIsSanitized(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})
	start := h.start(machineA, p.name, false)
	flowID := start.str("flow_id")

	// A well-formed denial keeps its code.
	h.relay(machineA, flowID, map[string]string{
		"error": "access_denied", "state": oauthStateFrom(t, start.str("authorization_url"))})
	relay := h.awaitTerminal(machineA, flowID)
	if relay.str("state") != string(credflow.StateDenied) {
		t.Fatalf("state = %q, want denied (body %s)", relay.str("state"), relay.raw)
	}
	if msg, _ := relay.diagnostic()["message"].(string); !strings.Contains(msg, "access_denied") {
		t.Errorf("denial message lost the provider's error code: %q", msg)
	}

	// An abusive one does not.
	start2 := h.start(machineA, p.name, false)
	h.relay(machineA, start2.str("flow_id"), map[string]string{
		"error": "<script>alert(1)</script> ya29.TOKEN", "state": oauthStateFrom(t, start2.str("authorization_url"))})
	relay2 := h.awaitTerminal(machineA, start2.str("flow_id"))
	msg, _ := relay2.diagnostic()["message"].(string)
	if strings.Contains(msg, "script") || strings.Contains(msg, "ya29") {
		t.Fatalf("unsanitized provider error reached the diagnostic: %q", msg)
	}
	if !strings.Contains(msg, "unspecified") {
		t.Errorf("sanitized message = %q, want it to say the reason was unspecified", msg)
	}
}

// TestMissingClientCredentialsAreRefusedBeforeAFlowStarts — a provider whose
// client credentials were never imported cannot produce a usable authorization
// URL, and saying so at start is far kinder than failing after consent.
func TestMissingClientCredentialsAreRefusedBeforeAFlowStarts(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}, skipClientSecrets: true})

	res := h.start(machineA, p.name, false)
	if res.status != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 (body %s)", res.status, res.raw)
	}
	if !strings.Contains(res.str("message"), "admin secret import") {
		t.Errorf("message does not name the fix: %q", res.str("message"))
	}
}

// TestFlowLifecycleIsAudited — a credential that appeared in the store with no
// record of which machine brokered it would be unattributable.
func TestFlowLifecycleIsAudited(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})

	flowID, _ := h.runFlow(machineA, p, false)

	events := h.auditEvents()
	var started, committed *store.AuditEvent
	for i, e := range events {
		switch e.Event {
		case store.EventCredentialFlowStarted:
			started = &events[i]
		case store.EventCredentialFlowCommitted:
			committed = &events[i]
		}
	}
	if started == nil || committed == nil {
		t.Fatalf("missing lifecycle rows: started=%v committed=%v", started, committed)
	}
	for _, e := range []*store.AuditEvent{started, committed} {
		if e.AuthMachineID != machineA {
			t.Errorf("%s attributed to %q, want %q", e.Event, e.AuthMachineID, machineA)
		}
		if e.Detail["flow_id"] != flowID {
			t.Errorf("%s flow_id = %q, want %q", e.Event, e.Detail["flow_id"], flowID)
		}
		if e.Detail["provider"] != p.name {
			t.Errorf("%s provider = %q, want %q", e.Event, e.Detail["provider"], p.name)
		}
	}
	if committed.Detail["secret_generation"] != "1" {
		t.Errorf("commit generation = %q, want 1", committed.Detail["secret_generation"])
	}
}

// TestStartIsRefusedWhenItCannotBeRecorded — the audit log is authoritative
// (D13), so a flow that cannot be recorded does not begin.
func TestStartIsRefusedWhenItCannotBeRecorded(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}, audit: brokenAudit{}})

	res := h.start(machineA, p.name, false)
	if res.status != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 (body %s)", res.status, res.raw)
	}
}

// TestCredentialIsImmediatelyVisibleToAGrantHoldingCaller — the point of
// brokering a credential is that existing grants can use it at once, with no
// restart and no re-issue.
func TestCredentialIsImmediatelyVisibleToAGrantHoldingCaller(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})

	if _, _, err := h.credential(p.name); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("credential before the flow: %v, want not found", err)
	}
	h.runFlow(machineA, p, false)

	// This is the shape of a connector call resolving its provider credential:
	// look the provider up, get the token, use it. No knowledge of flows.
	token, err := stubConnectorToken(h, p.name)
	if err != nil {
		t.Fatalf("connector could not resolve the new credential: %v", err)
	}
	if token != "alpha-access-token" {
		t.Fatalf("connector resolved %q, want the freshly brokered token", token)
	}
}

func stubConnectorToken(h *harness, provider string) (string, error) {
	cred, _, err := h.svc.Credential(context.Background(), provider)
	if err != nil {
		return "", err
	}
	return cred.Access, nil
}

// failingSecretStore fails writes on demand while reads keep working — the
// shape of a real store failure after a successful token exchange.
type failingSecretStore struct {
	delegate   *store.SQLite
	failWrites bool
}

func (f *failingSecretStore) GetSecret(ctx context.Context, ref string) (store.Secret, error) {
	return f.delegate.GetSecret(ctx, ref)
}

func (f *failingSecretStore) PutSecretCAS(ctx context.Context, ref string, ciphertext []byte,
	expectedGeneration int64, audit func(int64) []store.AuditEvent) (int64, error) {
	if f.failWrites {
		return 0, errors.New("simulated credential store failure")
	}
	return f.delegate.PutSecretCAS(ctx, ref, ciphertext, expectedGeneration, audit)
}

type brokenAudit struct{}

func (brokenAudit) AppendAudit(context.Context, store.AuditEvent) error {
	return errors.New("simulated audit failure")
}

// TestCommitHookRunsBeforeTheFlowReportsCompleted. `add-credentials` polls
// until terminal and a caller that sees `completed` may make a connector call
// in the next second — so a deployment's delivery step (materializing the
// credential into the workload's directory) has to have run by then, or the
// first call after a successful consent fails on a credential that is stored
// and not yet readable by anything.
func TestCommitHookRunsBeforeTheFlowReportsCompleted(t *testing.T) {
	p := newFakeProvider(t, "google")
	var (
		mu           sync.Mutex
		hookProvider string
		hookGen      int64
		hookSawCred  bool
	)
	var h *harness
	h = newHarness(t, harnessOptions{
		providers: []*fakeProvider{p},
		onCommitted: func(ctx context.Context, provider string, generation int64) error {
			mu.Lock()
			defer mu.Unlock()
			hookProvider, hookGen = provider, generation
			// The credential must already be readable from the store when the
			// hook runs: delivery reads it back rather than being handed it.
			cred, _, err := h.svc.Credential(ctx, provider)
			hookSawCred = err == nil && cred.Access != ""
			return nil
		},
	})

	_, terminal := h.runFlow(machineA, p, false)
	if got := terminal.str("state"); got != string(credflow.StateCompleted) {
		t.Fatalf("flow state %q, want completed", got)
	}

	mu.Lock()
	defer mu.Unlock()
	if hookProvider != "google" {
		t.Errorf("the commit hook was called with provider %q, want google", hookProvider)
	}
	if hookGen == 0 {
		t.Error("the commit hook was not given the stored generation")
	}
	if !hookSawCred {
		t.Error("the commit hook ran before the credential was readable from the store")
	}
}

// TestCommitHookFailureEndsTheFlowUndelivered. `completed` is the promise that
// a client which polls its way there can use the credential next, so a delivery
// that failed must not reach it — a conforming client stops polling on
// `completed` and would walk straight into an unusable connector. It ends in
// its own terminal state instead: stored, not ready, and not a consent problem.
func TestCommitHookFailureEndsTheFlowUndelivered(t *testing.T) {
	p := newFakeProvider(t, "google")
	h := newHarness(t, harnessOptions{
		providers: []*fakeProvider{p},
		onCommitted: func(context.Context, string, int64) error {
			return errors.New("the workload's credential directory is not writable")
		},
	})

	_, terminal := h.runFlow(machineA, p, false)
	if got := terminal.str("state"); got != string(credflow.StateUndelivered) {
		t.Fatalf("flow state %q, want undelivered", got)
	}
	diag := terminal.diagnostic()
	if diag == nil || diag["error_code"] != credflow.CodeDeliveryFailed {
		t.Fatalf("undelivered flow carries diagnostic %v, want %q", diag, credflow.CodeDeliveryFailed)
	}
	// Re-authorizing would change nothing, so the fault must not invite a retry.
	if retryable, _ := diag["retryable"].(bool); retryable {
		t.Error("a delivery fault was reported as retryable; consent is not what is broken")
	}
	// …and it must not leak what actually broke on the server.
	if msg, _ := diag["message"].(string); strings.Contains(msg, "not writable") {
		t.Errorf("the diagnostic repeats the server's internal error: %q", msg)
	}
	cred, _, err := h.credential("google")
	if err != nil || cred.Access == "" {
		t.Fatalf("credential after a failed delivery: %v (access %q)", err, cred.Access)
	}
}

// TestSuccessfulDeliveryLeavesACleanOutcome — the ordinary case must stay clean,
// or the signal above means nothing.
func TestSuccessfulDeliveryLeavesACleanOutcome(t *testing.T) {
	p := newFakeProvider(t, "google")
	h := newHarness(t, harnessOptions{
		providers:   []*fakeProvider{p},
		onCommitted: func(context.Context, string, int64) error { return nil },
	})
	_, terminal := h.runFlow(machineA, p, false)
	if got := terminal.str("state"); got != string(credflow.StateCompleted) {
		t.Fatalf("flow state %q, want completed", got)
	}
	if diag := terminal.diagnostic(); diag != nil {
		t.Errorf("a successful delivery left a diagnostic: %v", diag)
	}
}

// TestCommitHookFailureDoesNotUnstoreTheCredential. The provider has already
// issued the credential and the store already committed it; a delivery fault is
// an operational problem an operator fixes. Reporting `failed` would contradict
// the store — `failed` means nothing was changed — and would send a human back
// through consent for a credential that is right there.
func TestCommitHookFailureDoesNotUnstoreTheCredential(t *testing.T) {
	p := newFakeProvider(t, "google")
	h := newHarness(t, harnessOptions{
		providers: []*fakeProvider{p},
		onCommitted: func(context.Context, string, int64) error {
			return errors.New("the workload's credential directory is not writable")
		},
	})

	_, terminal := h.runFlow(machineA, p, false)
	if got := terminal.str("state"); got != string(credflow.StateUndelivered) {
		t.Fatalf("flow state %q, want undelivered", got)
	}
	// Both facts are on the record: the credential was committed, and the flow
	// did not end usable.
	committed, terminals := 0, 0
	for _, e := range h.auditEvents() {
		switch e.Event {
		case store.EventCredentialFlowCommitted:
			committed++
		case store.EventCredentialFlowFailed:
			terminals++
		}
	}
	if committed != 1 || terminals != 1 {
		t.Fatalf("committed=%d terminal=%d rows, want exactly one of each", committed, terminals)
	}
	cred, _, err := h.credential("google")
	if err != nil || cred.Access == "" {
		t.Fatalf("credential after a failed delivery: %v (access %q)", err, cred.Access)
	}
}
