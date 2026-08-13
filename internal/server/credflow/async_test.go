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

// TestRelayReturnsBeforeTheExchangeFinishes is the property that makes the flow
// genuinely asynchronous rather than a synchronous call wearing a state
// machine's clothes.
//
// It matters because of what a slow provider used to cause: the relay request
// would outlive the agent's own deadline, the CLI would report a transport
// failure, and the server would store the credential anyway — the machine
// telling its operator the opposite of what happened. With the exchange owned
// by the server, a lost or slow relay costs nothing but another poll.
func TestRelayReturnsBeforeTheExchangeFinishes(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})

	release := p.hold() // the provider will not answer until this is called

	start := h.start(machineA, p.name, false)
	code, _, state := p.consent(t, h.client, start.str("authorization_url"))
	flowID := start.str("flow_id")

	relayed := make(chan response, 1)
	go func() {
		relayed <- h.relay(machineA, flowID, map[string]string{"code": code, "state": state})
	}()

	select {
	case res := <-relayed:
		if res.status != http.StatusAccepted {
			t.Fatalf("relay: status %d body %s", res.status, res.raw)
		}
		if res.str("state") != string(credflow.StatePending) {
			t.Fatalf("relay state = %q, want pending: the handler must not wait for the provider", res.str("state"))
		}
	case <-time.After(5 * time.Second):
		release()
		t.Fatal("the relay handler blocked on the provider's token endpoint")
	}

	// The flow is still pending, and the credential is not stored yet.
	if got := h.poll(machineA, flowID).str("state"); got != string(credflow.StatePending) {
		t.Fatalf("state while the provider is still thinking = %q, want pending", got)
	}
	if _, _, err := h.credential(p.name); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("credential exists before the exchange finished: %v", err)
	}

	release()
	if final := h.awaitTerminal(machineA, flowID); final.str("state") != string(credflow.StateCompleted) {
		t.Fatalf("state after the provider answered = %q, want completed (body %s)", final.str("state"), final.raw)
	}
	if cred, _, err := h.credential(p.name); err != nil || cred.Access != "alpha-access-token" {
		t.Fatalf("credential = %+v (%v), want the provider's token", cred, err)
	}
}

// TestTerminalStateIsNotShownUntilItIsRecorded — the audit log is authoritative
// (D13), so a flow that finished while the log was down must not report an
// outcome the record does not have. It reports "not yet" and keeps retrying.
func TestTerminalStateIsNotShownUntilItIsRecorded(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	audit := &toggleAudit{}
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}, audit: audit})
	audit.delegate = h.st

	start := h.start(machineA, p.name, false)
	flowID := start.str("flow_id")

	// The log breaks after the flow has begun.
	audit.setFailing(true)
	relay := h.relay(machineA, flowID, map[string]string{
		"error": "access_denied", "state": oauthStateFrom(t, start.str("authorization_url"))})
	if relay.status != http.StatusServiceUnavailable {
		t.Fatalf("relay while the audit log is down: status %d, want 503 (body %s)", relay.status, relay.raw)
	}
	poll := h.poll(machineA, flowID)
	if poll.status != http.StatusServiceUnavailable {
		t.Fatalf("poll while the audit log is down: status %d, want 503 (body %s)", poll.status, poll.raw)
	}
	if strings.Contains(poll.raw, string(credflow.StateDenied)) {
		t.Fatalf("a terminal state was exposed without being recorded: %s", poll.raw)
	}

	// The log recovers: the same outcome is recorded and then shown.
	audit.setFailing(false)
	final := h.awaitTerminal(machineA, flowID)
	if final.str("state") != string(credflow.StateDenied) {
		t.Fatalf("state after the audit log recovered = %q, want denied (body %s)", final.str("state"), final.raw)
	}

	// Exactly one terminal row, despite the failed attempts.
	terminals := 0
	for _, e := range h.auditEvents() {
		if e.Event == store.EventCredentialFlowFailed {
			terminals++
		}
	}
	if terminals != 1 {
		t.Fatalf("terminal audit rows = %d, want exactly 1", terminals)
	}
}

// TestTerminalEventsCarryTheActorThatCausedThem — a clock-driven expiry is the
// server's doing, not the machine's, and an audit reader has to be able to tell
// those apart.
func TestTerminalEventsCarryTheActorThatCausedThem(t *testing.T) {
	cases := []struct {
		name      string
		wantActor store.ActorKind
		wantCode  string
		run       func(t *testing.T, h *harness, p *fakeProvider)
	}{
		{
			name: "relayed denial is the machine's report", wantActor: store.ActorMachine,
			wantCode: credflow.CodeProviderDenied,
			run: func(t *testing.T, h *harness, p *fakeProvider) {
				p.mu.Lock()
				p.denyConsent = true
				p.mu.Unlock()
				h.runFlow(machineA, p, false)
			},
		},
		{
			name: "expiry is the server's clock", wantActor: store.ActorSystem,
			wantCode: credflow.CodeFlowExpired,
			run: func(t *testing.T, h *harness, p *fakeProvider) {
				flowID := h.start(machineA, p.name, false).str("flow_id")
				h.advance(2 * time.Hour)
				h.awaitTerminal(machineA, flowID)
			},
		},
		{
			name: "exchange failure is the server's job", wantActor: store.ActorSystem,
			wantCode: credflow.CodeExchangeFailed,
			run: func(t *testing.T, h *harness, p *fakeProvider) {
				p.mu.Lock()
				p.tokenStatus = http.StatusBadRequest
				p.tokenBody = `{"error":"invalid_grant"}`
				p.mu.Unlock()
				h.runFlow(machineA, p, false)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeProvider(t, "alpha")
			h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}, clock: newClock()})
			tc.run(t, h, p)

			var terminal *store.AuditEvent
			events := h.auditEvents()
			for i, e := range events {
				if e.Event == store.EventCredentialFlowFailed {
					terminal = &events[i]
				}
			}
			if terminal == nil {
				t.Fatal("no terminal audit row")
			}
			if terminal.ActorKind != tc.wantActor {
				t.Errorf("actor = %q, want %q", terminal.ActorKind, tc.wantActor)
			}
			if terminal.Reason != tc.wantCode {
				t.Errorf("reason = %q, want %q", terminal.Reason, tc.wantCode)
			}
			if terminal.AuthMachineID != machineA {
				t.Errorf("machine = %q, want the flow's machine even when the server acted", terminal.AuthMachineID)
			}
		})
	}
}

// TestMissingClientSecretIsRefusedBeforeConsent — spending a human's consent
// and then reporting a storage failure that never happened is a bad trade;
// both driver secrets are checked while refusing is still cheap.
func TestMissingClientSecretIsRefusedBeforeConsent(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}, skipClientSecrets: true})
	// Only the client id is imported: the secret is missing.
	h.importSecret(p.name+"/client-id", []byte(p.clientID))

	res := h.start(machineA, p.name, false)
	if res.status != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 (body %s)", res.status, res.raw)
	}
	if !strings.Contains(res.str("message"), "client_secret_ref") {
		t.Errorf("message does not name the missing secret: %q", res.str("message"))
	}
	// Nothing was started, so the provider was never contacted.
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.authorizeCalls) != 0 {
		t.Errorf("authorize calls = %d, want 0: the flow must not begin", len(p.authorizeCalls))
	}
}

// TestOpenFlowsAreBounded — every flow is created by an authenticated caller,
// so without a ceiling a machine stuck in a retry loop would grow the server's
// memory for as long as it runs.
func TestOpenFlowsAreBounded(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}, clock: newClock(), maxActiveFlows: 2})

	for i := range 2 {
		if res := h.start(machineA, p.name, false); res.status != http.StatusCreated {
			t.Fatalf("flow %d: status %d body %s", i, res.status, res.raw)
		}
	}
	refused := h.start(machineA, p.name, false)
	if refused.status != http.StatusTooManyRequests {
		t.Fatalf("third flow: status %d, want 429 (body %s)", refused.status, refused.raw)
	}
	if !strings.Contains(refused.str("message"), "open") {
		t.Errorf("refusal does not explain itself: %q", refused.str("message"))
	}

	// Another machine is unaffected: the budget is per machine.
	if res := h.start(machineB, p.name, false); res.status != http.StatusCreated {
		t.Fatalf("other machine: status %d, want 201 (body %s)", res.status, res.raw)
	}

	// Once the abandoned flows expire, the budget frees up again — without
	// anybody having polled them.
	h.advance(2 * time.Hour)
	if res := h.start(machineA, p.name, false); res.status != http.StatusCreated {
		t.Fatalf("after the open flows expired: status %d, want 201 (body %s)", res.status, res.raw)
	}
}

// TestAbandonedAndFinishedFlowsAreForgotten — the flow map must not be a leak.
func TestAbandonedAndFinishedFlowsAreForgotten(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{
		providers: []*fakeProvider{p}, clock: newClock(),
		terminalRetention: 5 * time.Minute,
	})

	// A finished flow stays readable for a while: the agent is still polling.
	flowID, final := h.runFlow(machineA, p, false)
	if final.str("state") != string(credflow.StateCompleted) {
		t.Fatalf("flow state = %q, want completed", final.str("state"))
	}
	h.advance(time.Minute)
	h.start(machineA, p.name, true) // any start sweeps
	if res := h.poll(machineA, flowID); res.status != http.StatusOK {
		t.Fatalf("finished flow within its retention: status %d, want 200", res.status)
	}

	// Past the retention window it is gone.
	h.advance(30 * time.Minute)
	h.start(machineA, p.name, true)
	if res := h.poll(machineA, flowID); res.status != http.StatusNotFound {
		t.Fatalf("finished flow past its retention: status %d, want 404 (body %s)", res.status, res.raw)
	}

	// An abandoned flow expires on the sweep alone, with nobody polling it —
	// and is forgotten once its outcome has been readable for the retention
	// window (which starts when the expiry is recorded, so a late-arriving
	// agent still learns what happened).
	abandoned := h.start(machineA, p.name, true).str("flow_id")
	h.advance(2 * time.Hour)
	h.start(machineA, p.name, true) // sweep: expires it
	if res := h.poll(machineA, abandoned); res.str("state") != string(credflow.StateExpired) {
		t.Fatalf("abandoned flow after its window closed = %q, want expired (body %s)", res.str("state"), res.raw)
	}
	h.advance(30 * time.Minute)
	h.start(machineA, p.name, true) // sweep: forgets it
	if res := h.poll(machineA, abandoned); res.status != http.StatusNotFound {
		t.Fatalf("abandoned flow past its retention: status %d, want 404 (body %s)", res.status, res.raw)
	}
	// Its expiry is on the record even though nobody ever polled it.
	expiries := 0
	for _, e := range h.auditEvents() {
		if e.Event == store.EventCredentialFlowFailed && e.Reason == credflow.CodeFlowExpired {
			expiries++
		}
	}
	if expiries == 0 {
		t.Fatal("an abandoned flow expired without an audit row")
	}
}

// TestShutdownWaitsForAnInFlightExchange — a credential the provider has
// already issued must not be abandoned halfway by a server stopping.
func TestShutdownWaitsForAnInFlightExchange(t *testing.T) {
	p := newFakeProvider(t, "alpha")
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}})

	release := p.hold()
	start := h.start(machineA, p.name, false)
	code, _, state := p.consent(t, h.client, start.str("authorization_url"))
	h.relay(machineA, start.str("flow_id"), map[string]string{"code": code, "state": state})

	// While the provider is held, shutdown cannot finish.
	quick, cancelQuick := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelQuick()
	if err := h.svc.Shutdown(quick); err == nil {
		t.Fatal("Shutdown returned while an exchange was still running")
	}

	release()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.svc.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown after the exchange finished: %v", err)
	}
	if cred, _, err := h.credential(p.name); err != nil || cred.Access == "" {
		t.Fatalf("credential = %+v (%v), want it stored before shutdown returned", cred, err)
	}
}

// toggleAudit is an audit sink that can be broken and repaired mid-test.
type toggleAudit struct {
	delegate *store.SQLite

	mu      sync.Mutex
	failing bool
}

func (a *toggleAudit) setFailing(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failing = v
}

func (a *toggleAudit) AppendAudit(ctx context.Context, e store.AuditEvent) error {
	a.mu.Lock()
	failing := a.failing
	a.mu.Unlock()
	if failing {
		return errors.New("simulated audit outage")
	}
	return a.delegate.AppendAudit(ctx, e)
}

// TestARelayedFlowIsNotExpiredByTheConsentWindow closes the race the
// asynchronous exchange introduced.
//
// The flow's window exists to bound how long the HUMAN has to consent. Once an
// outcome is relayed the human is done, and the server-owned exchange job is
// the sole author of the ending. Applying the consent deadline to a flow whose
// exchange is still running produced two endings for one flow: the sweep
// audited `expired`, and moments later the job stored the credential and
// reported `completed` — an audit trail that disagrees with the credential
// store, which is the one failure this package must never produce quietly.
func TestARelayedFlowIsNotExpiredByTheConsentWindow(t *testing.T) {
	cases := []struct {
		name       string
		wantState  credflow.State
		wantFailed bool
		// breakProvider makes the held exchange fail once released.
		breakProvider bool
	}{
		{name: "exchange succeeds after the deadline", wantState: credflow.StateCompleted},
		{name: "exchange fails after the deadline", wantState: credflow.StateFailed, wantFailed: true, breakProvider: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeProvider(t, "alpha")
			h := newHarness(t, harnessOptions{providers: []*fakeProvider{p}, clock: newClock()})

			release := p.hold()
			start := h.start(machineA, p.name, false)
			flowID := start.str("flow_id")
			code, _, state := p.consent(t, h.client, start.str("authorization_url"))
			if relay := h.relay(machineA, flowID, map[string]string{"code": code, "state": state}); relay.status != http.StatusAccepted {
				release()
				t.Fatalf("relay: status %d body %s", relay.status, relay.raw)
			}

			// The consent window closes while the provider is still thinking.
			h.advance(2 * time.Hour)
			if got := h.poll(machineA, flowID).str("state"); got != string(credflow.StatePending) {
				release()
				t.Fatalf("state after the consent window closed = %q, want pending: "+
					"the exchange owns this flow's ending now", got)
			}
			// A sweep (any start triggers one) must not expire it either.
			sweeper := h.start(machineB, p.name, false).str("flow_id")
			if got := h.poll(machineA, flowID).str("state"); got != string(credflow.StatePending) {
				release()
				t.Fatalf("a sweep expired a relayed flow: state = %q, want pending", got)
			}

			if tc.breakProvider {
				p.mu.Lock()
				p.tokenStatus = http.StatusBadRequest
				p.tokenBody = `{"error":"invalid_grant"}`
				p.mu.Unlock()
			}
			release()

			final := h.awaitTerminal(machineA, flowID)
			if final.str("state") != string(tc.wantState) {
				t.Fatalf("final state = %q, want %q (body %s)", final.str("state"), tc.wantState, final.raw)
			}

			// Exactly one ending, and the audit log tells the same story as the
			// credential store.
			committed, failed := 0, 0
			for _, e := range h.auditEvents() {
				if e.Detail["flow_id"] != flowID {
					continue // the sweeper flow has its own (expired) ending
				}
				switch e.Event {
				case store.EventCredentialFlowCommitted:
					committed++
				case store.EventCredentialFlowFailed:
					failed++
				}
			}
			switch {
			case tc.wantFailed && (failed != 1 || committed != 0):
				t.Fatalf("audit rows for a failed flow: committed=%d failed=%d, want 0 and 1", committed, failed)
			case !tc.wantFailed && (committed != 1 || failed != 0):
				t.Fatalf("audit rows for a stored credential: committed=%d failed=%d, want 1 and 0", committed, failed)
			}

			_, _, err := h.credential(p.name)
			if tc.wantFailed && !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("a failed flow stored a credential: %v", err)
			}
			if !tc.wantFailed && err != nil {
				t.Fatalf("a completed flow stored no credential: %v", err)
			}

			// The unrelayed flow started along the way DOES expire once its own
			// window closes — the consent deadline still governs a flow nobody
			// has consented on.
			h.advance(2 * time.Hour)
			if got := h.poll(machineB, sweeper).str("state"); got != string(credflow.StateExpired) {
				t.Errorf("unrelayed flow state = %q, want expired", got)
			}
		})
	}
}
