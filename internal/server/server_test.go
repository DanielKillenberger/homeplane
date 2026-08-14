package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/health"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/secrets"
	"github.com/DanielKillenberger/homeplane/internal/server"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// Two simulated tailnet machines. Every authorization test in this file turns
// on the server telling these two apart from the network alone.
var (
	machineA = store.Identity{NodeID: "node-aaaa", NodeName: "mac-a"}
	machineB = store.Identity{NodeID: "node-bbbb", NodeName: "linux-b"}

	addrA = "100.64.0.1:41000"
	addrB = "100.64.0.2:41000"
	addrC = "100.64.0.3:41000" // a node with no WhoIs identity at all
)

// fakeResolver stands in for tsnet WhoIs: it maps a peer address to a tailnet
// identity exactly as the real resolver does, and refuses unknown peers.
type fakeResolver struct{ byAddr map[string]store.Identity }

func (f fakeResolver) Resolve(_ context.Context, remoteAddr string) (store.Identity, error) {
	id, ok := f.byAddr[remoteAddr]
	if !ok {
		return store.Identity{}, fmt.Errorf("no tailnet identity for %s", remoteAddr)
	}
	return id, nil
}

type harness struct {
	t       *testing.T
	st      *store.SQLite
	handler http.Handler
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st := newStore(t)
	checker := health.New(health.Component{Name: health.ComponentStore, Probe: health.StoreProbe(st)})
	srv, err := server.New(st, fakeResolver{byAddr: map[string]store.Identity{
		addrA: machineA,
		addrB: machineB,
	}}, checker, server.Config{
		ConnectorEndpointURL: "https://homeplane.example.ts.net/mcp",
		Policy:               policy.Default(),
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &harness{t: t, st: st, handler: srv.Handler()}
}

func newStore(t *testing.T) *store.SQLite {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "homeplane.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

type response struct {
	status int
	body   map[string]any
	raw    string
}

func (h *harness) do(method, path, remoteAddr, token string, body any) response {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal request: %v", err)
		}
		reader = strings.NewReader(string(b))
	}
	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = remoteAddr
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	res := response{status: rec.Code, raw: rec.Body.String()}
	if res.raw != "" {
		_ = json.Unmarshal([]byte(res.raw), &res.body)
	}
	return res
}

// enrol registers a machine and returns its machine id and credential.
func (h *harness) enrol(addr, name, osName string) (string, string, response) {
	h.t.Helper()
	res := h.do(http.MethodPost, "/enrol", addr, "", map[string]string{"machine_name": name, "os": osName})
	id, _ := res.body["machine_id"].(string)
	credential, _ := res.body["machine_credential"].(string)
	return id, credential, res
}

func (h *harness) issueGrant(addr, credential, harnessName string, capabilities []string) response {
	h.t.Helper()
	body := map[string]any{"harness": harnessName}
	if capabilities != nil {
		body["capabilities"] = capabilities
	}
	return h.do(http.MethodPost, "/grants", addr, credential, body)
}

// auditFailureStore wraps the real store and makes every audit write fail, to
// prove the server refuses the mutation rather than completing it unrecorded.
type auditFailureStore struct{ *store.SQLite }

func (auditFailureStore) AppendAudit(context.Context, store.AuditEvent) error {
	return errors.New("audit backend unavailable")
}

func (s auditFailureStore) Enrol(ctx context.Context, id store.Identity, name, osName, hash string,
	_ func(store.Machine, bool) []store.AuditEvent) (store.Machine, bool, error) {
	return s.SQLite.Enrol(ctx, id, name, osName, hash, func(store.Machine, bool) []store.AuditEvent {
		return []store.AuditEvent{{Event: store.EventEnrolment, ActorKind: store.ActorMachine,
			Outcome: store.OutcomeAllowed, Detail: map[string]string{"unwritable_key": "x"}}}
	})
}

func (h *harness) auditEvents() []store.AuditEvent {
	h.t.Helper()
	events, err := h.st.QueryAudit(context.Background(), store.AuditQuery{})
	if err != nil {
		h.t.Fatalf("QueryAudit: %v", err)
	}
	return events
}

func (h *harness) lastAuditOf(event string) store.AuditEvent {
	h.t.Helper()
	events := h.auditEvents()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Event == event {
			return events[i]
		}
	}
	h.t.Fatalf("no audit event %q in %d rows", event, len(events))
	return store.AuditEvent{}
}

func TestEnrolAutoApprovesTailnetNodeAndAudits(t *testing.T) {
	h := newHarness(t)

	id, credential, res := h.enrol(addrA, "mac-a", "darwin")
	if res.status != http.StatusCreated {
		t.Fatalf("enrol status = %d, want 201 (body %s)", res.status, res.raw)
	}
	if id == "" || credential == "" {
		t.Fatalf("enrol returned empty identity/credential: %s", res.raw)
	}
	if rotated, _ := res.body["rotated"].(bool); rotated {
		t.Error("first enrolment reported rotated=true")
	}

	ev := h.lastAuditOf(store.EventEnrolment)
	if ev.ObservedNodeID != machineA.NodeID {
		t.Errorf("audit observed node = %q, want %q", ev.ObservedNodeID, machineA.NodeID)
	}
	if ev.AuthMachineID != id {
		t.Errorf("audit authenticated machine = %q, want %q", ev.AuthMachineID, id)
	}
	if ev.ActorKind != store.ActorMachine {
		t.Errorf("audit actor = %q, want machine", ev.ActorKind)
	}
}

func TestEnrolWithoutTailnetIdentityIsRefused(t *testing.T) {
	h := newHarness(t)
	// addrC resolves to no identity: tailnet reachability alone is not enough.
	res := h.do(http.MethodPost, "/enrol", addrC, "", map[string]string{"machine_name": "ghost", "os": "linux"})
	if res.status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", res.status, res.raw)
	}
}

func TestReenrolRotatesCredentialInPlace(t *testing.T) {
	h := newHarness(t)

	firstID, firstCredential, _ := h.enrol(addrA, "mac-a", "darwin")

	secondID, secondCredential, res := h.enrol(addrA, "mac-a", "darwin")
	if res.status != http.StatusOK {
		t.Fatalf("re-enrol status = %d, want 200 (body %s)", res.status, res.raw)
	}
	if rotated, _ := res.body["rotated"].(bool); !rotated {
		t.Error("re-enrol did not report rotated=true")
	}
	if secondID != firstID {
		t.Errorf("re-enrol created a new identity: %q != %q", secondID, firstID)
	}
	if secondCredential == firstCredential {
		t.Fatal("re-enrol returned the same credential; rotation must mint a new one")
	}

	// The old credential must be dead immediately — rotation is not additive.
	if res := h.issueGrant(addrA, firstCredential, policy.HarnessCodex, nil); res.status != http.StatusUnauthorized {
		t.Errorf("old credential status = %d, want 401 (body %s)", res.status, res.raw)
	}
	if res := h.issueGrant(addrA, secondCredential, policy.HarnessCodex, nil); res.status != http.StatusCreated {
		t.Errorf("new credential status = %d, want 201 (body %s)", res.status, res.raw)
	}

	// And there must be exactly one machine record for the node.
	if _, err := h.st.MachineByNodeID(context.Background(), machineA.NodeID); err != nil {
		t.Fatalf("MachineByNodeID: %v", err)
	}
	ev := h.lastAuditOf(store.EventCredentialRotation)
	if ev.Detail["credential_version"] != "2" {
		t.Errorf("rotation audit credential_version = %q, want 2", ev.Detail["credential_version"])
	}
}

func TestGrantSupersedesPriorGrantForSameHarness(t *testing.T) {
	h := newHarness(t)
	_, credential, _ := h.enrol(addrA, "mac-a", "darwin")

	first := h.issueGrant(addrA, credential, policy.HarnessClaudeCode, nil)
	if first.status != http.StatusCreated {
		t.Fatalf("first grant status = %d (body %s)", first.status, first.raw)
	}
	firstID, _ := first.body["grant_id"].(string)

	second := h.issueGrant(addrA, credential, policy.HarnessClaudeCode, nil)
	if second.status != http.StatusCreated {
		t.Fatalf("second grant status = %d (body %s)", second.status, second.raw)
	}
	secondID, _ := second.body["grant_id"].(string)
	if secondID == firstID {
		t.Fatal("second grant reused the first grant id")
	}
	if got, _ := second.body["superseded_grant_id"].(string); got != firstID {
		t.Errorf("superseded_grant_id = %q, want %q", got, firstID)
	}

	// Exactly one active grant per (machine, harness).
	grants := h.listGrants(addrA, credential)
	active := 0
	for _, g := range grants {
		if g["state"] == string(store.GrantActive) {
			active++
			if g["grant_id"] != secondID {
				t.Errorf("active grant is %v, want %s", g["grant_id"], secondID)
			}
		}
	}
	if active != 1 {
		t.Errorf("active grants for harness = %d, want 1", active)
	}

	ev := h.lastAuditOf(store.EventGrantSuperseded)
	if ev.GrantID != firstID {
		t.Errorf("supersede audit grant = %q, want %q", ev.GrantID, firstID)
	}
	if ev.ActorKind != store.ActorSystem {
		t.Errorf("supersede audit actor = %q, want system", ev.ActorKind)
	}
}

func TestGrantForOtherHarnessIsIndependent(t *testing.T) {
	h := newHarness(t)
	_, credential, _ := h.enrol(addrA, "mac-a", "darwin")

	claude := h.issueGrant(addrA, credential, policy.HarnessClaudeCode, nil)
	codex := h.issueGrant(addrA, credential, policy.HarnessCodex, nil)
	if claude.status != http.StatusCreated || codex.status != http.StatusCreated {
		t.Fatalf("grants failed: %d / %d", claude.status, codex.status)
	}
	// Issuing for codex must not disturb claude-code's grant.
	if _, ok := codex.body["superseded_grant_id"]; ok {
		t.Error("issuing a grant for a second harness superseded the first harness's grant")
	}
	active := 0
	for _, g := range h.listGrants(addrA, credential) {
		if g["state"] == string(store.GrantActive) {
			active++
		}
	}
	if active != 2 {
		t.Errorf("active grants = %d, want 2 (one per harness)", active)
	}
}

func TestCapabilitiesAreServerPolicyBound(t *testing.T) {
	h := newHarness(t)
	_, credential, _ := h.enrol(addrA, "mac-a", "darwin")

	t.Run("over-policy capability refused", func(t *testing.T) {
		res := h.issueGrant(addrA, credential, policy.HarnessCodex, []string{
			string(policy.ConnectorRead), string(policy.ConnectorSend),
		})
		if res.status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body %s)", res.status, res.raw)
		}
		ev := h.lastAuditOf(store.EventGrantIssued)
		if ev.Outcome != store.OutcomeDenied || ev.Reason != "capability_not_permitted" {
			t.Errorf("audit outcome/reason = %s/%s, want denied/capability_not_permitted", ev.Outcome, ev.Reason)
		}
	})

	t.Run("unknown harness refused", func(t *testing.T) {
		res := h.issueGrant(addrA, credential, "some-unknown-harness", nil)
		if res.status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body %s)", res.status, res.raw)
		}
		if ev := h.lastAuditOf(store.EventGrantIssued); ev.Reason != "unknown_harness" {
			t.Errorf("audit reason = %q, want unknown_harness", ev.Reason)
		}
	})

	t.Run("subset request is honored exactly", func(t *testing.T) {
		res := h.issueGrant(addrA, credential, policy.HarnessCodex, []string{string(policy.ConnectorRead)})
		if res.status != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body %s)", res.status, res.raw)
		}
		caps, _ := res.body["capabilities"].([]any)
		if len(caps) != 1 || caps[0] != string(policy.ConnectorRead) {
			t.Errorf("capabilities = %v, want [connector.read]", caps)
		}
	})

	t.Run("empty request gets the policy default", func(t *testing.T) {
		res := h.issueGrant(addrA, credential, policy.HarnessClaudeCode, nil)
		caps, _ := res.body["capabilities"].([]any)
		if len(caps) != 3 {
			t.Errorf("default capabilities = %v, want the 3-capability default", caps)
		}
	})
}

func (h *harness) listGrants(addr, credential string) []map[string]any {
	h.t.Helper()
	res := h.do(http.MethodGet, "/grants", addr, credential, nil)
	if res.status != http.StatusOK {
		h.t.Fatalf("GET /grants status = %d (body %s)", res.status, res.raw)
	}
	raw, _ := res.body["grants"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, _ := r.(map[string]any)
		out = append(out, m)
	}
	return out
}

func TestListGrantsIsScopedToCallerAndNonSecret(t *testing.T) {
	h := newHarness(t)
	_, credentialA, _ := h.enrol(addrA, "mac-a", "darwin")
	_, credentialB, _ := h.enrol(addrB, "linux-b", "linux")

	h.issueGrant(addrA, credentialA, policy.HarnessClaudeCode, nil)
	h.issueGrant(addrB, credentialB, policy.HarnessCodex, nil)

	res := h.do(http.MethodGet, "/grants", addrA, credentialA, nil)
	if res.status != http.StatusOK {
		t.Fatalf("status = %d (body %s)", res.status, res.raw)
	}
	grants := h.listGrants(addrA, credentialA)
	if len(grants) != 1 {
		t.Fatalf("machine A sees %d grants, want only its own 1", len(grants))
	}
	if grants[0]["harness"] != policy.HarnessClaudeCode {
		t.Errorf("harness = %v, want %s", grants[0]["harness"], policy.HarnessClaudeCode)
	}
	// Non-secret projection: no token material in any form.
	for _, forbidden := range []string{"token", "grant_token", "token_hash", "secret", "credential"} {
		if strings.Contains(res.raw, forbidden) {
			t.Errorf("GET /grants body leaked %q: %s", forbidden, res.raw)
		}
	}
	for _, key := range []string{"grant_id", "harness", "capabilities", "state"} {
		if _, ok := grants[0][key]; !ok {
			t.Errorf("GET /grants missing metadata field %q", key)
		}
	}
}

func TestRevocationIsIdempotentAndScoped(t *testing.T) {
	h := newHarness(t)
	_, credentialA, _ := h.enrol(addrA, "mac-a", "darwin")
	_, credentialB, _ := h.enrol(addrB, "linux-b", "linux")

	issued := h.issueGrant(addrA, credentialA, policy.HarnessClaudeCode, nil)
	grantID, _ := issued.body["grant_id"].(string)

	t.Run("unknown grant is 404", func(t *testing.T) {
		res := h.do(http.MethodDelete, "/grants/g-doesnotexist", addrA, credentialA, nil)
		if res.status != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body %s)", res.status, res.raw)
		}
	})

	t.Run("another machine cannot revoke it", func(t *testing.T) {
		res := h.do(http.MethodDelete, "/grants/"+grantID, addrB, credentialB, nil)
		if res.status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body %s)", res.status, res.raw)
		}
		ev := h.lastAuditOf(store.EventGrantRevoked)
		if ev.Outcome != store.OutcomeDenied || ev.Reason != "cross_machine_revocation" {
			t.Errorf("audit = %s/%s, want denied/cross_machine_revocation", ev.Outcome, ev.Reason)
		}
		// The grant is untouched.
		grants := h.listGrants(addrA, credentialA)
		if grants[0]["state"] != string(store.GrantActive) {
			t.Errorf("grant state = %v after refused cross-machine revocation, want active", grants[0]["state"])
		}
	})

	t.Run("owner revokes, then repeats idempotently", func(t *testing.T) {
		first := h.do(http.MethodDelete, "/grants/"+grantID, addrA, credentialA, nil)
		if first.status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", first.status, first.raw)
		}
		if revoked, _ := first.body["revoked"].(bool); !revoked {
			t.Error("first revocation reported revoked=false")
		}
		second := h.do(http.MethodDelete, "/grants/"+grantID, addrA, credentialA, nil)
		if second.status != http.StatusOK {
			t.Fatalf("repeat status = %d, want 200 (body %s)", second.status, second.raw)
		}
		if revoked, _ := second.body["revoked"].(bool); revoked {
			t.Error("repeat revocation claimed to revoke an already-revoked grant")
		}
		if second.body["state"] != string(store.GrantRevoked) {
			t.Errorf("state = %v, want revoked", second.body["state"])
		}
	})
}

func TestCrossMachineGrantIssuanceIsImpossible(t *testing.T) {
	h := newHarness(t)
	_, credentialA, _ := h.enrol(addrA, "mac-a", "darwin")
	idB, _, _ := h.enrol(addrB, "linux-b", "linux")

	// There is no machine_id field to forge, and an attempt to smuggle one in
	// is rejected outright rather than silently ignored.
	res := h.do(http.MethodPost, "/grants", addrA, credentialA, map[string]any{
		"harness":    policy.HarnessCodex,
		"machine_id": idB,
	})
	if res.status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown field (body %s)", res.status, res.raw)
	}

	// And a grant issued normally by A belongs to A, never to B.
	issued := h.issueGrant(addrA, credentialA, policy.HarnessCodex, nil)
	grantID, _ := issued.body["grant_id"].(string)
	g, err := h.st.GrantByID(context.Background(), grantID)
	if err != nil {
		t.Fatalf("GrantByID: %v", err)
	}
	if g.MachineID == idB {
		t.Fatal("grant was issued against the other machine")
	}
}

func TestCredentialReplayedFromAnotherMachineIsForbidden(t *testing.T) {
	h := newHarness(t)
	idA, credentialA, _ := h.enrol(addrA, "mac-a", "darwin")
	h.enrol(addrB, "linux-b", "linux")

	// Machine A's credential, presented from machine B's node.
	res := h.issueGrant(addrB, credentialA, policy.HarnessCodex, nil)
	if res.status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", res.status, res.raw)
	}

	ev := h.lastAuditOf(store.EventAuthDenied)
	if ev.Reason != "machine_mismatch" {
		t.Fatalf("audit reason = %q, want machine_mismatch", ev.Reason)
	}
	// Attribution honesty: the row records the OBSERVED node, never claims the
	// credential's owner as the actor, and carries a fingerprint instead.
	if ev.ObservedNodeID != machineB.NodeID {
		t.Errorf("observed node = %q, want %q", ev.ObservedNodeID, machineB.NodeID)
	}
	if ev.AuthMachineID != "" {
		t.Errorf("denied row claims authenticated machine %q; must be empty", ev.AuthMachineID)
	}
	if ev.Detail["bound_machine_id"] != idA {
		t.Errorf("bound_machine_id = %q, want %q", ev.Detail["bound_machine_id"], idA)
	}
	if ev.TokenFingerprint == "" {
		t.Error("denied row has no token fingerprint")
	}
	if strings.Contains(ev.TokenFingerprint, credentialA) {
		t.Error("fingerprint contains the raw credential")
	}
}

func TestUnauthenticatedAndUnenrolledCallsAreRejected(t *testing.T) {
	h := newHarness(t)
	_, credentialA, _ := h.enrol(addrA, "mac-a", "darwin")

	cases := []struct {
		name       string
		addr       string
		credential string
		want       int
		reason     string
	}{
		{"no credential", addrA, "", http.StatusUnauthorized, "missing_machine_credential"},
		{"garbage credential", addrA, "not-a-real-credential", http.StatusUnauthorized, "invalid_machine_credential"},
		{"node never enrolled", addrB, credentialA, http.StatusUnauthorized, "machine_not_enrolled"},
		{"unresolvable peer", addrC, credentialA, http.StatusForbidden, "identity_unresolvable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := h.do(http.MethodGet, "/grants", tc.addr, tc.credential, nil)
			if res.status != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", res.status, tc.want, res.raw)
			}
			if ev := h.lastAuditOf(store.EventAuthDenied); ev.Reason != tc.reason {
				t.Errorf("audit reason = %q, want %q", ev.Reason, tc.reason)
			}
		})
	}
}

func TestAuditRowsAreMetadataOnly(t *testing.T) {
	h := newHarness(t)
	_, credential, _ := h.enrol(addrA, "mac-a", "darwin")
	h.issueGrant(addrA, credential, policy.HarnessClaudeCode, nil)

	events := h.auditEvents()
	if len(events) < 2 {
		t.Fatalf("expected enrolment + grant events, got %d", len(events))
	}
	allowed := map[string]bool{}
	for _, k := range store.AllowedDetailKeys() {
		allowed[k] = true
	}
	for _, e := range events {
		if e.Outcome == "" {
			t.Errorf("event %q has no outcome", e.Event)
		}
		if e.ActorKind == "" {
			t.Errorf("event %q has no actor kind", e.Event)
		}
		for k, v := range e.Detail {
			if !allowed[k] {
				t.Errorf("event %q carries non-allow-listed detail key %q", e.Event, k)
			}
			if len(v) > store.MaxDetailValueLen {
				t.Errorf("event %q detail %q exceeds the metadata bound", e.Event, k)
			}
		}
		// The credential minted during this test must appear nowhere.
		blob, _ := json.Marshal(e)
		if strings.Contains(string(blob), credential) {
			t.Fatalf("audit row for %q contains a live credential", e.Event)
		}
	}
}

func TestHealthzReportsServerComponentsOnly(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "homeplane.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	keyPath := filepath.Join(dir, "secrets.age-key")
	if _, err := secrets.GenerateKeyFile(keyPath); err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(gateway.Close)

	checker := health.New(
		health.Component{Name: health.ComponentStore, Probe: health.StoreProbe(st)},
		health.Component{Name: health.ComponentCredentialStore, Probe: health.CredentialStoreProbe(keyPath)},
		health.Component{Name: health.ComponentGatewayRuntime, Probe: health.GatewayProbe(gateway.URL, time.Second)},
	)
	srv, err := server.New(st, fakeResolver{byAddr: map[string]store.Identity{addrA: machineA}}, checker, server.Config{Policy: policy.Default()})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h := &harness{t: t, st: st, handler: srv.Handler()}

	healthy := h.do(http.MethodGet, "/healthz", addrA, "", nil)
	if healthy.status != http.StatusOK {
		t.Fatalf("healthy status = %d, want 200 (body %s)", healthy.status, healthy.raw)
	}
	if healthy.body["status"] != string(health.StatusOK) {
		t.Errorf("status field = %v, want ok", healthy.body["status"])
	}

	degrade := func(t *testing.T, component string) {
		t.Helper()
		res := h.do(http.MethodGet, "/healthz", addrA, "", nil)
		// A degraded server must fail `curl -sf` AND name the component.
		if res.status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503 (body %s)", res.status, res.raw)
		}
		if res.body["status"] != string(health.StatusDegraded) {
			t.Errorf("status field = %v, want degraded", res.body["status"])
		}
		components, _ := res.body["components"].([]any)
		found := false
		for _, c := range components {
			m, _ := c.(map[string]any)
			if m["name"] == component {
				found = true
				if m["status"] != string(health.StatusDegraded) {
					t.Errorf("component %s status = %v, want degraded", component, m["status"])
				}
				if m["detail"] == "" || m["detail"] == nil {
					t.Errorf("component %s degraded without a detail", component)
				}
			}
		}
		if !found {
			t.Errorf("degraded payload does not name %s: %s", component, res.raw)
		}
	}

	t.Run("gateway down", func(t *testing.T) {
		gateway.Close()
		degrade(t, health.ComponentGatewayRuntime)
	})

	t.Run("credential store down", func(t *testing.T) {
		if err := os.Chmod(keyPath, 0o644); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		degrade(t, health.ComponentCredentialStore)
		if err := os.Remove(keyPath); err != nil {
			t.Fatalf("remove: %v", err)
		}
		degrade(t, health.ComponentCredentialStore)
	})

	t.Run("store down", func(t *testing.T) {
		if err := st.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
		degrade(t, health.ComponentStore)
	})
}

// TestDenialsFailClosedWhenTheyCannotBeRecorded covers the other half of the
// audit guarantee: a rejected call must never be answered as an ordinary denial
// when the server could not write the record of it. Probing an endpoint with a
// stolen or bogus credential is exactly what an operator reads the log to find.
func TestDenialsFailClosedWhenTheyCannotBeRecorded(t *testing.T) {
	st := newStore(t)
	// Seed a machine directly, so a real credential exists to authenticate with.
	ctx := context.Background()
	if _, _, err := st.Enrol(ctx, machineA, "mac-a", "darwin", "hash-a",
		func(store.Machine, bool) []store.AuditEvent { return nil }); err != nil {
		t.Fatalf("seed enrol: %v", err)
	}

	srv, err := server.New(auditFailureStore{st},
		fakeResolver{byAddr: map[string]store.Identity{addrA: machineA, addrB: machineB}},
		health.New(health.Component{Name: health.ComponentStore, Probe: health.StoreProbe(st)}),
		server.Config{Policy: policy.Default()})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h := &harness{t: t, st: st, handler: srv.Handler()}

	cases := []struct {
		name       string
		addr       string
		credential string
	}{
		{"unresolvable peer", addrC, "irrelevant"},
		{"missing credential", addrA, ""},
		{"invalid credential", addrA, "not-a-real-credential"},
		{"unenrolled node", addrB, "not-a-real-credential"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := h.do(http.MethodGet, "/grants", tc.addr, tc.credential, nil)
			if res.status != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503 when the denial cannot be recorded (body %s)", res.status, res.raw)
			}
			if res.body["error"] != "unavailable" {
				t.Errorf("error code = %v, want unavailable", res.body["error"])
			}
			// Whatever else happens, the call must not have been served.
			if strings.Contains(res.raw, "grants") {
				t.Errorf("a refused request returned grant data: %s", res.raw)
			}
		})
	}
}

// TestMutationFailsWhenItsAuditRecordCannotBeWritten proves the fail-closed
// posture end-to-end: a machine must not walk away holding a credential the
// server has no record of issuing.
func TestMutationFailsWhenItsAuditRecordCannotBeWritten(t *testing.T) {
	st := newStore(t)
	srv, err := server.New(auditFailureStore{st},
		fakeResolver{byAddr: map[string]store.Identity{addrA: machineA}},
		health.New(health.Component{Name: health.ComponentStore, Probe: health.StoreProbe(st)}),
		server.Config{Policy: policy.Default()})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h := &harness{t: t, st: st, handler: srv.Handler()}

	_, credential, res := h.enrol(addrA, "mac-a", "darwin")
	if res.status != http.StatusInternalServerError {
		t.Fatalf("enrol status = %d, want 500 when the audit write fails (body %s)", res.status, res.raw)
	}
	if credential != "" {
		t.Fatal("server returned a credential for an enrolment it could not record")
	}
	if _, err := st.MachineByNodeID(context.Background(), machineA.NodeID); err == nil {
		t.Fatal("machine record persisted despite the failed audit write")
	}
}
