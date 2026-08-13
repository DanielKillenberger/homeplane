package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/health"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/server"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// The agent is tested against the REAL control plane from task .2 — the same
// handlers, store, policy, and auth the machine will talk to in production —
// over a real HTTP connection. Only the tailnet leg is simulated: httptest
// gives us a loopback listener, and the resolver below stands in for tsnet
// WhoIs. Everything the agent asserts about rotation, revocation, and
// unreachability is therefore a claim about the actual server, not a mock.

// fakeResolver stands in for tsnet WhoIs. Its identity is mutable so a test can
// make the SAME loopback connection appear to come from a different node.
type fakeResolver struct{ identity *store.Identity }

func (f fakeResolver) Resolve(context.Context, string) (store.Identity, error) {
	return *f.identity, nil
}

type controlPlane struct {
	t        *testing.T
	url      string
	identity *store.Identity
	http     *httptest.Server
}

func newControlPlane(t *testing.T) *controlPlane {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "homeplane.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	identity := &store.Identity{NodeID: "node-test-a", NodeName: "test-machine"}
	checker := health.New(health.Component{Name: health.ComponentStore, Probe: health.StoreProbe(st)})
	srv, err := server.New(st, fakeResolver{identity: identity}, checker, server.Config{
		ConnectorEndpointURL: "https://homeplane.example.ts.net/mcp",
		Policy:               policy.Default(),
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return &controlPlane{t: t, url: hs.URL, identity: identity, http: hs}
}

// issueGrant asks the server for a grant using the machine's own credential —
// the same call the harness-configuration task will make.
func (cp *controlPlane) issueGrant(credential, harness string) string {
	cp.t.Helper()
	body := strings.NewReader(`{"harness":"` + harness + `","capabilities":["connector.read"]}`)
	req, err := http.NewRequest(http.MethodPost, cp.url+"/grants", body)
	if err != nil {
		cp.t.Fatalf("build grant request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	res, err := cp.http.Client().Do(req)
	if err != nil {
		cp.t.Fatalf("issue grant: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		cp.t.Fatalf("issue grant: status %d", res.StatusCode)
	}
	var out struct {
		GrantID string `json:"grant_id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		cp.t.Fatalf("decode grant: %v", err)
	}
	return out.GrantID
}

func (cp *controlPlane) revokeGrant(credential, grantID string) {
	cp.t.Helper()
	req, err := http.NewRequest(http.MethodDelete, cp.url+"/grants/"+grantID, nil)
	if err != nil {
		cp.t.Fatalf("build revoke request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	res, err := cp.http.Client().Do(req)
	if err != nil {
		cp.t.Fatalf("revoke grant: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		cp.t.Fatalf("revoke grant: status %d", res.StatusCode)
	}
}

// stateDir returns a path inside a temp dir that does NOT exist yet, so tests
// can assert that a failed enrolment creates nothing at all.
func stateDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "agent-state")
}

func enrol(t *testing.T, dir, serverURL string) agent.EnrolOutcome {
	t.Helper()
	outcome, err := agent.Enrol(context.Background(), agent.EnrolOptions{
		StateDir:    dir,
		ServerURL:   serverURL,
		MachineName: "test-machine",
		Timeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	return outcome
}

func readCredential(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "machine.cred"))
	if err != nil {
		t.Fatalf("read credential: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

func mode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

func componentByName(t *testing.T, report agent.Report, name string) agent.ComponentReport {
	t.Helper()
	for _, c := range report.Components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("report has no component %q (components: %+v)", name, report.Components)
	return agent.ComponentReport{}
}

func status(t *testing.T, dir string) agent.Report {
	t.Helper()
	report, err := agent.Status(context.Background(), agent.StatusOptions{StateDir: dir, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	return report
}

func TestEnrolStoresIdentityWithOwnerOnlyPermissions(t *testing.T) {
	cp := newControlPlane(t)
	dir := stateDir(t)

	outcome := enrol(t, dir, cp.url)

	if outcome.MachineID == "" {
		t.Fatal("enrolment returned no machine id")
	}
	if outcome.Rotated {
		t.Error("first enrolment reported a rotation")
	}
	if got := mode(t, dir); got != 0o700 {
		t.Errorf("state dir mode = %o, want 700", got)
	}
	for _, name := range []string{"state.json", "machine.cred"} {
		if got := mode(t, filepath.Join(dir, name)); got != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, got)
		}
	}

	// The credential must exist in exactly one place on disk.
	credential := readCredential(t, dir)
	if credential == "" {
		t.Fatal("credential file is empty")
	}
	stateJSON, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	if strings.Contains(string(stateJSON), credential) {
		t.Error("state.json contains the machine credential; it must live only in machine.cred")
	}
}

func TestReEnrolRotatesTheCredentialAndKillsTheOldOne(t *testing.T) {
	cp := newControlPlane(t)
	dir := stateDir(t)

	first := enrol(t, dir, cp.url)
	firstCredential := readCredential(t, dir)

	second := enrol(t, dir, cp.url)
	secondCredential := readCredential(t, dir)

	if !second.Rotated {
		t.Error("re-enrolment did not report a rotation")
	}
	if second.MachineID != first.MachineID {
		t.Errorf("re-enrolment changed the machine id: %s -> %s (rotation must be identity-preserving)",
			first.MachineID, second.MachineID)
	}
	if secondCredential == firstCredential {
		t.Fatal("re-enrolment left the credential unchanged")
	}
	if second.CredentialVersion <= first.CredentialVersion {
		t.Errorf("credential version did not advance: %d -> %d", first.CredentialVersion, second.CredentialVersion)
	}

	// The old credential must be dead against the real server.
	client, err := agent.NewClient(cp.url, 5*time.Second)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if _, err := client.WithCredential(firstCredential).ListGrants(context.Background()); err == nil {
		t.Error("the superseded credential still authenticates")
	}
	if _, err := client.WithCredential(secondCredential).ListGrants(context.Background()); err != nil {
		t.Errorf("the rotated credential does not authenticate: %v", err)
	}

	// And the agent's own state must agree with the server about who it is.
	state, ok, err := agent.PeekState(dir)
	if err != nil || !ok {
		t.Fatalf("peek state: ok=%v err=%v", ok, err)
	}
	if state.MachineID != second.MachineID || state.CredentialVersion != second.CredentialVersion {
		t.Errorf("state is inconsistent after rotation: %+v", state)
	}
	if state.RotatedAt == nil {
		t.Error("state does not record the rotation time")
	}
}

func TestEnrolAgainstAnUnreachableServerLeavesNoLocalState(t *testing.T) {
	// A listener that is closed immediately gives us an address nothing is
	// listening on — the "server is down" case, not a DNS failure.
	cp := newControlPlane(t)
	url := cp.url
	cp.http.Close()

	dir := stateDir(t)
	_, err := agent.Enrol(context.Background(), agent.EnrolOptions{
		StateDir:    dir,
		ServerURL:   url,
		MachineName: "test-machine",
		Timeout:     2 * time.Second,
	})
	if err == nil {
		t.Fatal("enrol against a dead server succeeded")
	}
	if !agent.Unreachable(err) {
		t.Errorf("error is not classified as unreachable: %v", err)
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error does not tell the operator that %s is untouched: %v", dir, err)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Errorf("failed enrolment created local state at %s (stat err: %v)", dir, statErr)
	}
}

func TestReEnrolPreservesStateOwnedByLaterTasks(t *testing.T) {
	cp := newControlPlane(t)
	dir := stateDir(t)
	enrol(t, dir, cp.url)

	// Simulate task .5 recording a vault, and a future agent version writing a
	// key this build has never heard of.
	statePath := filepath.Join(dir, "state.json")
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse state: %v", err)
	}
	doc["vault_path"] = "/Users/daniel/Vault"
	doc["invented_by_a_later_task"] = map[string]any{"keep": true}
	updated, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode state: %v", err)
	}
	if err := os.WriteFile(statePath, updated, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	enrol(t, dir, cp.url)

	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("re-read state: %v", err)
	}
	var post map[string]any
	if err := json.Unmarshal(after, &post); err != nil {
		t.Fatalf("parse state after re-enrol: %v", err)
	}
	if post["vault_path"] != "/Users/daniel/Vault" {
		t.Errorf("re-enrol dropped vault_path: %v", post["vault_path"])
	}
	if _, ok := post["invented_by_a_later_task"]; !ok {
		t.Error("re-enrol dropped an unrecognised state key instead of preserving it")
	}
}

func TestEnrolWithoutAServerURLIsRefused(t *testing.T) {
	dir := stateDir(t)
	_, err := agent.Enrol(context.Background(), agent.EnrolOptions{StateDir: dir, MachineName: "m"})
	if err == nil {
		t.Fatal("enrol without a server URL succeeded")
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Error("refused enrolment still created a state directory")
	}
}

func TestReEnrolReusesTheRecordedServerURL(t *testing.T) {
	cp := newControlPlane(t)
	dir := stateDir(t)
	enrol(t, dir, cp.url)

	outcome, err := agent.Enrol(context.Background(), agent.EnrolOptions{StateDir: dir, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("re-enrol without -server: %v", err)
	}
	if outcome.ServerURL != cp.url {
		t.Errorf("server url = %q, want %q", outcome.ServerURL, cp.url)
	}
}

// --- concurrent rotation ----------------------------------------------------

func TestPersistingAStaleEnrolmentResponseIsRefused(t *testing.T) {
	cp := newControlPlane(t)
	dir := stateDir(t)

	client, err := agent.NewClient(cp.url, 5*time.Second)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx := context.Background()

	// Two rotations, oldest first — exactly what two racing `enrol` processes
	// obtain from the server.
	older, err := client.Enrol(ctx, "test-machine", "darwin")
	if err != nil {
		t.Fatalf("first enrol: %v", err)
	}
	newer, err := client.Enrol(ctx, "test-machine", "darwin")
	if err != nil {
		t.Fatalf("second enrol: %v", err)
	}
	if newer.CredentialVersion <= older.CredentialVersion {
		t.Fatalf("precondition: versions did not advance (%d -> %d)", older.CredentialVersion, newer.CredentialVersion)
	}

	id := agent.EnrolIdentity{ServerURL: cp.url, MachineName: "test-machine", OS: "darwin"}
	if _, err := agent.PersistEnrolment(dir, newer, id); err != nil {
		t.Fatalf("persist newer: %v", err)
	}

	// The loser lands second. It must be refused, not written.
	_, err = agent.PersistEnrolment(dir, older, id)
	if err == nil {
		t.Fatal("persisting a superseded credential succeeded")
	}
	if !errors.Is(err, agent.ErrStaleEnrolment) {
		t.Errorf("error = %v, want ErrStaleEnrolment", err)
	}

	stored := readCredential(t, dir)
	if stored != newer.MachineCredential {
		t.Error("the stale response overwrote the live credential")
	}
	state, _, err := agent.PeekState(dir)
	if err != nil {
		t.Fatalf("peek state: %v", err)
	}
	if state.CredentialVersion != newer.CredentialVersion {
		t.Errorf("stored credential version = %d, want %d", state.CredentialVersion, newer.CredentialVersion)
	}
	if _, err := client.WithCredential(stored).ListGrants(ctx); err != nil {
		t.Errorf("the stored credential does not authenticate: %v", err)
	}
}

func TestConcurrentEnrolmentsLeaveTheMachineHoldingALiveCredential(t *testing.T) {
	cp := newControlPlane(t)
	dir := stateDir(t)
	enrol(t, dir, cp.url)

	const racers = 8
	var wg sync.WaitGroup
	errs := make([]error, racers)
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := agent.Enrol(context.Background(), agent.EnrolOptions{
				StateDir:    dir,
				ServerURL:   cp.url,
				MachineName: "test-machine",
				Timeout:     10 * time.Second,
			})
			errs[i] = err
		}(i)
	}
	wg.Wait()

	succeeded := 0
	for i, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, agent.ErrStaleEnrolment):
			// The expected way to lose the race: the response was discarded
			// rather than written over a newer credential.
		default:
			t.Errorf("racer %d failed unexpectedly: %v", i, err)
		}
	}
	if succeeded == 0 {
		t.Fatal("no concurrent enrolment succeeded")
	}

	// The property that matters: whatever landed, the machine can still talk to
	// the server. Persisting a superseded credential would break exactly this.
	client, err := agent.NewClient(cp.url, 5*time.Second)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	stored := readCredential(t, dir)
	if _, err := client.WithCredential(stored).ListGrants(context.Background()); err != nil {
		t.Errorf("after %d concurrent enrolments the stored credential is dead: %v", racers, err)
	}

	state, _, err := agent.PeekState(dir)
	if err != nil {
		t.Fatalf("peek state: %v", err)
	}
	if state.MachineID == "" || state.CredentialVersion == 0 {
		t.Errorf("state is inconsistent after the race: %+v", state)
	}
}

// --- status truth table -----------------------------------------------------

func TestStatusNotEnrolled(t *testing.T) {
	dir := stateDir(t)
	report := status(t, dir)

	if report.Status != agent.OverallNotEnrolled {
		t.Errorf("status = %q, want %q", report.Status, agent.OverallNotEnrolled)
	}
	if report.ExitCode() != agent.ExitNotEnrolled {
		t.Errorf("exit code = %d, want %d", report.ExitCode(), agent.ExitNotEnrolled)
	}
	if report.Enroled {
		t.Error("report claims the machine is enrolled")
	}
	if c := componentByName(t, report, agent.ComponentEnrolment); c.State != agent.StateDegraded {
		t.Errorf("enrolment component = %q, want degraded", c.State)
	}
	if c := componentByName(t, report, agent.ComponentGrants); c.State != agent.StateUnknown {
		t.Errorf("grants component = %q, want unknown for an unenrolled machine", c.State)
	}
}

func TestStatusEnrolledWithoutVault(t *testing.T) {
	cp := newControlPlane(t)
	dir := stateDir(t)
	enrol(t, dir, cp.url)

	report := status(t, dir)

	if !report.Enroled {
		t.Fatal("report does not consider the machine enrolled")
	}
	if report.Status != agent.OverallDegraded {
		t.Errorf("status = %q, want degraded (no vault yet)", report.Status)
	}
	if report.ExitCode() != agent.ExitDegraded {
		t.Errorf("exit code = %d, want %d", report.ExitCode(), agent.ExitDegraded)
	}
	if c := componentByName(t, report, agent.ComponentEnrolment); c.State != agent.StateOK {
		t.Errorf("enrolment component = %q, want ok", c.State)
	}
	if c := componentByName(t, report, agent.ComponentVault); c.State != agent.StateNotConfigured {
		t.Errorf("vault component = %q, want not_configured", c.State)
	}
	if c := componentByName(t, report, agent.ComponentServer); c.State != agent.StateOK {
		t.Errorf("server component = %q (%s), want ok", c.State, c.Detail)
	}
	if c := componentByName(t, report, agent.ComponentGrants); c.State != agent.StateNotConfigured {
		t.Errorf("grants component = %q, want not_configured with no grants", c.State)
	}
	// The named degraded components are what makes a non-zero exit actionable.
	names := map[string]bool{}
	for _, c := range report.Degraded() {
		names[c.Name] = true
	}
	if !names[agent.ComponentVault] || !names[agent.ComponentGNO] {
		t.Errorf("degraded set does not name the unconfigured components: %v", report.Degraded())
	}
}

func TestStatusReconcilesARevokedGrantLive(t *testing.T) {
	cp := newControlPlane(t)
	dir := stateDir(t)
	enrol(t, dir, cp.url)
	credential := readCredential(t, dir)

	grantID := cp.issueGrant(credential, policy.HarnessClaudeCode)

	active := status(t, dir)
	activeGrants := componentByName(t, active, agent.ComponentGrants)
	if activeGrants.State != agent.StateOK {
		t.Fatalf("grants component = %q (%s), want ok with a live grant", activeGrants.State, activeGrants.Detail)
	}
	if len(active.Grants) != 1 || active.Grants[0].State != "active" {
		t.Fatalf("grants = %+v, want one active grant", active.Grants)
	}

	// Revocation happens entirely server-side: nothing touches this machine.
	cp.revokeGrant(credential, grantID)

	after := status(t, dir)
	revoked := componentByName(t, after, agent.ComponentGrants)
	if revoked.State != agent.StateDegraded {
		t.Errorf("grants component = %q (%s), want degraded after revocation", revoked.State, revoked.Detail)
	}
	if len(after.Grants) != 1 {
		t.Fatalf("grants = %+v, want the revoked grant reported", after.Grants)
	}
	if after.Grants[0].State != "revoked" {
		t.Errorf("grant state = %q, want revoked — status must never report a revoked grant as active", after.Grants[0].State)
	}
	if after.Grants[0].RevokedAt == "" {
		t.Error("revoked grant has no revocation time")
	}
	if after.Status != agent.OverallDegraded || after.ExitCode() != agent.ExitDegraded {
		t.Errorf("status = %q exit = %d, want degraded/%d", after.Status, after.ExitCode(), agent.ExitDegraded)
	}
}

func TestStatusWithAnUnreachableServerReportsUnknownNotStale(t *testing.T) {
	cp := newControlPlane(t)
	dir := stateDir(t)
	enrol(t, dir, cp.url)
	credential := readCredential(t, dir)
	cp.issueGrant(credential, policy.HarnessCodex)

	// Prove the agent HAS seen an active grant, so a stale answer would be
	// available to report if the implementation cached one.
	before := status(t, dir)
	if c := componentByName(t, before, agent.ComponentGrants); c.State != agent.StateOK {
		t.Fatalf("precondition: grants component = %q, want ok", c.State)
	}

	cp.http.Close()

	after := status(t, dir)
	grants := componentByName(t, after, agent.ComponentGrants)
	if grants.State != agent.StateUnknown {
		t.Errorf("grants component = %q (%s), want unknown when the server is unreachable", grants.State, grants.Detail)
	}
	if !strings.Contains(grants.Detail, "unreachable") {
		t.Errorf("grants detail = %q, want it to name the unreachable server", grants.Detail)
	}
	if len(after.Grants) != 0 {
		t.Errorf("grants = %+v, want none reported when they could not be reconciled", after.Grants)
	}
	if c := componentByName(t, after, agent.ComponentServer); c.State != agent.StateUnknown {
		t.Errorf("server component = %q, want unknown", c.State)
	}
	// Enrolment is a purely local fact and must survive the server going away.
	if c := componentByName(t, after, agent.ComponentEnrolment); c.State != agent.StateOK {
		t.Errorf("enrolment component = %q, want ok (enrolment is local state)", c.State)
	}
	if after.Status != agent.OverallDegraded || after.ExitCode() != agent.ExitDegraded {
		t.Errorf("status = %q exit = %d, want degraded/%d", after.Status, after.ExitCode(), agent.ExitDegraded)
	}
}

func TestStatusReportsAMissingCredentialAsNotEnrolled(t *testing.T) {
	cp := newControlPlane(t)
	dir := stateDir(t)
	enrol(t, dir, cp.url)

	if err := os.Remove(filepath.Join(dir, "machine.cred")); err != nil {
		t.Fatalf("remove credential: %v", err)
	}

	report := status(t, dir)
	if report.Status != agent.OverallNotEnrolled {
		t.Errorf("status = %q, want not_enrolled when the credential is gone", report.Status)
	}
	if c := componentByName(t, report, agent.ComponentEnrolment); c.State != agent.StateDegraded {
		t.Errorf("enrolment component = %q, want degraded", c.State)
	}
	if c := componentByName(t, report, agent.ComponentGrants); c.State != agent.StateUnknown {
		t.Errorf("grants component = %q, want unknown", c.State)
	}
}

func TestStatusReportsADegradedServer(t *testing.T) {
	// A server whose store probe fails answers /healthz with 503 and a named
	// component; the agent must relay that rather than flattening it to "down".
	st, err := store.Open(filepath.Join(t.TempDir(), "homeplane.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	identity := &store.Identity{NodeID: "node-degraded", NodeName: "degraded"}
	checker := health.New(health.Component{Name: health.ComponentStore, Probe: health.StoreProbe(st)})
	srv, err := server.New(st, fakeResolver{identity: identity}, checker, server.Config{Policy: policy.Default()})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	dir := stateDir(t)
	enrol(t, dir, hs.URL)

	// Break the store AFTER enrolment: the machine is enrolled, the server is
	// sick. Closing it makes the probe fail for real.
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	report := status(t, dir)
	srvComponent := componentByName(t, report, agent.ComponentServer)
	if srvComponent.State != agent.StateOK && srvComponent.State != agent.StateDegraded {
		t.Fatalf("server component = %q (%s), want ok or degraded", srvComponent.State, srvComponent.Detail)
	}
	if srvComponent.State == agent.StateDegraded && !strings.Contains(srvComponent.Detail, health.ComponentStore) {
		t.Errorf("degraded server detail = %q, want it to name the store component", srvComponent.Detail)
	}
	if report.Status == agent.OverallOK {
		t.Error("status is ok while the server is degraded")
	}
}

func TestStatusOfflineNeverClaimsServerState(t *testing.T) {
	cp := newControlPlane(t)
	dir := stateDir(t)
	enrol(t, dir, cp.url)

	report, err := agent.Status(context.Background(), agent.StatusOptions{StateDir: dir, SkipServer: true})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, name := range []string{agent.ComponentGrants, agent.ComponentServer} {
		if c := componentByName(t, report, name); c.State != agent.StateUnknown {
			t.Errorf("%s component = %q, want unknown in offline mode", name, c.State)
		}
	}
}
