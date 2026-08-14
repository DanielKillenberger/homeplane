package agent_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/agent/gno"
	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
)

// R4 requires `status` to be truthful about the retrieval engine in the same way
// R14 requires it about sync — and for the same reason: launchd and systemd
// restart a dying process forever without telling anyone, so the recorded state
// is a claim and the restart ledger is what actually happened.
//
// The one addition specific to R4 is the precondition: a machine with no vault
// must report the engine as "not started because there is no vault", not as an
// undifferentiated not_configured.

func gnoReport(t *testing.T, dir string, probe supervise.Probe) agent.ComponentReport {
	t.Helper()
	report, err := agent.Status(context.Background(), agent.StatusOptions{
		StateDir: dir, SkipServer: true, GNOLiveness: probe,
	})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	for _, c := range report.Components {
		if c.Name == agent.ComponentGNO {
			return c
		}
	}
	t.Fatal("no gno component in the report")
	return agent.ComponentReport{}
}

func TestStatusNamesTheMissingVaultAsTheReasonTheEngineIsNotRunning(t *testing.T) {
	dir := t.TempDir()
	writeVaultState(t, dir, agent.State{})

	c := gnoReport(t, dir, nil)
	// R4 asks for a NAMED degraded state, not a shrug: "not_configured" reads as
	// "nobody has got round to it", which is a different machine from one that
	// cannot run its retrieval engine because there is nothing to index.
	if c.State != agent.StateDegraded {
		t.Fatalf("expected degraded, got %s (%q)", c.State, c.Detail)
	}
	if !strings.Contains(c.Detail, "no vault") {
		t.Fatalf("the blocker is not named: %q", c.Detail)
	}
}

// The dangerous case is not the fresh machine — it is the machine that
// activated weeks ago whose vault has since vanished. Its recorded state still
// says ok and its daemon pid is still alive, because GNO happily serves a stale
// index.
func TestStatusReportsAVanishedVaultEvenWithALiveEngine(t *testing.T) {
	dir := t.TempDir()
	gone := filepath.Join(dir, "Daniel-OS")
	writeVaultState(t, dir, agent.State{
		VaultPath: gone,
		GNO:       &agent.ComponentState{State: agent.StateOK, Detail: "indexing"},
	})
	tracker := supervise.Tracker{Dir: dir, Label: supervise.GNOLabel}
	if _, err := tracker.RecordStart(time.Now(), 4242, "supervised start"); err != nil {
		t.Fatal(err)
	}

	c := gnoReport(t, dir, aliveProbe)
	if c.State != agent.StateDegraded {
		t.Fatalf("a live daemon over a vanished vault reported %s: %q", c.State, c.Detail)
	}
	if !strings.Contains(c.Detail, "no longer exists") {
		t.Fatalf("the detail does not name the vanished vault: %q", c.Detail)
	}
}

func TestStatusReportsAVaultPathThatIsNotADirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-vault")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeVaultState(t, dir, agent.State{
		VaultPath: file,
		GNO:       &agent.ComponentState{State: agent.StateOK, Detail: "indexing"},
	})

	c := gnoReport(t, dir, aliveProbe)
	if c.State != agent.StateDegraded || !strings.Contains(c.Detail, "not a directory") {
		t.Fatalf("a file masquerading as a vault reported %s: %q", c.State, c.Detail)
	}
}

// The stdio endpoint and the daemon fail independently: a healthy indexer with
// every harness launch failing is a broken machine, and status has to say so.
func TestStatusSurfacesFailingHarnessLaunches(t *testing.T) {
	dir := t.TempDir()
	writeVaultState(t, dir, agent.State{
		VaultPath: dir,
		GNO:       &agent.ComponentState{State: agent.StateOK, Detail: "collection daniel-os"},
	})
	tracker := supervise.Tracker{Dir: dir, Label: supervise.GNOLabel}
	if _, err := tracker.RecordStart(time.Now(), 4242, "supervised start"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := gno.RecordLaunch(dir, gno.Launch{
			At: time.Now(), OK: false, ExitCode: 127, Detail: "bun: command not found",
		}); err != nil {
			t.Fatal(err)
		}
	}

	c := gnoReport(t, dir, aliveProbe)
	if c.State != agent.StateDegraded {
		t.Fatalf("failing harness launches reported %s: %q", c.State, c.Detail)
	}
	if !strings.Contains(c.Detail, "harness launches are FAILING") {
		t.Fatalf("the failing half is not named: %q", c.Detail)
	}
	if !strings.Contains(c.Detail, "bun: command not found") {
		t.Fatalf("the launch failure reason was dropped: %q", c.Detail)
	}
}

// A successful launch is reported with its timestamp and never as a pid.
func TestStatusReportsTheLastSuccessfulLaunchWithoutClaimingAPid(t *testing.T) {
	dir := t.TempDir()
	writeVaultState(t, dir, agent.State{
		VaultPath: dir,
		GNO:       &agent.ComponentState{State: agent.StateOK, Detail: "collection daniel-os"},
	})
	tracker := supervise.Tracker{Dir: dir, Label: supervise.GNOLabel}
	if _, err := tracker.RecordStart(time.Now(), 4242, "supervised start"); err != nil {
		t.Fatal(err)
	}
	if _, err := gno.RecordLaunch(dir, gno.Launch{At: time.Now(), OK: true, PID: 999}); err != nil {
		t.Fatal(err)
	}

	c := gnoReport(t, dir, aliveProbe)
	if c.State != agent.StateOK {
		t.Fatalf("a healthy machine reported %s: %q", c.State, c.Detail)
	}
	if !strings.Contains(c.Detail, "stdio endpoint: last launch ok at") {
		t.Fatalf("the launch history is missing: %q", c.Detail)
	}
	if strings.Contains(c.Detail, "stdio endpoint: pid") {
		t.Fatalf("status claimed a pid for the stdio endpoint: %q", c.Detail)
	}
}

func TestStatusReportsAnInstalledButUnloadedEngineAsDegraded(t *testing.T) {
	dir := t.TempDir()
	writeVaultState(t, dir, agent.State{
		VaultPath: dir,
		GNO:       &agent.ComponentState{State: agent.StateInstalled, Detail: "unit installed but not loaded"},
	})

	c := gnoReport(t, dir, nil)
	if c.State != agent.StateDegraded {
		t.Fatalf("an unloaded unit reported %s; nothing is keeping the index current", c.State)
	}
	if !strings.Contains(c.Detail, "NOT being kept current") {
		t.Fatalf("the consequence is not stated: %q", c.Detail)
	}
}

func TestStatusReportsAKilledEngineThatRecordedNoExit(t *testing.T) {
	dir := t.TempDir()
	writeVaultState(t, dir, agent.State{
		VaultPath: dir,
		GNO:       &agent.ComponentState{State: agent.StateOK, Detail: "indexing"},
	})
	tracker := supervise.Tracker{Dir: dir, Label: supervise.GNOLabel}
	if _, err := tracker.RecordStart(time.Now(), 4242, "supervised start"); err != nil {
		t.Fatal(err)
	}

	// The ledger ends on a start — a SIGKILLed process records no exit — so only
	// an external probe can tell the truth here.
	c := gnoReport(t, dir, deadProbe)
	if c.State != agent.StateDegraded {
		t.Fatalf("a dead engine reported %s: %q", c.State, c.Detail)
	}
	if !strings.Contains(c.Detail, "not running") {
		t.Fatalf("the detail does not say it is not running: %q", c.Detail)
	}
	if !strings.Contains(c.Detail, "vault remains readable locally") {
		t.Fatalf("the detail does not distinguish a stopped engine from a lost vault: %q", c.Detail)
	}
}

func TestStatusReportsACrashLoopingEngineAsDegraded(t *testing.T) {
	dir := t.TempDir()
	writeVaultState(t, dir, agent.State{
		VaultPath: dir,
		GNO:       &agent.ComponentState{State: agent.StateOK, Detail: "indexing"},
	})
	tracker := supervise.Tracker{Dir: dir, Label: supervise.GNOLabel}
	now := time.Now()
	for i := 0; i < 7; i++ {
		if _, err := tracker.RecordStart(now.Add(time.Duration(i)*time.Second), 5000+i, "restart"); err != nil {
			t.Fatal(err)
		}
	}

	c := gnoReport(t, dir, aliveProbe)
	if c.State != agent.StateDegraded {
		t.Fatalf("a crash loop reported %s: %q", c.State, c.Detail)
	}
	if !strings.Contains(c.Detail, "crash-looping") {
		t.Fatalf("the crash loop is not surfaced: %q", c.Detail)
	}
}

func TestStatusReportsUnknownWhenTheEnginesLivenessCannotBeEstablished(t *testing.T) {
	dir := t.TempDir()
	writeVaultState(t, dir, agent.State{
		VaultPath: dir,
		GNO:       &agent.ComponentState{State: agent.StateOK, Detail: "indexing"},
	})
	tracker := supervise.Tracker{Dir: dir, Label: supervise.GNOLabel}
	if _, err := tracker.RecordStart(time.Now(), 4242, "supervised start"); err != nil {
		t.Fatal(err)
	}

	c := gnoReport(t, dir, func(supervise.Ledger) supervise.Liveness {
		return supervise.Liveness{Known: false, Detail: "pid is not ours (reused?)"}
	})
	if c.State != agent.StateUnknown {
		t.Fatalf("an unobservable engine reported %s, not unknown: %q", c.State, c.Detail)
	}
}

func TestStatusReportsARunningEngineAsOK(t *testing.T) {
	dir := t.TempDir()
	writeVaultState(t, dir, agent.State{
		VaultPath: dir,
		GNO:       &agent.ComponentState{State: agent.StateOK, Detail: "collection daniel-os"},
	})
	tracker := supervise.Tracker{Dir: dir, Label: supervise.GNOLabel}
	if _, err := tracker.RecordStart(time.Now(), 4242, "supervised start"); err != nil {
		t.Fatal(err)
	}

	c := gnoReport(t, dir, aliveProbe)
	if c.State != agent.StateOK {
		t.Fatalf("a running engine reported %s: %q", c.State, c.Detail)
	}
	if !strings.Contains(c.Detail, "collection daniel-os") {
		t.Fatalf("the recorded detail was dropped: %q", c.Detail)
	}
}

// A recorded activation FAILURE is the whole story: nothing was supervised, so
// consulting the ledger would only add noise.
func TestStatusKeepsARecordedEngineActivationFailure(t *testing.T) {
	dir := t.TempDir()
	writeVaultState(t, dir, agent.State{
		VaultPath: dir,
		GNO: &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "NOT activated: the index would not be machine-local",
		},
	})

	c := gnoReport(t, dir, aliveProbe)
	if c.State != agent.StateDegraded || !strings.Contains(c.Detail, "machine-local") {
		t.Fatalf("the recorded refusal was lost: %s / %q", c.State, c.Detail)
	}
}
