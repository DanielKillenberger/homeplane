package agent_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent"
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
	if c.State != agent.StateNotConfigured {
		t.Fatalf("expected not_configured, got %s", c.State)
	}
	if !strings.Contains(c.Detail, "no vault") {
		t.Fatalf("the blocker is not named: %q", c.Detail)
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
