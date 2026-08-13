package agent_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
)

// R3 requires `status` to distinguish "no vault on this machine" from "the
// vault could not be retrieved because authentication failed". Both leave
// vault_path empty, so the recorded reason is the only thing that can tell
// them apart.
//
// R14 requires more than that for sync: the recorded state is a CLAIM made at
// activation time, and a machine can be SIGKILLed, crash-loop, or never load
// the unit at all afterwards. So the restart ledger — what the supervised
// process actually did — is authoritative for liveness.

func writeVaultState(t *testing.T, dir string, st agent.State) {
	t.Helper()
	store, err := agent.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := store.Save(st); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

// aliveProbe / deadProbe stage liveness without killing real processes.
func aliveProbe(l supervise.Ledger) supervise.Liveness {
	return supervise.Liveness{Known: true, Alive: true, Detail: "pid is alive"}
}

func deadProbe(l supervise.Ledger) supervise.Liveness {
	return supervise.Liveness{Known: true, Alive: false, Detail: "pid is gone and recorded no exit (killed)"}
}

func componentOf(t *testing.T, dir, name string) agent.ComponentReport {
	t.Helper()
	return componentWithProbe(t, dir, name, aliveProbe)
}

func componentWithProbe(t *testing.T, dir, name string, probe supervise.Probe) agent.ComponentReport {
	t.Helper()
	report, err := agent.Status(context.Background(), agent.StatusOptions{
		StateDir: dir, SkipServer: true, SyncLiveness: probe,
	})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	for _, c := range report.Components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s component in %+v", name, report.Components)
	return agent.ComponentReport{}
}

func TestStatusReportsNoVaultDistinctlyFromAuthFailure(t *testing.T) {
	t.Run("no vault found", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")
		writeVaultState(t, dir, agent.State{
			Vault: &agent.ComponentState{State: agent.StateDegraded, Detail: "no vault found on this machine — retryable"},
		})
		c := componentOf(t, dir, agent.ComponentVault)
		if c.State != agent.StateDegraded || !strings.Contains(c.Detail, "no vault found") {
			t.Fatalf("vault component = %+v", c)
		}
	})

	t.Run("auth failure", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")
		writeVaultState(t, dir, agent.State{
			Vault: &agent.ComponentState{State: agent.StateDegraded, Detail: "Obsidian authentication failed — retryable"},
		})
		c := componentOf(t, dir, agent.ComponentVault)
		if c.State != agent.StateDegraded || !strings.Contains(c.Detail, "authentication failed") {
			t.Fatalf("vault component = %+v", c)
		}
	})

	t.Run("nothing recorded", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")
		writeVaultState(t, dir, agent.State{})
		c := componentOf(t, dir, agent.ComponentVault)
		if c.State != agent.StateNotConfigured {
			t.Fatalf("vault component = %+v, want not_configured", c)
		}
	})
}

func TestStatusPrefersTheLiveVaultPathOverTheRecordedReason(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	vaultDir := filepath.Join(t.TempDir(), "Daniel-OS")
	if err := os.MkdirAll(filepath.Join(vaultDir, ".obsidian"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeVaultState(t, dir, agent.State{
		VaultPath: vaultDir,
		Vault:     &agent.ComponentState{State: agent.StateDegraded, Detail: "stale detail from an earlier run"},
	})
	if c := componentOf(t, dir, agent.ComponentVault); c.State != agent.StateOK || c.Detail != vaultDir {
		t.Fatalf("vault component = %+v, want ok with the path", c)
	}
	if err := os.RemoveAll(vaultDir); err != nil {
		t.Fatal(err)
	}
	if c := componentOf(t, dir, agent.ComponentVault); c.State != agent.StateDegraded {
		t.Fatalf("vault component = %+v, want degraded", c)
	}
}

// ── sync liveness, derived from the ledger ───────────────────────────────────

func syncTracker(dir string) supervise.Tracker {
	return supervise.Tracker{Dir: dir, Label: supervise.VaultSyncLabel}
}

// An installed-but-never-loaded unit is NOT a syncing vault. This used to
// report `ok` while the very next line of output said "not loaded".
func TestStatusReportsAnInstalledButUnloadedUnitAsDegraded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	writeVaultState(t, dir, agent.State{
		Sync: &agent.ComponentState{State: agent.StateInstalled, Detail: "unit installed but not loaded"},
	})
	c := componentOf(t, dir, agent.ComponentSync)
	if c.State != agent.StateDegraded {
		t.Fatalf("sync component = %+v, want degraded", c)
	}
	if !strings.Contains(c.Detail, "NOT syncing") {
		t.Fatalf("detail = %q, want it to say the vault is not syncing", c.Detail)
	}
}

// Recorded `ok` with nothing ever started is a supervisor that never ran it.
func TestStatusReportsSupervisedButNeverStartedAsDegraded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	writeVaultState(t, dir, agent.State{
		Sync: &agent.ComponentState{State: agent.StateOK, Detail: "supervised"},
	})
	c := componentOf(t, dir, agent.ComponentSync)
	if c.State != agent.StateDegraded || !strings.Contains(c.Detail, "never started") {
		t.Fatalf("sync component = %+v", c)
	}
}

func TestStatusReportsARunningSyncAsOK(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	writeVaultState(t, dir, agent.State{
		Sync: &agent.ComponentState{State: agent.StateOK, Detail: "supervised"},
	})
	if _, err := syncTracker(dir).RecordStart(time.Now().Add(-time.Hour), 4242, "supervised start"); err != nil {
		t.Fatal(err)
	}
	c := componentOf(t, dir, agent.ComponentSync)
	if c.State != agent.StateOK {
		t.Fatalf("sync component = %+v, want ok", c)
	}
	if !strings.Contains(c.Detail, "pid 4242") {
		t.Fatalf("detail = %q, want the pid from the ledger", c.Detail)
	}
}

// THE case the ledger cannot see on its own: the process was SIGKILLed, so it
// recorded NO exit, and the supervisor never restarted it. The ledger still
// ends on a start event — believing itself healthy — and only an external probe
// can tell the truth. No simulated RecordExit here on purpose.
func TestStatusReportsAKilledSyncThatRecordedNoExit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	writeVaultState(t, dir, agent.State{
		Sync: &agent.ComponentState{State: agent.StateOK, Detail: "supervised"},
	})
	// One start, months ago. No exit. No restart.
	if _, err := syncTracker(dir).RecordStart(time.Now().Add(-90*24*time.Hour), 4242, "supervised start"); err != nil {
		t.Fatal(err)
	}
	ledger, err := syncTracker(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if !ledger.SelfReportedRunning() {
		t.Fatal("precondition: the ledger must still BELIEVE it is running")
	}

	c := componentWithProbe(t, dir, agent.ComponentSync, deadProbe)
	if c.State != agent.StateDegraded {
		t.Fatalf("sync component = %+v, want degraded for a killed process", c)
	}
	if !strings.Contains(c.Detail, "not running") {
		t.Fatalf("detail = %q, want it to say the process is not running", c.Detail)
	}
	if !strings.Contains(c.Detail, "recorded no exit") {
		t.Fatalf("detail = %q, want it to name why the ledger looked healthy", c.Detail)
	}
}

// An unobservable process is `unknown`, not `ok` — the same truthfulness rule
// the server-dependent components follow.
func TestStatusReportsUnknownWhenLivenessCannotBeEstablished(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	writeVaultState(t, dir, agent.State{
		Sync: &agent.ComponentState{State: agent.StateOK, Detail: "supervised"},
	})
	if _, err := syncTracker(dir).RecordStart(time.Now().Add(-time.Hour), 0, ""); err != nil {
		t.Fatal(err)
	}
	unknown := func(supervise.Ledger) supervise.Liveness {
		return supervise.Liveness{Known: false, Detail: "the last start recorded no pid"}
	}
	c := componentWithProbe(t, dir, agent.ComponentSync, unknown)
	if c.State != agent.StateUnknown {
		t.Fatalf("sync component = %+v, want unknown", c)
	}
	if !strings.Contains(c.Detail, "cannot tell") {
		t.Fatalf("detail = %q", c.Detail)
	}
}

// SIGKILL followed by a recorded exit: the supervisor observed it and the
// status must still be degraded.
func TestStatusReportsAnExitedSyncAsDegraded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	writeVaultState(t, dir, agent.State{
		Sync: &agent.ComponentState{State: agent.StateOK, Detail: "supervised"},
	})
	tr := syncTracker(dir)
	base := time.Now().Add(-2 * time.Hour)
	if _, err := tr.RecordStart(base, 1, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.RecordExit(base.Add(time.Minute), 137, "SIGKILL"); err != nil {
		t.Fatal(err)
	}
	c := componentWithProbe(t, dir, agent.ComponentSync, deadProbe)
	if c.State != agent.StateDegraded || !strings.Contains(c.Detail, "not running") {
		t.Fatalf("sync component = %+v", c)
	}
	if !strings.Contains(c.Detail, "retryable") || !strings.Contains(c.Detail, "readable locally") {
		t.Fatalf("detail = %q, want it to say the vault is still readable", c.Detail)
	}
}

// Killed and restarted by the supervisor: healthy again, and the earlier
// degraded record must not stick.
func TestStatusClearsAfterASupervisorRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	writeVaultState(t, dir, agent.State{
		Sync: &agent.ComponentState{State: agent.StateOK, Detail: "supervised"},
	})
	tr := syncTracker(dir)
	base := time.Now().Add(-3 * time.Hour)
	if _, err := tr.RecordStart(base, 1, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.RecordExit(base.Add(time.Minute), 137, "SIGKILL"); err != nil {
		t.Fatal(err)
	}
	if c := componentWithProbe(t, dir, agent.ComponentSync, deadProbe); c.State != agent.StateDegraded {
		t.Fatalf("component before restart = %+v", c)
	}
	// The supervisor brings it back an hour later — not a crash loop.
	if _, err := tr.RecordStart(base.Add(time.Hour), 2, "restart"); err != nil {
		t.Fatal(err)
	}
	c := componentOf(t, dir, agent.ComponentSync)
	if c.State != agent.StateOK {
		t.Fatalf("component after restart = %+v, want ok", c)
	}
}

// Six restarts in a minute is a service failing to start, not a service being
// restarted — and launchd/systemd will do it forever without telling anyone.
func TestStatusReportsACrashLoopAsDegraded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	writeVaultState(t, dir, agent.State{
		Sync: &agent.ComponentState{State: agent.StateOK, Detail: "supervised"},
	})
	tr := syncTracker(dir)
	base := time.Now().Add(-time.Minute)
	for i := 0; i < 6; i++ {
		if _, err := tr.RecordStart(base.Add(time.Duration(i)*5*time.Second), i, ""); err != nil {
			t.Fatal(err)
		}
	}
	c := componentOf(t, dir, agent.ComponentSync)
	if c.State != agent.StateDegraded || !strings.Contains(c.Detail, "crash-looping") {
		t.Fatalf("sync component = %+v, want a crash-loop report", c)
	}
}

// A recorded FAILURE (bad pin, destructive diff, auth failure) is the whole
// story — nothing was supervised, so there is no ledger to consult and the
// reason must survive unchanged.
func TestStatusKeepsARecordedActivationFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	writeVaultState(t, dir, agent.State{
		Sync: &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "sync NOT activated: destructive diff refused (0 added, 0 modified, 412 deleted)",
		},
	})
	c := componentOf(t, dir, agent.ComponentSync)
	if c.State != agent.StateDegraded || !strings.Contains(c.Detail, "destructive diff refused") {
		t.Fatalf("sync component = %+v", c)
	}
}

func TestStatusReportsUnconfiguredSync(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	writeVaultState(t, dir, agent.State{})
	if c := componentOf(t, dir, agent.ComponentSync); c.State != agent.StateNotConfigured {
		t.Fatalf("sync component = %+v, want not_configured", c)
	}
}

// The vault reason is a first-class state key, so an older agent must not drop
// it — the same preservation guarantee the other component fields have.
func TestVaultReasonRoundTripsThroughState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	writeVaultState(t, dir, agent.State{
		VaultPath: "/vaults/Daniel-OS",
		Vault:     &agent.ComponentState{State: agent.StateOK, Detail: "detected"},
		Sync:      &agent.ComponentState{State: agent.StateOK, Detail: "supervised"},
	})
	state, ok, err := agent.PeekState(dir)
	if err != nil || !ok {
		t.Fatalf("PeekState: %v (ok=%v)", err, ok)
	}
	if state.Vault == nil || state.Vault.Detail != "detected" {
		t.Fatalf("vault state = %+v", state.Vault)
	}
	if state.Sync == nil || state.Sync.Detail != "supervised" {
		t.Fatalf("sync state = %+v", state.Sync)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["vault"]; !ok {
		t.Fatalf("state.json has no `vault` key: %s", raw)
	}
}
