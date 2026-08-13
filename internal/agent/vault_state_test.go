package agent_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/agent"
)

// R3 requires `status` to distinguish "no vault on this machine" from "the
// vault could not be retrieved because authentication failed". Both leave
// vault_path empty, so the recorded reason is the only thing that can tell
// them apart — and status must prefer it over a generic "not configured".

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

func vaultComponentOf(t *testing.T, dir string) agent.ComponentReport {
	t.Helper()
	report, err := agent.Status(context.Background(), agent.StatusOptions{StateDir: dir, SkipServer: true})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	for _, c := range report.Components {
		if c.Name == agent.ComponentVault {
			return c
		}
	}
	t.Fatalf("no vault component in %+v", report.Components)
	return agent.ComponentReport{}
}

func TestStatusReportsNoVaultDistinctlyFromAuthFailure(t *testing.T) {
	t.Run("no vault found", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")
		writeVaultState(t, dir, agent.State{
			Vault: &agent.ComponentState{State: agent.StateDegraded, Detail: "no vault found on this machine — retryable"},
		})
		c := vaultComponentOf(t, dir)
		if c.State != agent.StateDegraded || !strings.Contains(c.Detail, "no vault found") {
			t.Fatalf("vault component = %+v", c)
		}
	})

	t.Run("auth failure", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")
		writeVaultState(t, dir, agent.State{
			Vault: &agent.ComponentState{State: agent.StateDegraded, Detail: "Obsidian Sync authentication failed — retryable"},
		})
		c := vaultComponentOf(t, dir)
		if c.State != agent.StateDegraded || !strings.Contains(c.Detail, "authentication failed") {
			t.Fatalf("vault component = %+v", c)
		}
	})

	t.Run("nothing recorded", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")
		writeVaultState(t, dir, agent.State{})
		c := vaultComponentOf(t, dir)
		if c.State != agent.StateNotConfigured {
			t.Fatalf("vault component = %+v, want not_configured", c)
		}
	})
}

// A healthy recorded path still reports the path itself: the recorded reason is
// a fallback, not a way to claim `ok` for a vault that is not there.
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
	c := vaultComponentOf(t, dir)
	if c.State != agent.StateOK || c.Detail != vaultDir {
		t.Fatalf("vault component = %+v, want ok with the path", c)
	}

	// And a recorded path that has since vanished is degraded, not ok.
	if err := os.RemoveAll(vaultDir); err != nil {
		t.Fatal(err)
	}
	if c := vaultComponentOf(t, dir); c.State != agent.StateDegraded {
		t.Fatalf("vault component = %+v, want degraded", c)
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
