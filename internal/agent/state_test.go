package agent_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/agent"
)

func TestOpenTightensAnOverPermissiveStateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := agent.Open(dir); err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := mode(t, dir); got != 0o700 {
		t.Errorf("state dir mode = %o, want 700 (Open must tighten, not merely tolerate)", got)
	}
}

func TestSaveEnrolmentRefusesAnEmptyCredential(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store, err := agent.Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.SaveEnrolment(agent.State{MachineID: "m", ServerURL: "http://x"}, ""); err == nil {
		t.Fatal("an empty credential was accepted")
	}
	if _, err := os.Stat(store.CredentialPath()); !os.IsNotExist(err) {
		t.Error("a credential file was created for an empty credential")
	}
}

func TestSaveEnrolmentLeavesNoTemporaryFilesBehind(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store, err := agent.Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.SaveEnrolment(agent.State{MachineID: "m", ServerURL: "http://x"}, "secret-token"); err != nil {
		t.Fatalf("save: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if e.Name() == ".lock" { // the enrolment lock is expected bookkeeping
			continue
		}
		names = append(names, e.Name())
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("atomic write left a temporary file behind: %s", e.Name())
		}
	}
	if len(names) != 2 {
		t.Errorf("state dir contains %v, want exactly state.json and machine.cred", names)
	}

	got, err := store.Credential()
	if err != nil {
		t.Fatalf("read credential: %v", err)
	}
	if got != "secret-token" {
		t.Errorf("credential = %q, want %q (the trailing newline must not become part of the secret)", got, "secret-token")
	}
}

func TestCredentialOfAnUnenrolledMachineIsNotAnIOError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store, err := agent.Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := store.Credential(); err == nil {
		t.Fatal("reading a missing credential succeeded")
	} else if err != agent.ErrNotEnroled {
		t.Errorf("error = %v, want ErrNotEnroled so callers can tell it from an unreadable file", err)
	}
}

func TestDefaultStateDirHonoursTheEnvironmentOverride(t *testing.T) {
	t.Setenv(agent.EnvStateDir, "/tmp/homeplane-test-state")
	got, err := agent.DefaultStateDir()
	if err != nil {
		t.Fatalf("default state dir: %v", err)
	}
	if got != "/tmp/homeplane-test-state" {
		t.Errorf("state dir = %q, want the override", got)
	}
}

func TestDefaultStateDirFallsBackToHome(t *testing.T) {
	t.Setenv(agent.EnvStateDir, "")
	if runtime.GOOS == "linux" {
		t.Setenv("XDG_STATE_HOME", "")
	}
	got, err := agent.DefaultStateDir()
	if err != nil {
		t.Fatalf("default state dir: %v", err)
	}
	if filepath.Base(got) != ".homeplane" {
		t.Errorf("state dir = %q, want ~/.homeplane", got)
	}
}
