package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/agent/vault"
)

// These tests drive the CLI against temporary directories only. Nothing here
// reads a real vault, a real Obsidian configuration, or the real sync service.

func vaultDir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(filepath.Join(dir, ".obsidian"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "note.md"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestVaultDetectRecordsThePathAndStatusReportsIt(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	v := vaultDir(t, "Daniel-OS")

	got := invoke(t, "vault", "detect", "-state-dir", state, "-vault-path", v, "-record")
	if got.code != 0 {
		t.Fatalf("detect failed: %d\n%s", got.code, got.stderr)
	}
	if !strings.Contains(got.stdout, v) {
		t.Fatalf("stdout = %q, want the vault path", got.stdout)
	}

	report := invoke(t, "status", "-state-dir", state, "-offline", "-json")
	var doc agent.Report
	if err := json.Unmarshal([]byte(report.stdout), &doc); err != nil {
		t.Fatalf("status json: %v\n%s", err, report.stdout)
	}
	var found bool
	for _, c := range doc.Components {
		if c.Name == agent.ComponentVault {
			found = true
			if c.State != agent.StateOK || c.Detail != v {
				t.Fatalf("vault component = %+v, want ok at %s", c, v)
			}
		}
	}
	if !found {
		t.Fatal("status did not report a vault component")
	}
}

func TestVaultDetectRefusesANonVaultPath(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	got := invoke(t, "vault", "detect", "-state-dir", state, "-vault-path", t.TempDir())
	if got.code == 0 {
		t.Fatal("a non-vault directory was accepted")
	}
	if !strings.Contains(got.stderr, ".obsidian") {
		t.Fatalf("stderr = %q, want an explanation", got.stderr)
	}
}

// R3: no vault must be recorded as degraded-and-retryable, never as ok and
// never as a silent success.
func TestVaultDetectRecordsNoVaultAsDegraded(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))

	got := invoke(t, "vault", "detect", "-state-dir", state, "-name", "Daniel-OS-nonexistent", "-record")
	if got.code == 0 {
		t.Fatalf("detect succeeded with no vault: %s", got.stdout)
	}
	st, ok, err := agent.PeekState(state)
	if err != nil || !ok {
		t.Fatalf("PeekState: %v (ok=%v)", err, ok)
	}
	if st.Vault == nil || st.Vault.State != agent.StateDegraded {
		t.Fatalf("recorded vault state = %+v, want degraded", st.Vault)
	}
	if !strings.Contains(st.Vault.Detail, "retryable") {
		t.Fatalf("detail = %q, want it to say retryable", st.Vault.Detail)
	}
	if st.VaultPath != "" {
		t.Fatalf("a vault path was recorded despite no vault: %q", st.VaultPath)
	}
}

func TestVaultSetCredentialStoresItSecurelyFromStdin(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	const secret = "obsidian-sync-password"

	var out, errBuf bytes.Buffer
	code := runVaultSetCredential([]string{"-state-dir", state}, strings.NewReader(secret+"\n"), &out, &errBuf)
	if code != 0 {
		t.Fatalf("set-credential failed: %d\n%s", code, errBuf.String())
	}
	// The command must not echo the secret back.
	if strings.Contains(out.String(), secret) {
		t.Fatalf("the credential was echoed: %q", out.String())
	}
	got, err := vault.LoadCredential(state)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if got != secret {
		t.Fatalf("credential = %q", got)
	}
	info, err := os.Stat(vault.CredentialPath(state))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 0600", perm)
	}
	// The credential must never reach state.json.
	if raw, err := os.ReadFile(filepath.Join(state, "state.json")); err == nil && strings.Contains(string(raw), secret) {
		t.Fatal("the credential leaked into state.json")
	}
}

// Activation must refuse before it touches anything when the pin is PENDING,
// and it must record that refusal where `status` can see it.
func TestVaultSyncActivateRefusesThePendingPinAndRecordsIt(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	v := vaultDir(t, "Daniel-OS")

	if got := invoke(t, "vault", "detect", "-state-dir", state, "-vault-path", v, "-record"); got.code != 0 {
		t.Fatalf("detect: %s", got.stderr)
	}
	if err := vault.SaveCredential(state, "pw"); err != nil {
		t.Fatal(err)
	}
	ob := filepath.Join(t.TempDir(), "ob")
	if err := os.WriteFile(ob, []byte("#!/bin/sh\necho 0.0.13\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := invoke(t, "vault", "sync", "activate",
		"-state-dir", state, "-ob", ob, "-unit-dir", filepath.Join(t.TempDir(), "units"))
	if got.code == 0 {
		t.Fatal("activation succeeded with a PENDING pin")
	}
	if !strings.Contains(got.stderr, "PENDING") {
		t.Fatalf("stderr = %q, want the pin refusal", got.stderr)
	}

	st, _, err := agent.PeekState(state)
	if err != nil {
		t.Fatal(err)
	}
	if st.Sync == nil || st.Sync.State != agent.StateDegraded {
		t.Fatalf("recorded sync state = %+v, want degraded", st.Sync)
	}
	// The vault itself stays readable and recorded — a refused activation must
	// not look like a lost vault.
	if st.VaultPath != v {
		t.Fatalf("vault path = %q, want %q", st.VaultPath, v)
	}
	if body, err := os.ReadFile(filepath.Join(v, "note.md")); err != nil || string(body) != "hello\n" {
		t.Fatalf("the vault was touched by a refused activation (%v, %q)", err, body)
	}
}

func TestVaultSyncActivateRequiresARecordedVault(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	got := invoke(t, "vault", "sync", "activate", "-state-dir", state)
	if got.code == 0 {
		t.Fatal("activation ran without a recorded vault")
	}
	if !strings.Contains(got.stderr, "vault detect") {
		t.Fatalf("stderr = %q, want a pointer at `vault detect`", got.stderr)
	}
}

func TestVaultSyncActivateRequiresACredential(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	v := vaultDir(t, "Daniel-OS")
	if got := invoke(t, "vault", "detect", "-state-dir", state, "-vault-path", v, "-record"); got.code != 0 {
		t.Fatalf("detect: %s", got.stderr)
	}
	got := invoke(t, "vault", "sync", "activate", "-state-dir", state)
	if got.code == 0 {
		t.Fatal("activation ran without a sync credential")
	}
	st, _, err := agent.PeekState(state)
	if err != nil {
		t.Fatal(err)
	}
	if st.Sync == nil || st.Sync.State != agent.StateDegraded {
		t.Fatalf("recorded sync state = %+v, want degraded", st.Sync)
	}
}

func TestVaultUsageAndUnknownSubcommands(t *testing.T) {
	if got := invoke(t, "vault"); got.code != exitUsage {
		t.Fatalf("bare `vault` exit = %d, want %d", got.code, exitUsage)
	}
	if got := invoke(t, "vault", "nonsense"); got.code != exitUsage {
		t.Fatalf("unknown subcommand exit = %d, want %d", got.code, exitUsage)
	}
	if got := invoke(t, "vault", "sync", "nonsense"); got.code != exitUsage {
		t.Fatalf("unknown sync subcommand exit = %d, want %d", got.code, exitUsage)
	}
	if got := invoke(t, "vault", "--help"); got.code != 0 || !strings.Contains(got.stdout, "detect") {
		t.Fatalf("help = %d, %q", got.code, got.stdout)
	}
}

func TestSyncComponentForClassifiesFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"destructive", &vault.DestructiveDiffError{Reason: "too many", SnapshotPath: "/snap"}, "destructive diff refused"},
		{"pin pending", vault.ErrPinUnset, "PENDING"},
		{"pin mismatch", vault.ErrPinMismatch, "does not match the pinned build"},
		{"auth", &vault.AuthError{Detail: "401"}, "authentication failed"},
		{"network", &vault.NetworkError{Detail: "refused"}, "network failure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := syncComponentFor(tc.err, vault.ActivateResult{})
			if got.State != agent.StateDegraded {
				t.Fatalf("state = %q, want degraded", got.State)
			}
			if !strings.Contains(got.Detail, tc.want) {
				t.Fatalf("detail = %q, want it to mention %q", got.Detail, tc.want)
			}
		})
	}
	// Every failure must read as retryable rather than terminal.
	for _, tc := range cases[3:] {
		if got := syncComponentFor(tc.err, vault.ActivateResult{}); !strings.Contains(got.Detail, "retryable") {
			t.Fatalf("%s detail = %q, want it to say retryable", tc.name, got.Detail)
		}
	}
}

func TestVaultIsRegisteredInTheTopLevelUsage(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &out, &out); code != 0 {
		t.Fatalf("help exit = %d", code)
	}
	if !strings.Contains(out.String(), "vault") {
		t.Fatalf("usage does not mention the vault subcommand:\n%s", out.String())
	}
}
