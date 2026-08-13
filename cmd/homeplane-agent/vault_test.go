package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
	"github.com/DanielKillenberger/homeplane/internal/agent/vault"
)

// These tests drive the CLI against temporary directories and a fake
// obsidian-headless stub. Nothing here reads a real vault, a real Obsidian
// configuration, or the real network.

const fakeOB = `#!/bin/sh
case "$1" in
  --version|-V) echo "0.0.13"; exit 0 ;;
  sync-list-remote)
    if [ -z "$OBSIDIAN_AUTH_TOKEN" ]; then echo "error: unauthorized" >&2; exit 1; fi
    echo "Remote vaults:"; echo "Daniel-OS"; exit 0 ;;
  sync-setup)
    shift; DIR="$PWD"
    while [ $# -gt 0 ]; do case "$1" in --path) DIR="$2"; shift 2 ;; *) shift ;; esac; done
    mkdir -p "$DIR/.obsidian"; printf '{}\n' > "$DIR/.obsidian/app.json"; exit 0 ;;
  sync-config) exit 0 ;;
  sync)
    shift; DIR="$PWD"
    while [ $# -gt 0 ]; do case "$1" in --path) DIR="$2"; shift 2 ;; *) shift ;; esac; done
    if [ -n "$FAKE_OB_PULL" ]; then
      mkdir -p "$DIR/.obsidian"; printf '{}\n' > "$DIR/.obsidian/app.json"
      echo "# pulled" > "$DIR/pulled.md"
    fi
    exit 0 ;;
esac
echo "error: unknown command $1" >&2; exit 1
`

func tmp(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	return dir
}

// writeOB installs the stub. The compiled-in pin still refuses it — which is
// what the refusal tests want.
func writeOB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(tmp(t), "ob")
	if err := os.WriteFile(path, []byte(fakeOB), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// pinnedOB installs the stub AND points the pin at it for the duration of one
// test, so a happy path can run without a 40-package npm install.
func pinnedOB(t *testing.T) string {
	t.Helper()
	path := writeOB(t)
	sum := sha256File(t, path)
	prev := loadPin
	loadPin = func() (vault.Pin, error) {
		return vault.Pin{Version: "0.0.13", Checksum: sum}, nil
	}
	t.Cleanup(func() { loadPin = prev })
	return path
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func vaultDir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(tmp(t), name)
	if err := os.MkdirAll(filepath.Join(dir, ".obsidian"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "note.md"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestVaultDetectRecordsThePathAndStatusReportsIt(t *testing.T) {
	state := filepath.Join(tmp(t), "state")
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
	state := filepath.Join(tmp(t), "state")
	got := invoke(t, "vault", "detect", "-state-dir", state, "-vault-path", tmp(t))
	if got.code == 0 {
		t.Fatal("a non-vault directory was accepted")
	}
	if !strings.Contains(got.stderr, ".obsidian") {
		t.Fatalf("stderr = %q, want an explanation", got.stderr)
	}
}

// R3: no vault must be recorded as degraded-and-retryable, never as ok.
func TestVaultDetectRecordsNoVaultAsDegraded(t *testing.T) {
	state := filepath.Join(tmp(t), "state")
	home := tmp(t)
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

func TestVaultSetE2EPasswordStoresItSecurelyFromStdin(t *testing.T) {
	state := filepath.Join(tmp(t), "state")
	const secret = "e2e-encryption-password"

	var out, errBuf bytes.Buffer
	code := runVaultSetE2E([]string{"-state-dir", state}, strings.NewReader(secret+"\n"), &out, &errBuf)
	if code != 0 {
		t.Fatalf("set-e2e-password failed: %d\n%s", code, errBuf.String())
	}
	if strings.Contains(out.String(), secret) {
		t.Fatalf("the password was echoed: %q", out.String())
	}
	got, err := vault.LoadE2EPassword(state)
	if err != nil {
		t.Fatalf("LoadE2EPassword: %v", err)
	}
	if got != secret {
		t.Fatalf("password = %q", got)
	}
	info, err := os.Stat(vault.E2EPasswordPath(state))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 0600", perm)
	}
	if raw, err := os.ReadFile(filepath.Join(state, "state.json")); err == nil && strings.Contains(string(raw), secret) {
		t.Fatal("the password leaked into state.json")
	}
}

// R3's absent-vault path, end to end through the command surface.
func TestVaultRetrieveFetchesAnAbsentVault(t *testing.T) {
	state := filepath.Join(tmp(t), "state")
	dest := filepath.Join(tmp(t), "Daniel-OS")
	if err := vault.SaveAuthToken(state, "tok"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_OB_PULL", "1")

	got := invoke(t, "vault", "retrieve", "-state-dir", state, "-path", dest, "-ob", pinnedOB(t))
	if got.code != 0 {
		t.Fatalf("retrieve failed: %d\n%s", got.code, got.stderr)
	}
	st, _, err := agent.PeekState(state)
	if err != nil {
		t.Fatal(err)
	}
	if st.VaultPath == "" {
		t.Fatal("retrieval did not record a vault path")
	}
	if !vault.IsVault(st.VaultPath) {
		t.Fatalf("%s is not a vault", st.VaultPath)
	}
	if st.Vault == nil || st.Vault.State != agent.StateOK {
		t.Fatalf("recorded vault state = %+v", st.Vault)
	}
}

// The previously unreachable branch: retrieval without a stored token reports
// an auth problem, distinct from "no vault found".
func TestVaultRetrieveWithoutATokenReportsAnAuthProblem(t *testing.T) {
	state := filepath.Join(tmp(t), "state")
	got := invoke(t, "vault", "retrieve", "-state-dir", state, "-path", filepath.Join(tmp(t), "v"), "-ob", writeOB(t))
	if got.code == 0 {
		t.Fatal("retrieval ran without a token")
	}
	if !strings.Contains(got.stderr, "vault login") {
		t.Fatalf("stderr = %q, want a pointer at `vault login`", got.stderr)
	}
	st, _, err := agent.PeekState(state)
	if err != nil {
		t.Fatal(err)
	}
	if st.Vault == nil || !strings.Contains(st.Vault.Detail, "auth token") {
		t.Fatalf("recorded vault state = %+v, want an auth-token reason", st.Vault)
	}
}

func TestVaultRetrieveRequiresAPath(t *testing.T) {
	if got := invoke(t, "vault", "retrieve", "-state-dir", filepath.Join(tmp(t), "s")); got.code != exitUsage {
		t.Fatalf("exit = %d, want %d", got.code, exitUsage)
	}
}

// Activation must refuse before touching anything when the CLI is not the
// pinned build, and record that refusal where `status` can see it.
func TestVaultSyncActivateRefusesAnUnpinnedCLI(t *testing.T) {
	state := filepath.Join(tmp(t), "state")
	v := vaultDir(t, "Daniel-OS")
	if got := invoke(t, "vault", "detect", "-state-dir", state, "-vault-path", v, "-record"); got.code != 0 {
		t.Fatalf("detect: %s", got.stderr)
	}
	if err := vault.SaveAuthToken(state, "tok"); err != nil {
		t.Fatal(err)
	}

	got := invoke(t, "vault", "sync", "activate",
		"-state-dir", state, "-ob", writeOB(t), "-unit-dir", filepath.Join(tmp(t), "units"))
	if got.code == 0 {
		t.Fatal("activation succeeded with an unpinned CLI")
	}
	if !strings.Contains(got.stderr, "does not match the pin") {
		t.Fatalf("stderr = %q, want the pin refusal", got.stderr)
	}

	st, _, err := agent.PeekState(state)
	if err != nil {
		t.Fatal(err)
	}
	if st.Sync == nil || st.Sync.State != agent.StateDegraded {
		t.Fatalf("recorded sync state = %+v, want degraded", st.Sync)
	}
	// The vault stays readable and recorded — a refused activation must never
	// look like a lost vault.
	if st.VaultPath != v {
		t.Fatalf("vault path = %q, want %q", st.VaultPath, v)
	}
	if body, err := os.ReadFile(filepath.Join(v, "note.md")); err != nil || string(body) != "hello\n" {
		t.Fatalf("the vault was touched by a refused activation (%v, %q)", err, body)
	}
}

func TestVaultSyncActivateRequiresARecordedVault(t *testing.T) {
	state := filepath.Join(tmp(t), "state")
	got := invoke(t, "vault", "sync", "activate", "-state-dir", state)
	if got.code == 0 {
		t.Fatal("activation ran without a recorded vault")
	}
	if !strings.Contains(got.stderr, "vault detect") {
		t.Fatalf("stderr = %q, want a pointer at `vault detect`", got.stderr)
	}
}

func TestVaultSyncActivateRequiresAnAuthToken(t *testing.T) {
	state := filepath.Join(tmp(t), "state")
	v := vaultDir(t, "Daniel-OS")
	if got := invoke(t, "vault", "detect", "-state-dir", state, "-vault-path", v, "-record"); got.code != 0 {
		t.Fatalf("detect: %s", got.stderr)
	}
	got := invoke(t, "vault", "sync", "activate", "-state-dir", state, "-ob", writeOB(t))
	if got.code == 0 {
		t.Fatal("activation ran without an auth token")
	}
	if !strings.Contains(got.stderr, "vault login") {
		t.Fatalf("stderr = %q, want a pointer at `vault login`", got.stderr)
	}
}

// The bug that made every installed service crash-loop: the supervision unit
// omitted the resolved CLI path, so the supervised `vault sync run` refused
// with "no obsidian-headless CLI path configured" on every launch.
//
// This drives the RENDERED UNIT'S EXACT ARGV back through the command surface.
func TestSupervisedRunUsesTheUnitsOwnArgv(t *testing.T) {
	state := filepath.Join(tmp(t), "state")
	v := vaultDir(t, "Daniel-OS")
	ob := writeOB(t)

	// Stand in for what activation persists, without needing a matching pin.
	if err := vault.SaveConfig(state, vault.Config{
		VaultPath: v, OBPath: ob, UnitLabel: vault.SyncUnitLabel, PinVersion: "0.0.13",
	}); err != nil {
		t.Fatal(err)
	}
	if err := vault.SaveAuthToken(state, "tok"); err != nil {
		t.Fatal(err)
	}

	unit, err := vault.SyncUnit("/opt/homeplane/bin/homeplane-agent", state, v, ob)
	if err != nil {
		t.Fatalf("SyncUnit: %v", err)
	}
	// Exactly what launchd/systemd would exec, minus the program itself.
	got := invoke(t, append(unit.Args, "-once")...)
	if strings.Contains(got.stderr, "no obsidian-headless CLI path configured") {
		t.Fatalf("the supervised argv cannot find the CLI:\n%s", got.stderr)
	}
	// The stub is not the pinned build, so a pin refusal is the expected
	// outcome — what matters is that it got as far as verifying a real path.
	if got.code == 0 && !strings.Contains(got.stdout, "exited cleanly") {
		t.Fatalf("unexpected output: %q / %q", got.stdout, got.stderr)
	}
	if got.code != 0 && !strings.Contains(got.stderr, "does not match the pin") {
		t.Fatalf("supervised run failed for the wrong reason: %s", got.stderr)
	}
}

func TestSupervisedUnitArgvCarriesTheCLIPath(t *testing.T) {
	state := filepath.Join(tmp(t), "state")
	ob := writeOB(t)
	unit, err := vault.SyncUnit("/opt/homeplane/bin/homeplane-agent", state, "/vaults/Daniel-OS", ob)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Join(unit.Args, " ")
	for _, want := range []string{"vault", "sync", "run", "-state-dir " + state, "-ob " + ob} {
		if !strings.Contains(argv, want) {
			t.Fatalf("unit argv %q is missing %q", argv, want)
		}
	}
	rendered, err := unit.Render(supervise.Launchd)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered, ob) {
		t.Fatalf("the rendered unit omits the CLI path:\n%s", rendered)
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
		{"no token", vault.ErrNoAuthToken, "vault login"},
		{"auth", &vault.AuthError{Detail: "401"}, "authentication failed"},
		{"network", &vault.NetworkError{Detail: "refused"}, "network failure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := syncComponentFor(tc.err, vault.PrepareResult{})
			if got.State != agent.StateDegraded {
				t.Fatalf("state = %q, want degraded", got.State)
			}
			if !strings.Contains(got.Detail, tc.want) {
				t.Fatalf("detail = %q, want it to mention %q", got.Detail, tc.want)
			}
		})
	}
	for _, tc := range cases[3:] {
		if got := syncComponentFor(tc.err, vault.PrepareResult{}); !strings.Contains(got.Detail, "retryable") {
			t.Fatalf("%s detail = %q, want it to say retryable", tc.name, got.Detail)
		}
	}
}

// An installed-but-unloaded unit must NOT project as ok. This is the exact
// conflation that let a machine report a healthy sync while nothing ran.
func TestSyncComponentForResultSeparatesInstalledFromActive(t *testing.T) {
	cfg := vault.Config{VaultPath: "/v", UnitPath: "/u/com.homeplane.vault-sync.plist", PinVersion: "0.0.13"}

	installed := syncComponentForResult(cfg, vault.PrepareResult{})
	if installed.State != agent.StateInstalled {
		t.Fatalf("unapplied state = %q, want %q", installed.State, agent.StateInstalled)
	}
	if !strings.Contains(installed.Detail, "not loaded") {
		t.Fatalf("detail = %q", installed.Detail)
	}

	cfg.Applied = true
	applied := syncComponentForResult(cfg, vault.PrepareResult{})
	if applied.State != agent.StateOK {
		t.Fatalf("applied state = %q, want ok", applied.State)
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
