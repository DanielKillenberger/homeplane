package vault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
)

func activateOpts(t *testing.T, v string, cli CLI) ActivateOptions {
	t.Helper()
	stateDir := tempDir(t)
	unitDir := filepath.Join(tempDir(t), "units")
	agentBin := filepath.Join(tempDir(t), "homeplane-agent")
	if err := os.WriteFile(agentBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return ActivateOptions{
		StateDir:    stateDir,
		VaultPath:   v,
		CLI:         cli,
		Credential:  "sync-password",
		Installer:   supervise.Installer{Platform: supervise.Launchd, Dir: unitDir},
		AgentBinary: agentBin,
		UID:         "501",
		Now:         func() time.Time { return time.Unix(1, 0).UTC() },
	}
}

func TestActivateRunsTheWholeSafetySequence(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "alpha\n", "b.md": "beta\n"})
	opts := activateOpts(t, v, pinnedFakeCLI(t))
	t.Setenv("FAKE_OB_MODE", "add") // another machine's note arrives: benign

	res, err := Activate(context.Background(), opts)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if !res.SmokePassed {
		t.Fatal("the disposable-vault smoke did not run")
	}
	if res.SnapshotPath == "" {
		t.Fatal("no snapshot was taken")
	}
	// The snapshot must contain the pre-sync vault, which is what makes the
	// guard's refusal recoverable.
	snap := filepath.Join(res.SnapshotPath, SnapshotTreeDirName, "a.md")
	if body, err := os.ReadFile(snap); err != nil || string(body) != "alpha\n" {
		t.Fatalf("snapshot missing or wrong (%v, %q)", err, body)
	}
	if len(res.Diff.Added) != 1 || res.Diff.Added[0] != "arrived.md" {
		t.Fatalf("diff = %+v, want one added file", res.Diff)
	}
	if res.UnitPath == "" {
		t.Fatal("no supervision unit was installed")
	}
	if _, err := os.Stat(res.UnitPath); err != nil {
		t.Fatalf("unit file missing: %v", err)
	}
	if len(res.Commands) == 0 {
		t.Fatal("no activation commands were reported")
	}
}

// The headline safety property: a sync pass that eats the vault must abort
// activation, leave the vault unsupervised, and point at the snapshot.
func TestActivateRefusesADestructiveSyncPass(t *testing.T) {
	notes := manyNotes(40)
	v := makeVault(t, notes)
	opts := activateOpts(t, v, pinnedFakeCLI(t))
	t.Setenv("FAKE_OB_MODE", "wipe")
	// The smoke vault would be wiped too, so smoke it separately: this test is
	// about the REAL-vault guard, and the smoke guard has its own test.
	opts.SkipSmoke = true

	res, err := Activate(context.Background(), opts)
	var destructive *DestructiveDiffError
	if !errors.As(err, &destructive) {
		t.Fatalf("err = %v, want *DestructiveDiffError", err)
	}
	if len(destructive.Diff.Deleted) != len(notes) {
		t.Fatalf("recorded %d deletions, want %d", len(destructive.Diff.Deleted), len(notes))
	}
	if res.UnitPath != "" {
		t.Fatal("a supervision unit was installed despite a destructive diff")
	}
	entries, _ := os.ReadDir(opts.Installer.Dir)
	if len(entries) != 0 {
		t.Fatalf("unit directory is not empty: %v", entries)
	}
	// The snapshot is the undo, and it must still hold the deleted notes.
	restored := filepath.Join(destructive.SnapshotPath, SnapshotTreeDirName)
	m, err := Scan(restored)
	if err != nil {
		t.Fatalf("scan snapshot: %v", err)
	}
	if len(m.Files) != len(notes)+1 { // notes + .obsidian/app.json
		t.Fatalf("snapshot holds %d files, want %d", len(m.Files), len(notes)+1)
	}
}

// A build that eats a DISPOSABLE vault never gets pointed at the real one.
func TestActivateRefusesWhenTheSmokeVaultIsDestroyed(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "alpha\n"})
	opts := activateOpts(t, v, pinnedFakeCLI(t))
	t.Setenv("FAKE_OB_MODE", "wipe")

	res, err := Activate(context.Background(), opts)
	if err == nil {
		t.Fatal("a destructive build passed the smoke")
	}
	if !strings.Contains(err.Error(), "smoke") {
		t.Fatalf("err = %v, want a smoke failure", err)
	}
	if res.SnapshotPath != "" {
		t.Fatal("the real vault was snapshotted after the smoke failed — it should not have been reached")
	}
	// The real vault must be untouched.
	if body, err := os.ReadFile(filepath.Join(v, "a.md")); err != nil || string(body) != "alpha\n" {
		t.Fatalf("the real vault was touched during a failed smoke (%v, %q)", err, body)
	}
}

func TestActivateRefusesAPendingPin(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	bin, _ := writeFakeOB(t)
	opts := activateOpts(t, v, CLI{Bin: bin, Pin: Pin{Version: "0.0.13", Checksum: PinPending}})

	res, err := Activate(context.Background(), opts)
	if !errors.Is(err, ErrPinUnset) {
		t.Fatalf("err = %v, want ErrPinUnset", err)
	}
	if res.SnapshotPath != "" || res.SmokePassed {
		t.Fatal("the pin check did not run first")
	}
}

func TestActivateRefusesAnUnpinnedBinary(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	bin, _ := writeFakeOB(t)
	opts := activateOpts(t, v, CLI{Bin: bin, Pin: Pin{Version: "0.0.13", Checksum: strings.Repeat("cd", 32)}})
	if _, err := Activate(context.Background(), opts); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("err = %v, want ErrPinMismatch", err)
	}
}

func TestActivateRequiresACredential(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	opts := activateOpts(t, v, pinnedFakeCLI(t))
	opts.Credential = ""
	if _, err := Activate(context.Background(), opts); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("err = %v, want ErrNoCredential", err)
	}
}

func TestActivateRefusesANonVault(t *testing.T) {
	opts := activateOpts(t, tempDir(t), pinnedFakeCLI(t))
	if _, err := Activate(context.Background(), opts); !errors.Is(err, ErrNotAVault) {
		t.Fatalf("err = %v, want ErrNotAVault", err)
	}
}

// An auth failure during the real pass leaves the vault readable and does not
// supervise anything (R14).
func TestActivateSurfacesAuthFailureWithoutSupervising(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "alpha\n"})
	opts := activateOpts(t, v, pinnedFakeCLI(t))
	opts.SkipSmoke = true
	t.Setenv("FAKE_OB_FAIL", "error: unauthorized")

	res, err := Activate(context.Background(), opts)
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %v, want *AuthError", err)
	}
	if res.UnitPath != "" {
		t.Fatal("sync was supervised despite an auth failure")
	}
	if body, _ := os.ReadFile(filepath.Join(v, "a.md")); string(body) != "alpha\n" {
		t.Fatal("the vault stopped being readable after an auth failure")
	}
}

// Custody: the installed unit must not contain the credential anywhere.
func TestActivateInstallsASecretFreeUnit(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	opts := activateOpts(t, v, pinnedFakeCLI(t))
	opts.Credential = "very-secret-password"

	res, err := Activate(context.Background(), opts)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	raw, err := os.ReadFile(res.UnitPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), opts.Credential) {
		t.Fatal("the supervision unit contains the sync credential")
	}
	if !strings.Contains(string(raw), "vault") || !strings.Contains(string(raw), "sync") {
		t.Fatalf("the unit does not run the agent's sync subcommand:\n%s", raw)
	}
}

// Without a runner, activation must not touch the live launchd/systemd session.
func TestActivateDoesNotMutateTheSessionWithoutARunner(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	opts := activateOpts(t, v, pinnedFakeCLI(t))
	res, err := Activate(context.Background(), opts)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if len(res.Commands) == 0 {
		t.Fatal("the commands that WOULD be run were not reported")
	}
	for _, c := range res.Commands {
		if !strings.HasPrefix(c.Name, "launchctl") {
			t.Fatalf("unexpected activation command for launchd: %s", c)
		}
	}
}

func TestActivateRunsTheRunnerWhenGiven(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	opts := activateOpts(t, v, pinnedFakeCLI(t))
	var ran []string
	opts.Installer.Runner = func(name string, args ...string) error {
		ran = append(ran, name)
		return nil
	}
	if _, err := Activate(context.Background(), opts); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if len(ran) != 3 {
		t.Fatalf("ran %v, want the three launchd steps", ran)
	}
}

// R14's index contract, enforced where the sync that would propagate it lives.
func TestEnsureOutsideVault(t *testing.T) {
	v := makeVault(t, nil)
	if err := EnsureOutsideVault(filepath.Join(v, ".gno-index"), v); !errors.Is(err, ErrIndexInsideVault) {
		t.Fatalf("err = %v, want ErrIndexInsideVault", err)
	}
	if err := EnsureOutsideVault(filepath.Join(v, "notes", "deep", "index.db"), v); !errors.Is(err, ErrIndexInsideVault) {
		t.Fatalf("nested index accepted: %v", err)
	}
	if err := EnsureOutsideVault(filepath.Join(tempDir(t), "index"), v); err != nil {
		t.Fatalf("an outside path was refused: %v", err)
	}
	if err := EnsureOutsideVault("", v); err == nil {
		t.Fatal("an empty path was accepted")
	}
}

func TestSyncUnitShape(t *testing.T) {
	stateDir := tempDir(t)
	u, err := SyncUnit("/opt/homeplane/bin/homeplane-agent", stateDir, "/vaults/Daniel-OS")
	if err != nil {
		t.Fatalf("SyncUnit: %v", err)
	}
	if u.Label != SyncUnitLabel || !u.KeepAlive || u.ThrottleSeconds <= 0 {
		t.Fatalf("unit = %+v", u)
	}
	if strings.Join(u.Args, " ") != "vault sync run -state-dir "+stateDir {
		t.Fatalf("args = %v", u.Args)
	}
	if _, err := SyncUnit("", stateDir, "/v"); err == nil {
		t.Fatal("a unit without an agent binary was accepted")
	}
}

// The supervised body records its own starts, which is what makes a restart
// visible to `status` without parsing launchd or journald.
func TestRunSyncRecordsStartAndExit(t *testing.T) {
	stateDir := tempDir(t)
	now := time.Unix(1000, 0).UTC()

	err := RunSync(context.Background(), RunOptions{
		StateDir: stateDir,
		Now:      func() time.Time { return now },
		Run:      func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatalf("RunSync: %v", err)
	}

	tracker := supervise.Tracker{Dir: stateDir, Label: SyncUnitLabel}
	ledger, err := tracker.Load()
	if err != nil {
		t.Fatal(err)
	}
	if ledger.TotalStarts != 1 || ledger.TotalExits != 1 {
		t.Fatalf("ledger = %+v, want one start and one exit", ledger)
	}
	if exit, ok := ledger.LastExit(); !ok || exit.Code != 0 {
		t.Fatalf("exit = %+v, want code 0", exit)
	}
}

func TestRunSyncRecordsAFailedExit(t *testing.T) {
	stateDir := tempDir(t)
	want := errors.New("sync died")
	err := RunSync(context.Background(), RunOptions{
		StateDir: stateDir,
		Run:      func(context.Context) error { return want },
	})
	if !errors.Is(err, want) {
		t.Fatalf("RunSync = %v, want the underlying error", err)
	}
	ledger, err := (supervise.Tracker{Dir: stateDir, Label: SyncUnitLabel}).Load()
	if err != nil {
		t.Fatal(err)
	}
	exit, ok := ledger.LastExit()
	if !ok || exit.Code == 0 {
		t.Fatalf("exit = %+v, want a non-zero code", exit)
	}
}

// Kill → restart: three supervised launches leave three recorded starts, and a
// burst of them reads as a crash-loop rather than as a healthy service.
func TestRepeatedRestartsSurfaceAsACrashLoop(t *testing.T) {
	stateDir := tempDir(t)
	base := time.Unix(2000, 0).UTC()
	for i := 0; i < 6; i++ {
		at := base.Add(time.Duration(i) * 10 * time.Second)
		err := RunSync(context.Background(), RunOptions{
			StateDir: stateDir,
			Now:      func() time.Time { return at },
			Run:      func(context.Context) error { return errors.New("killed") },
		})
		if err == nil {
			t.Fatal("expected the supervised body to fail")
		}
	}
	ledger, err := (supervise.Tracker{Dir: stateDir, Label: SyncUnitLabel}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if ledger.TotalStarts != 6 {
		t.Fatalf("starts = %d, want 6", ledger.TotalStarts)
	}
	now := base.Add(time.Minute)
	if !ledger.CrashLooping(now, supervise.DefaultCrashLoopWindow, supervise.DefaultCrashLoopThreshold) {
		t.Fatal("six restarts in a minute did not read as a crash loop")
	}
	if !strings.Contains(ledger.Summary(now), "CRASH-LOOPING") {
		t.Fatalf("summary hides the crash loop: %s", ledger.Summary(now))
	}
}
