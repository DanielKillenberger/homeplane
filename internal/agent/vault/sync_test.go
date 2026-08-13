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

func prepareOpts(t *testing.T, v string, cli CLI) PrepareOptions {
	t.Helper()
	return PrepareOptions{
		StateDir:  tempDir(t),
		VaultPath: v,
		CLI:       cli,
		Secrets:   testSecrets(),
		Now:       func() time.Time { return time.Unix(1, 0).UTC() },
	}
}

func fakeAgentBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(tempDir(t), "homeplane-agent")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// activate runs the three stages the way the CLI does, so the tests exercise
// the same sequence the command uses.
func activate(t *testing.T, opts PrepareOptions, installer supervise.Installer, apply bool) (PrepareResult, Config, []supervise.Command, error) {
	t.Helper()
	prepared, err := Prepare(context.Background(), opts)
	if err != nil {
		return prepared, Config{}, nil, err
	}
	cfg, err := Install(InstallOptions{
		StateDir:    opts.StateDir,
		Installer:   installer,
		AgentBinary: fakeAgentBinary(t),
		Prepared:    prepared,
		Now:         opts.Now,
	})
	if err != nil {
		return prepared, cfg, nil, err
	}
	if !apply {
		installer.Runner = nil
	}
	cfg, cmds, err := Apply(opts.StateDir, installer, "501", opts.Now)
	return prepared, cfg, cmds, err
}

func launchdInstaller(t *testing.T) supervise.Installer {
	t.Helper()
	return supervise.Installer{Platform: supervise.Launchd, Dir: filepath.Join(tempDir(t), "units")}
}

func TestPrepareRunsTheWholeSafetySequence(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "alpha\n", "b.md": "beta\n"})
	opts := prepareOpts(t, v, pinnedFakeCLI(t))
	t.Setenv("FAKE_OB_MODE", "add") // another machine's note arrives: benign

	prepared, cfg, cmds, err := activate(t, opts, launchdInstaller(t), false)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if !prepared.SmokePassed {
		t.Fatal("the disposable-vault smoke did not run")
	}
	if prepared.SnapshotPath == "" {
		t.Fatal("no snapshot was taken")
	}
	snap := filepath.Join(prepared.SnapshotPath, SnapshotTreeDirName, "a.md")
	if body, err := os.ReadFile(snap); err != nil || string(body) != "alpha\n" {
		t.Fatalf("snapshot missing or wrong (%v, %q)", err, body)
	}
	if len(prepared.Diff.Added) != 1 || prepared.Diff.Added[0] != "arrived.md" {
		t.Fatalf("diff = %+v, want one added file", prepared.Diff)
	}
	if cfg.UnitPath == "" {
		t.Fatal("no supervision unit was installed")
	}
	if _, err := os.Stat(cfg.UnitPath); err != nil {
		t.Fatalf("unit file missing: %v", err)
	}
	if cfg.Applied {
		t.Fatal("the unit was reported applied without a runner")
	}
	if len(cmds) == 0 {
		t.Fatal("no activation commands were reported")
	}
}

// The headline safety property: a sync pass that eats the vault must abort
// activation, leave the vault unsupervised, and point at the snapshot.
func TestPrepareRefusesADestructiveSyncPass(t *testing.T) {
	notes := manyNotes(40)
	v := makeVault(t, notes)
	opts := prepareOpts(t, v, pinnedFakeCLI(t))
	t.Setenv("FAKE_OB_MODE", "wipe")
	opts.SkipSmoke = true // the smoke guard has its own test

	installer := launchdInstaller(t)
	_, cfg, _, err := activate(t, opts, installer, false)
	var destructive *DestructiveDiffError
	if !errors.As(err, &destructive) {
		t.Fatalf("err = %v, want *DestructiveDiffError", err)
	}
	if len(destructive.Diff.Deleted) != len(notes) {
		t.Fatalf("recorded %d deletions, want %d", len(destructive.Diff.Deleted), len(notes))
	}
	if cfg.UnitPath != "" {
		t.Fatal("a supervision unit was installed despite a destructive diff")
	}
	entries, _ := os.ReadDir(installer.Dir)
	if len(entries) != 0 {
		t.Fatalf("unit directory is not empty: %v", entries)
	}
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
func TestPrepareRefusesWhenTheSmokeVaultIsDestroyed(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "alpha\n"})
	opts := prepareOpts(t, v, pinnedFakeCLI(t))
	t.Setenv("FAKE_OB_MODE", "wipe")

	prepared, err := Prepare(context.Background(), opts)
	if err == nil {
		t.Fatal("a destructive build passed the smoke")
	}
	if !strings.Contains(err.Error(), "smoke") {
		t.Fatalf("err = %v, want a smoke failure", err)
	}
	if prepared.SnapshotPath != "" {
		t.Fatal("the real vault was snapshotted after the smoke failed")
	}
	if body, err := os.ReadFile(filepath.Join(v, "a.md")); err != nil || string(body) != "alpha\n" {
		t.Fatalf("the real vault was touched during a failed smoke (%v, %q)", err, body)
	}
}

// The smoke is UNAUTHENTICATED-safe: the pinned build refusing to log in proves
// it ran and left the vault alone, which is what this stage is for. The
// authenticated round-trip is task .7's, with Daniel present.
func TestSmokeToleratesAnAuthFailureButNotDestruction(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "alpha\n"})
	opts := prepareOpts(t, v, pinnedFakeCLI(t))
	t.Setenv("FAKE_OB_FAIL", "error: unauthorized - please log in")

	// The smoke itself passes (build ran, vault intact) — the REAL pass then
	// surfaces the auth failure honestly.
	_, err := Prepare(context.Background(), opts)
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %v, want the real pass to report *AuthError", err)
	}
	if strings.Contains(err.Error(), "smoke") {
		t.Fatalf("the smoke treated an auth refusal as destruction: %v", err)
	}
}

func TestPrepareRefusesAPendingPin(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	bin, _ := writeFakeOB(t)
	opts := prepareOpts(t, v, CLI{Bin: bin, Pin: Pin{Version: "0.0.13", Checksum: PinPending}})

	res, err := Prepare(context.Background(), opts)
	if !errors.Is(err, ErrPinUnset) {
		t.Fatalf("err = %v, want ErrPinUnset", err)
	}
	if res.SnapshotPath != "" || res.SmokePassed {
		t.Fatal("the pin check did not run first")
	}
}

func TestPrepareRefusesAnUnpinnedBinary(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	bin, _ := writeFakeOB(t)
	opts := prepareOpts(t, v, CLI{Bin: bin, Pin: Pin{Version: "0.0.13", Checksum: strings.Repeat("cd", 32)}})
	if _, err := Prepare(context.Background(), opts); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("err = %v, want ErrPinMismatch", err)
	}
}

func TestPrepareRequiresAnAuthToken(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	opts := prepareOpts(t, v, pinnedFakeCLI(t))
	opts.Secrets = Secrets{}
	if _, err := Prepare(context.Background(), opts); !errors.Is(err, ErrNoAuthToken) {
		t.Fatalf("err = %v, want ErrNoAuthToken", err)
	}
}

func TestPrepareRefusesANonVault(t *testing.T) {
	opts := prepareOpts(t, tempDir(t), pinnedFakeCLI(t))
	if _, err := Prepare(context.Background(), opts); !errors.Is(err, ErrNotAVault) {
		t.Fatalf("err = %v, want ErrNotAVault", err)
	}
}

// A symlinked vault root used to snapshot NOTHING while the real CLI resolved
// the link and synced the target — the guard would then compare two empty
// manifests and wave a wipe through.
func TestSymlinkedVaultRootIsCanonicalized(t *testing.T) {
	real := makeVault(t, map[string]string{"a.md": "alpha\n", "b.md": "beta\n"})
	link := filepath.Join(tempDir(t), "vault-link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	// Detection through the link must record the REAL path.
	candidate, err := Detect(DetectOptions{ExplicitPath: link})
	if err != nil {
		t.Fatalf("Detect through a symlink: %v", err)
	}
	if candidate.Path != real {
		t.Fatalf("detected %q, want the canonical %q", candidate.Path, real)
	}

	// And a scan through the link must see the files, not an empty manifest.
	m, err := Scan(link)
	if err != nil {
		t.Fatalf("Scan through a symlink: %v", err)
	}
	if len(m.Files) != 3 { // two notes + .obsidian/app.json
		t.Fatalf("scan through a symlink found %d files, want 3: %v", len(m.Files), m.Paths())
	}

	// The full sequence, driven through the link, must snapshot real content.
	opts := prepareOpts(t, link, pinnedFakeCLI(t))
	prepared, err := Prepare(context.Background(), opts)
	if err != nil {
		t.Fatalf("Prepare through a symlink: %v", err)
	}
	if prepared.VaultPath != real {
		t.Fatalf("prepared vault path = %q, want %q", prepared.VaultPath, real)
	}
	if prepared.FileCount != 3 {
		t.Fatalf("snapshotted %d files through a symlink, want 3", prepared.FileCount)
	}
	snapshot := filepath.Join(prepared.SnapshotPath, SnapshotTreeDirName, "a.md")
	if body, err := os.ReadFile(snapshot); err != nil || string(body) != "alpha\n" {
		t.Fatalf("the snapshot through a symlink is empty or wrong (%v, %q)", err, body)
	}
}

// An auth failure during the real pass leaves the vault readable and does not
// supervise anything (R14).
func TestPrepareSurfacesAuthFailureWithoutSupervising(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "alpha\n"})
	opts := prepareOpts(t, v, pinnedFakeCLI(t))
	opts.SkipSmoke = true
	t.Setenv("FAKE_OB_FAIL", "error: unauthorized")

	installer := launchdInstaller(t)
	_, cfg, _, err := activate(t, opts, installer, false)
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %v, want *AuthError", err)
	}
	if cfg.UnitPath != "" {
		t.Fatal("sync was supervised despite an auth failure")
	}
	if body, _ := os.ReadFile(filepath.Join(v, "a.md")); string(body) != "alpha\n" {
		t.Fatal("the vault stopped being readable after an auth failure")
	}
}

// Custody: the installed unit must not contain any stored credential.
func TestInstalledUnitIsSecretFree(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	opts := prepareOpts(t, v, pinnedFakeCLI(t))
	if err := SaveAuthToken(opts.StateDir, "tok-supersecret"); err != nil {
		t.Fatal(err)
	}
	if err := SaveE2EPassword(opts.StateDir, "e2e-supersecret"); err != nil {
		t.Fatal(err)
	}
	opts.Secrets = Secrets{AuthToken: "tok-supersecret", E2EPassword: "e2e-supersecret"}

	_, cfg, _, err := activate(t, opts, launchdInstaller(t), false)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	raw, err := os.ReadFile(cfg.UnitPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"tok-supersecret", "e2e-supersecret"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the supervision unit contains %q", secret)
		}
	}
}

// The bug that made every supervised launch refuse: the unit omitted the
// resolved CLI path, so `vault sync run` had nothing to verify.
func TestInstalledUnitCarriesTheResolvedCLIPath(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	opts := prepareOpts(t, v, pinnedFakeCLI(t))

	prepared, cfg, _, err := activate(t, opts, launchdInstaller(t), false)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	unit, err := SyncUnit(fakeAgentBinary(t), opts.StateDir, prepared.VaultPath, prepared.OBPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Join(unit.Args, " ")
	if !strings.Contains(argv, "-ob "+opts.CLI.Bin) {
		t.Fatalf("unit argv omits the CLI path: %s", argv)
	}
	raw, err := os.ReadFile(cfg.UnitPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), opts.CLI.Bin) {
		t.Fatalf("the rendered unit omits the CLI path:\n%s", raw)
	}
	// And the same path is persisted, so a run without the flag still works.
	stored, err := LoadConfig(opts.StateDir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if stored.OBPath != opts.CLI.Bin {
		t.Fatalf("persisted ob path = %q, want %q", stored.OBPath, opts.CLI.Bin)
	}
	if stored.Applied {
		t.Fatal("an unapplied unit was persisted as applied")
	}
}

func TestSyncUnitRequiresBothPaths(t *testing.T) {
	stateDir := tempDir(t)
	if _, err := SyncUnit("", stateDir, "/v", "/ob"); err == nil {
		t.Fatal("a unit without an agent binary was accepted")
	}
	if _, err := SyncUnit("/bin/agent", stateDir, "/v", ""); err == nil {
		t.Fatal("a unit without the verified CLI path was accepted")
	}
	u, err := SyncUnit("/bin/agent", stateDir, "/v", "/ob")
	if err != nil {
		t.Fatalf("SyncUnit: %v", err)
	}
	if u.Label != SyncUnitLabel || !u.KeepAlive || u.ThrottleSeconds <= 0 {
		t.Fatalf("unit = %+v", u)
	}
}

// Apply is what turns an installed unit into a running one, and it is explicit.
func TestApplyRecordsTheLiveSessionChange(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	opts := prepareOpts(t, v, pinnedFakeCLI(t))
	installer := launchdInstaller(t)
	var ran []string
	installer.Runner = func(name string, args ...string) error {
		ran = append(ran, name)
		return nil
	}

	_, cfg, cmds, err := activate(t, opts, installer, true)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if len(ran) != 3 {
		t.Fatalf("ran %v, want the three launchd steps", ran)
	}
	if !cfg.Applied {
		t.Fatal("Applied was not recorded after a successful load")
	}
	stored, err := LoadConfig(opts.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Applied || stored.AppliedAt.IsZero() {
		t.Fatalf("persisted config = %+v", stored)
	}
	for _, c := range cmds {
		if !strings.HasPrefix(c.Name, "launchctl") {
			t.Fatalf("unexpected activation command for launchd: %s", c)
		}
	}
}

func TestApplyWithoutActivationIsNotActivated(t *testing.T) {
	if _, _, err := Apply(tempDir(t), launchdInstaller(t), "501", nil); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("err = %v, want ErrNotActivated", err)
	}
}

// A reinstall must not inherit a previous unit's crash history.
func TestInstallResetsTheRestartLedger(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	opts := prepareOpts(t, v, pinnedFakeCLI(t))
	tracker := supervise.Tracker{Dir: opts.StateDir, Label: SyncUnitLabel}
	for i := 0; i < 4; i++ {
		if _, err := tracker.RecordStart(time.Unix(int64(i), 0), i, "old"); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := activate(t, opts, launchdInstaller(t), false); err != nil {
		t.Fatalf("activate: %v", err)
	}
	ledger, err := tracker.Load()
	if err != nil {
		t.Fatal(err)
	}
	if ledger.TotalStarts != 0 {
		t.Fatalf("a reinstall inherited %d starts", ledger.TotalStarts)
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
	ledger, err := (supervise.Tracker{Dir: stateDir, Label: SyncUnitLabel}).Load()
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

// Kill → restart: six supervised launches in a minute read as a crash loop
// rather than as a healthy service.
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

func TestConfigRoundTrip(t *testing.T) {
	dir := tempDir(t)
	if _, err := LoadConfig(dir); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("err = %v, want ErrNotActivated", err)
	}
	want := Config{VaultPath: "/v", OBPath: "/ob", UnitLabel: SyncUnitLabel, Applied: true}
	if err := SaveConfig(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.VaultPath != want.VaultPath || got.OBPath != want.OBPath || !got.Applied {
		t.Fatalf("config = %+v", got)
	}
	info, err := os.Stat(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config mode = %o, want 0600", perm)
	}
}
