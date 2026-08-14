package gno

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

// fixture is one activated machine, entirely inside temporary directories.
type fixture struct {
	stateDir  string
	vaultPath string
	unitDir   string
	cli       CLI
	installer supervise.Installer
	agentBin  string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	vaultPath := filepath.Join(root, "Daniel-OS")
	unitDir := filepath.Join(root, "units")
	for _, d := range []string{state, vaultPath, unitDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(vaultPath, "note.md"), []byte("# note\nzarquon\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	agentBin := filepath.Join(root, "homeplane-agent")
	if err := os.WriteFile(agentBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return fixture{
		stateDir:  state,
		vaultPath: vaultPath,
		unitDir:   unitDir,
		cli:       newTestCLI(t, state),
		installer: supervise.Installer{Platform: supervise.Launchd, Dir: unitDir},
		agentBin:  agentBin,
	}
}

func (f fixture) prepare(t *testing.T) PrepareResult {
	t.Helper()
	res, err := Prepare(context.Background(), PrepareOptions{
		StateDir:   f.stateDir,
		VaultPath:  f.vaultPath,
		Collection: "daniel-os",
		CLI:        f.cli,
		ProbeQuery: "zarquon",
	})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return res
}

func (f fixture) install(t *testing.T, prepared PrepareResult) (Config, Descriptor) {
	t.Helper()
	cfg, d, err := Install(InstallOptions{
		StateDir:    f.stateDir,
		Installer:   f.installer,
		AgentBinary: f.agentBin,
		Prepared:    prepared,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	return cfg, d
}

func TestPrepareBindsVerifiesAndProbes(t *testing.T) {
	f := newFixture(t)
	res := f.prepare(t)

	if res.IndexBytes == 0 {
		t.Fatal("prepare reported no index")
	}
	if !strings.HasPrefix(res.IndexDBPath, f.stateDir) {
		t.Fatalf("the index is not machine-local: %s", res.IndexDBPath)
	}
	if !res.Doctor.Healthy {
		t.Fatalf("prepare accepted an unhealthy engine: %+v", res.Doctor)
	}
	if !res.Probe.OK {
		t.Fatalf("the stdio probe did not pass: %+v", res.Probe)
	}
	if res.Probe.ToolCount == 0 || res.Probe.CalledTool != "gno_search" {
		t.Fatalf("the probe did not exercise a real tool call: %+v", res.Probe)
	}
	if res.Launch.Command == "" || res.Launch.DerivedFrom == "" {
		t.Fatalf("the launch template was not derived from upstream: %+v", res.Launch)
	}
}

// The precondition R4 names: no vault, no engine — and the refusal says so.
func TestPrepareRefusesWithoutAVault(t *testing.T) {
	f := newFixture(t)
	_, err := Prepare(context.Background(), PrepareOptions{StateDir: f.stateDir, CLI: f.cli})
	if !errors.Is(err, ErrNoVaultPath) {
		t.Fatalf("expected ErrNoVaultPath, got %v", err)
	}
}

// A `setup` that "succeeds" without producing an index where the contract says
// it must live means the engine is writing somewhere unasserted.
func TestPrepareRefusesWhenSetupProducesNoIndex(t *testing.T) {
	f := newFixture(t)
	// An empty vault makes the stub refuse verification, exactly as upstream
	// does when no document can be retrieved.
	empty := filepath.Join(t.TempDir(), "empty-vault")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Prepare(context.Background(), PrepareOptions{
		StateDir: f.stateDir, VaultPath: empty, CLI: f.cli,
	})
	if err == nil {
		t.Fatal("an unverifiable binding was accepted")
	}
	if !strings.Contains(err.Error(), "setup") {
		t.Fatalf("the refusal does not name the failing step: %v", err)
	}
}

func TestPrepareRefusesAFailingStdioEndpoint(t *testing.T) {
	f := newFixture(t)
	t.Setenv("FAKE_GNO_CALL_FAIL", "1")
	_, err := Prepare(context.Background(), PrepareOptions{
		StateDir: f.stateDir, VaultPath: f.vaultPath, CLI: f.cli, ProbeQuery: "zarquon",
	})
	if err == nil {
		t.Fatal("an endpoint that cannot answer a tool call was accepted")
	}
	if !strings.Contains(err.Error(), "stdio MCP endpoint") {
		t.Fatalf("the refusal does not name the endpoint: %v", err)
	}
}

func TestPrepareRefusesAnUnhealthyEngine(t *testing.T) {
	f := newFixture(t)
	t.Setenv("FAKE_GNO_DOCTOR_ERROR", "1")
	_, err := Prepare(context.Background(), PrepareOptions{
		StateDir: f.stateDir, VaultPath: f.vaultPath, CLI: f.cli,
	})
	if err == nil || !strings.Contains(err.Error(), "failing check") {
		t.Fatalf("an error-level health check did not stop activation: %v", err)
	}
}

func TestInstallWritesUnitDescriptorAndRemovalPlan(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, d := f.install(t, prepared)

	if cfg.Applied {
		t.Fatal("install must not load the unit")
	}
	if _, err := os.Stat(cfg.UnitPath); err != nil {
		t.Fatalf("no unit file: %v", err)
	}
	unit, err := os.ReadFile(cfg.UnitPath)
	if err != nil {
		t.Fatal(err)
	}
	// The unit runs the AGENT, not gno: that indirection is the only thing that
	// makes a crash loop visible to status.
	if !strings.Contains(string(unit), f.agentBin) {
		t.Fatalf("the unit does not run the agent:\n%s", unit)
	}
	for _, want := range []string{"gno", "run", "-state-dir"} {
		if !strings.Contains(string(unit), want) {
			t.Fatalf("the unit is missing %q:\n%s", want, unit)
		}
	}

	if d.Transport != TransportStdio || d.Component != ComponentRetrievalEngine {
		t.Fatalf("wrong descriptor shape: %+v", d)
	}
	if d.Supervision == nil || d.Supervision.Mode != "daemon" {
		t.Fatalf("the descriptor does not describe the supervised daemon: %+v", d.Supervision)
	}
	// The two lifecycles must stay separable: the harness transport is stdio and
	// the daemon's port is diagnostics, not the harness path.
	if strings.Contains(strings.ToLower(d.Transport), "http") {
		t.Fatalf("the harness transport must not be the daemon's HTTP gateway: %+v", d)
	}

	plan, err := LoadRemovalPlan(f.stateDir)
	if err != nil {
		t.Fatalf("no removal plan registered: %v", err)
	}
	if len(plan.Deactivate) == 0 {
		t.Fatal("the removal plan has no deactivation commands")
	}
	if plan.UnitPath != cfg.UnitPath {
		t.Fatalf("the plan points at %q, the unit is at %q", plan.UnitPath, cfg.UnitPath)
	}
	// The recorded vault path is canonicalized, so the plan is compared against
	// the config's copy rather than the fixture's pre-canonical one.
	if len(plan.Keep) == 0 || plan.Keep[0] != cfg.VaultPath {
		t.Fatalf("the plan does not protect the vault: %+v", plan.Keep)
	}
	if len(plan.HarnessCleanup) != 2 {
		t.Fatalf("the plan must undo both harnesses' MCP entries: %+v", plan.HarnessCleanup)
	}
}

func TestApplyRecordsOnlyWhenItActuallyRan(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	f.install(t, prepared)

	// No runner: report what WOULD run, change nothing.
	cfg, cmds, err := Apply(f.stateDir, f.installer, "501", nil)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if cfg.Applied {
		t.Fatal("apply claimed to have loaded the unit without a runner")
	}
	if len(cmds) == 0 {
		t.Fatal("apply reported no activation commands")
	}

	var ran []string
	installer := f.installer
	installer.Runner = func(name string, args ...string) error {
		ran = append(ran, name)
		return nil
	}
	cfg, _, err = Apply(f.stateDir, installer, "501", func() time.Time { return time.Unix(1700000000, 0) })
	if err != nil {
		t.Fatalf("apply with runner: %v", err)
	}
	if !cfg.Applied || cfg.AppliedAt.IsZero() {
		t.Fatalf("a real activation was not recorded: %+v", cfg)
	}
	if len(ran) == 0 {
		t.Fatal("no supervisor command was executed")
	}
}

// The supervised body must record its start AND its exit, because that ledger
// is the only crash-loop signal launchd and systemd give anyone.
func TestRunDaemonRecordsStartAndExit(t *testing.T) {
	state := t.TempDir()
	err := RunDaemon(context.Background(), RunOptions{
		StateDir: state,
		Run:      func(context.Context) error { return errors.New("daemon died") },
	})
	if err == nil {
		t.Fatal("the failure was swallowed")
	}
	ledger, lerr := (supervise.Tracker{Dir: state, Label: UnitLabel}).Load()
	if lerr != nil {
		t.Fatal(lerr)
	}
	if ledger.TotalStarts != 1 || ledger.TotalExits != 1 {
		t.Fatalf("the ledger did not record the lifecycle: %+v", ledger)
	}
	if exit, ok := ledger.LastExit(); !ok || exit.Code == 0 {
		t.Fatalf("a failed run was recorded as a clean exit: %+v", ledger.Exits)
	}
}

func TestCrashLoopBecomesVisibleInTheLedger(t *testing.T) {
	state := t.TempDir()
	tracker := supervise.Tracker{Dir: state, Label: UnitLabel}
	now := time.Now()
	for i := 0; i < 6; i++ {
		if _, err := tracker.RecordStart(now.Add(time.Duration(i)*time.Second), 1000+i, "restart"); err != nil {
			t.Fatal(err)
		}
		if _, err := tracker.RecordExit(now.Add(time.Duration(i)*time.Second+500*time.Millisecond), 1, "boom"); err != nil {
			t.Fatal(err)
		}
	}
	ledger, err := tracker.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !ledger.CrashLooping(now.Add(10*time.Second), supervise.DefaultCrashLoopWindow, supervise.DefaultCrashLoopThreshold) {
		t.Fatalf("six restarts in ten seconds was not flagged: %+v", ledger)
	}
}

// The disposable contract, exercised: delete the index, rebuild from the vault.
func TestRebuildSelfHealsADeletedIndex(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, _ := f.install(t, prepared)

	if !IndexExists(cfg.Paths, cfg.Index) {
		t.Fatal("no index after activation")
	}
	if err := os.Remove(cfg.IndexDBPath); err != nil {
		t.Fatalf("delete the index: %v", err)
	}
	if IndexExists(cfg.Paths, cfg.Index) {
		t.Fatal("the index was not actually deleted")
	}

	res, err := Rebuild(context.Background(), f.cli, cfg, RebuildOptions{StateDir: f.stateDir})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if !IndexExists(cfg.Paths, cfg.Index) {
		t.Fatal("the index did not come back")
	}
	if res.IndexBytes == 0 {
		t.Fatalf("the rebuilt index is empty: %+v", res)
	}
	// The vault is untouched: rebuilding is derived-state recovery, not a sync.
	if _, err := os.Stat(filepath.Join(f.vaultPath, "note.md")); err != nil {
		t.Fatalf("the rebuild disturbed the vault: %v", err)
	}
}

func TestRebuildRefusesAnIndexThatIsNoLongerMachineLocal(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, _ := f.install(t, prepared)
	// Simulate a config that has drifted to point inside the vault.
	cfg.Paths = Paths{
		Config: filepath.Join(f.vaultPath, ".gno", "config"),
		Data:   filepath.Join(f.vaultPath, ".gno", "data"),
		Cache:  filepath.Join(f.vaultPath, ".gno", "cache"),
	}
	if _, err := Rebuild(context.Background(), f.cli, cfg, RebuildOptions{StateDir: f.stateDir}); err == nil {
		t.Fatal("a rebuild into the vault was accepted")
	}
}
