package gno

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
)

// Regression tests for the implementation review of task .11.
//
// Each one pins a specific way the component used to claim success while being
// broken. They are grouped here rather than scattered so the failure modes stay
// legible as a set: every one of them is "the transport worked, therefore the
// capability works", which is the single mistake this component is most prone to.

// ── 1. MCP application errors are not successes ──────────────────────────────

// mcpStub writes a stdio server that answers the handshake and then returns
// whatever tool result the test asks for.
func mcpStub(t *testing.T, toolResult string) string {
	t.Helper()
	script := `#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"gno","version":"1.29.6"}},"jsonrpc":"2.0","id":1}\n' ;;
    *'"method":"tools/list"'*)
      printf '{"result":{"tools":[{"name":"gno_search"}]},"jsonrpc":"2.0","id":2}\n' ;;
    *'"method":"tools/call"'*)
      printf '%s\n' '` + toolResult + `' ;;
  esac
done
`
	path := filepath.Join(t.TempDir(), "stub-mcp")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	return path
}

func TestProbeRejectsAnMCPErrorResult(t *testing.T) {
	// A JSON-RPC success carrying an application error. The transport worked
	// perfectly; the retrieval did not.
	bin := mcpStub(t, `{"result":{"isError":true,"content":[{"type":"text","text":"index unavailable: gno://c/note.md"}]},"jsonrpc":"2.0","id":3}`)

	probe := ProbeMCP(context.Background(), MCPProbeOptions{
		Command:  bin,
		CallTool: "gno_search",
		CallArgs: map[string]any{"query": "anything"},
		// Deliberately present in the error text: matching content alone must not
		// rescue a result that upstream flagged as an error.
		Expect:  "gno://c/note.md",
		Timeout: 20 * time.Second,
	})
	if probe.OK {
		t.Fatalf("an isError result passed the probe: %+v", probe)
	}
	if !strings.Contains(probe.Detail, "MCP error result") {
		t.Fatalf("the detail does not name the in-band error: %q", probe.Detail)
	}
}

func TestProbeRejectsAnEmptyResult(t *testing.T) {
	bin := mcpStub(t, `{"result":{"content":[]},"jsonrpc":"2.0","id":3}`)

	probe := ProbeMCP(context.Background(), MCPProbeOptions{
		Command: bin, CallTool: "gno_search",
		CallArgs: map[string]any{"query": "anything"},
		Expect:   "gno://c/note.md", Timeout: 20 * time.Second,
	})
	if probe.OK {
		t.Fatalf("an empty result passed the probe: %+v", probe)
	}
}

// An endpoint that answers from SOMEBODY ELSE'S index is the subtlest failure:
// everything about the call succeeds and the content is real.
func TestProbeRejectsContentFromAnotherIndex(t *testing.T) {
	bin := mcpStub(t, `{"result":{"content":[{"type":"text","text":"Found 1 results [#zz] gno://other/elsewhere.md"}]},"jsonrpc":"2.0","id":3}`)

	probe := ProbeMCP(context.Background(), MCPProbeOptions{
		Command: bin, CallTool: "gno_search",
		CallArgs: map[string]any{"query": "anything"},
		Expect:   "gno://c/note.md", Timeout: 20 * time.Second,
	})
	if probe.OK {
		t.Fatalf("a response from a different index passed: %+v", probe)
	}
	if !strings.Contains(probe.Detail, "not from this index") {
		t.Fatalf("the detail does not explain the mismatch: %q", probe.Detail)
	}
}

// Asking a tool for a verdict with nothing to check against is itself a bug.
func TestProbeRefusesToCallAToolWithoutExpectedEvidence(t *testing.T) {
	bin := mcpStub(t, `{"result":{"content":[{"type":"text","text":"anything at all"}]},"jsonrpc":"2.0","id":3}`)

	probe := ProbeMCP(context.Background(), MCPProbeOptions{
		Command: bin, CallTool: "gno_search",
		CallArgs: map[string]any{"query": "x"}, Timeout: 20 * time.Second,
	})
	if probe.OK {
		t.Fatalf("a tool call with nothing to verify passed: %+v", probe)
	}
}

// Structured content counts as evidence: GNO puts the document URIs there.
func TestProbeAcceptsEvidenceFromStructuredContent(t *testing.T) {
	bin := mcpStub(t, `{"result":{"content":[{"type":"text","text":"Found 1 results"}],"structuredContent":{"results":[{"uri":"gno://c/note.md"}]}},"jsonrpc":"2.0","id":3}`)

	probe := ProbeMCP(context.Background(), MCPProbeOptions{
		Command: bin, CallTool: "gno_search",
		CallArgs: map[string]any{"query": "x"},
		Expect:   "gno://c/note.md", Timeout: 20 * time.Second,
	})
	if !probe.OK {
		t.Fatalf("structured evidence was not accepted: %+v", probe)
	}
}

// Prepare must hold the endpoint to a document the index actually returned,
// rather than to whatever the caller happened to type.
func TestPrepareVerifiesTheEndpointAgainstTheIndexsOwnAnswer(t *testing.T) {
	f := newFixture(t)
	res := f.prepare(t)
	if res.ProbeExpect == "" {
		t.Fatal("prepare recorded no evidence for the endpoint probe")
	}
	if !strings.HasPrefix(res.ProbeExpect, "gno://") {
		t.Fatalf("the evidence is not a document URI: %q", res.ProbeExpect)
	}
	if res.ProbeQuery == "" {
		t.Fatal("prepare recorded no probe query")
	}
}

// If the index answers nothing at all, there is no correct answer to hold the
// endpoint to — and activation must say so rather than proceed.
func TestPrepareRefusesWhenTheIndexAnswersNothing(t *testing.T) {
	f := newFixture(t)
	t.Setenv("FAKE_GNO_NO_RESULTS", "1")
	_, err := Prepare(context.Background(), PrepareOptions{
		StateDir: f.stateDir, VaultPath: f.vaultPath, CLI: f.cli,
	})
	if !errors.Is(err, ErrNoGroundTruth) {
		t.Fatalf("expected ErrNoGroundTruth, got %v", err)
	}
}

// ── 2. The activation probe survives `apply` ─────────────────────────────────

func TestApplyPreservesTheRecordedEndpointProbe(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, _ := f.install(t, prepared)

	if !cfg.Activation.Probe.OK {
		t.Fatalf("install did not persist the endpoint probe: %+v", cfg.Activation)
	}
	before := cfg.Activation.Probe.At

	installer := f.installer
	installer.Runner = func(string, ...string) error { return nil }
	if _, _, err := Apply(f.stateDir, installer, "501", nil); err != nil {
		t.Fatalf("apply: %v", err)
	}

	after, err := LoadConfig(f.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Activation.Probe.OK || !after.Activation.Probe.At.Equal(before) {
		t.Fatalf("apply erased the activation probe: %+v", after.Activation.Probe)
	}
	if after.Activation.Launch.Command == "" {
		t.Fatalf("apply erased the derived launch template: %+v", after.Activation.Launch)
	}
	if strings.Contains(after.Activation.Probe.Summary(), "never probed") {
		t.Fatalf("the probe summary regressed to 'never probed': %q", after.Activation.Probe.Summary())
	}
}

// ── 2b. Every harness launch is recorded ─────────────────────────────────────

func TestStdioWrapperRecordsASuccessfulLaunch(t *testing.T) {
	state := t.TempDir()
	if err := RunStdioEndpoint(context.Background(), StdioOptions{
		StateDir: state,
		Command:  "/bin/sh",
		Args:     []string{"-c", "exit 0"},
	}); err != nil {
		t.Fatalf("wrapper: %v", err)
	}
	ledger, err := LoadLaunchLedger(state)
	if err != nil {
		t.Fatal(err)
	}
	if ledger.TotalLaunches != 1 || ledger.TotalFailures != 0 {
		t.Fatalf("the launch was not recorded: %+v", ledger)
	}
	if strings.Contains(ledger.Summary(), "pid") {
		t.Fatalf("the summary claims a live process: %q", ledger.Summary())
	}
}

func TestStdioWrapperRecordsAFailedLaunch(t *testing.T) {
	state := t.TempDir()
	err := RunStdioEndpoint(context.Background(), StdioOptions{
		StateDir: state,
		Command:  "/bin/sh",
		Args:     []string{"-c", "echo 'bun: command not found' >&2; exit 127"},
	})
	if err == nil {
		t.Fatal("a failing launch was reported as success")
	}
	ledger, err2 := LoadLaunchLedger(state)
	if err2 != nil {
		t.Fatal(err2)
	}
	last, ok := ledger.LastLaunch()
	if !ok || last.OK || last.ExitCode != 127 {
		t.Fatalf("the failure was not recorded truthfully: %+v", ledger)
	}
	if ledger.ConsecutiveFailures() != 1 {
		t.Fatalf("consecutive failures = %d", ledger.ConsecutiveFailures())
	}
	if !strings.Contains(ledger.Summary(), "FAILED") {
		t.Fatalf("the summary hides the failure: %q", ledger.Summary())
	}
}

// A machine that was never activated still has to fail informatively rather than
// launching nothing and reporting success.
func TestStdioWrapperRecordsAMissingTemplate(t *testing.T) {
	state := t.TempDir()
	if err := RunStdioEndpoint(context.Background(), StdioOptions{StateDir: state}); err == nil {
		t.Fatal("the wrapper accepted an empty launch template")
	}
	ledger, err := LoadLaunchLedger(state)
	if err != nil {
		t.Fatal(err)
	}
	if ledger.TotalFailures != 1 {
		t.Fatalf("the missing template was not recorded: %+v", ledger)
	}
}

func TestDescriptorPublishesTheWrapperAndTheUnderlyingTemplate(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	_, d := f.install(t, prepared)

	if d.Command != f.agentBin {
		t.Fatalf("harnesses were pointed at %q, not the agent", d.Command)
	}
	if len(d.Args) < 2 || d.Args[0] != "gno" || d.Args[1] != "mcp" {
		t.Fatalf("the wrapper argv is wrong: %v", d.Args)
	}
	if d.Underlying == nil || d.Underlying.Command != prepared.Launch.Command {
		t.Fatalf("the underlying engine template was not published: %+v", d.Underlying)
	}
	if d.Underlying.Args[len(d.Underlying.Args)-1] != "mcp" {
		t.Fatalf("the underlying template is not the stdio server: %v", d.Underlying.Args)
	}
}

// ── 5. The gateway is loopback-only ──────────────────────────────────────────

func TestValidateGatewayRefusesAnythingReachableFromOutside(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "::", "192.168.1.10", "10.0.0.5", "localhost", "example.com", ""} {
		if err := ValidateGateway(host, 3077); !errors.Is(err, ErrGatewayNotLoopback) {
			t.Fatalf("%q was accepted as loopback: %v", host, err)
		}
	}
	for _, host := range []string{"127.0.0.1", "127.0.0.53", "::1"} {
		if err := ValidateGateway(host, 3077); err != nil {
			t.Fatalf("%q was refused: %v", host, err)
		}
	}
	for _, port := range []int{0, -1, 65536, 99999} {
		if err := ValidateGateway("127.0.0.1", port); !errors.Is(err, ErrGatewayPort) {
			t.Fatalf("port %d was accepted: %v", port, err)
		}
	}
}

func TestDaemonUnitRefusesANonLoopbackGateway(t *testing.T) {
	state := t.TempDir()
	if _, err := DaemonUnit("/usr/local/bin/homeplane-agent", state, "0.0.0.0", 3077, ""); !errors.Is(err, ErrGatewayNotLoopback) {
		t.Fatalf("a unit binding 0.0.0.0 was written: %v", err)
	}
}

func TestInstallRefusesANonLoopbackGateway(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	_, _, err := Install(InstallOptions{
		StateDir: f.stateDir, Installer: f.installer, AgentBinary: f.agentBin,
		Prepared: prepared, DaemonHost: "0.0.0.0",
	})
	if !errors.Is(err, ErrGatewayNotLoopback) {
		t.Fatalf("install accepted a world-reachable gateway: %v", err)
	}
	if _, err := LoadDescriptor(f.stateDir); err == nil {
		t.Fatal("a descriptor was published for a refused install")
	}
}

func TestTheDaemonGatewayIsTokenProtected(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, _ := f.install(t, prepared)

	if cfg.GatewayToken == "" {
		t.Fatal("no gateway token was provisioned")
	}
	info, err := os.Stat(cfg.GatewayToken)
	if err != nil {
		t.Fatalf("the token file was not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the gateway token is %v, want 0600", perm)
	}
	raw, err := os.ReadFile(cfg.GatewayToken)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(raw))
	if len(token) < 32 {
		t.Fatalf("the gateway token is too short to be useful: %q", token)
	}

	// The unit must carry the PATH, never the token: unit files are 0644.
	unit, err := os.ReadFile(cfg.UnitPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unit), token) {
		t.Fatal("the gateway token itself was written into the world-readable unit file")
	}
	if !strings.Contains(string(unit), cfg.GatewayToken) {
		t.Fatalf("the unit does not pass the token file:\n%s", unit)
	}
	args := DaemonArgs("127.0.0.1", 3077, cfg.GatewayToken)
	if !containsArg(args, "--mcp-token-file") {
		t.Fatalf("the daemon runs its gateway unauthenticated: %v", args)
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// ── 6. A failed install leaves nothing behind ────────────────────────────────

func TestAFailedInstallPublishesNoDescriptor(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)

	// Make the removal-plan write fail by putting a FILE where its directory
	// must go. The unit and config are written before it, so this exercises the
	// rollback of everything already on disk.
	if err := os.WriteFile(RemovalDir(f.stateDir), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := Install(InstallOptions{
		StateDir: f.stateDir, Installer: f.installer, AgentBinary: f.agentBin, Prepared: prepared,
	})
	if err == nil {
		t.Fatal("install succeeded despite an unwritable removal plan")
	}

	// The descriptor is the file task .6 consumes: it must not exist for an
	// activation that failed.
	if _, err := LoadDescriptor(f.stateDir); !errors.Is(err, ErrNoDescriptor) {
		t.Fatalf("a descriptor was published for a failed install: %v", err)
	}
	if _, err := LoadConfig(f.stateDir); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("a config survived a failed install: %v", err)
	}
	unitPath := filepath.Join(f.unitDir, UnitLabel+".plist")
	if _, err := os.Stat(unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the supervision unit survived a failed install: %v", err)
	}
}

func TestInstallRefusesAnUnprovenEndpoint(t *testing.T) {
	f := newFixture(t)
	prepared, err := Prepare(context.Background(), PrepareOptions{
		StateDir: f.stateDir, VaultPath: f.vaultPath, CLI: f.cli, SkipMCPProbe: true,
	})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, _, err := Install(InstallOptions{
		StateDir: f.stateDir, Installer: f.installer, AgentBinary: f.agentBin, Prepared: prepared,
	}); err == nil {
		t.Fatal("an endpoint that was never probed was published")
	}
	if _, err := LoadDescriptor(f.stateDir); err == nil {
		t.Fatal("a descriptor was published for an unproven endpoint")
	}
}

// ── 4. Rebuild does not race the daemon ──────────────────────────────────────

func TestRebuildRefusesWhileTheEngineIsRunning(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, _ := f.install(t, prepared)

	// Stage a ledger that says the daemon is up, and a probe that agrees.
	tracker := supervise.Tracker{Dir: f.stateDir, Label: UnitLabel}
	if _, err := tracker.RecordStart(time.Now(), os.Getpid(), "supervised start"); err != nil {
		t.Fatal(err)
	}
	alive := func(supervise.Ledger) supervise.Liveness {
		return supervise.Liveness{Known: true, Alive: true, Detail: "pid is alive"}
	}

	_, err := Rebuild(context.Background(), f.cli, cfg, RebuildOptions{StateDir: f.stateDir, Probe: alive})
	if !errors.Is(err, ErrEngineRunning) {
		t.Fatalf("rebuild raced the running daemon: %v", err)
	}
	// And it changed nothing: refusing has to be genuinely inert.
	if !IndexExists(cfg.Paths, cfg.Index) {
		t.Fatal("the refused rebuild deleted the index anyway")
	}
}

// An unobservable daemon is treated as running: the cost of a needless refusal
// is a message, the cost of a wrong "it is not running" is a corrupt index.
func TestRebuildRefusesWhenLivenessIsUnknown(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, _ := f.install(t, prepared)
	tracker := supervise.Tracker{Dir: f.stateDir, Label: UnitLabel}
	if _, err := tracker.RecordStart(time.Now(), 999999, "supervised start"); err != nil {
		t.Fatal(err)
	}

	_, err := Rebuild(context.Background(), f.cli, cfg, RebuildOptions{
		StateDir: f.stateDir,
		Probe: func(supervise.Ledger) supervise.Liveness {
			return supervise.Liveness{Known: false, Detail: "pid is not ours (reused?)"}
		},
	})
	if !errors.Is(err, ErrEngineRunning) {
		t.Fatalf("an unobservable daemon was assumed dead: %v", err)
	}
}

func TestRebuildStopsAndResumesTheEngine(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, _ := f.install(t, prepared)

	var stopped, resumed bool
	res, err := Rebuild(context.Background(), f.cli, cfg, RebuildOptions{
		StateDir: f.stateDir,
		Quiesce: func(context.Context) (func() error, error) {
			stopped = true
			return func() error { resumed = true; return nil }, nil
		},
	})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if !stopped || !resumed {
		t.Fatalf("the engine was not stopped and resumed (stopped=%v resumed=%v)", stopped, resumed)
	}
	if res.IndexBytes == 0 {
		t.Fatalf("the rebuilt index is empty: %+v", res)
	}
}

// A failed rebuild must still bring the engine back: a recoverable problem must
// not become an outage.
func TestRebuildResumesTheEngineEvenWhenItFails(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, _ := f.install(t, prepared)
	t.Setenv("FAKE_GNO_SETUP_FAIL", "1")

	var resumed bool
	if _, err := Rebuild(context.Background(), f.cli, cfg, RebuildOptions{
		StateDir: f.stateDir,
		Quiesce: func(context.Context) (func() error, error) {
			return func() error { resumed = true; return nil }, nil
		},
	}); err == nil {
		t.Fatal("a failing rebuild reported success")
	}
	if !resumed {
		t.Fatal("a failed rebuild left the engine stopped")
	}
}

func TestConcurrentRebuildsAreRefused(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, _ := f.install(t, prepared)

	// Hold the lock the way a rebuild in another process would.
	lock := filepath.Join(f.stateDir, "gno.rebuild.lock")
	if err := os.WriteFile(lock, []byte("pid 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Rebuild(context.Background(), f.cli, cfg, RebuildOptions{
		StateDir: f.stateDir,
		Quiesce:  func(context.Context) (func() error, error) { return nil, nil },
	})
	if !errors.Is(err, ErrRebuildInProgress) {
		t.Fatalf("two rebuilds ran at once: %v", err)
	}
}

// ── 7. RunDaemon distinguishes a stop from a crash ───────────────────────────

func TestRunDaemonRecordsACancellationAsACleanExit(t *testing.T) {
	state := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := RunDaemon(ctx, RunOptions{
		StateDir: state,
		Run:      func(ctx context.Context) error { return ctx.Err() },
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected the cancellation to propagate, got %v", err)
	}
	ledger, lerr := (supervise.Tracker{Dir: state, Label: UnitLabel}).Load()
	if lerr != nil {
		t.Fatal(lerr)
	}
	exit, ok := ledger.LastExit()
	if !ok {
		t.Fatal("no exit was recorded")
	}
	if exit.Code != 0 {
		t.Fatalf("a deliberate stop was recorded as a failure: %+v", exit)
	}
	if !strings.Contains(exit.Detail, "stopped on request") {
		t.Fatalf("the exit detail does not say it was asked to stop: %q", exit.Detail)
	}
}

// The persisted config must round-trip the activation record, since every later
// command reads its endpoint evidence from there.
func TestActivationRecordRoundTrips(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, _ := f.install(t, prepared)

	raw, err := os.ReadFile(ConfigPath(f.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk map[string]any
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if _, ok := onDisk["activation"]; !ok {
		t.Fatalf("the config does not persist the activation record:\n%s", raw)
	}
	loaded, err := LoadConfig(f.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Activation.Probe.OK != cfg.Activation.Probe.OK ||
		loaded.Activation.Launch.Command != cfg.Activation.Launch.Command {
		t.Fatalf("the activation record did not survive a round trip: %+v", loaded.Activation)
	}
}
