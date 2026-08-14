package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/agent/gno"
	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
)

const gnoUsage = `homeplane-agent gno — the local retrieval engine over the vault

Usage:
  homeplane-agent gno activate [flags]     bind the vault, supervise, publish the endpoint
  homeplane-agent gno apply                load the installed unit into launchd/systemd
  homeplane-agent gno run [flags]          the supervised continuous-indexing process
  homeplane-agent gno doctor [-json]       the engine's own health report
  homeplane-agent gno endpoint [-json]     print the published endpoint descriptor
  homeplane-agent gno rebuild [-json]      delete the machine-local index and rebuild it
  homeplane-agent gno mcp                  the stdio MCP endpoint harnesses launch
  homeplane-agent gno deactivate [flags]   stop the engine and (optionally) drop its state

Two lifecycles, deliberately not conflated:
  the DAEMON is supervised by this agent — it has a pid, a restart count, and a
    crash-loop threshold, and ` + "`status`" + ` reports all three;
  the HARNESS endpoint is stdio — each client launches its own short-lived
    server, so there is no pid to report, only the result of the last launch.

The index is machine-local and disposable: it lives under the agent state
directory, never inside the vault or any synchronized tree, and deleting it is a
supported operation that ` + "`gno rebuild`" + ` recovers from using the vault alone.
`

func runGNO(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, gnoUsage)
		return exitUsage
	}
	switch args[0] {
	case "activate":
		return runGNOActivate(ctx, args[1:], stdout, stderr)
	case "apply":
		return runGNOApply(args[1:], stdout, stderr)
	case "run":
		return runGNORun(ctx, args[1:], stdout, stderr)
	case "doctor":
		return runGNODoctor(ctx, args[1:], stdout, stderr)
	case "endpoint", "descriptor":
		return runGNOEndpoint(args[1:], stdout, stderr)
	case "rebuild":
		return runGNORebuild(ctx, args[1:], stdout, stderr)
	case "mcp":
		return runGNOMCP(ctx, args[1:], stdout, stderr)
	case "deactivate":
		return runGNODeactivate(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, gnoUsage)
		return 0
	default:
		fmt.Fprint(stderr, gnoUsage)
		fmt.Fprintf(stderr, "\nhomeplane-agent gno: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

// gnoFlags are the flags every gno subcommand shares.
type gnoFlags struct {
	set      *flag.FlagSet
	stateDir *string
	bin      *string
}

func newGNOFlags(name string, stderr io.Writer) gnoFlags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return gnoFlags{
		set:      fs,
		stateDir: fs.String("state-dir", "", "agent state directory (default: ~/.homeplane)"),
		bin:      fs.String("bin", "", "path to the pinned GNO CLI (default: what activation recorded, else $PATH)"),
	}
}

// loadGNOPin is a test seam, for the same reason loadPin is: a test can
// substitute a pin for its own stub, and nothing outside the compiled binary
// can weaken it at run time.
var loadGNOPin = gno.LoadPin

// resolveGNO builds the version-verified CLI wrapper. The path comes from -bin,
// then from what activation recorded, then from $PATH — so the supervised
// process works without the operator repeating a flag it can never see.
func resolveGNO(stateDir, flagValue string, log io.Writer) (gno.CLI, error) {
	pin, err := loadGNOPin()
	if err != nil {
		return gno.CLI{}, err
	}
	cfg, cfgErr := gno.LoadConfig(stateDir)

	bin := strings.TrimSpace(flagValue)
	if bin == "" && cfgErr == nil {
		bin = cfg.Bin
	}
	if bin == "" {
		if found, err := exec.LookPath("gno"); err == nil {
			bin = found
		}
	}
	dirs := gno.DefaultPaths(stateDir)
	index := ""
	if cfgErr == nil {
		if cfg.Paths.Complete() {
			dirs = cfg.Paths
		}
		index = cfg.Index
	}
	return gno.CLI{Bin: bin, Pin: pin, Dirs: dirs, Index: index, Log: log}, nil
}

// ErrVaultUnavailable is the daemon's own precondition failure (R4): the engine
// cannot index a vault that is not there, and starting anyway would serve a
// stale index while reporting a healthy component.
var ErrVaultUnavailable = errors.New("the vault is not available")

func requireVault(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: no vault recorded — run `homeplane-agent vault detect -record` first", ErrVaultUnavailable)
	}
	info, err := os.Stat(path)
	switch {
	case err != nil:
		return fmt.Errorf("%w: %s: %v", ErrVaultUnavailable, path, err)
	case !info.IsDir():
		return fmt.Errorf("%w: %s is not a directory", ErrVaultUnavailable, path)
	}
	return nil
}

func recordGNO(dir string, component *agent.ComponentState) {
	// A failure to record status must never mask the failure being recorded.
	_ = mutateState(dir, func(st *agent.State) { st.GNO = component })
}

// gnoComponentFor turns an activation FAILURE into the state `status` shows.
// Every branch names the fix, and every branch is honest that the vault itself
// is unaffected: a retrieval engine that will not start is not a lost vault.
func gnoComponentFor(err error) *agent.ComponentState {
	switch {
	case errors.Is(err, ErrVaultUnavailable):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "not started: " + firstLine(err.Error()) + " (retryable; nothing was indexed)",
		}
	case errors.Is(err, gno.ErrGatewayNotLoopback), errors.Is(err, gno.ErrGatewayPort):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "NOT started: " + firstLine(err.Error()) + " — the engine serves the whole vault and must never bind beyond this machine",
		}
	case errors.Is(err, gno.ErrEngineRunning), errors.Is(err, gno.ErrRebuildInProgress):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "index rebuild refused: " + firstLine(err.Error()) + " (retryable)",
		}
	case errors.Is(err, gno.ErrNoVaultPath):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "not started: no vault on this machine — run `homeplane-agent vault detect -record` or `vault retrieve` first",
		}
	case errors.Is(err, gno.ErrVersionMismatch):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "the installed GNO does not match the pinned version — re-run scripts/fetch-gno.sh",
		}
	case errors.Is(err, gno.ErrNoBin):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "GNO is not installed on this machine — run scripts/fetch-gno.sh (needs Bun >= 1.3)",
		}
	case errors.Is(err, gno.ErrIndexInSyncedPath), errors.Is(err, gno.ErrIndexMissing):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "NOT activated: the index would not be machine-local — " + firstLine(err.Error()),
		}
	case errors.Is(err, gno.ErrOfflineModelMissing):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "a required model is not cached and the engine runs offline (retryable): run `gno models pull`",
		}
	default:
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "retrieval engine activation failed (retryable): " + firstLine(err.Error()),
		}
	}
}

// gnoComponentForResult projects an activation OUTCOME into status. An
// installed-but-unloaded unit is NOT ok: nothing is keeping the index current.
func gnoComponentForResult(cfg gno.Config) *agent.ComponentState {
	// The activation evidence comes from the PERSISTED record, not from whatever
	// result the calling command happens to hold. `gno apply` has no
	// PrepareResult — it only loads a unit — and reconstructing the detail from
	// an empty one used to overwrite a real endpoint probe with "never probed".
	base := fmt.Sprintf("%s → collection %q (gno %s); index %s; %s; %s",
		cfg.VaultPath, cfg.Collection, cfg.Version, cfg.IndexDBPath,
		cfg.Activation.Doctor.Summary(), cfg.Activation.Probe.Summary())
	if !cfg.Applied {
		return &agent.ComponentState{
			State:  agent.StateInstalled,
			Detail: "unit installed but not loaded — run `homeplane-agent gno apply`; " + base,
		}
	}
	return &agent.ComponentState{State: agent.StateOK, Detail: base}
}

// ── activate ─────────────────────────────────────────────────────────────────

func runGNOActivate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newGNOFlags("gno activate", stderr)
	var (
		vaultPath  = f.set.String("vault-path", "", "vault to index (default: what the agent recorded)")
		collection = f.set.String("collection", gno.DefaultCollection, "GNO collection name for the vault")
		unitDir    = f.set.String("unit-dir", "", "where to write the supervision unit (default: the platform's user unit directory)")
		host       = f.set.String("host", gno.DefaultDaemonHost, "loopback address for the engine's own gateway")
		port       = f.set.Int("port", gno.DefaultDaemonPort, "port for the engine's own gateway")
		query      = f.set.String("probe-query", "", "retrieval used to prove the endpoint answers (default: the collection name)")
		apply      = f.set.Bool("apply", false, "also load the unit into launchd/systemd (default: install the file only)")
		asJSON     = f.set.Bool("json", false, "print the activation record as JSON")
	)
	f.set.Usage = func() {
		fmt.Fprint(f.set.Output(), `homeplane-agent gno activate — bind the vault and supervise the retrieval engine

Refuses unless GNO matches the pinned version, the index location is outside the
vault and outside every known synchronized tree, `+"`gno setup`"+` verifies the binding
with a real retrieval, and one launch of the stdio MCP template answers a tool
call with real vault content.

Without -apply the unit file is installed but NOT loaded — status reports that as
degraded, because an index nobody is updating is not a current index.

`)
		f.set.PrintDefaults()
	}
	if err := f.set.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*f.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}

	vault := strings.TrimSpace(*vaultPath)
	if vault == "" {
		state, _, err := agent.PeekState(dir)
		if err != nil {
			fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
			return 1
		}
		vault = state.VaultPath
	}

	cli, err := resolveGNO(dir, *f.bin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordGNO(dir, gnoComponentFor(err))
		return 1
	}
	cli.Dirs = gno.DefaultPaths(dir)

	platform, err := supervise.DetectPlatform("")
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordGNO(dir, gnoComponentFor(err))
		return 1
	}
	units := *unitDir
	if units == "" {
		if units, err = supervise.DefaultUnitDir(platform, ""); err != nil {
			fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
			return 1
		}
	}
	installer := supervise.Installer{Platform: platform, Dir: units}
	if *apply {
		installer.Runner = supervisorRunner(stdout, stderr)
	}
	agentBin, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: locate own executable: "+err.Error())
		return 1
	}

	// STAGE 0 — quiesce. Re-activating a machine that is ALREADY supervised has
	// to stop the running engine first: it holds the index open, and `gno setup`
	// against a locked database fails with a message about permissions that has
	// nothing to do with the actual cause. The unit is started again by stage 3,
	// and on any failure in between by the resume below — a failed activation
	// must not leave a machine with its engine stopped.
	// A holder stranded by a previously killed engine blocks `gno setup` exactly
	// as it blocks the daemon, and reports it as a permissions problem. Clearing
	// it here is what makes activation work on a machine whose engine was killed
	// rather than stopped.
	if res, rErr := gno.ReclaimResidentRuntime(ctx, cli.Dirs.Data, 3*time.Second); rErr == nil &&
		(res.Cleared() || res.Detail != "") {
		fmt.Fprintln(stdout, "homeplane-agent: "+res.Summary())
	}

	resume := func() {}
	if prev, loadErr := gno.LoadConfig(dir); loadErr == nil && prev.UnitLabel != "" {
		quiesce := supervise.Installer{Platform: platform, Dir: units, Runner: supervisorRunner(stdout, stderr)}
		start, quiesceErr := gno.SupervisorQuiesce(dir, prev, quiesce, strconv.Itoa(os.Getuid()))(ctx)
		if quiesceErr != nil {
			fmt.Fprintln(stderr, "homeplane-agent: stop the supervised engine before re-binding: "+quiesceErr.Error())
			recordGNO(dir, gnoComponentFor(quiesceErr))
			return 1
		}
		if start != nil {
			resume = func() {
				if err := start(); err != nil {
					fmt.Fprintln(stderr, "homeplane-agent: WARNING: the supervised engine did not restart: "+err.Error())
				}
			}
		}
	}

	// STAGE 1 — prepare: every refusal that must precede supervision.
	prepared, err := gno.Prepare(ctx, gno.PrepareOptions{
		StateDir:   dir,
		VaultPath:  vault,
		Collection: *collection,
		CLI:        cli,
		ProbeQuery: *query,
	})
	if err != nil {
		resume()
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordGNO(dir, gnoComponentFor(err))
		return 1
	}

	// STAGE 2 — install: unit, endpoint descriptor, removal plan.
	cfg, descriptor, err := gno.Install(gno.InstallOptions{
		StateDir:    dir,
		Installer:   installer,
		AgentBinary: agentBin,
		Prepared:    prepared,
		DaemonHost:  *host,
		DaemonPort:  *port,
		Index:       cli.Index,
	})
	if err != nil {
		resume()
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordGNO(dir, gnoComponentFor(err))
		return 1
	}

	// STAGE 3 — apply: load it into the supervisor, only when asked.
	cfg, cmds, err := gno.Apply(dir, installer, strconv.Itoa(os.Getuid()), nil)
	if err != nil {
		resume()
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordGNO(dir, gnoComponentFor(err))
		return 1
	}

	// STAGE 4 — project the outcome into status, honestly.
	recordGNO(dir, gnoComponentForResult(cfg))
	if *asJSON {
		return encodeJSON(stdout, stderr, struct {
			Config     gno.Config          `json:"config"`
			Prepared   gno.PrepareResult   `json:"prepared"`
			Descriptor gno.Descriptor      `json:"endpoint_descriptor"`
			Commands   []supervise.Command `json:"activation_commands"`
		}{cfg, prepared, descriptor, cmds})
	}
	printGNOActivation(stdout, cfg, prepared, descriptor, cmds)
	return 0
}

func printGNOActivation(w io.Writer, cfg gno.Config, prepared gno.PrepareResult, d gno.Descriptor, cmds []supervise.Command) {
	fmt.Fprintf(w, "retrieval engine %s for %s\n", appliedWord(cfg.Applied), cfg.VaultPath)
	fmt.Fprintf(w, "  engine:     gno %s (%s)\n", cfg.Version, cfg.Bin)
	fmt.Fprintf(w, "  collection: %s\n", cfg.Collection)
	fmt.Fprintf(w, "  index:      %s (%d bytes, machine-local and disposable)\n", cfg.IndexDBPath, prepared.IndexBytes)
	fmt.Fprintf(w, "  health:     %s\n", prepared.Doctor.Summary())
	fmt.Fprintf(w, "  endpoint:   %s via %s (%d tools)\n", d.Transport, gno.DescriptorPath(cfgStateDir(cfg)), prepared.Probe.ToolCount)
	fmt.Fprintf(w, "  probe:      %s\n", prepared.Probe.Summary())
	fmt.Fprintf(w, "  daemon:     %s:%d, unit %s\n", cfg.DaemonHost, cfg.DaemonPort, cfg.UnitPath)
	if !cfg.Applied {
		fmt.Fprintln(w, "  NOT LOADED — the index is not being kept current. Run `gno apply`, or:")
		for _, c := range cmds {
			fmt.Fprintf(w, "    %s\n", c)
		}
	}
}

// cfgStateDir recovers the state directory from the recorded paths, so the
// printout can name the descriptor without threading the directory through.
func cfgStateDir(cfg gno.Config) string {
	// Paths.Config is <stateDir>/gno/config.
	return strings.TrimSuffix(strings.TrimSuffix(cfg.Paths.Config, "/config"), "/gno")
}

// ── apply ────────────────────────────────────────────────────────────────────

func runGNOApply(args []string, stdout, stderr io.Writer) int {
	f := newGNOFlags("gno apply", stderr)
	unitDir := f.set.String("unit-dir", "", "unit directory (default: the platform's user unit directory)")
	if err := f.set.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*f.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	platform, err := supervise.DetectPlatform("")
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	units := *unitDir
	if units == "" {
		if units, err = supervise.DefaultUnitDir(platform, ""); err != nil {
			fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
			return 1
		}
	}
	installer := supervise.Installer{Platform: platform, Dir: units, Runner: supervisorRunner(stdout, stderr)}
	cfg, cmds, err := gno.Apply(dir, installer, strconv.Itoa(os.Getuid()), nil)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordGNO(dir, gnoComponentFor(err))
		return 1
	}
	recordGNO(dir, gnoComponentForResult(cfg))
	for _, c := range cmds {
		fmt.Fprintf(stdout, "  %s\n", c)
	}
	fmt.Fprintf(stdout, "retrieval engine loaded into %s\n", cfg.Platform)
	return 0
}

// ── run (the supervised process) ─────────────────────────────────────────────

func runGNORun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newGNOFlags("gno run", stderr)
	var (
		host      = f.set.String("host", "", "loopback address (default: what activation recorded)")
		port      = f.set.Int("port", 0, "gateway port (default: what activation recorded)")
		tokenFile = f.set.String("gateway-token-file", "", "bearer token file for the engine's own HTTP gateway")
	)
	if err := f.set.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*f.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	cfg, err := gno.LoadConfig(dir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	cli, err := resolveGNO(dir, *f.bin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	daemonHost := cfg.DaemonHost
	if strings.TrimSpace(*host) != "" {
		daemonHost = *host
	}
	daemonPort := cfg.DaemonPort
	if *port > 0 {
		daemonPort = *port
	}
	// The unit is written once and then runs for months; re-validating here means
	// an edited plist cannot quietly turn the engine's gateway into a LAN
	// service on the next reboot.
	if err := gno.ValidateGateway(daemonHost, daemonPort); err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordGNO(dir, gnoComponentFor(err))
		return 1
	}
	// No vault, no engine (R4). Starting the daemon against a vanished vault
	// would index nothing and serve a stale index while looking healthy, so the
	// supervised process refuses at the same gate `status` reports on.
	if err := requireVault(cfg.VaultPath); err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordGNO(dir, gnoComponentFor(err))
		return 1
	}
	gatewayToken := cfg.GatewayToken
	if strings.TrimSpace(*tokenFile) != "" {
		gatewayToken = *tokenFile
	}

	err = gno.RunDaemon(ctx, gno.RunOptions{
		StateDir: dir,
		DataDir:  cli.Dirs.Data,
		Log:      func(line string) { fmt.Fprintln(stdout, "homeplane-agent: "+line) },
		Run: func(ctx context.Context) error {
			if err := cli.Verify(ctx); err != nil {
				return err
			}
			// Continuous indexing is UNBOUNDED: it must not be killed on a timer.
			return cli.Stream(ctx, gno.Invocation{
				Args:       gno.DaemonArgs(daemonHost, daemonPort, gatewayToken),
				WorkingDir: dir,
			})
		},
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordGNO(dir, gnoComponentFor(err))
		return 1
	}
	fmt.Fprintln(stdout, "retrieval engine exited cleanly")
	return 0
}

// ── doctor / endpoint / rebuild / deactivate ─────────────────────────────────

func runGNODoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newGNOFlags("gno doctor", stderr)
	asJSON := f.set.Bool("json", false, "print the report as JSON")
	if err := f.set.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*f.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	cli, err := resolveGNO(dir, *f.bin, nil)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	report, err := cli.Doctor(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	if *asJSON {
		return encodeJSON(stdout, stderr, report)
	}
	fmt.Fprintf(stdout, "retrieval engine: %s\n", report.Summary())
	for _, c := range report.Checks {
		fmt.Fprintf(stdout, "  %-16s %-5s %s\n", c.Name, c.Status, c.Message)
	}
	if len(report.Errors()) > 0 {
		return 1
	}
	return 0
}

func runGNOEndpoint(args []string, stdout, stderr io.Writer) int {
	f := newGNOFlags("gno endpoint", stderr)
	asJSON := f.set.Bool("json", false, "print the descriptor as JSON")
	if err := f.set.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*f.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	d, err := gno.LoadDescriptor(dir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	if *asJSON {
		return encodeJSON(stdout, stderr, d)
	}
	fmt.Fprintf(stdout, "component:  %s (engine %s %s)\n", d.Component, d.Engine, d.EngineVersion)
	fmt.Fprintf(stdout, "transport:  %s\n", d.Transport)
	fmt.Fprintf(stdout, "server:     %s\n", d.ServerName)
	fmt.Fprintf(stdout, "command:    %s %s\n", d.Command, strings.Join(d.Args, " "))
	for k, v := range d.Env {
		fmt.Fprintf(stdout, "env:        %s=%s\n", k, v)
	}
	fmt.Fprintf(stdout, "collection: %s (%s)\n", d.Collection, d.VaultPath)
	fmt.Fprintf(stdout, "derived:    %s\n", d.DerivedFrom)
	return 0
}

func runGNORebuild(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newGNOFlags("gno rebuild", stderr)
	var (
		unitDir = f.set.String("unit-dir", "", "unit directory (default: the platform's user unit directory)")
		asJSON  = f.set.Bool("json", false, "print the result as JSON")
	)
	f.set.Usage = func() {
		fmt.Fprint(f.set.Output(), `homeplane-agent gno rebuild — discard the machine-local index and rebuild it

The index is derived state. Deleting it is a supported operation: this command
removes it and rebuilds from the vault, which is the only thing that syncs. The
vault is never modified.

The supervised daemon holds the index open continuously, so it is STOPPED for
the rebuild and started again afterwards — replacing a database underneath a
running writer leaves it indexing into an unlinked file. If the daemon cannot be
stopped, the rebuild refuses rather than racing it.

`)
		f.set.PrintDefaults()
	}
	if err := f.set.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*f.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	cfg, err := gno.LoadConfig(dir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	cli, err := resolveGNO(dir, *f.bin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}

	opts := gno.RebuildOptions{StateDir: dir}
	if cfg.Applied {
		platform, err := supervise.DetectPlatform("")
		if err != nil {
			fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
			return 1
		}
		units := *unitDir
		if units == "" {
			if units, err = supervise.DefaultUnitDir(platform, ""); err != nil {
				fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
				return 1
			}
		}
		installer := supervise.Installer{
			Platform: platform, Dir: units, Runner: supervisorRunner(stdout, stderr),
		}
		opts.Quiesce = gno.SupervisorQuiesce(dir, cfg, installer, strconv.Itoa(os.Getuid()))
	}

	res, err := gno.Rebuild(ctx, cli, cfg, opts)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordGNO(dir, gnoComponentFor(err))
		return 1
	}
	if *asJSON {
		return encodeJSON(stdout, stderr, res)
	}
	fmt.Fprintf(stdout, "index rebuilt: %s (%d bytes) from %s\n", res.IndexDBPath, res.IndexBytes, res.VaultPath)
	return 0
}

// ── mcp: the stdio endpoint harnesses actually launch ────────────────────────

func runGNOMCP(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newGNOFlags("gno mcp", stderr)
	f.set.Usage = func() {
		fmt.Fprint(f.set.Output(), `homeplane-agent gno mcp — the retrieval engine's stdio MCP server, wrapped

This is what harness configurations point at, and it is what the endpoint
descriptor publishes. It runs the engine's own stdio server with this process's
pipes attached — no parsing, no buffering, no interpretation — and records the
outcome of every launch.

That recording is the point. A harness starts its own server whenever it likes,
so a probe taken once at activation cannot tell anyone that launches have been
failing since. `+"`homeplane-agent status`"+` reads the launch history this writes.

`)
		f.set.PrintDefaults()
	}
	if err := f.set.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*f.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	cfg, err := gno.LoadConfig(dir)
	if err != nil {
		// Diagnostics go to STDERR only: stdout belongs to the MCP stream, and a
		// friendly message written there would corrupt the client's parser.
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}

	launch := cfg.Activation.Launch
	if err := gno.RunStdioEndpoint(ctx, gno.StdioOptions{
		StateDir: dir,
		Command:  launch.Command,
		Args:     launch.Args,
		Env:      launch.Env,
		Stdin:    os.Stdin,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		Client:   gno.ClientFromEnv(os.Environ()),
	}); err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	return 0
}

func runGNODeactivate(args []string, stdout, stderr io.Writer) int {
	f := newGNOFlags("gno deactivate", stderr)
	var (
		execute     = f.set.Bool("execute", false, "actually run the registered removal steps (default: print them)")
		deleteState = f.set.Bool("delete-state", false, "also delete the machine-local index and endpoint descriptor")
		asJSON      = f.set.Bool("json", false, "print the result as JSON")
	)
	f.set.Usage = func() {
		fmt.Fprint(f.set.Output(), `homeplane-agent gno deactivate — stop the retrieval engine using its registered removal plan

Activation registers exactly what it created and how to undo it. This runs the
component's half of that plan. The vault is listed as KEEP and the plan refuses
to delete anything inside it — deleting synchronized content would propagate to
every other machine.

Without -execute nothing is changed and the steps are printed.

`)
		f.set.PrintDefaults()
	}
	if err := f.set.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*f.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	var runner func(string, ...string) error
	if *execute {
		runner = supervisorRunner(stdout, stderr)
	}
	res, err := gno.Deactivate(dir, runner, *deleteState)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	if *execute {
		recordGNO(dir, &agent.ComponentState{
			State:  agent.StateNotConfigured,
			Detail: "the retrieval engine was deactivated on this machine",
		})
	}
	if *asJSON {
		return encodeJSON(stdout, stderr, res)
	}
	for _, c := range res.Commands {
		fmt.Fprintf(stdout, "  %s\n", c)
	}
	for _, p := range res.Removed {
		fmt.Fprintf(stdout, "  removed %s\n", p)
	}
	for _, p := range res.Kept {
		fmt.Fprintf(stdout, "  kept    %s\n", p)
	}
	for _, r := range res.Remaining {
		fmt.Fprintf(stderr, "  note: %s\n", r)
	}
	if !res.Executed {
		fmt.Fprintln(stdout, "nothing was changed — re-run with -execute")
	}
	return 0
}
