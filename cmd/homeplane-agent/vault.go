package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
	"github.com/DanielKillenberger/homeplane/internal/agent/vault"
)

const vaultUsage = `homeplane-agent vault — find or retrieve the Daniel-OS vault, and keep it synchronized

Usage:
  homeplane-agent vault detect [-vault-path DIR] [-record]   find the vault (never guesses)
  homeplane-agent vault login -email ADDR                    authenticate (password on stdin)
  homeplane-agent vault set-e2e-password                     store the vault encryption password (stdin)
  homeplane-agent vault retrieve -path DIR [-remote NAME]    fetch an absent vault
  homeplane-agent vault sync activate [flags]                smoke, snapshot, guard, then supervise
  homeplane-agent vault sync apply                           load the installed unit
  homeplane-agent vault sync run [flags]                     the supervised continuous-sync process

Sync activation is a fixed safety sequence and every step can refuse:
  1 the CLI must be the pinned, checksummed obsidian-headless build
  2 a DISPOSABLE vault must survive a pass on that build
  3 the real vault is snapshotted before it is ever synced
  4 a sync pass that deletes or rewrites too much aborts activation

Credentials never touch argv: the account token is passed through the
environment, and passwords answer the CLI's own prompts on stdin.
`

func runVault(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, vaultUsage)
		return exitUsage
	}
	switch args[0] {
	case "detect":
		return runVaultDetect(args[1:], stdout, stderr)
	case "login":
		return runVaultLogin(ctx, args[1:], os.Stdin, stdout, stderr)
	case "set-e2e-password":
		return runVaultSetE2E(args[1:], os.Stdin, stdout, stderr)
	case "retrieve":
		return runVaultRetrieve(ctx, args[1:], stdout, stderr)
	case "sync":
		return runVaultSync(ctx, args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, vaultUsage)
		return 0
	default:
		fmt.Fprint(stderr, vaultUsage)
		fmt.Fprintf(stderr, "\nhomeplane-agent vault: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

// ── shared plumbing ──────────────────────────────────────────────────────────

// vaultFlags are the flags every vault subcommand shares.
type vaultFlags struct {
	set      *flag.FlagSet
	stateDir *string
	obBin    *string
}

func newVaultFlags(name string, stderr io.Writer) vaultFlags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return vaultFlags{
		set:      fs,
		stateDir: fs.String("state-dir", "", "agent state directory (default: ~/.homeplane)"),
		obBin:    fs.String("ob", "", "path to the pinned obsidian-headless CLI"),
	}
}

// loadPin is a test seam. It is a package-level function value rather than an
// environment override on purpose: a test in this package can substitute a pin
// for its own stub, while nothing outside the compiled binary can weaken the
// pin at run time — which is the entire point of having one.
var loadPin = vault.LoadPin

// resolveOB builds the verified-CLI wrapper. The path comes from -ob, else from
// what activation recorded — which is what lets the supervised process work
// without the operator repeating a flag it can never see.
func resolveOB(stateDir, flagValue string, log io.Writer) (vault.CLI, error) {
	pin, err := loadPin()
	if err != nil {
		return vault.CLI{}, err
	}
	bin := strings.TrimSpace(flagValue)
	if bin == "" {
		if cfg, err := vault.LoadConfig(stateDir); err == nil {
			bin = cfg.OBPath
		}
	}
	return vault.CLI{
		Bin:       bin,
		Pin:       pin,
		ConfigDir: vault.CLIConfigDir(stateDir),
		Log:       log,
	}, nil
}

func readSecretLine(r io.Reader) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

func mutateState(dir string, fn func(*agent.State)) error {
	store, err := agent.Open(dir)
	if err != nil {
		return err
	}
	state, _, err := store.Load()
	if err != nil {
		return err
	}
	fn(&state)
	return store.Save(state)
}

func recordVaultPath(dir, path string, component *agent.ComponentState) error {
	return mutateState(dir, func(st *agent.State) {
		st.VaultPath = path
		st.Vault = component
	})
}

func recordSync(dir string, component *agent.ComponentState) {
	// A failure to record status must never mask the failure being recorded.
	_ = mutateState(dir, func(st *agent.State) { st.Sync = component })
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// ── detect ───────────────────────────────────────────────────────────────────

func runVaultDetect(args []string, stdout, stderr io.Writer) int {
	f := newVaultFlags("vault detect", stderr)
	var (
		vaultPath = f.set.String("vault-path", "", "explicit vault directory (skips detection)")
		name      = f.set.String("name", "", "only consider vaults with this directory name")
		record    = f.set.Bool("record", false, "record the result in the agent state")
		asJSON    = f.set.Bool("json", false, "print the result as JSON")
	)
	if err := f.set.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*f.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}

	candidate, detectErr := vault.Detect(vault.DetectOptions{ExplicitPath: *vaultPath, Name: *name})
	if detectErr != nil {
		var ambiguous *vault.AmbiguousError
		if errors.As(detectErr, &ambiguous) {
			fmt.Fprintln(stderr, detectErr.Error())
			for _, c := range ambiguous.Candidates {
				fmt.Fprintf(stderr, "  %s  (%s)\n", c.Path, c.Source)
			}
		} else {
			fmt.Fprintln(stderr, detectErr.Error())
		}
		if *record {
			if err := recordVaultPath(dir, "", vaultComponentFor(detectErr)); err != nil {
				fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
			}
		}
		return 1
	}

	if *record {
		detail := candidate.Path + " (" + candidate.Source + ")"
		if err := recordVaultPath(dir, candidate.Path, &agent.ComponentState{State: agent.StateOK, Detail: detail}); err != nil {
			fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
			return 1
		}
	}
	if *asJSON {
		return encodeJSON(stdout, stderr, candidate)
	}
	fmt.Fprintf(stdout, "vault: %s (%s)\n", candidate.Path, candidate.Source)
	return 0
}

// vaultComponentFor phrases a detection or retrieval failure the way status
// should report it, keeping "no vault" distinct from an authentication problem
// (R3) — they need different fixes.
func vaultComponentFor(err error) *agent.ComponentState {
	var (
		ambiguous       *vault.AmbiguousError
		ambiguousRemote *vault.ErrAmbiguousRemote
		authErr         *vault.AuthError
		netErr          *vault.NetworkError
	)
	switch {
	case errors.As(err, &authErr):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "Obsidian authentication failed — re-run `homeplane-agent vault login` (retryable)",
		}
	case errors.Is(err, vault.ErrNoAuthToken):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "no Obsidian auth token stored — run `homeplane-agent vault login` (retryable)",
		}
	case errors.As(err, &netErr):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "vault retrieval hit a network failure (retryable)",
		}
	case errors.Is(err, vault.ErrNoVault):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "no vault found on this machine — retryable; pass -vault-path or run `vault retrieve`",
		}
	case errors.Is(err, vault.ErrNoRemoteVault):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "the Obsidian account has no matching remote vault — retryable (this is NOT an auth failure)",
		}
	case errors.As(err, &ambiguous):
		paths := make([]string, 0, len(ambiguous.Candidates))
		for _, c := range ambiguous.Candidates {
			paths = append(paths, c.Path)
		}
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "multiple candidate vaults require explicit selection: " + strings.Join(paths, ", "),
		}
	case errors.As(err, &ambiguousRemote):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "multiple remote vaults require explicit selection: " + firstLine(ambiguousRemote.Error()),
		}
	default:
		return &agent.ComponentState{State: agent.StateDegraded, Detail: firstLine(err.Error())}
	}
}

// ── credentials ──────────────────────────────────────────────────────────────

func runVaultLogin(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	f := newVaultFlags("vault login", stderr)
	var (
		email = f.set.String("email", "", "Obsidian account email")
		mfa   = f.set.String("mfa", "", "MFA code, when the account requires one")
	)
	f.set.Usage = func() {
		fmt.Fprint(f.set.Output(), `homeplane-agent vault login — authenticate this machine to Obsidian

The password is read from STDIN, never from a flag: an argument would be visible
in `+"`ps`"+` to every process on the machine. The resulting account token is stored
0600 in the agent state directory and handed to the sync CLI through the
environment.

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
	password, err := readSecretLine(stdin)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: read password: "+err.Error())
		return 1
	}
	cli, err := resolveOB(dir, *f.obBin, nil)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	if err := vault.Login(ctx, vault.LoginOptions{
		StateDir: dir, CLI: cli, Email: *email, Password: password, MFACode: *mfa,
	}); err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+vault.Redact(err.Error(), password, *mfa))
		recordSync(dir, vaultComponentFor(err))
		return 1
	}
	fmt.Fprintf(stdout, "stored Obsidian auth token at %s (0600)\n", vault.AuthTokenPath(dir))
	return 0
}

func runVaultSetE2E(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	f := newVaultFlags("vault set-e2e-password", stderr)
	f.set.Usage = func() {
		fmt.Fprint(f.set.Output(), `homeplane-agent vault set-e2e-password — store the vault encryption password

Read from STDIN, never a flag. This is the END-TO-END encryption password, which
is NOT the account password: it decrypts vault content and cannot be recovered
from the account if it is lost.

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
	password, err := readSecretLine(stdin)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: read password: "+err.Error())
		return 1
	}
	if err := vault.SaveE2EPassword(dir, password); err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "stored Obsidian E2E password at %s (0600)\n", vault.E2EPasswordPath(dir))
	return 0
}

// ── retrieve ─────────────────────────────────────────────────────────────────

func runVaultRetrieve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newVaultFlags("vault retrieve", stderr)
	var (
		path       = f.set.String("path", "", "directory to retrieve the vault into (required)")
		remote     = f.set.String("remote", "", "remote vault name or id (required when the account has more than one)")
		deviceName = f.set.String("device-name", "", "name for this machine in the sync version history")
		appFallbck = f.set.Bool("app-fallback", false, "if headless retrieval fails, launch Obsidian once and wait for the vault")
		waitFor    = f.set.Duration("wait", 5*time.Minute, "how long the app fallback waits for the vault to appear")
		asJSON     = f.set.Bool("json", false, "print the result as JSON")
	)
	f.set.Usage = func() {
		fmt.Fprint(f.set.Output(), `homeplane-agent vault retrieve — fetch a vault onto a machine that has none

Runs the upstream lifecycle: sync-list-remote, sync-setup, then a PULL-ONLY
first sync. Pull-only is not optional — a bidirectional first pass against an
empty directory is how an empty local side gets propagated to the remote.

Refuses to retrieve on top of an existing vault, and refuses to guess when the
account has more than one matching remote vault.

`)
		f.set.PrintDefaults()
	}
	if err := f.set.Parse(args); err != nil {
		return exitUsage
	}
	if strings.TrimSpace(*path) == "" {
		fmt.Fprintln(stderr, "homeplane-agent vault retrieve: -path is required")
		return exitUsage
	}
	dir, err := resolveStateDir(*f.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	secrets, err := vault.LoadSecrets(dir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		_ = recordVaultPath(dir, "", vaultComponentFor(err))
		return 1
	}
	cli, err := resolveOB(dir, *f.obBin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}

	opts := vault.RetrieveOptions{
		StateDir:   dir,
		CLI:        cli,
		Secrets:    secrets,
		RemoteName: *remote,
		LocalPath:  *path,
		DeviceName: *deviceName,
	}
	if *appFallbck {
		opts.Fallback = func(ctx context.Context, local string) error {
			if err := launchObsidian(ctx, local); err != nil {
				return err
			}
			fmt.Fprintf(stderr, "waiting up to %s for Obsidian to populate %s…\n", *waitFor, local)
			return vault.WaitForVault(ctx, local, *waitFor, 2*time.Second)
		}
	}

	res, err := vault.Retrieve(ctx, opts)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+vault.Redact(err.Error(), secrets.AuthToken, secrets.E2EPassword))
		_ = recordVaultPath(dir, "", vaultComponentFor(err))
		return 1
	}
	detail := fmt.Sprintf("%s (retrieved from %q, %d files)", res.VaultPath, res.RemoteName, res.FileCount)
	if err := recordVaultPath(dir, res.VaultPath, &agent.ComponentState{State: agent.StateOK, Detail: detail}); err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	if *asJSON {
		return encodeJSON(stdout, stderr, res)
	}
	fmt.Fprintf(stdout, "vault retrieved: %s (%d files from remote %q)\n", res.VaultPath, res.FileCount, res.RemoteName)
	return 0
}

// launchObsidian opens the desktop app once. It is the documented fallback for
// a machine where the headless path does not work; the waiting half is
// vault.WaitForVault.
func launchObsidian(ctx context.Context, localPath string) error {
	var cmd *exec.Cmd
	switch {
	case commandExists("open"): // macOS
		cmd = exec.CommandContext(ctx, "open", "-a", "Obsidian")
	case commandExists("obsidian"):
		cmd = exec.CommandContext(ctx, "obsidian")
	case commandExists("xdg-open"):
		cmd = exec.CommandContext(ctx, "xdg-open", "obsidian://open")
	default:
		return errors.New("no way to launch Obsidian on this machine — open it manually and re-run")
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch Obsidian: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// ── sync ─────────────────────────────────────────────────────────────────────

func runVaultSync(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, vaultUsage)
		return exitUsage
	}
	switch args[0] {
	case "activate":
		return runVaultSyncActivate(ctx, args[1:], stdout, stderr)
	case "apply":
		return runVaultSyncApply(args[1:], stdout, stderr)
	case "run":
		return runVaultSyncRun(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprint(stderr, vaultUsage)
		fmt.Fprintf(stderr, "\nhomeplane-agent vault sync: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

// activateInputs is everything `sync activate` needs, gathered in one place so
// the command body is a sequence of stages rather than a single long function.
type activateInputs struct {
	stateDir  string
	vaultPath string
	cli       vault.CLI
	secrets   vault.Secrets
	installer supervise.Installer
	agentBin  string
	uid       string
}

// gatherActivateInputs is the PREPARE-the-inputs stage: state, credentials,
// platform, installer. It performs no side effects beyond reading.
func gatherActivateInputs(stateDir, obFlag, unitDir string, apply bool, stdout, stderr io.Writer) (activateInputs, error) {
	var in activateInputs
	in.stateDir = stateDir

	store, err := agent.Open(stateDir)
	if err != nil {
		return in, err
	}
	state, _, err := store.Load()
	if err != nil {
		return in, err
	}
	if strings.TrimSpace(state.VaultPath) == "" {
		return in, errors.New("no vault recorded — run `homeplane-agent vault detect -record` or `vault retrieve` first")
	}
	in.vaultPath = state.VaultPath

	if in.cli, err = resolveOB(stateDir, obFlag, stderr); err != nil {
		return in, err
	}
	if in.secrets, err = vault.LoadSecrets(stateDir); err != nil {
		return in, err
	}
	platform, err := supervise.DetectPlatform("")
	if err != nil {
		return in, err
	}
	if unitDir == "" {
		if unitDir, err = supervise.DefaultUnitDir(platform, ""); err != nil {
			return in, err
		}
	}
	in.installer = supervise.Installer{Platform: platform, Dir: unitDir}
	if apply {
		in.installer.Runner = supervisorRunner(stdout, stderr)
	}
	if in.agentBin, err = os.Executable(); err != nil {
		return in, fmt.Errorf("locate own executable: %w", err)
	}
	in.uid = strconv.Itoa(os.Getuid())
	return in, nil
}

func supervisorRunner(stdout, stderr io.Writer) func(string, ...string) error {
	return func(name string, args ...string) error {
		cmd := exec.Command(name, args...)
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		return cmd.Run()
	}
}

func runVaultSyncActivate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newVaultFlags("vault sync activate", stderr)
	var (
		unitDir = f.set.String("unit-dir", "", "where to write the supervision unit (default: the platform's user unit directory)")
		apply   = f.set.Bool("apply", false, "also load the unit into launchd/systemd (default: install the file only)")
		asJSON  = f.set.Bool("json", false, "print the activation record as JSON")
		// The DISPOSABLE remote the pre-activation rehearsal runs against. With
		// it, the rehearsal is the real lifecycle — `sync-setup` and a genuine
		// pass on the pinned build — instead of the unauthenticated contract
		// check, and only then has anything proven that this build can sync at
		// all before it is pointed at a vault that matters.
		smokeRemote = f.set.String("smoke-remote", "",
			"name of a DISPOSABLE remote vault to rehearse the full sync lifecycle against "+
				"(create one for the purpose; its contents are not preserved)")
	)
	f.set.Usage = func() {
		fmt.Fprint(f.set.Output(), `homeplane-agent vault sync activate — safely turn on continuous sync

Refuses unless the obsidian-headless CLI matches the compiled-in version and
SHA-256 pin, a disposable vault survives a pass on that build, and the real
vault's post-sync diff stays inside the destructive-diff guard. The vault is
snapshotted before the first sync either way.

Without -apply the unit file is installed but NOT loaded — status reports that
as degraded, because a vault that is not syncing is not a vault that is synced.

The rehearsal that precedes everything runs against a DISPOSABLE vault. Without
-smoke-remote it is an unauthenticated CONTRACT check (the build must refuse an
unconfigured directory the way upstream does); with -smoke-remote it is the full
authenticated lifecycle against the throwaway remote you name — which is the
only version that proves this build can actually sync.

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

	in, err := gatherActivateInputs(dir, *f.obBin, *unitDir, *apply, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordSync(dir, syncComponentFor(err, vault.PrepareResult{}))
		return 1
	}

	// STAGE 1 — prepare: every refusal that must precede supervision.
	prepared, err := vault.Prepare(ctx, vault.PrepareOptions{
		StateDir:         in.stateDir,
		VaultPath:        in.vaultPath,
		CLI:              in.cli,
		Secrets:          in.secrets,
		SmokeRemoteVault: strings.TrimSpace(*smokeRemote),
	})
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+vault.Redact(err.Error(), in.secrets.AuthToken, in.secrets.E2EPassword))
		recordSync(dir, syncComponentFor(err, prepared))
		return 1
	}

	// STAGE 2 — install: write the unit, persist the resolved CLI path.
	cfg, err := vault.Install(vault.InstallOptions{
		StateDir:    in.stateDir,
		Installer:   in.installer,
		AgentBinary: in.agentBin,
		Prepared:    prepared,
	})
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordSync(dir, syncComponentFor(err, prepared))
		return 1
	}

	// STAGE 3 — apply: load it into the supervisor, only when asked.
	cfg, cmds, err := vault.Apply(in.stateDir, in.installer, in.uid, nil)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordSync(dir, syncComponentFor(err, prepared))
		return 1
	}

	// STAGE 4 — project the outcome into status, honestly.
	recordSync(dir, syncComponentForResult(cfg, prepared))
	if *asJSON {
		return encodeJSON(stdout, stderr, struct {
			Config   vault.Config        `json:"config"`
			Prepared vault.PrepareResult `json:"prepared"`
			Commands []supervise.Command `json:"activation_commands"`
		}{cfg, prepared, cmds})
	}
	printActivation(stdout, cfg, prepared, cmds)
	return 0
}

func printActivation(w io.Writer, cfg vault.Config, prepared vault.PrepareResult, cmds []supervise.Command) {
	fmt.Fprintf(w, "vault sync %s for %s\n", appliedWord(cfg.Applied), prepared.VaultPath)
	fmt.Fprintf(w, "  pin:        obsidian-headless %s\n", prepared.Pin.Version)
	fmt.Fprintf(w, "  cli:        %s\n", cfg.OBPath)
	fmt.Fprintf(w, "  smoke:      %v\n", prepared.SmokePassed)
	fmt.Fprintf(w, "  snapshot:   %s (%d files)\n", prepared.SnapshotPath, prepared.FileCount)
	fmt.Fprintf(w, "  first pass: %s\n", prepared.Diff.Summary())
	fmt.Fprintf(w, "  unit:       %s\n", cfg.UnitPath)
	if !cfg.Applied {
		fmt.Fprintln(w, "  NOT LOADED — the vault is not syncing yet. Run `vault sync apply`, or:")
		for _, c := range cmds {
			fmt.Fprintf(w, "    %s\n", c)
		}
	}
}

func appliedWord(applied bool) string {
	if applied {
		return "activated"
	}
	return "installed (not loaded)"
}

func runVaultSyncApply(args []string, stdout, stderr io.Writer) int {
	f := newVaultFlags("vault sync apply", stderr)
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
	cfg, cmds, err := vault.Apply(dir, installer, strconv.Itoa(os.Getuid()), nil)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordSync(dir, syncComponentFor(err, vault.PrepareResult{}))
		return 1
	}
	recordSync(dir, syncComponentForResult(cfg, vault.PrepareResult{VaultPath: cfg.VaultPath, SnapshotPath: cfg.SnapshotPath}))
	for _, c := range cmds {
		fmt.Fprintf(stdout, "  %s\n", c)
	}
	fmt.Fprintf(stdout, "vault sync loaded into %s\n", cfg.Platform)
	return 0
}

// syncComponentForResult projects an activation OUTCOME into status.
//
// The distinction that matters: an installed-but-unloaded unit is NOT ok. It
// used to be recorded as ok while the very next line of output said "not
// loaded" — a machine could report a healthy sync while nothing was running.
func syncComponentForResult(cfg vault.Config, prepared vault.PrepareResult) *agent.ComponentState {
	base := fmt.Sprintf("%s via %s (obsidian-headless %s)", cfg.VaultPath, filepath.Base(cfg.UnitPath), cfg.PinVersion)
	if prepared.SnapshotPath != "" {
		base += "; snapshot " + prepared.SnapshotPath
	}
	if !cfg.Applied {
		return &agent.ComponentState{
			State:  agent.StateInstalled,
			Detail: "unit installed but not loaded — run `homeplane-agent vault sync apply`; " + base,
		}
	}
	return &agent.ComponentState{State: agent.StateOK, Detail: base}
}

// syncComponentFor turns an activation FAILURE into the state `status` shows.
// Every branch is degraded-and-retryable: the vault stays locally readable, so
// a sync failure must never look like a lost vault (R14).
func syncComponentFor(err error, prepared vault.PrepareResult) *agent.ComponentState {
	var (
		destructive *vault.DestructiveDiffError
		authErr     *vault.AuthError
		netErr      *vault.NetworkError
	)
	switch {
	case errors.As(err, &destructive):
		return &agent.ComponentState{
			State: agent.StateDegraded,
			Detail: "sync NOT activated: destructive diff refused (" + destructive.Diff.Summary() +
				"); snapshot at " + destructive.SnapshotPath,
		}
	case errors.Is(err, vault.ErrPinUnset):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "sync NOT activated: the obsidian-headless checksum pin is still PENDING",
		}
	case errors.Is(err, vault.ErrPinMismatch):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "sync NOT activated: the obsidian-headless CLI does not match the pinned build",
		}
	case errors.Is(err, vault.ErrNoAuthToken):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "no Obsidian auth token stored — run `homeplane-agent vault login` (retryable)",
		}
	case errors.As(err, &authErr):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "Obsidian authentication failed (retryable); the vault remains readable locally",
		}
	case errors.As(err, &netErr):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "Obsidian Sync network failure (retryable); the vault remains readable locally",
		}
	default:
		detail := "sync activation failed (retryable): " + firstLine(err.Error())
		if prepared.SnapshotPath != "" {
			detail += "; snapshot at " + prepared.SnapshotPath
		}
		return &agent.ComponentState{State: agent.StateDegraded, Detail: detail}
	}
}

func runVaultSyncRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newVaultFlags("vault sync run", stderr)
	once := f.set.Bool("once", false, "run a single sync pass instead of the continuous one")
	if err := f.set.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*f.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	cfg, err := vault.LoadConfig(dir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	secrets, err := vault.LoadSecrets(dir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	cli, err := resolveOB(dir, *f.obBin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}

	err = vault.RunSync(ctx, vault.RunOptions{
		StateDir: dir,
		Run: func(ctx context.Context) error {
			if err := cli.Verify(ctx); err != nil {
				return err
			}
			inv := vault.Invocation{
				Secrets:    secrets,
				WorkingDir: cfg.VaultPath,
			}
			if *once {
				inv.Args = vault.SyncArgs(cfg.VaultPath)
				_, err := cli.Run(ctx, inv)
				return err
			}
			// Continuous sync is UNBOUNDED: it must not be killed on a timer.
			inv.Args = vault.SyncContinuousArgs(cfg.VaultPath)
			return cli.Stream(ctx, inv)
		},
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "homeplane-agent: "+vault.Redact(err.Error(), secrets.AuthToken, secrets.E2EPassword))
		recordSync(dir, syncComponentFor(err, vault.PrepareResult{}))
		return 1
	}
	fmt.Fprintln(stdout, "vault sync exited cleanly")
	return 0
}

func encodeJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	return 0
}
