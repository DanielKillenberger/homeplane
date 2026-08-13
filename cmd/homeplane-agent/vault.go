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

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
	"github.com/DanielKillenberger/homeplane/internal/agent/vault"
)

const vaultUsage = `homeplane-agent vault — find the Daniel-OS vault and keep it synchronized

Usage:
  homeplane-agent vault detect [-vault-path DIR] [-record]   find the vault (never guesses)
  homeplane-agent vault set-credential                       store the Obsidian Sync credential (stdin)
  homeplane-agent vault sync activate [flags]                smoke, snapshot, guard, then supervise
  homeplane-agent vault sync run [flags]                     the supervised continuous-sync process

Sync activation is a fixed safety sequence and every step can refuse:
  1 the CLI must be the pinned, checksummed obsidian-headless build
  2 a DISPOSABLE vault must sync cleanly on that build
  3 the real vault is snapshotted before it is ever synced
  4 a sync pass that deletes or rewrites too much aborts activation
`

func runVault(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, vaultUsage)
		return exitUsage
	}
	switch args[0] {
	case "detect":
		return runVaultDetect(args[1:], stdout, stderr)
	case "set-credential":
		return runVaultSetCredential(args[1:], os.Stdin, stdout, stderr)
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

func runVaultDetect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vault detect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		stateDir  = fs.String("state-dir", "", "agent state directory (default: ~/.homeplane)")
		vaultPath = fs.String("vault-path", "", "explicit vault directory (skips detection)")
		name      = fs.String("name", "", "only consider vaults with this directory name")
		record    = fs.Bool("record", false, "record the result in the agent state")
		asJSON    = fs.Bool("json", false, "print the result as JSON")
	)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*stateDir)
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
			if err := recordVaultPath(dir, "", componentFor(detectErr)); err != nil {
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
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(candidate); err != nil {
			fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "vault: %s (%s)\n", candidate.Path, candidate.Source)
	return 0
}

// componentFor phrases a detection failure the way status should report it,
// keeping "no vault" distinct from an authentication problem (R3).
func componentFor(err error) *agent.ComponentState {
	switch {
	case errors.Is(err, vault.ErrNoVault):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "no vault found on this machine — retryable; pass -vault-path or retrieve via Obsidian Sync",
		}
	case isAuthError(err):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "Obsidian Sync authentication failed — re-run `homeplane-agent vault set-credential` (retryable)",
		}
	default:
		var ambiguous *vault.AmbiguousError
		if errors.As(err, &ambiguous) {
			paths := make([]string, 0, len(ambiguous.Candidates))
			for _, c := range ambiguous.Candidates {
				paths = append(paths, c.Path)
			}
			return &agent.ComponentState{
				State:  agent.StateDegraded,
				Detail: "multiple candidate vaults require explicit selection: " + strings.Join(paths, ", "),
			}
		}
		return &agent.ComponentState{State: agent.StateDegraded, Detail: err.Error()}
	}
}

func isAuthError(err error) bool {
	var authErr *vault.AuthError
	return errors.As(err, &authErr)
}

func runVaultSetCredential(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vault set-credential", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", "", "agent state directory (default: ~/.homeplane)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `homeplane-agent vault set-credential — store the Obsidian Sync credential

The credential is read from STDIN, never from a flag: an argument would be
visible in `+"`ps`"+` to every process on the machine. It is stored 0600 beside the
machine credential and never enters state.json, argv, or a supervision unit.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 4096))
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: read credential: "+err.Error())
		return 1
	}
	credential := strings.TrimRight(string(raw), "\r\n")
	if err := vault.SaveCredential(dir, credential); err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "stored Obsidian Sync credential at %s (0600)\n", vault.CredentialPath(dir))
	return 0
}

func runVaultSync(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, vaultUsage)
		return exitUsage
	}
	switch args[0] {
	case "activate":
		return runVaultSyncActivate(ctx, args[1:], stdout, stderr)
	case "run":
		return runVaultSyncRun(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprint(stderr, vaultUsage)
		fmt.Fprintf(stderr, "\nhomeplane-agent vault sync: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

func runVaultSyncActivate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vault sync activate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		stateDir = fs.String("state-dir", "", "agent state directory (default: ~/.homeplane)")
		obBin    = fs.String("ob", "", "path to the pinned obsidian-headless CLI")
		unitDir  = fs.String("unit-dir", "", "where to write the supervision unit (default: the platform's user unit directory)")
		apply    = fs.Bool("apply", false, "actually load the unit into launchd/systemd (default: install the file only)")
		asJSON   = fs.Bool("json", false, "print the activation record as JSON")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `homeplane-agent vault sync activate — safely turn on continuous sync

Refuses unless the obsidian-headless CLI matches the compiled-in version and
SHA-256 pin, a disposable vault syncs cleanly on that build, and the real
vault's post-sync diff stays inside the destructive-diff guard. The vault is
snapshotted before the first sync either way.

Without -apply the unit file is written but not loaded, and the commands that
would load it are printed.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}

	store, err := agent.Open(dir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	state, _, err := store.Load()
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	if strings.TrimSpace(state.VaultPath) == "" {
		fmt.Fprintln(stderr, "homeplane-agent: no vault recorded — run `homeplane-agent vault detect -record` first")
		return 1
	}

	pin, err := vault.LoadPin()
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	credential, err := vault.LoadCredential(dir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		recordSync(dir, &agent.ComponentState{State: agent.StateDegraded, Detail: "no Obsidian Sync credential stored (retryable)"})
		return 1
	}
	platform, err := supervise.DetectPlatform("")
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	units := *unitDir
	if units == "" {
		units, err = supervise.DefaultUnitDir(platform, "")
		if err != nil {
			fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
			return 1
		}
	}
	installer := supervise.Installer{Platform: platform, Dir: units}
	if *apply {
		installer.Runner = func(name string, args ...string) error {
			cmd := exec.Command(name, args...)
			cmd.Stdout = stdout
			cmd.Stderr = stderr
			return cmd.Run()
		}
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: locate own executable: "+err.Error())
		return 1
	}

	result, err := vault.Activate(ctx, vault.ActivateOptions{
		StateDir:    dir,
		VaultPath:   state.VaultPath,
		CLI:         vault.CLI{Bin: *obBin, Pin: pin},
		Credential:  credential,
		Installer:   installer,
		AgentBinary: self,
		UID:         strconv.Itoa(os.Getuid()),
	})
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+vault.Redact(err.Error(), credential))
		recordSync(dir, syncComponentFor(err, result))
		return 1
	}

	detail := fmt.Sprintf("supervised by %s (%s); %d files snapshotted at %s; first pass %s",
		result.Platform, filepath.Base(result.UnitPath), result.FileCount, result.SnapshotPath, result.Diff.Summary())
	recordSync(dir, &agent.ComponentState{State: agent.StateOK, Detail: detail})

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "vault sync activated for %s\n", result.VaultPath)
	fmt.Fprintf(stdout, "  pin:       obsidian-headless %s\n", result.Pin.Version)
	fmt.Fprintf(stdout, "  smoke:     %v\n", result.SmokePassed)
	fmt.Fprintf(stdout, "  snapshot:  %s (%d files)\n", result.SnapshotPath, result.FileCount)
	fmt.Fprintf(stdout, "  first pass: %s\n", result.Diff.Summary())
	fmt.Fprintf(stdout, "  unit:      %s\n", result.UnitPath)
	if !*apply {
		fmt.Fprintln(stdout, "  not loaded (re-run with -apply, or run these yourself):")
		for _, c := range result.Commands {
			fmt.Fprintf(stdout, "    %s\n", c)
		}
	}
	return 0
}

// syncComponentFor turns an activation failure into the state `status` shows.
// Every branch is degraded-and-retryable: the vault stays locally readable, so
// a sync failure must never look like a lost vault (R14).
func syncComponentFor(err error, result vault.ActivateResult) *agent.ComponentState {
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
	case errors.As(err, &authErr):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "Obsidian Sync authentication failed (retryable); the vault remains readable locally",
		}
	case errors.As(err, &netErr):
		return &agent.ComponentState{
			State:  agent.StateDegraded,
			Detail: "Obsidian Sync network failure (retryable); the vault remains readable locally",
		}
	default:
		detail := "sync activation failed (retryable): " + firstLine(err.Error())
		if result.SnapshotPath != "" {
			detail += "; snapshot at " + result.SnapshotPath
		}
		return &agent.ComponentState{State: agent.StateDegraded, Detail: detail}
	}
}

func runVaultSyncRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vault sync run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		stateDir = fs.String("state-dir", "", "agent state directory (default: ~/.homeplane)")
		obBin    = fs.String("ob", "", "path to the pinned obsidian-headless CLI")
		once     = fs.Bool("once", false, "run a single sync pass instead of the continuous one")
	)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	dir, err := resolveStateDir(*stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	store, err := agent.Open(dir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	state, _, err := store.Load()
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	credential, err := vault.LoadCredential(dir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	pin, err := vault.LoadPin()
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	cli := vault.CLI{Bin: *obBin, Pin: pin, Stderr: stderr, Timeout: 0}

	err = vault.RunSync(ctx, vault.RunOptions{
		StateDir: dir,
		Run: func(ctx context.Context) error {
			if err := cli.Verify(ctx); err != nil {
				return err
			}
			if *once {
				return cli.SyncOnce(ctx, state.VaultPath, credential)
			}
			return cli.SyncContinuous(ctx, state.VaultPath, credential)
		},
	})
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+vault.Redact(err.Error(), credential))
		recordSync(dir, syncComponentFor(err, vault.ActivateResult{}))
		return 1
	}
	fmt.Fprintln(stdout, "vault sync exited cleanly")
	return 0
}

// recordVaultPath stores a detected vault path plus its component state.
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

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
