package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
)

// Sync activation is the dangerous operation in this package, so it is written
// as an explicit, ordered sequence with a refusal at every step:
//
//	1. the vault is a vault                       else: not a vault
//	2. the CLI is the pinned, checksummed build   else: ErrPinUnset / ErrPinMismatch
//	3. a DISPOSABLE vault syncs cleanly           else: smoke failure, nothing touched
//	4. the real vault is snapshotted              else: abort before any sync
//	5. one real sync pass, then a content diff    else: auth/network failure, retryable
//	6. the diff is within the guard policy        else: DestructiveDiffError, no supervision
//	7. only now: install + activate supervision
//
// Steps 3 and 4 are the whole point of the ordering. The first time this runs
// against Daniel's real vault, the vault has already been copied aside and the
// same CLI has already been proven against a throwaway vault.

// SyncUnitLabel identifies the supervised continuous-sync process.
const SyncUnitLabel = "com.homeplane.vault-sync"

// SmokeVaultName is the disposable vault created for the pre-activation smoke.
const SmokeVaultName = "smoke-vault"

// ActivateOptions describes one activation.
type ActivateOptions struct {
	// StateDir is the agent state directory (credential, snapshots, ledger).
	StateDir string
	// VaultPath is the REAL vault.
	VaultPath string
	// CLI is the verified obsidian-headless wrapper.
	CLI CLI
	// Credential is the Obsidian Sync credential. Empty means "not configured",
	// which is a refusal rather than an anonymous sync attempt.
	Credential string
	// Policy bounds the destructive diff. Zero value means DefaultGuardPolicy.
	Policy GuardPolicy
	// SnapshotDir overrides where the pre-activation snapshot is written.
	SnapshotDir string
	// SmokeVaultDir overrides the disposable smoke vault. When empty a fresh
	// one is created under the state directory and removed afterwards.
	SmokeVaultDir string
	// Installer installs the supervision unit. Its Runner stays nil unless the
	// caller explicitly wants the live session mutated.
	Installer supervise.Installer
	// AgentBinary is the homeplane-agent executable the unit runs. The unit
	// never runs the sync CLI directly, so no credential can reach the unit.
	AgentBinary string
	// UID is the numeric user id launchd targets.
	UID string
	// Now overrides the clock.
	Now func() time.Time
	// SkipSmoke is honoured ONLY when the caller has already smoked this exact
	// CLI build in this run; it exists so a re-activation does not re-smoke.
	SkipSmoke bool
}

// ActivateResult records what activation actually did — the evidence that the
// safety sequence ran, rather than a claim that it did.
type ActivateResult struct {
	VaultPath    string              `json:"vault_path"`
	SnapshotPath string              `json:"snapshot_path"`
	SmokePassed  bool                `json:"smoke_passed"`
	SmokeSkipped bool                `json:"smoke_skipped"`
	Pin          Pin                 `json:"pin"`
	Diff         Diff                `json:"diff"`
	FileCount    int                 `json:"file_count"`
	UnitPath     string              `json:"unit_path"`
	Commands     []supervise.Command `json:"activation_commands"`
	ActivatedAt  time.Time           `json:"activated_at"`
	Platform     supervise.Platform  `json:"platform"`
}

// Activate runs the full safety sequence and, only on success, supervises
// continuous sync.
func Activate(ctx context.Context, opts ActivateOptions) (ActivateResult, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	policy := opts.Policy
	if policy == (GuardPolicy{}) {
		policy = DefaultGuardPolicy()
	}
	res := ActivateResult{VaultPath: opts.VaultPath, Pin: opts.CLI.Pin, Platform: opts.Installer.Platform}

	if strings.TrimSpace(opts.StateDir) == "" {
		return res, errors.New("vault: state directory is required")
	}
	// 1. the vault is a vault.
	if err := ValidatePath(opts.VaultPath); err != nil {
		return res, err
	}
	// A credential is required before anything is attempted: an unauthenticated
	// sync against a real vault is exactly the "remote side looks empty" case
	// the guard exists to catch, and it should never be reached.
	if strings.TrimSpace(opts.Credential) == "" {
		return res, ErrNoCredential
	}
	// 2. the CLI is the pinned build.
	if err := opts.CLI.Verify(ctx); err != nil {
		return res, err
	}

	// 3. disposable-vault smoke, on this exact build, before the real vault.
	if opts.SkipSmoke {
		res.SmokeSkipped = true
	} else {
		if err := smoke(ctx, opts); err != nil {
			return res, fmt.Errorf("vault: pre-activation smoke on a disposable vault failed (the real vault was not touched): %w", err)
		}
		res.SmokePassed = true
	}

	// 4. snapshot the real vault.
	snapshotDir := opts.SnapshotDir
	if snapshotDir == "" {
		snapshotDir = filepath.Join(opts.StateDir, "snapshots", now().UTC().Format("20060102T150405Z"))
	}
	before, err := Snapshot(opts.VaultPath, snapshotDir)
	if err != nil {
		return res, err
	}
	res.SnapshotPath = snapshotDir
	res.FileCount = len(before.Files)

	// 5. one real sync pass.
	if err := opts.CLI.SyncOnce(ctx, opts.VaultPath, opts.Credential); err != nil {
		return res, err
	}
	after, err := Scan(opts.VaultPath)
	if err != nil {
		return res, err
	}
	res.Diff = Compare(before, after)

	// 6. the guard.
	if err := policy.Check(before, res.Diff, snapshotDir); err != nil {
		return res, err
	}

	// 7. supervision.
	unit, err := SyncUnit(opts.AgentBinary, opts.StateDir, opts.VaultPath)
	if err != nil {
		return res, err
	}
	unitPath, err := opts.Installer.Install(unit, opts.Credential)
	if err != nil {
		return res, err
	}
	res.UnitPath = unitPath
	cmds, err := opts.Installer.Activate(unit, opts.UID)
	if err != nil {
		return res, err
	}
	res.Commands = cmds
	res.ActivatedAt = now().UTC()
	return res, nil
}

// smoke proves the pinned CLI against a throwaway vault. It is not a claim that
// Obsidian Sync works — it is a claim that THIS build runs, authenticates, and
// leaves a vault it was pointed at intact.
func smoke(ctx context.Context, opts ActivateOptions) error {
	dir := opts.SmokeVaultDir
	if dir == "" {
		base, err := os.MkdirTemp(opts.StateDir, SmokeVaultName+"-")
		if err != nil {
			return fmt.Errorf("create disposable smoke vault: %w", err)
		}
		defer os.RemoveAll(base)
		dir = base
	}
	if err := scaffoldVault(dir); err != nil {
		return err
	}
	before, err := Scan(dir)
	if err != nil {
		return err
	}
	if err := opts.CLI.SyncOnce(ctx, dir, opts.Credential); err != nil {
		return err
	}
	after, err := Scan(dir)
	if err != nil {
		return err
	}
	// The smoke vault is judged by the SAME guard as the real one; a build that
	// eats a throwaway vault must never be pointed at the real one.
	policy := opts.Policy
	if policy == (GuardPolicy{}) {
		policy = DefaultGuardPolicy()
	}
	if err := policy.Check(before, Compare(before, after), dir); err != nil {
		return err
	}
	return nil
}

// scaffoldVault makes a directory look like a real vault: a .obsidian config
// and a note, so a sync pass has something to reconcile and something to lose.
func scaffoldVault(dir string) error {
	if err := os.MkdirAll(filepath.Join(dir, ConfigDirName), credDirPerm); err != nil {
		return fmt.Errorf("create smoke vault config: %w", err)
	}
	files := map[string]string{
		filepath.Join(dir, ConfigDirName, "app.json"): "{}\n",
		filepath.Join(dir, "smoke-note.md"):           "# homeplane smoke\n\nDisposable. Safe to delete.\n",
	}
	for path, body := range files {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return fmt.Errorf("write smoke vault file: %w", err)
		}
	}
	return nil
}

// SyncUnit builds the supervised continuous-sync unit.
//
// The unit runs `homeplane-agent vault sync run`, NOT the sync CLI: the agent
// reads the credential from its own 0600 file and records its own start in the
// restart ledger. That keeps the unit file free of secrets and gives `status`
// a restart count on both platforms without parsing supervisor logs.
func SyncUnit(agentBinary, stateDir, vaultPath string) (supervise.Unit, error) {
	if strings.TrimSpace(agentBinary) == "" {
		return supervise.Unit{}, errors.New("vault: the supervision unit needs the homeplane-agent path")
	}
	logDir := filepath.Join(stateDir, "logs")
	if err := os.MkdirAll(logDir, credDirPerm); err != nil {
		return supervise.Unit{}, fmt.Errorf("vault: create log directory: %w", err)
	}
	u := supervise.Unit{
		Label:           SyncUnitLabel,
		Description:     "Homeplane: continuous Obsidian Sync for " + vaultPath,
		Program:         agentBinary,
		Args:            []string{"vault", "sync", "run", "-state-dir", stateDir},
		WorkingDir:      stateDir,
		StdoutPath:      filepath.Join(logDir, "vault-sync.log"),
		StderrPath:      filepath.Join(logDir, "vault-sync.err.log"),
		KeepAlive:       true,
		RunAtLoad:       true,
		ThrottleSeconds: supervise.DefaultThrottleSeconds,
	}
	return u, u.Validate()
}

// ErrIndexInsideVault names the R14 invariant that keeps machine-local state
// out of the synchronized tree. Task .11 owns the GNO index itself; the
// CONTRACT lives here, next to the sync that would otherwise propagate it.
var ErrIndexInsideVault = errors.New("vault: machine-local state must not live inside the synchronized vault")

// EnsureOutsideVault refuses any machine-local path (a GNO index, a snapshot, a
// log) that resolves inside the vault.
func EnsureOutsideVault(path, vaultPath string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("vault: path is required")
	}
	inside, err := isInside(path, vaultPath)
	if err != nil {
		return err
	}
	if inside {
		return fmt.Errorf("%w: %s is inside %s", ErrIndexInsideVault, path, vaultPath)
	}
	return nil
}

// RunSync is the body of the supervised process: record the start, sync
// continuously, record the exit. It is what `homeplane-agent vault sync run`
// calls, and it is the only place a restart becomes visible to `status`.
func RunSync(ctx context.Context, opts RunOptions) error {
	tracker := supervise.Tracker{Dir: opts.StateDir, Label: SyncUnitLabel}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if _, err := tracker.RecordStart(now(), os.Getpid(), "supervised start"); err != nil {
		return err
	}
	err := opts.Run(ctx)
	code := 0
	detail := ""
	if err != nil {
		code = 1
		detail = firstLine(err.Error())
	}
	if _, recErr := tracker.RecordExit(now(), code, detail); recErr != nil && err == nil {
		return recErr
	}
	return err
}

// RunOptions parameterises the supervised body so the process lifecycle is
// testable without ever launching a real sync.
type RunOptions struct {
	StateDir string
	Now      func() time.Time
	// Run performs the actual continuous sync and returns when it stops.
	Run func(context.Context) error
}
