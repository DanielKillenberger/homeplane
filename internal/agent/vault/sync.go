package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
)

// Sync activation is the dangerous operation in this package, so it is split
// into explicit stages that each refuse independently:
//
//	Prepare   1. the vault is a real directory (canonicalized)
//	          2. an auth token is stored
//	          3. the CLI is the pinned, checksummed build
//	          4. a DISPOSABLE vault survives the same build      (unauthenticated
//	             contract checks here; the AUTHENTICATED smoke is .7-gated)
//	          5. the real vault is snapshotted
//	          6. one real sync pass, then a content diff
//	          7. the diff is inside the guard policy
//	Install   8. write the supervision unit + persist the resolved CLI path
//	Apply     9. load the unit into launchd/systemd (explicit, never implicit)
//
// Steps 4 and 5 are the point of the ordering: by the time the real vault is
// synced, the same build has been exercised against a throwaway vault and the
// real vault has already been copied aside.

// SyncUnitLabel identifies the supervised continuous-sync process.
const SyncUnitLabel = supervise.VaultSyncLabel

// SmokeVaultName is the disposable vault created for the pre-activation smoke.
const SmokeVaultName = "smoke-vault"

// ConfigFileName records what activation resolved, so the supervised process
// and `status` do not have to re-derive it (and cannot disagree).
const ConfigFileName = "vault-sync.json"

// ConfigSchemaVersion is bumped when the on-disk shape changes.
const ConfigSchemaVersion = 1

// Config is the persisted result of activation.
//
// OBPath is the load-bearing field: the supervised `vault sync run` gets the
// resolved, verified CLI path from the unit's own argv, and falls back to this
// file. Without it the supervised process refuses on every launch and the
// service crash-loops forever while looking "installed".
type Config struct {
	SchemaVersion int       `json:"schema_version"`
	VaultPath     string    `json:"vault_path"`
	OBPath        string    `json:"ob_path"`
	PinVersion    string    `json:"pin_version"`
	UnitLabel     string    `json:"unit_label"`
	UnitPath      string    `json:"unit_path"`
	Platform      string    `json:"platform"`
	Applied       bool      `json:"applied"`
	SnapshotPath  string    `json:"snapshot_path,omitempty"`
	InstalledAt   time.Time `json:"installed_at"`
	AppliedAt     time.Time `json:"applied_at,omitempty"`
}

// ConfigPath is where the activation record lives.
func ConfigPath(stateDir string) string { return filepath.Join(stateDir, ConfigFileName) }

// ErrNotActivated means sync has never been activated on this machine.
var ErrNotActivated = errors.New("vault: sync has not been activated on this machine")

// LoadConfig reads the activation record.
func LoadConfig(stateDir string) (Config, error) {
	raw, err := os.ReadFile(ConfigPath(stateDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, ErrNotActivated
		}
		return Config{}, fmt.Errorf("vault: read sync config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("vault: parse %s: %w", ConfigPath(stateDir), err)
	}
	return c, nil
}

// SaveConfig persists the activation record atomically.
func SaveConfig(stateDir string, c Config) error {
	c.SchemaVersion = ConfigSchemaVersion
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("vault: encode sync config: %w", err)
	}
	return writeFileAtomic(ConfigPath(stateDir), append(raw, '\n'), credFilePerm)
}

// ── Stage 1: Prepare ─────────────────────────────────────────────────────────

// PrepareOptions describes the safety sequence up to (not including) install.
type PrepareOptions struct {
	// StateDir is the agent state directory.
	StateDir string
	// VaultPath is the REAL vault. It is canonicalized before anything uses it.
	VaultPath string
	// CLI is the obsidian-headless wrapper.
	CLI CLI
	// Secrets carries the account token and, when the vault is end-to-end
	// encrypted, its password.
	Secrets Secrets
	// Policy bounds the destructive diff. Zero value means DefaultGuardPolicy.
	Policy GuardPolicy
	// SnapshotDir overrides where the pre-activation snapshot is written.
	SnapshotDir string
	// SmokeVaultDir overrides the disposable smoke vault.
	SmokeVaultDir string
	// SmokeRemoteVault names a DISPOSABLE remote vault to rehearse the full
	// authenticated lifecycle against (`sync-setup` then `sync`). Empty runs the
	// unauthenticated CONTRACT rehearsal instead — see smoke() for exactly what
	// each one does and does not prove. Task .7 supplies this, with Daniel
	// present and a throwaway remote vault created for the purpose.
	SmokeRemoteVault string
	// SkipSmoke skips the disposable-vault rehearsal. Only for a re-activation
	// that already smoked this exact build in the same run.
	SkipSmoke bool
	// Now overrides the clock.
	Now func() time.Time
}

// PrepareResult is the evidence that the safety sequence actually ran.
type PrepareResult struct {
	VaultPath    string `json:"vault_path"`
	OBPath       string `json:"ob_path"`
	SnapshotPath string `json:"snapshot_path"`
	SmokePassed  bool   `json:"smoke_passed"`
	SmokeSkipped bool   `json:"smoke_skipped"`
	// SmokeMode is "lifecycle" (authenticated sync-setup + sync against a
	// disposable remote), "contract" (unauthenticated), or "skipped". Recording
	// it keeps the evidence honest about which rehearsal actually ran.
	SmokeMode string `json:"smoke_mode"`
	Pin       Pin    `json:"pin"`
	Diff      Diff   `json:"diff"`
	FileCount int    `json:"file_count"`
}

// Prepare runs every refusal that must happen before a machine is allowed to
// supervise continuous sync.
func Prepare(ctx context.Context, opts PrepareOptions) (PrepareResult, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	res := PrepareResult{Pin: opts.CLI.Pin}

	if strings.TrimSpace(opts.StateDir) == "" {
		return res, errors.New("vault: state directory is required")
	}
	// 1. canonicalize + validate. Everything below uses this one path.
	vaultPath, err := ValidatePath(opts.VaultPath)
	if err != nil {
		return res, err
	}
	res.VaultPath = vaultPath

	// 2. an auth token, or nothing can authenticate. An unauthenticated sync
	// against a real vault is exactly the "remote side looks empty" case the
	// guard exists to catch, and it must never be reached.
	if strings.TrimSpace(opts.Secrets.AuthToken) == "" {
		return res, ErrNoAuthToken
	}

	// 3. the pinned build.
	if err := opts.CLI.Verify(ctx); err != nil {
		return res, err
	}
	entrypoint, err := opts.CLI.Entrypoint()
	if err != nil {
		return res, err
	}
	res.OBPath = opts.CLI.Bin
	_ = entrypoint

	// 4. disposable-vault rehearsal on this exact build, before the real vault.
	if opts.SkipSmoke {
		res.SmokeSkipped = true
		res.SmokeMode = SmokeModeSkipped
	} else {
		mode, err := smoke(ctx, opts)
		res.SmokeMode = mode
		if err != nil {
			return res, fmt.Errorf("vault: pre-activation smoke on a disposable vault failed (the real vault was not touched): %w", err)
		}
		res.SmokePassed = true
	}

	// 5. snapshot the real vault.
	snapshotDir := opts.SnapshotDir
	if snapshotDir == "" {
		snapshotDir = filepath.Join(opts.StateDir, "snapshots", now().UTC().Format("20060102T150405Z"))
	}
	before, err := Snapshot(vaultPath, snapshotDir)
	if err != nil {
		return res, err
	}
	res.SnapshotPath = snapshotDir
	res.FileCount = len(before.Files)

	// 6. one real sync pass.
	if _, err := opts.CLI.Run(ctx, Invocation{
		Args:       SyncArgs(vaultPath),
		Secrets:    opts.Secrets,
		Stdin:      promptAnswers(opts.Secrets),
		WorkingDir: vaultPath,
	}); err != nil {
		if errors.Is(err, ErrNotConfigured) {
			return res, fmt.Errorf("%w — %s has never been bound to a remote vault; "+
				"run `homeplane-agent vault retrieve` for a new machine, or `ob sync-setup` for an existing vault",
				err, vaultPath)
		}
		return res, err
	}
	after, err := Scan(vaultPath)
	if err != nil {
		return res, err
	}
	res.Diff = Compare(before, after)

	// 7. the guard.
	policy := opts.Policy
	if policy == (GuardPolicy{}) {
		policy = DefaultGuardPolicy()
	}
	if err := policy.Check(before, res.Diff, snapshotDir); err != nil {
		return res, err
	}
	return res, nil
}

// promptAnswers feeds upstream's interactive prompts on stdin. Upstream also
// accepts `--password`, which this agent never uses: argv is world-readable.
// The trailing newlines matter — each answer is one prompt.
func promptAnswers(s Secrets) string {
	var sb strings.Builder
	if s.E2EPassword != "" {
		sb.WriteString(s.E2EPassword + "\n")
	}
	if s.MFACode != "" {
		sb.WriteString(s.MFACode + "\n")
	}
	return sb.String()
}

// Smoke modes, recorded in the evidence so nobody has to guess which rehearsal
// a given activation actually performed.
const (
	// SmokeModeLifecycle ran the real authenticated lifecycle — `sync-setup`
	// against a DISPOSABLE remote vault, then a real `sync` pass.
	SmokeModeLifecycle = "lifecycle"
	// SmokeModeContract ran the unauthenticated contract rehearsal.
	SmokeModeContract = "contract"
	// SmokeModeSkipped means no rehearsal ran.
	SmokeModeSkipped = "skipped"
)

// smoke rehearses the pinned CLI against a throwaway vault, and returns which
// rehearsal it performed.
//
// There are two, because they prove different things and only one of them is
// available without Daniel's account:
//
//	LIFECYCLE (opts.SmokeRemoteVault set) — the real thing. `sync-setup` binds
//	  the disposable directory to a DISPOSABLE remote vault, then a real `sync`
//	  pass runs. This is the rehearsal the spec asks for, and task .7 supplies
//	  the throwaway remote to make it possible.
//
//	CONTRACT (default) — explicitly NOT a sync rehearsal. Calling `sync` on a
//	  directory that was never `sync-setup`, just because it has a `.obsidian`
//	  folder, is not a valid lifecycle: upstream refuses it with a missing-
//	  configuration error, so a "successful" pass would only ever mean the fake
//	  accepted something the real build rejects. Instead this asserts the pinned
//	  build executes, that it REFUSES an unconfigured directory the way upstream
//	  documents, and that it leaves that directory byte-identical.
//
// Both end in the same guard: a build that damages a throwaway vault must never
// be pointed at the real one.
func smoke(ctx context.Context, opts PrepareOptions) (string, error) {
	mode := SmokeModeContract
	if strings.TrimSpace(opts.SmokeRemoteVault) != "" {
		mode = SmokeModeLifecycle
	}

	dir := opts.SmokeVaultDir
	if dir == "" {
		base, err := os.MkdirTemp(opts.StateDir, SmokeVaultName+"-")
		if err != nil {
			return mode, fmt.Errorf("create disposable smoke vault: %w", err)
		}
		defer os.RemoveAll(base)
		dir = base
	}
	if err := scaffoldVault(dir); err != nil {
		return mode, err
	}
	canonical, err := Canonicalize(dir)
	if err != nil {
		return mode, err
	}
	before, err := Scan(canonical)
	if err != nil {
		return mode, err
	}

	var runErr error
	switch mode {
	case SmokeModeLifecycle:
		runErr = smokeLifecycle(ctx, opts, canonical)
	default:
		runErr = smokeContract(ctx, opts, canonical)
	}

	after, err := Scan(canonical)
	if err != nil {
		return mode, err
	}
	// The guard runs whether or not the CLI reported success: a destructive
	// failure is still destructive, and this is the check that matters most.
	policy := opts.Policy
	if policy == (GuardPolicy{}) {
		policy = DefaultGuardPolicy()
	}
	if err := policy.Check(before, Compare(before, after), canonical); err != nil {
		return mode, err
	}
	return mode, runErr
}

// smokeLifecycle runs the genuine upstream sequence against a disposable pair.
func smokeLifecycle(ctx context.Context, opts PrepareOptions, dir string) error {
	if _, err := opts.CLI.Run(ctx, Invocation{
		Args:       SyncSetupArgs(opts.SmokeRemoteVault, dir),
		Secrets:    opts.Secrets,
		Stdin:      promptAnswers(opts.Secrets),
		WorkingDir: dir,
	}); err != nil {
		return fmt.Errorf("sync-setup on the disposable vault: %w", err)
	}
	if _, err := opts.CLI.Run(ctx, Invocation{
		Args:       SyncArgs(dir),
		Secrets:    opts.Secrets,
		Stdin:      promptAnswers(opts.Secrets),
		WorkingDir: dir,
	}); err != nil {
		return fmt.Errorf("sync on the disposable vault: %w", err)
	}
	return nil
}

// smokeContract proves the build runs and refuses an unconfigured directory.
//
// The refusal IS the assertion. `sync-status` on a directory that was never
// bound to a remote vault must come back as ErrNotConfigured — if it comes back
// as success, the binary is not behaving like the pinned build and nothing
// further should be trusted to it.
func smokeContract(ctx context.Context, opts PrepareOptions, dir string) error {
	_, err := opts.CLI.Run(ctx, Invocation{
		Args:       SyncStatusArgs(dir),
		Secrets:    opts.Secrets,
		WorkingDir: dir,
	})
	switch {
	case errors.Is(err, ErrNotConfigured):
		return nil // exactly what upstream documents for an unconfigured path
	case err == nil:
		return errors.New("the CLI reported success for a directory that was never `sync-setup` — " +
			"the pinned build refuses that, so this binary is not behaving like the pinned build")
	default:
		// An auth failure here still means the build ran and declined; anything
		// else is a build we should not point at the real vault.
		var authErr *AuthError
		if errors.As(err, &authErr) {
			return nil
		}
		return err
	}
}

// scaffoldVault makes a directory look like a real vault: a config directory
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

// ── Stage 2: Install ─────────────────────────────────────────────────────────

// InstallOptions describes writing the supervision unit.
type InstallOptions struct {
	StateDir    string
	Installer   supervise.Installer
	AgentBinary string
	Prepared    PrepareResult
	Now         func() time.Time
}

// Install writes the supervision unit and persists the activation record.
//
// Installing is NOT activating: the unit file exists but the supervisor has not
// been told about it. That distinction is recorded, because a machine with an
// installed-but-unloaded unit is a machine whose vault is not syncing.
func Install(opts InstallOptions) (Config, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	unit, err := SyncUnit(opts.AgentBinary, opts.StateDir, opts.Prepared.VaultPath, opts.Prepared.OBPath)
	if err != nil {
		return Config{}, err
	}
	// A unit file is world-readable; every stored secret is asserted absent.
	secrets, _ := LoadSecrets(opts.StateDir)
	unitPath, err := opts.Installer.Install(unit, secrets.all()...)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		VaultPath:    opts.Prepared.VaultPath,
		OBPath:       opts.Prepared.OBPath,
		PinVersion:   opts.Prepared.Pin.Version,
		UnitLabel:    unit.Label,
		UnitPath:     unitPath,
		Platform:     string(opts.Installer.Platform),
		Applied:      false,
		SnapshotPath: opts.Prepared.SnapshotPath,
		InstalledAt:  now().UTC(),
	}
	if err := SaveConfig(opts.StateDir, cfg); err != nil {
		return Config{}, err
	}
	// A fresh unit starts a fresh restart history; otherwise an old crash loop
	// would keep a newly installed unit looking broken.
	_ = (supervise.Tracker{Dir: opts.StateDir, Label: unit.Label}).Reset()
	return cfg, nil
}

// ── Stage 3: Apply ───────────────────────────────────────────────────────────

// Apply loads the installed unit into launchd/systemd.
//
// Without a runner on the installer this reports what WOULD run and leaves
// Applied false — the default, because mutating a live user session is not
// something a status-reporting command should do implicitly.
func Apply(stateDir string, installer supervise.Installer, uid string, now func() time.Time) (Config, []supervise.Command, error) {
	if now == nil {
		now = time.Now
	}
	cfg, err := LoadConfig(stateDir)
	if err != nil {
		return Config{}, nil, err
	}
	unit, err := SyncUnit(agentBinaryFromConfig(cfg), stateDir, cfg.VaultPath, cfg.OBPath)
	if err != nil {
		return cfg, nil, err
	}
	cmds, err := installer.Activate(unit, uid)
	if err != nil {
		return cfg, cmds, err
	}
	if installer.Runner == nil {
		return cfg, cmds, nil
	}
	cfg.Applied = true
	cfg.AppliedAt = now().UTC()
	if err := SaveConfig(stateDir, cfg); err != nil {
		return cfg, cmds, err
	}
	return cfg, cmds, nil
}

// agentBinaryFromConfig recovers the program the installed unit runs. The unit
// file itself is the record; this only needs to reproduce the same Unit value
// for the supervisor's own label-based commands.
func agentBinaryFromConfig(cfg Config) string {
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return cfg.OBPath
}

// SyncUnit builds the supervised continuous-sync unit.
//
// The unit runs `homeplane-agent vault sync run`, NOT the sync CLI: the agent
// reads credentials from its own 0600 files and records its own start in the
// restart ledger. The resolved CLI path is passed as an ordinary argument —
// it is a path, not a secret — so the supervised process never has to guess it.
func SyncUnit(agentBinary, stateDir, vaultPath, obPath string) (supervise.Unit, error) {
	if strings.TrimSpace(agentBinary) == "" {
		return supervise.Unit{}, errors.New("vault: the supervision unit needs the homeplane-agent path")
	}
	if strings.TrimSpace(obPath) == "" {
		return supervise.Unit{}, errors.New("vault: the supervision unit needs the verified obsidian-headless path")
	}
	logDir := filepath.Join(stateDir, "logs")
	if err := os.MkdirAll(logDir, credDirPerm); err != nil {
		return supervise.Unit{}, fmt.Errorf("vault: create log directory: %w", err)
	}
	u := supervise.Unit{
		Label:           SyncUnitLabel,
		Description:     "Homeplane: continuous Obsidian Sync for " + vaultPath,
		Program:         agentBinary,
		Args:            []string{"vault", "sync", "run", "-state-dir", stateDir, "-ob", obPath},
		WorkingDir:      stateDir,
		StdoutPath:      filepath.Join(logDir, "vault-sync.log"),
		StderrPath:      filepath.Join(logDir, "vault-sync.err.log"),
		KeepAlive:       true,
		RunAtLoad:       true,
		ThrottleSeconds: supervise.DefaultThrottleSeconds,
	}
	return u, u.Validate()
}

// ── The index-location contract (reserved for .11) ───────────────────────────

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

// ── The supervised process ───────────────────────────────────────────────────

// RunOptions parameterises the supervised body so the process lifecycle is
// testable without ever launching a real sync.
type RunOptions struct {
	StateDir string
	Now      func() time.Time
	// Run performs the actual continuous sync and returns when it stops.
	Run func(context.Context) error
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
