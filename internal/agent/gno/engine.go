package gno

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
)

// Activation is staged, and every stage can refuse:
//
//	Prepare  1. the vault is a real directory
//	         2. the CLI is the pinned version
//	         3. the index location is machine-local and disposable (R14)
//	         4. `gno setup` binds the vault and VERIFIES it — upstream only
//	            reports success after a real lexical retrieval hits a document
//	         5. the index database exists where we asserted it would
//	         6. `gno doctor` says what state the engine is in
//	         7. the stdio launch template is derived from upstream and probed
//	Install  8. write the supervision unit, publish the endpoint descriptor,
//	            register the removal plan
//	Apply    9. load the unit into launchd/systemd (explicit, never implicit)
//
// Steps 4 and 7 are the ones that make this more than configuration: an
// activation that "succeeded" without a retrieval hit and without a successful
// stdio launch would be a machine that reports a working retrieval engine and
// answers nothing.

// UnitLabel identifies the supervised retrieval engine.
const UnitLabel = supervise.GNOLabel

// ConfigFileName records what activation resolved.
const ConfigFileName = "gno.json"

// ConfigSchemaVersion is bumped when the on-disk shape changes.
const ConfigSchemaVersion = 1

// DefaultCollection is the collection name the vault is bound to.
const DefaultCollection = "daniel-os"

// DefaultDaemonHost and DefaultDaemonPort bind the engine's own gateway to
// loopback. Nothing outside this machine may reach the index: vault content is
// the most sensitive data the machine plane holds.
const (
	DefaultDaemonHost = "127.0.0.1"
	DefaultDaemonPort = 3077
)

// Config is the persisted result of activation.
type Config struct {
	SchemaVersion int       `json:"schema_version"`
	Bin           string    `json:"bin"`
	Version       string    `json:"version"`
	Collection    string    `json:"collection"`
	VaultPath     string    `json:"vault_path"`
	Index         string    `json:"index"`
	Paths         Paths     `json:"paths"`
	IndexDBPath   string    `json:"index_db_path"`
	UnitLabel     string    `json:"unit_label"`
	UnitPath      string    `json:"unit_path"`
	Platform      string    `json:"platform"`
	DaemonHost    string    `json:"daemon_host"`
	DaemonPort    int       `json:"daemon_port"`
	Applied       bool      `json:"applied"`
	InstalledAt   time.Time `json:"installed_at"`
	AppliedAt     time.Time `json:"applied_at,omitempty"`
}

// ConfigPath is where the activation record lives.
func ConfigPath(stateDir string) string { return filepath.Join(stateDir, ConfigFileName) }

// ErrNotActivated means GNO has never been activated on this machine.
var ErrNotActivated = errors.New("gno: the retrieval engine has not been activated on this machine")

// LoadConfig reads the activation record.
func LoadConfig(stateDir string) (Config, error) {
	raw, err := os.ReadFile(ConfigPath(stateDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, ErrNotActivated
		}
		return Config{}, fmt.Errorf("gno: read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("gno: parse %s: %w", ConfigPath(stateDir), err)
	}
	return c, nil
}

// SaveConfig persists the activation record atomically.
func SaveConfig(stateDir string, c Config) error {
	c.SchemaVersion = ConfigSchemaVersion
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("gno: encode config: %w", err)
	}
	return writeFileAtomic(ConfigPath(stateDir), append(raw, '\n'), filePerm)
}

// ── Stage 1: Prepare ─────────────────────────────────────────────────────────

// PrepareOptions describes everything that must hold before supervision.
type PrepareOptions struct {
	StateDir   string
	VaultPath  string
	Collection string
	CLI        CLI
	// ExtraSyncedRoots names machine-specific synchronized trees beyond the
	// ones the marker list knows about.
	ExtraSyncedRoots []string
	// ProbeQuery is the retrieval used to prove the endpoint answers with real
	// vault content. Empty means the collection name, which any bound vault
	// indexes by path.
	ProbeQuery string
	// SkipMCPProbe suppresses the stdio launch probe. Only for a re-activation
	// that already probed this exact build in the same run.
	SkipMCPProbe bool
	Now          func() time.Time
}

// PrepareResult is the evidence that the sequence actually ran.
type PrepareResult struct {
	VaultPath   string         `json:"vault_path"`
	Collection  string         `json:"collection"`
	Bin         string         `json:"bin"`
	Version     string         `json:"version"`
	Paths       Paths          `json:"paths"`
	IndexDBPath string         `json:"index_db_path"`
	IndexBytes  int64          `json:"index_bytes"`
	SyncedRoots []string       `json:"synced_roots_checked,omitempty"`
	Doctor      DoctorReport   `json:"doctor"`
	Launch      LaunchTemplate `json:"launch_template"`
	Probe       MCPProbe       `json:"mcp_probe"`
	SetupOutput string         `json:"setup_summary,omitempty"`
}

// LaunchTemplate is the stdio server entry derived from upstream.
type LaunchTemplate struct {
	Command     string            `json:"command"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env,omitempty"`
	DerivedFrom string            `json:"derived_from"`
}

// ErrNoVaultPath means activation was asked to bind nothing.
var ErrNoVaultPath = errors.New("gno: no vault path — run `homeplane-agent vault detect -record` first")

// ErrIndexMissing means `gno setup` reported success but produced no index
// database where the contract says it must live. That combination means the
// engine is writing its index somewhere unasserted, which is precisely the
// failure R14 forbids.
var ErrIndexMissing = errors.New("gno: setup produced no index database at the asserted machine-local path")

// Prepare runs every refusal that must precede supervision.
func Prepare(ctx context.Context, opts PrepareOptions) (PrepareResult, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	res := PrepareResult{Collection: opts.Collection}
	if strings.TrimSpace(res.Collection) == "" {
		res.Collection = DefaultCollection
	}
	if strings.TrimSpace(opts.StateDir) == "" {
		return res, errors.New("gno: state directory is required")
	}

	// 1. a real vault.
	if strings.TrimSpace(opts.VaultPath) == "" {
		return res, ErrNoVaultPath
	}
	vaultPath, err := absClean(opts.VaultPath)
	if err != nil {
		return res, err
	}
	info, err := os.Stat(vaultPath)
	if err != nil {
		return res, fmt.Errorf("gno: vault path %s: %w", vaultPath, err)
	}
	if !info.IsDir() {
		return res, fmt.Errorf("gno: vault path %s is not a directory", vaultPath)
	}
	res.VaultPath = vaultPath

	// 2. the pinned build.
	cli := opts.CLI
	if err := cli.Verify(ctx); err != nil {
		return res, err
	}
	res.Bin = cli.Bin
	res.Version = cli.Pin.Version

	// 3. the index is machine-local and disposable.
	paths := cli.Dirs
	if !paths.Complete() {
		paths = DefaultPaths(opts.StateDir)
		cli.Dirs = paths
	}
	syncedRoots := append(KnownSyncedRoots(), opts.ExtraSyncedRoots...)
	if err := EnsureDisposable(paths, vaultPath, syncedRoots...); err != nil {
		return res, err
	}
	if err := paths.Create(); err != nil {
		return res, err
	}
	res.Paths = paths
	res.SyncedRoots = syncedRoots
	res.IndexDBPath = paths.IndexDBPath(cli.Index)

	// 4. bind and VERIFY. Upstream's `setup` only succeeds after a real lexical
	// retrieval returns a hit, so this is the step that proves the engine can
	// actually answer from this vault.
	out, err := cli.Run(ctx, Invocation{Args: SetupArgs(vaultPath, res.Collection), WorkingDir: opts.StateDir})
	if err != nil {
		return res, fmt.Errorf("gno: bind the vault (`gno setup`): %w", err)
	}
	res.SetupOutput = firstLine(out)

	// 5. the index landed where we asserted it would.
	dbInfo, err := os.Stat(res.IndexDBPath)
	if err != nil || dbInfo.Size() == 0 {
		return res, fmt.Errorf("%w: expected %s", ErrIndexMissing, res.IndexDBPath)
	}
	res.IndexBytes = dbInfo.Size()

	// 6. health.
	doctor, err := cli.Doctor(ctx)
	if err != nil {
		return res, fmt.Errorf("gno: health probe: %w", err)
	}
	res.Doctor = doctor
	if failing := doctor.Errors(); len(failing) > 0 {
		return res, fmt.Errorf("gno: the engine reports %d failing check(s): %s", len(failing), doctor.Summary())
	}

	// 7. derive the stdio launch template from upstream, then probe it.
	command, args, env, err := cli.DeriveLaunchTemplate(ctx, TargetClaudeCode, ScopeUser)
	if err != nil {
		return res, fmt.Errorf("gno: derive the MCP launch template: %w", err)
	}
	res.Launch = LaunchTemplate{
		Command:     command,
		Args:        args,
		Env:         env,
		DerivedFrom: "gno " + strings.Join(MCPInstallArgs(TargetClaudeCode, ScopeUser, true), " "),
	}
	if opts.SkipMCPProbe {
		return res, nil
	}
	query := strings.TrimSpace(opts.ProbeQuery)
	if query == "" {
		query = res.Collection
	}
	res.Probe = ProbeMCP(ctx, MCPProbeOptions{
		Command:  command,
		Args:     args,
		Env:      env,
		CallTool: "gno_search",
		CallArgs: map[string]any{"query": query},
	})
	if !res.Probe.OK {
		return res, fmt.Errorf("gno: the stdio MCP endpoint did not answer: %s", res.Probe.Detail)
	}
	return res, nil
}

// ── Stage 2: Install ─────────────────────────────────────────────────────────

// InstallOptions describes writing the unit, the descriptor, and the removal
// plan.
type InstallOptions struct {
	StateDir    string
	Installer   supervise.Installer
	AgentBinary string
	Prepared    PrepareResult
	DaemonHost  string
	DaemonPort  int
	Index       string
	Now         func() time.Time
}

// Install writes the supervision unit, publishes the endpoint descriptor, and
// registers the removal plan.
//
// Installing is NOT activating: the unit file exists but the supervisor has not
// been told about it, and that distinction is recorded — a machine with an
// installed-but-unloaded unit is a machine whose index is going stale.
func Install(opts InstallOptions) (Config, Descriptor, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	host := opts.DaemonHost
	if strings.TrimSpace(host) == "" {
		host = DefaultDaemonHost
	}
	port := opts.DaemonPort
	if port <= 0 {
		port = DefaultDaemonPort
	}

	unit, err := DaemonUnit(opts.AgentBinary, opts.StateDir, host, port)
	if err != nil {
		return Config{}, Descriptor{}, err
	}
	unitPath, err := opts.Installer.Install(unit)
	if err != nil {
		return Config{}, Descriptor{}, err
	}

	descriptor := Descriptor{
		SchemaVersion: DescriptorSchemaVersion,
		Component:     ComponentRetrievalEngine,
		Engine:        "gno",
		EngineVersion: opts.Prepared.Version,
		Transport:     TransportStdio,
		Command:       opts.Prepared.Launch.Command,
		Args:          opts.Prepared.Launch.Args,
		Env:           opts.Prepared.Launch.Env,
		ServerName:    "gno",
		Collection:    opts.Prepared.Collection,
		VaultPath:     opts.Prepared.VaultPath,
		DerivedFrom:   opts.Prepared.Launch.DerivedFrom,
		Supervision: &SupervisionInfo{
			Mode:          "daemon",
			UnitLabel:     unit.Label,
			Host:          host,
			Port:          port,
			HealthCommand: opts.Prepared.Bin,
			HealthArgs:    DoctorArgs(),
		},
		WrittenAt: now().UTC(),
	}
	if err := SaveDescriptor(opts.StateDir, descriptor); err != nil {
		return Config{}, Descriptor{}, err
	}

	cfg := Config{
		Bin:         opts.Prepared.Bin,
		Version:     opts.Prepared.Version,
		Collection:  opts.Prepared.Collection,
		VaultPath:   opts.Prepared.VaultPath,
		Index:       opts.Index,
		Paths:       opts.Prepared.Paths,
		IndexDBPath: opts.Prepared.IndexDBPath,
		UnitLabel:   unit.Label,
		UnitPath:    unitPath,
		Platform:    string(opts.Installer.Platform),
		DaemonHost:  host,
		DaemonPort:  port,
		Applied:     false,
		InstalledAt: now().UTC(),
	}
	if err := SaveConfig(opts.StateDir, cfg); err != nil {
		return Config{}, Descriptor{}, err
	}
	if err := RegisterRemoval(opts.StateDir, cfg, opts.Installer, currentUID(), now()); err != nil {
		return Config{}, Descriptor{}, err
	}
	// A fresh unit starts a fresh restart history.
	_ = (supervise.Tracker{Dir: opts.StateDir, Label: unit.Label}).Reset()
	return cfg, descriptor, nil
}

// DaemonUnit builds the supervised engine unit.
//
// The unit runs `homeplane-agent gno run`, not `gno daemon` directly: the agent
// records its own start and exit in the shared restart ledger, which is the only
// thing that makes a crash loop visible to `status` (launchd and systemd both
// restart forever without telling anyone).
func DaemonUnit(agentBinary, stateDir, host string, port int) (supervise.Unit, error) {
	if strings.TrimSpace(agentBinary) == "" {
		return supervise.Unit{}, errors.New("gno: the supervision unit needs the homeplane-agent path")
	}
	logDir := filepath.Join(stateDir, "logs")
	if err := os.MkdirAll(logDir, dirPerm); err != nil {
		return supervise.Unit{}, fmt.Errorf("gno: create log directory: %w", err)
	}
	u := supervise.Unit{
		Label:       UnitLabel,
		Description: "Homeplane: retrieval engine (GNO) continuous indexing",
		Program:     agentBinary,
		Args: []string{"gno", "run",
			"-state-dir", stateDir,
			"-host", host,
			"-port", strconv.Itoa(port)},
		WorkingDir:      stateDir,
		StdoutPath:      filepath.Join(logDir, "gno.log"),
		StderrPath:      filepath.Join(logDir, "gno.err.log"),
		KeepAlive:       true,
		RunAtLoad:       true,
		ThrottleSeconds: supervise.DefaultThrottleSeconds,
	}
	return u, u.Validate()
}

// ── Stage 3: Apply ───────────────────────────────────────────────────────────

// Apply loads the installed unit into launchd/systemd.
func Apply(stateDir string, installer supervise.Installer, uid string, now func() time.Time) (Config, []supervise.Command, error) {
	if now == nil {
		now = time.Now
	}
	cfg, err := LoadConfig(stateDir)
	if err != nil {
		return Config{}, nil, err
	}
	agentBin := cfg.UnitPath
	if exe, err := os.Executable(); err == nil {
		agentBin = exe
	}
	unit, err := DaemonUnit(agentBin, stateDir, cfg.DaemonHost, cfg.DaemonPort)
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

// ── The supervised process ───────────────────────────────────────────────────

// RunOptions parameterises the supervised body so the lifecycle is testable
// without launching a real daemon.
type RunOptions struct {
	StateDir string
	Now      func() time.Time
	// Run performs the actual continuous indexing and returns when it stops.
	Run func(context.Context) error
}

// RunDaemon is the body of the supervised process: record the start, index
// continuously, record the exit. It is what `homeplane-agent gno run` calls,
// and the only place a restart becomes visible to `status`.
func RunDaemon(ctx context.Context, opts RunOptions) error {
	tracker := supervise.Tracker{Dir: opts.StateDir, Label: UnitLabel}
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

// ── Rebuild: the disposable contract, exercised ──────────────────────────────

// Rebuild deletes the machine-local index and rebuilds it from the vault.
//
// This is the self-heal path: deleting the index is a supported operation, and
// the ONLY thing needed to recover from it is the vault, which syncs. Nothing
// here touches the vault itself.
func Rebuild(ctx context.Context, cli CLI, cfg Config) (PrepareResult, error) {
	res := PrepareResult{
		VaultPath:  cfg.VaultPath,
		Collection: cfg.Collection,
		Bin:        cli.Bin,
		Version:    cli.Pin.Version,
		Paths:      cfg.Paths,
	}
	if err := EnsureDisposable(cfg.Paths, cfg.VaultPath); err != nil {
		return res, err
	}
	if err := Discard(cfg.Paths); err != nil {
		return res, err
	}
	// `setup` re-binds AND re-verifies. Using it rather than `index` means the
	// rebuild is held to the same proof as the first activation: a rebuild that
	// produced an index nothing could retrieve from would be worse than no
	// rebuild at all.
	if _, err := cli.Run(ctx, Invocation{Args: SetupArgs(cfg.VaultPath, cfg.Collection)}); err != nil {
		return res, fmt.Errorf("gno: rebuild the index: %w", err)
	}
	dbPath := cfg.Paths.IndexDBPath(cfg.Index)
	info, err := os.Stat(dbPath)
	if err != nil || info.Size() == 0 {
		return res, fmt.Errorf("%w: expected %s", ErrIndexMissing, dbPath)
	}
	res.IndexDBPath = dbPath
	res.IndexBytes = info.Size()
	if doctor, err := cli.Doctor(ctx); err == nil {
		res.Doctor = doctor
	}
	return res, nil
}

func currentUID() string { return strconv.Itoa(os.Getuid()) }
