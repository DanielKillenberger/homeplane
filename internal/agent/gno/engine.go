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
	GatewayToken  string    `json:"gateway_token_file,omitempty"`
	Applied       bool      `json:"applied"`
	InstalledAt   time.Time `json:"installed_at"`
	AppliedAt     time.Time `json:"applied_at,omitempty"`

	// Activation is what the activation sequence actually established: the
	// health report, the derived stdio launch template, and the endpoint probe.
	//
	// It is PERSISTED rather than recomputed because every later command needs
	// it and only activation can produce it. `gno apply` used to re-derive the
	// status detail from an empty result and overwrite a real probe with "never
	// probed" — a command that loads a unit was erasing the evidence that the
	// endpoint works.
	Activation ActivationRecord `json:"activation"`
}

// ActivationRecord is the evidence activation produced, kept with the config.
type ActivationRecord struct {
	Doctor      DoctorReport   `json:"doctor"`
	Launch      LaunchTemplate `json:"launch_template"`
	Probe       MCPProbe       `json:"mcp_probe"`
	ProbeQuery  string         `json:"probe_query,omitempty"`
	ProbeExpect string         `json:"probe_expect,omitempty"`
	IndexBytes  int64          `json:"index_bytes,omitempty"`
}

// activationRecord projects a PrepareResult into the persisted record.
func activationRecord(p PrepareResult) ActivationRecord {
	return ActivationRecord{
		Doctor:      p.Doctor,
		Launch:      p.Launch,
		Probe:       p.Probe,
		ProbeQuery:  p.ProbeQuery,
		ProbeExpect: p.ProbeExpect,
		IndexBytes:  p.IndexBytes,
	}
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
	// ProbeQuery and ProbeExpect record what the endpoint was held to, so the
	// evidence names the document that proved it works rather than merely
	// asserting that something did.
	ProbeQuery  string `json:"probe_query,omitempty"`
	ProbeExpect string `json:"probe_expect,omitempty"`
	SetupOutput string `json:"setup_summary,omitempty"`
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

	// The probe needs GROUND TRUTH, not just a query. A tool call that "worked"
	// proves nothing unless we already know what a correct answer contains — so
	// the index is asked directly first, and the endpoint then has to return the
	// same document. Without this the probe passes on an empty result, an
	// in-band MCP error, or a server talking to somebody else's index.
	truth, query, err := groundTruth(ctx, cli, res.Collection, opts.ProbeQuery, vaultPath)
	if err != nil {
		return res, err
	}
	res.ProbeQuery = query
	res.ProbeExpect = truth
	res.Probe = ProbeMCP(ctx, MCPProbeOptions{
		Command:  command,
		Args:     args,
		Env:      env,
		CallTool: SearchToolName,
		CallArgs: map[string]any{"query": query},
		Expect:   truth,
	})
	if !res.Probe.OK {
		return res, fmt.Errorf("gno: the stdio MCP endpoint did not answer with indexed vault content: %s", res.Probe.Detail)
	}
	return res, nil
}

// SearchToolName is the engine's lexical retrieval tool, as published over MCP.
const SearchToolName = "gno_search"

// ErrNoGroundTruth means the freshly built index returns nothing for any probe
// query, so there is no correct answer to hold the endpoint to.
var ErrNoGroundTruth = errors.New("gno: the index returned no results for any probe query, so the endpoint cannot be verified")

// groundTruth asks the INDEX what a correct answer looks like, and returns the
// evidence string the MCP response must contain plus the query that produced it.
//
// Candidate queries are tried in order of how specific they are: the operator's
// own query, then a distinctive token taken from a real file in the vault, then
// the collection name. The document URI is used as the evidence because it
// appears in both GNO's text rendering and its structured content, and because
// it names the DOCUMENT — a response containing it cannot have come from an
// empty index or a different collection.
func groundTruth(ctx context.Context, cli CLI, collection, explicit, vaultPath string) (string, string, error) {
	var candidates []string
	if q := strings.TrimSpace(explicit); q != "" {
		candidates = append(candidates, q)
	}
	if token := vaultToken(vaultPath); token != "" {
		candidates = append(candidates, token)
	}
	if collection != "" {
		candidates = append(candidates, collection)
	}
	var lastErr error
	for _, q := range candidates {
		hits, err := cli.Search(ctx, q)
		if err != nil {
			if errors.Is(err, ErrNoResults) {
				lastErr = err
				continue
			}
			return "", q, fmt.Errorf("gno: probe the index: %w", err)
		}
		for _, hit := range hits {
			if evidence := strings.TrimSpace(hit.URI); evidence != "" {
				return evidence, q, nil
			}
		}
		lastErr = ErrNoResults
	}
	if lastErr == nil {
		lastErr = ErrNoResults
	}
	return "", "", fmt.Errorf("%w (tried %s)", ErrNoGroundTruth, strings.Join(candidates, ", "))
}

// vaultToken picks a distinctive search term from the vault itself: the base
// name of the first indexable file. It is a far better probe query than the
// collection name, because it is guaranteed to correspond to a document that
// exists rather than to a word that may appear nowhere.
func vaultToken(vaultPath string) string {
	entries, err := os.ReadDir(vaultPath)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".md", ".markdown", ".txt", ".org":
			name := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
			// Split on separators so a term like "meeting-notes-2026" becomes a
			// word the lexical index actually holds.
			for _, part := range strings.FieldsFunc(name, func(r rune) bool {
				return r == '-' || r == '_' || r == ' ' || r == '.'
			}) {
				if len(part) >= 4 {
					return part
				}
			}
			if len(name) >= 3 {
				return name
			}
		}
	}
	return ""
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
	// AllowUnprobed permits installing an activation whose stdio endpoint was
	// never probed. It exists only for the re-activation path that deliberately
	// skipped the probe; the default is to refuse, because publishing a
	// descriptor for an unproven endpoint is how task .6 ends up wiring a harness
	// to something that does not answer.
	AllowUnprobed bool
	Now           func() time.Time
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
	// Validate BEFORE anything is written: an install that has already placed a
	// unit and then discovers the gateway is world-reachable has to unwind, and
	// the simplest unwind is not to have started.
	if err := ValidateGateway(host, port); err != nil {
		return Config{}, Descriptor{}, err
	}
	if strings.TrimSpace(opts.Prepared.Launch.Command) == "" {
		return Config{}, Descriptor{}, errors.New("gno: refusing to install without a derived stdio launch template")
	}
	if !opts.Prepared.Probe.OK && !opts.AllowUnprobed {
		return Config{}, Descriptor{}, errors.New("gno: refusing to install an endpoint whose stdio launch was never proven")
	}

	tokenFile, err := EnsureGatewayToken(opts.Prepared.Paths)
	if err != nil {
		return Config{}, Descriptor{}, err
	}

	// Installation writes four things, and a failure part-way through used to
	// leave the earlier ones behind — including a published endpoint descriptor
	// for an activation that officially failed, which task .6 would then wire a
	// harness to. So every write is registered for rollback, and the DESCRIPTOR
	// IS PUBLISHED LAST: it is the file other components consume, so it must not
	// exist until everything it describes does.
	var written []string
	rollback := func() {
		for i := len(written) - 1; i >= 0; i-- {
			_ = os.Remove(written[i])
		}
	}

	unit, err := DaemonUnit(opts.AgentBinary, opts.StateDir, host, port, tokenFile)
	if err != nil {
		return Config{}, Descriptor{}, err
	}
	unitPath, err := opts.Installer.Install(unit)
	if err != nil {
		return Config{}, Descriptor{}, err
	}
	written = append(written, unitPath)

	cfg := Config{
		Bin:          opts.Prepared.Bin,
		Version:      opts.Prepared.Version,
		Collection:   opts.Prepared.Collection,
		VaultPath:    opts.Prepared.VaultPath,
		Index:        opts.Index,
		Paths:        opts.Prepared.Paths,
		IndexDBPath:  opts.Prepared.IndexDBPath,
		UnitLabel:    unit.Label,
		UnitPath:     unitPath,
		Platform:     string(opts.Installer.Platform),
		DaemonHost:   host,
		DaemonPort:   port,
		GatewayToken: tokenFile,
		Applied:      false,
		InstalledAt:  now().UTC(),
		Activation:   activationRecord(opts.Prepared),
	}
	if err := SaveConfig(opts.StateDir, cfg); err != nil {
		rollback()
		return Config{}, Descriptor{}, err
	}
	written = append(written, ConfigPath(opts.StateDir))

	if err := RegisterRemoval(opts.StateDir, cfg, opts.Installer, currentUID(), now()); err != nil {
		rollback()
		return Config{}, Descriptor{}, err
	}
	written = append(written, RemovalPlanPath(opts.StateDir))

	descriptor := Descriptor{
		SchemaVersion: DescriptorSchemaVersion,
		Component:     ComponentRetrievalEngine,
		Engine:        "gno",
		EngineVersion: opts.Prepared.Version,
		Transport:     TransportStdio,
		// Harnesses launch the AGENT, not the engine, for the same reason the
		// supervision unit does: a launch nobody records is a launch `status`
		// can never report on (R4). The agent is a transparent stdio pass-through
		// that runs the derived upstream template underneath.
		Command:    opts.AgentBinary,
		Args:       StdioWrapperArgs(opts.StateDir),
		Env:        opts.Prepared.Launch.Env,
		ServerName: "gno",
		Underlying: &LaunchTemplate{
			Command:     opts.Prepared.Launch.Command,
			Args:        opts.Prepared.Launch.Args,
			Env:         opts.Prepared.Launch.Env,
			DerivedFrom: opts.Prepared.Launch.DerivedFrom,
		},
		Collection:  opts.Prepared.Collection,
		VaultPath:   opts.Prepared.VaultPath,
		DerivedFrom: opts.Prepared.Launch.DerivedFrom,
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
		rollback()
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
func DaemonUnit(agentBinary, stateDir, host string, port int, tokenFile string) (supervise.Unit, error) {
	if strings.TrimSpace(agentBinary) == "" {
		return supervise.Unit{}, errors.New("gno: the supervision unit needs the homeplane-agent path")
	}
	// The unit is the thing that survives reboots, so the loopback guarantee is
	// re-checked at the moment it is written rather than trusted to whoever
	// called us.
	if err := ValidateGateway(host, port); err != nil {
		return supervise.Unit{}, err
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
			"-port", strconv.Itoa(port),
			// A PATH, never the token itself: unit files are world-readable.
			"-gateway-token-file", tokenFile},
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
	unit, err := DaemonUnit(agentBin, stateDir, cfg.DaemonHost, cfg.DaemonPort, cfg.GatewayToken)
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
	switch {
	case err == nil:
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// A cancelled context is how a supervised process is ASKED to stop —
		// during a rebuild, a shutdown, or a unit reload. Recording that as a
		// failed exit would make every deliberate stop look like a crash in the
		// ledger `status` reads.
		detail = "stopped on request"
	default:
		code = 1
		detail = firstLine(err.Error())
	}
	if _, recErr := tracker.RecordExit(now(), code, detail); recErr != nil && err == nil {
		return recErr
	}
	return err
}

// ── Rebuild: the disposable contract, exercised ──────────────────────────────

// ErrRebuildInProgress means another rebuild holds the lock.
var ErrRebuildInProgress = errors.New("gno: another index rebuild is already running")

// ErrEngineRunning means the supervised daemon is alive and nothing was supplied
// to stop it.
var ErrEngineRunning = errors.New("gno: the retrieval engine is running and holds the index open")

// RebuildOptions describes how to make the index safe to replace.
type RebuildOptions struct {
	StateDir string
	// Quiesce stops whatever is holding the index open and returns a resume
	// function. It is injected rather than assumed because the thing to stop
	// differs by caller: the CLI stops a launchd/systemd unit, a test stops a
	// goroutine, and a machine where the engine was never applied has nothing to
	// stop at all.
	Quiesce func(context.Context) (resume func() error, err error)
	// Probe reports daemon liveness for the refuse-if-running guard. Nil means
	// supervise.ProcessProbe.
	Probe supervise.Probe
}

// Rebuild deletes the machine-local index and rebuilds it from the vault.
//
// This is the self-heal path, and it is the one operation in this package that
// can corrupt state if it is careless. The supervised daemon holds the SQLite
// index open continuously; removing the data directory underneath it leaves the
// daemon writing to an unlinked file on Unix while every client reads the
// replacement — continuous indexing silently attached to a database nobody can
// see. So the daemon is STOPPED first, the rebuild runs under an exclusive lock,
// and the daemon comes back only after the new index has been verified.
//
// Nothing here touches the vault itself: the only thing needed to recover from a
// deleted index is the vault, which syncs.
func Rebuild(ctx context.Context, cli CLI, cfg Config, opts RebuildOptions) (PrepareResult, error) {
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

	stateDir := opts.StateDir
	if strings.TrimSpace(stateDir) == "" {
		return res, errors.New("gno: rebuild needs the agent state directory for its lock")
	}
	unlock, err := acquireRebuildLock(stateDir)
	if err != nil {
		return res, err
	}
	defer unlock()

	// Refuse rather than race. A rebuild that quietly proceeded while the daemon
	// held the old database open would "succeed" and leave the machine indexing
	// into a file that no longer exists.
	if opts.Quiesce == nil {
		if alive, detail := engineIsAlive(stateDir, opts.Probe); alive {
			return res, fmt.Errorf("%w (%s) — stop it first, or rebuild through `homeplane-agent gno rebuild`, which does", ErrEngineRunning, detail)
		}
	} else {
		resume, err := opts.Quiesce(ctx)
		if err != nil {
			return res, fmt.Errorf("gno: stop the retrieval engine before rebuilding: %w", err)
		}
		if resume != nil {
			// Resume runs whatever happened below: a failed rebuild that left the
			// engine stopped would turn a recoverable problem into an outage.
			defer func() { _ = resume() }()
		}
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

// engineIsAlive reports whether the supervised daemon appears to be running.
func engineIsAlive(stateDir string, probe supervise.Probe) (bool, string) {
	_, live, err := (supervise.Tracker{Dir: stateDir, Label: UnitLabel}).Observe(probe)
	if err != nil {
		// An unreadable ledger is not proof of absence, so assume the worst: the
		// cost of a needless refusal is an error message, the cost of a wrong
		// "it is not running" is a corrupted index.
		return true, "restart history unreadable: " + err.Error()
	}
	if !live.Known {
		return true, "cannot tell whether it is running (" + live.Detail + ")"
	}
	return live.Alive, live.Detail
}

// rebuildLockName is the exclusive lock guarding index replacement.
const rebuildLockName = "gno.rebuild.lock"

// staleRebuildLock is how long a lock may sit before it is treated as abandoned
// by a process that died mid-rebuild.
const staleRebuildLock = 30 * time.Minute

// acquireRebuildLock takes an exclusive, atomic lock via O_EXCL creation.
func acquireRebuildLock(stateDir string) (func(), error) {
	path := filepath.Join(stateDir, rebuildLockName)
	take := func() (*os.File, error) {
		return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, filePerm)
	}
	f, err := take()
	if errors.Is(err, os.ErrExist) {
		// A crashed rebuild must not lock the machine out forever, but a lock
		// that is merely OLD is still evidence, so the age threshold is generous.
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > staleRebuildLock {
			_ = os.Remove(path)
			f, err = take()
		}
	}
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, ErrRebuildInProgress
		}
		return nil, fmt.Errorf("gno: take the rebuild lock: %w", err)
	}
	fmt.Fprintf(f, "pid %d at %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	_ = f.Close()
	return func() { _ = os.Remove(path) }, nil
}

// SupervisorQuiesce stops the supervised unit through the platform supervisor
// and returns a resume that starts it again.
//
// It is a no-op when the unit was never applied: there is nothing holding the
// index open, so stopping and starting would only add failure modes.
func SupervisorQuiesce(stateDir string, cfg Config, installer supervise.Installer, uid string) func(context.Context) (func() error, error) {
	return func(ctx context.Context) (func() error, error) {
		if !cfg.Applied || installer.Runner == nil {
			return nil, nil
		}
		agentBin := cfg.UnitPath
		if exe, err := os.Executable(); err == nil {
			agentBin = exe
		}
		unit, err := DaemonUnit(agentBin, stateDir, cfg.DaemonHost, cfg.DaemonPort, cfg.GatewayToken)
		if err != nil {
			return nil, err
		}
		stop, err := installer.StopCommands(unit, uid)
		if err != nil {
			return nil, err
		}
		for _, c := range stop {
			if err := installer.Runner(c.Name, c.Args...); err != nil {
				return nil, fmt.Errorf("%s: %w", c, err)
			}
		}
		return func() error {
			start, err := installer.StartCommands(unit, uid)
			if err != nil {
				return err
			}
			for _, c := range start {
				if err := installer.Runner(c.Name, c.Args...); err != nil {
					return fmt.Errorf("%s: %w", c, err)
				}
			}
			return nil
		}, nil
	}
}

func currentUID() string { return strconv.Itoa(os.Getuid()) }
