// Package gno owns the machine-side retrieval engine: installing GNO against
// the synchronized vault, keeping its index machine-local and disposable,
// supervising it, and publishing the endpoint descriptor that harnesses are
// wired from.
//
// Three rules shape this package:
//
//   - The seam is the ROLE, not the product (D16). Everything a harness needs
//     is written to one endpoint descriptor for the "retrieval engine"
//     component; task .6 reads that file and never learns the word GNO. GNO is
//     the only implementation and there is no plugin interface.
//   - The index is machine-local and disposable (R14). It lives outside the
//     vault and outside every known synchronized root, deleting it is a
//     supported operation, and the agent can rebuild it from the vault alone.
//   - The upstream contract is captured, not invented. Every argv this package
//     emits is asserted against the pinned build's own parser output in
//     testdata/, and the MCP launch template in the descriptor is DERIVED from
//     `gno mcp install --dry-run --json` rather than hand-written.
package gno

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed gno-pinned.sha256
var pinnedFile string

// Pin is the exact GNO build this agent is allowed to run.
type Pin struct {
	Version string `json:"version"`
	Package string `json:"package"`
	Tarball string `json:"tarball,omitempty"`
}

// ErrVersionMismatch means the CLI on disk is not the pinned build.
var ErrVersionMismatch = errors.New("gno: the installed GNO does not match the pinned version")

// ErrNoBin means no CLI path is configured.
var ErrNoBin = errors.New("gno: no GNO CLI path configured")

// LoadPin reads the pin compiled into the binary.
func LoadPin() (Pin, error) { return parsePin(pinnedFile) }

func parsePin(text string) (Pin, error) {
	var p Pin
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Pin{}, fmt.Errorf("gno: malformed pin line %q", line)
		}
		switch strings.TrimSpace(key) {
		case "version":
			p.Version = strings.TrimSpace(value)
		case "package":
			p.Package = strings.TrimSpace(value)
		case "tarball":
			p.Tarball = strings.TrimSpace(value)
		default:
			return Pin{}, fmt.Errorf("gno: unknown pin key %q", strings.TrimSpace(key))
		}
	}
	if p.Version == "" {
		return Pin{}, errors.New("gno: pin is missing a version")
	}
	if p.Package == "" {
		return Pin{}, errors.New("gno: pin is missing a package name")
	}
	return p, nil
}

// ── The upstream contract ────────────────────────────────────────────────────
//
// These builders mirror gno 1.29.6's own parser, captured verbatim in
// testdata/gno-1.29.6-contract.txt by scripts/capture-gno-contract.sh and
// asserted by TestArgvMatchesThePinnedContract.
//
// One structural rule runs through all of them: GNO's global options
// (`--index`, `--config`, `--offline`, `--json`) are parsed BEFORE the
// subcommand, so anything global is prepended, never appended.

// Environment variables GNO reads for its own directories. Setting all three is
// what makes the index machine-local, isolated from a human's own `gno` state,
// and disposable.
const (
	EnvConfigDir = "GNO_CONFIG_DIR"
	EnvDataDir   = "GNO_DATA_DIR"
	EnvCacheDir  = "GNO_CACHE_DIR"
)

// DefaultIndexName is GNO's own default index name.
const DefaultIndexName = "default"

// SetupArgs binds a folder to a collection and VERIFIES it: upstream only
// reports success after a real lexical retrieval hits a document, which is why
// this is the activation step rather than a bare `collection add`.
//
// `--no-semantic` is deliberate. Semantic indexing downloads a multi-hundred-
// megabyte model; a first-run install must not silently pull that, so embedding
// is an explicit later step (`gno embed` / `gno models pull`).
func SetupArgs(folder, collection string) []string {
	args := []string{"setup", folder}
	if strings.TrimSpace(collection) != "" {
		args = append(args, "--name", collection)
	}
	return append(args, "--no-semantic", "--json")
}

// DoctorArgs asks GNO to diagnose itself. This is the health probe behind the
// retrieval-engine component's health slot.
func DoctorArgs() []string { return []string{"doctor", "--json"} }

// StatusArgs reports index status.
func StatusArgs() []string { return []string{"status", "--json"} }

// SearchArgs is the lexical retrieval used to prove the index answers with real
// vault content.
func SearchArgs(query string) []string { return []string{"search", query, "--json"} }

// UpdateArgs syncs files from disk into an existing index.
func UpdateArgs() []string { return []string{"update", "--json"} }

// IndexArgs re-indexes a collection from scratch. `--no-embed` keeps the
// rebuild lexical, for the same reason SetupArgs passes `--no-semantic`.
func IndexArgs(collection string) []string {
	args := []string{"index"}
	if strings.TrimSpace(collection) != "" {
		args = append(args, collection)
	}
	return append(args, "--no-embed", "--json")
}

// DaemonArgs is the SUPERVISED process: headless continuous indexing, bound to
// loopback and authenticated.
//
// `--offline` is global and load-bearing: without it the daemon downloads model
// weights on first start, so a freshly installed machine would spend its first
// ten minutes pulling 639 MB from a supervised unit that looks like it is
// hanging. Offline keeps the daemon to lexical indexing plus whatever models
// are already cached; pulling models is an explicit operator step.
//
// `--mcp-token-file` is defence in depth. Harnesses reach the engine over stdio
// and never use this HTTP gateway, so nothing legitimate needs it unauthenticated
// — and an unauthenticated retrieval endpoint over the whole vault is the single
// worst thing this component could leave running. The token is a FILE PATH in
// argv, never the token itself.
// There is deliberately NO `--json` here. Upstream accepts the flag on `daemon`
// only alongside `--status`, and rejects the long-running form with a VALIDATION
// error — so passing it would make the supervised unit fail on every start. The
// captured contract records that constraint; TestArgvMatchesThePinnedContract
// enforces it.
func DaemonArgs(host string, port int, tokenFile string) []string {
	args := []string{"--offline", "daemon", "--host", host, "--port", strconv.Itoa(port)}
	if strings.TrimSpace(tokenFile) != "" {
		args = append(args, "--mcp-token-file", tokenFile)
	}
	return args
}

// ErrGatewayNotLoopback means the engine's own HTTP gateway was pointed at an
// address other than this machine's loopback interface.
var ErrGatewayNotLoopback = errors.New("gno: the retrieval engine's gateway must bind loopback only")

// ErrGatewayPort means the port is outside the usable range.
var ErrGatewayPort = errors.New("gno: the retrieval engine's gateway port is out of range")

// ValidateGateway refuses any binding that would expose vault retrieval beyond
// this machine.
//
// "Documented as loopback-only" is not a control. The daemon serves search over
// the entire vault, so the address it binds is checked against the actual
// loopback ranges — 127.0.0.0/8 and ::1 — rather than trusted to a default or a
// comment. A hostname is refused outright: resolution is not this component's
// business and `localhost` can be re-pointed in /etc/hosts.
func ValidateGateway(host string, port int) error {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return fmt.Errorf("%w: no host configured", ErrGatewayNotLoopback)
	}
	ip := net.ParseIP(strings.Trim(trimmed, "[]"))
	if ip == nil {
		return fmt.Errorf("%w: %q is not a literal IP address", ErrGatewayNotLoopback, host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%w: %s is reachable from outside this machine", ErrGatewayNotLoopback, host)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: %d", ErrGatewayPort, port)
	}
	return nil
}

// GatewayTokenFile is the 0600 bearer token protecting the daemon's own HTTP
// gateway.
func GatewayTokenFile(p Paths) string { return filepath.Join(p.Config, "gateway-token") }

// EnsureGatewayToken creates the gateway token if it does not exist and returns
// its path. The token itself is never returned, logged, or put in argv.
func EnsureGatewayToken(p Paths) (string, error) {
	path := GatewayTokenFile(p)
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		// Tighten permissions on an existing token rather than merely noticing.
		if info.Mode().Perm() != filePerm {
			if err := os.Chmod(path, filePerm); err != nil {
				return "", fmt.Errorf("gno: tighten gateway token permissions: %w", err)
			}
		}
		return path, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return "", fmt.Errorf("gno: create config directory: %w", err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("gno: generate gateway token: %w", err)
	}
	if err := writeFileAtomic(path, []byte(hex.EncodeToString(raw)+"\n"), filePerm); err != nil {
		return "", fmt.Errorf("gno: write gateway token: %w", err)
	}
	return path, nil
}

// MCPServeArgs is the stdio MCP server a harness launches per client. `serve`
// is upstream's default subcommand of `mcp`, and upstream's own installer emits
// the bare `mcp` form — so this matches what clients will actually run.
func MCPServeArgs() []string { return []string{"mcp"} }

// MCPInstallArgs asks GNO to write its own client configuration. Homeplane uses
// it only with `--dry-run --json`, to DERIVE the launch template for the
// endpoint descriptor: task .6 owns writing harness config, under its own
// merge discipline.
// The dry run carries --force for a reason that only appears on a machine that
// is already configured: GNO refuses `mcp install` when the target client
// already has a `gno` entry, and it refuses it even in a dry run. Homeplane
// writes that entry itself (task .6), so without --force a machine could be
// activated exactly once and never re-activated — the failure surfaces as
// "no GNO configuration in the configured directories", which points at the
// wrong thing entirely.
//
// --force cannot make this write anything: it is still a dry run, and the
// caller refuses any answer whose reported action is not a dry-run action.
func MCPInstallArgs(target, scope string, dryRun bool) []string {
	args := []string{"mcp", "install", "--target", target, "--scope", scope}
	if dryRun {
		args = append(args, "--dry-run", "--force")
	}
	return append(args, "--json")
}

// MCPUninstallArgs removes GNO's entry from a client configuration. It is
// recorded in the removal plan rather than run at activation time.
func MCPUninstallArgs(target, scope string) []string {
	return []string{"mcp", "uninstall", "--target", target, "--scope", scope, "--json"}
}

// Harness targets Homeplane configures (D1: Claude Code + Codex).
const (
	TargetClaudeCode = "claude-code"
	TargetCodex      = "codex"
	ScopeUser        = "user"
)

// ── Execution ────────────────────────────────────────────────────────────────

// CLI is a version-verified GNO executable with its directories pinned.
type CLI struct {
	// Bin is the path to the `gno` executable.
	Bin string
	// Pin is the build this CLI must be.
	Pin Pin
	// Dirs pins GNO's config, data, and cache directories. Empty means the
	// process default, which is only ever right in an ad-hoc invocation.
	Dirs Paths
	// Index selects the named index. Empty means DefaultIndexName.
	Index string
	// Timeout bounds a ONE-SHOT invocation. It never applies to the daemon.
	Timeout time.Duration
	// Log, when set, receives the CLI's output.
	Log io.Writer
}

// DefaultTimeout bounds a single one-shot CLI call. Setup indexes a whole vault,
// so it is generous.
const DefaultTimeout = 10 * time.Minute

// maxCapturedOutput bounds what is retained from a long-lived process's output.
const maxCapturedOutput = 64 << 10

var versionPattern = regexp.MustCompile(`\d+\.\d+\.\d+`)

// Verify checks the executable is the pinned build.
//
// The check is a version probe, not a checksum — see gno-pinned.sha256 for why
// checksumming a multi-file TypeScript package's entrypoint would prove nothing.
func (c CLI) Verify(ctx context.Context) error {
	if strings.TrimSpace(c.Bin) == "" {
		return ErrNoBin
	}
	if strings.TrimSpace(c.Pin.Version) == "" {
		return errors.New("gno: no pinned version configured")
	}
	out, err := c.Run(ctx, Invocation{Args: []string{"--version"}})
	if err != nil {
		return fmt.Errorf("gno: probe version: %w", err)
	}
	reported := versionPattern.FindString(out)
	if reported == "" {
		return fmt.Errorf("%w: %s reported no parseable version (%q)", ErrVersionMismatch, c.Bin, strings.TrimSpace(out))
	}
	if reported != c.Pin.Version {
		return fmt.Errorf("%w: %s reports %s, pinned %s", ErrVersionMismatch, c.Bin, reported, c.Pin.Version)
	}
	return nil
}

// Invocation is one CLI call.
type Invocation struct {
	Args       []string
	Stdin      string
	WorkingDir string
}

// Run performs a BOUNDED, one-shot invocation and returns its captured output.
func (c CLI) Run(ctx context.Context, inv Invocation) (string, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return c.exec(ctx, inv, false)
}

// Stream performs an UNBOUNDED invocation, for the supervised daemon. It
// returns only when the process exits or ctx is cancelled.
func (c CLI) Stream(ctx context.Context, inv Invocation) error {
	_, err := c.exec(ctx, inv, true)
	return err
}

// Command builds the exec.Cmd for an invocation without running it. The MCP
// stdio probe needs the process's pipes, so it takes the command rather than
// the captured output.
func (c CLI) Command(ctx context.Context, inv Invocation) (*exec.Cmd, error) {
	if strings.TrimSpace(c.Bin) == "" {
		return nil, ErrNoBin
	}
	cmd := exec.CommandContext(ctx, c.Bin, c.argv(inv.Args)...)
	cmd.Dir = inv.WorkingDir
	cmd.Env = c.environ()
	return cmd, nil
}

// argv prepends the global options every invocation carries. `--version` is
// itself a global flag and must not be prefixed by another.
func (c CLI) argv(args []string) []string {
	if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		return args
	}
	var out []string
	if idx := strings.TrimSpace(c.Index); idx != "" && idx != DefaultIndexName {
		out = append(out, "--index", idx)
	}
	return append(out, args...)
}

func (c CLI) exec(ctx context.Context, inv Invocation, streaming bool) (string, error) {
	cmd, err := c.Command(ctx, inv)
	if err != nil {
		return "", err
	}
	if inv.Stdin != "" {
		cmd.Stdin = strings.NewReader(inv.Stdin)
	}

	tail := &tailBuffer{limit: maxCapturedOutput}
	var sink io.Writer = tail
	if c.Log != nil {
		sink = io.MultiWriter(tail, c.Log)
	}
	cmd.Stdout = sink
	cmd.Stderr = sink

	runErr := cmd.Run()
	output := tail.String()
	if runErr != nil {
		if streaming && ctx.Err() != nil {
			// Cancellation is how a supervised daemon is asked to stop.
			return output, ctx.Err()
		}
		return output, classify(output, runErr)
	}
	return output, nil
}

// environ builds the child environment with GNO's three directories pinned.
//
// Any ambient GNO_* variable is dropped first: a developer's own exported
// GNO_DATA_DIR must never redirect the supervised agent's index, because that
// is exactly how an index ends up somewhere nobody asserted it was safe.
func (c CLI) environ() []string {
	env := os.Environ()
	filtered := env[:0]
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		switch key {
		case EnvConfigDir, EnvDataDir, EnvCacheDir:
			continue
		}
		filtered = append(filtered, kv)
	}
	env = filtered
	if c.Dirs.Config != "" {
		env = append(env, EnvConfigDir+"="+c.Dirs.Config)
	}
	if c.Dirs.Data != "" {
		env = append(env, EnvDataDir+"="+c.Dirs.Data)
	}
	if c.Dirs.Cache != "" {
		env = append(env, EnvCacheDir+"="+c.Dirs.Cache)
	}
	return append(env, "PATH="+childPath(c.Bin))
}

// childPath is the PATH the engine runs with.
//
// The engine binary is invoked by absolute path, which is not enough: it is a
// script whose interpreter (`bun`) is resolved through PATH, and a SUPERVISED
// process has almost none — launchd hands a job `/usr/bin:/bin:/usr/sbin:/sbin`
// and systemd little more. The failure that produced this is exactly the
// "works in the terminal, not under the supervisor" shape the descriptor
// validation warns about, arriving from the other side: `gno` starts fine by
// hand and the daemon dies with `env: bun: No such file or directory`.
//
// So the runtime directories this machine actually provisioned are put in
// front: the engine's own directory (where a package manager puts the
// interpreter beside the script) and the agent's own bin directory (where the
// installer puts Node and Bun). The inherited PATH follows, so an interactive
// run keeps behaving the way it did.
func childPath(engineBin string) string {
	var dirs []string
	seen := map[string]bool{}
	add := func(dir string) {
		if dir == "" || dir == "." || seen[dir] {
			return
		}
		seen[dir] = true
		dirs = append(dirs, dir)
	}
	if filepath.IsAbs(engineBin) {
		add(filepath.Dir(engineBin))
	}
	if exe, err := os.Executable(); err == nil {
		add(filepath.Dir(exe))
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		add(dir)
	}
	// A supervised process may inherit no PATH at all; these are the paths a
	// POSIX system guarantees, and without them the engine could not run `env`.
	for _, dir := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		add(dir)
	}
	return strings.Join(dirs, string(filepath.ListSeparator))
}

// tailBuffer keeps at most limit bytes, discarding from the front, so a daemon
// that runs for months cannot grow an unbounded error buffer.
type tailBuffer struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.limit {
		t.buf = append([]byte(nil), t.buf[len(t.buf)-t.limit:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// ── Failure classification ───────────────────────────────────────────────────

// ErrNotInitialized means GNO has no configuration in the directories it was
// pointed at — the state a deleted index leaves behind, and therefore the state
// the rebuild path must recognise rather than treat as a broken install.
var ErrNotInitialized = errors.New("gno: no GNO configuration in the configured directories (run setup)")

// ErrNoResults means a retrieval ran and matched nothing. It is NOT a failure of
// the engine, and conflating the two would let an empty index pass for a healthy
// one.
var ErrNoResults = errors.New("gno: retrieval returned no results")

// ErrOfflineModelMissing means an operation needed a model that is not cached
// and the daemon runs offline by design. Retryable via `gno models pull`.
var ErrOfflineModelMissing = errors.New("gno: a required model is not cached and GNO is running offline")

func classify(output string, err error) error {
	lower := strings.ToLower(output)
	switch {
	case containsAny(lower, "config file not found", "no config", "not initialized", "run: gno init", "run `gno init`"):
		return fmt.Errorf("%w: %s", ErrNotInitialized, firstLine(output))
	case containsAny(lower, "model not cached", "offline mode", "models pull"):
		return fmt.Errorf("%w: %s", ErrOfflineModelMissing, firstLine(output))
	default:
		return fmt.Errorf("gno: %s failed: %s: %w", "command", firstLine(output), err)
	}
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// ── Output parsing ───────────────────────────────────────────────────────────

// DoctorCheck is one entry from `gno doctor --json`.
type DoctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// DoctorReport is `gno doctor --json`.
type DoctorReport struct {
	Healthy bool          `json:"healthy"`
	Checks  []DoctorCheck `json:"checks"`
}

// Failing names every check that is not ok. `warn` is included: an uncached
// model is a real, reportable degradation of what the engine can answer, even
// though upstream still calls the install healthy.
func (r DoctorReport) Failing() []DoctorCheck {
	var out []DoctorCheck
	for _, c := range r.Checks {
		if c.Status != "ok" {
			out = append(out, c)
		}
	}
	return out
}

// Errors names only the checks upstream considers failures.
func (r DoctorReport) Errors() []DoctorCheck {
	var out []DoctorCheck
	for _, c := range r.Checks {
		if c.Status == "error" || c.Status == "fail" {
			out = append(out, c)
		}
	}
	return out
}

// Summary is the one-line health detail `status` prints.
func (r DoctorReport) Summary() string {
	failing := r.Failing()
	if len(failing) == 0 {
		return fmt.Sprintf("all %d checks ok", len(r.Checks))
	}
	names := make([]string, 0, len(failing))
	for _, c := range failing {
		names = append(names, c.Name+" "+c.Status)
	}
	return fmt.Sprintf("%d/%d checks ok (%s)", len(r.Checks)-len(failing), len(r.Checks), strings.Join(names, ", "))
}

// Doctor runs the health probe and parses it.
func (c CLI) Doctor(ctx context.Context) (DoctorReport, error) {
	out, err := c.Run(ctx, Invocation{Args: DoctorArgs()})
	if err != nil {
		// `doctor` exits non-zero when it finds problems, and its JSON is still
		// the answer we want — a failing health probe is a report, not an error.
		if report, perr := parseDoctor(out); perr == nil {
			return report, nil
		}
		return DoctorReport{}, err
	}
	return parseDoctor(out)
}

func parseDoctor(out string) (DoctorReport, error) {
	raw, err := extractJSONObject(out)
	if err != nil {
		return DoctorReport{}, fmt.Errorf("gno: parse doctor output: %w", err)
	}
	var report DoctorReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return DoctorReport{}, fmt.Errorf("gno: parse doctor output: %w", err)
	}
	if len(report.Checks) == 0 {
		return DoctorReport{}, errors.New("gno: doctor reported no checks")
	}
	return report, nil
}

// SearchResult is one hit from `gno search --json`.
type SearchResult struct {
	DocID   string  `json:"docid"`
	Score   float64 `json:"score"`
	URI     string  `json:"uri"`
	Title   string  `json:"title"`
	Snippet string  `json:"snippet"`
	Source  struct {
		RelPath string `json:"relPath"`
		AbsPath string `json:"absPath"`
	} `json:"source"`
}

type searchEnvelope struct {
	Results []SearchResult `json:"results"`
}

// Search runs a lexical retrieval and returns its hits.
func (c CLI) Search(ctx context.Context, query string) ([]SearchResult, error) {
	out, err := c.Run(ctx, Invocation{Args: SearchArgs(query)})
	if err != nil {
		return nil, err
	}
	raw, err := extractJSONObject(out)
	if err != nil {
		return nil, fmt.Errorf("gno: parse search output: %w", err)
	}
	var env searchEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("gno: parse search output: %w", err)
	}
	if len(env.Results) == 0 {
		return nil, ErrNoResults
	}
	return env.Results, nil
}

// extractJSONObject pulls the JSON document out of a CLI's output.
//
// GNO writes progress lines to the same stream as its JSON, so the payload is
// located by its braces rather than assumed to be the whole output. Scanning
// from the FIRST `{` to the LAST `}` is what survives both a leading progress
// line and a trailing summary.
func extractJSONObject(out string) ([]byte, error) {
	start := strings.IndexByte(out, '{')
	end := strings.LastIndexByte(out, '}')
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no JSON object in %q", firstLine(out))
	}
	candidate := []byte(out[start : end+1])
	if !json.Valid(candidate) {
		// Fall back to the first complete object on its own line, which is what
		// a mixed progress/JSON stream produces.
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "{") && json.Valid([]byte(line)) {
				return []byte(line), nil
			}
		}
		return nil, errors.New("output contained no valid JSON object")
	}
	return bytes.TrimSpace(candidate), nil
}
