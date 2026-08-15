package harness

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EnvCodexHome mirrors Codex's own override for its configuration directory.
// Honouring it is not a convenience: a machine where the operator moved
// CODEX_HOME and a machine where they did not have DIFFERENT config files, and
// writing to the wrong one would configure a harness nobody runs.
const EnvCodexHome = "CODEX_HOME"

// EnvClaudeConfigDir mirrors Claude Code's own override for the directory
// holding its user-scope `.claude.json`.
//
// Ignoring it is not a cosmetic omission: Claude Code READS the relocated file,
// so an agent that wrote `~/.claude.json` anyway would report a configured
// harness while the harness itself saw nothing. Verified against the installed
// CLI, which lists servers from `$CLAUDE_CONFIG_DIR/.claude.json` and not from
// `$HOME/.claude.json` when the two differ.
const EnvClaudeConfigDir = "CLAUDE_CONFIG_DIR"

// EnvGrokHome is grok's CODEX_HOME-equivalent: it relocates grok's entire
// configuration home, config file and skills directory alike.
//
// That it relocates BOTH was proven, not assumed — the fn-3 capture points HOME
// and GROK_HOME at different roots, seeds a decoy config and skill at
// $HOME/.grok, and records zero decoy references next to the entries written
// into the relocated home (docs/decisions/fn3-grok-surfaces.md §0).
const EnvGrokHome = "GROK_HOME"

// GrokContractVersion is the grok release the CLI/config contract in
// docs/decisions/fn3-grok-surfaces.md was captured against, pinned verbatim in
// testdata/grok-1.0.3-contract.txt.
//
// It is not decoration. Everything this package writes for grok — the
// `[mcp_servers.<name>]` shape, the `headers` sub-table name, `enabled = true`,
// the `[compat.*] mcps` keys — is what THAT release was observed to read. A
// machine running something else is a machine whose config surface nobody
// verified, so the version is observed and reported rather than assumed.
const GrokContractVersion = "1.0.3"

// GrokMinVersion is the oldest grok this package will write to. It is the
// contract version: nothing older was ever observed, and writing a shape into a
// CLI whose behaviour is unknown is the failure mode this gate exists to stop.
const GrokMinVersion = "1.0.3"

// Support verdicts. They are DISTINCT from Installed on purpose: "grok is on
// this machine" and "this build knows how to write grok's config" are different
// facts, and collapsing them is how a version bump silently corrupts a config.
const (
	// SupportSupported means the observed version is exactly the captured
	// contract version.
	SupportSupported = "supported"
	// SupportDrifted means a version within the contract's major line but not
	// the captured one. Writing proceeds — the config surface is stable across a
	// patch line and refusing would strand every future release — but the drift
	// is reported in both output forms so an operator can re-capture.
	SupportDrifted = "drifted"
	// SupportUnsupported means positive evidence the CLI is outside the
	// contract: older than the minimum, or a different major. Configure REFUSES
	// such a harness before any grant is issued.
	SupportUnsupported = "unsupported"
	// SupportUnknown means no version could be observed, or the harness has no
	// pinned contract at all (Claude Code and Codex, which fn-1 did not
	// version-gate). It never blocks: absence of an observation is not evidence
	// of drift, and the local write is verified by re-parse and preservation
	// regardless.
	SupportUnknown = "unknown"
)

// versionProbeTimeout bounds `<harness> --version`. It is a local, non-network
// call, so anything slower than this is stuck rather than slow.
const versionProbeTimeout = 10 * time.Second

// versionProbeWaitDelay bounds how long a killed probe's output pipes may keep
// Wait blocked. A child that inherits them can outlive its parent.
const versionProbeWaitDelay = 2 * time.Second

// Locator resolves harness configuration paths and decides what is installed.
//
// Both fields are seams. Tests point Home at a temporary directory and stub
// LookPath, which is what lets the whole merge-discipline suite run against
// fixture copies instead of against the operator's real configuration.
type Locator struct {
	// Home is the user's home directory. Empty means ask the OS.
	Home string
	// CodexHome overrides the Codex configuration directory. Empty means read
	// EnvCodexHome, then fall back to <Home>/.codex.
	CodexHome string
	// ClaudeConfigDir overrides the directory holding Claude Code's user-scope
	// `.claude.json`. Empty means read EnvClaudeConfigDir, then fall back to
	// Home.
	ClaudeConfigDir string
	// GrokHome overrides grok's configuration home. Empty means read
	// EnvGrokHome, then fall back to <Home>/.grok.
	GrokHome string
	// LookPath finds an executable. Empty means exec.LookPath.
	LookPath func(string) (string, error)
	// Surface reports whether a harness CLI still exposes a required
	// subcommand, by running it read-only and returning its exit status. Empty
	// means run it for real, with a timeout.
	//
	// It is separate from Version because it answers a different question: a
	// version string tells us WHICH release this is, and this tells us whether
	// that release still has the surface the contract was captured against.
	Surface func(binary string, args ...string) error
	// Version reports a harness CLI's self-declared version string, given the
	// resolved binary path. Empty means run `<binary> --version` with a timeout.
	//
	// It is a seam for the same reason LookPath is: the support verdict must be
	// testable across every version a machine could be running, and no unit test
	// may depend on which grok happens to be installed on the developer's box.
	Version func(binary string) (string, error)
}

// Detection is what the machine says about one harness.
type Detection struct {
	Harness string `json:"harness"`
	// Installed reports whether the harness is present: either its config file
	// exists, or its CLI is on PATH. Either is sufficient — a fresh Codex
	// install has a binary and no config, and a machine whose config survived
	// an uninstall should still be repaired rather than silently ignored.
	Installed bool `json:"installed"`
	// ConfigPath is the USER-scoped configuration file. It is never a project
	// file: see assertUserScope.
	ConfigPath string `json:"config_path"`
	// ConfigExists reports whether that file is present today.
	ConfigExists bool `json:"config_exists"`
	// BinaryPath is the CLI found on PATH, when there is one.
	BinaryPath string `json:"binary_path,omitempty"`
	// Version is the harness CLI's self-declared version, when one could be
	// observed. Empty means the probe did not run or did not answer — never
	// "the harness has no version".
	Version string `json:"version,omitempty"`
	// Support is the verdict about this build's ability to write that version's
	// configuration: SupportSupported, SupportDrifted, SupportUnsupported or
	// SupportUnknown.
	Support string `json:"support"`
	// SupportReason explains the verdict in the operator's words. It is present
	// for every verdict except a plain "supported".
	SupportReason string `json:"support_reason,omitempty"`
	// NeverLaunched means the CLI is installed and has never written its
	// configuration. It is DETECTED, not absent: grok's first launch creates
	// docs/, logs/ and active_sessions.json but no config.toml, and a first
	// write creates the file (fn3-grok-surfaces.md §6). Treating this as absent
	// would refuse to configure a freshly installed harness.
	NeverLaunched bool `json:"never_launched,omitempty"`
	// CompatSources names the OTHER vendors' configurations this harness still
	// inherits MCP servers from. It exists because "configured" must never
	// silently mean "also reachable through someone else's grant": grok merges
	// `config.toml > claude > cursor > .mcp.json`, so an inherited entry would
	// carry another harness's bearer token and corrupt audit attribution
	// (fn3-grok-surfaces.md §5). Homeplane closes the two user-config sources
	// (D4/D4b); the project-scope one cannot be closed from user config, so it
	// is REPORTED rather than claimed absent.
	CompatSources []string `json:"compat_sources,omitempty"`
	// Reason explains a negative detection in the operator's words.
	Reason string `json:"reason,omitempty"`
}

// Usable reports whether configure may write to this harness. Only positive
// evidence of drift blocks: an unobserved version is not an unsupported one.
func (d Detection) Usable() bool { return d.Support != SupportUnsupported }

func (l Locator) home() (string, error) {
	if l.Home != "" {
		return l.Home, nil
	}
	return os.UserHomeDir()
}

func (l Locator) lookPath(name string) (string, error) {
	if l.LookPath != nil {
		return l.LookPath(name)
	}
	return exec.LookPath(name)
}

// ClaudeConfigPath is the Claude Code USER-scope configuration file.
//
// User scope, always. Claude Code also supports a project scope backed by a
// `.mcp.json` checked into the repository — which is precisely where a grant
// token must never go (R5/R17), so this package has no code path that can
// produce one.
func (l Locator) ClaudeConfigPath() (string, error) {
	dir := strings.TrimSpace(l.ClaudeConfigDir)
	if dir == "" {
		dir = strings.TrimSpace(os.Getenv(EnvClaudeConfigDir))
	}
	if dir == "" {
		home, err := l.home()
		if err != nil {
			return "", err
		}
		dir = home
	}
	return filepath.Join(dir, ".claude.json"), nil
}

// CodexConfigPath is the Codex configuration file, honouring CODEX_HOME.
func (l Locator) CodexConfigPath() (string, error) {
	dir := strings.TrimSpace(l.CodexHome)
	if dir == "" {
		dir = strings.TrimSpace(os.Getenv(EnvCodexHome))
	}
	if dir == "" {
		home, err := l.home()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".codex")
	}
	return filepath.Join(dir, "config.toml"), nil
}

// GrokHomeDir is grok's configuration home, honouring GROK_HOME.
func (l Locator) GrokHomeDir() (string, error) {
	dir := strings.TrimSpace(l.GrokHome)
	if dir == "" {
		dir = strings.TrimSpace(os.Getenv(EnvGrokHome))
	}
	if dir == "" {
		home, err := l.home()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".grok")
	}
	return dir, nil
}

// GrokConfigPath is grok's user-scope configuration file, honouring GROK_HOME.
//
// A missing file is normal rather than exceptional: a grok that has never been
// launched has no config.toml at all, and its read verbs answer cleanly on an
// empty home. The writer creates the file, at 0600.
func (l Locator) GrokConfigPath() (string, error) {
	dir, err := l.GrokHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.toml"), nil
}

// Detect reports what the machine says about one harness.
func (l Locator) Detect(harness string) (Detection, error) {
	d := Detection{Harness: harness, Support: SupportUnknown}
	var binary string
	var err error

	switch harness {
	case ClaudeCode:
		d.ConfigPath, err = l.ClaudeConfigPath()
		binary = "claude"
		d.SupportReason = "no version contract is pinned for claude-code, so its CLI surface is not version-gated"
	case Codex:
		d.ConfigPath, err = l.CodexConfigPath()
		binary = "codex"
		d.SupportReason = "no version contract is pinned for codex, so its CLI surface is not version-gated"
	case Grok:
		d.ConfigPath, err = l.GrokConfigPath()
		binary = "grok"
	default:
		return Detection{}, fmt.Errorf("harness: unknown harness %q (known: %s)", harness, strings.Join(Known(), ", "))
	}
	if err != nil {
		return Detection{}, err
	}
	if err := assertUserScope(d.ConfigPath); err != nil {
		return Detection{}, err
	}

	if info, statErr := os.Stat(d.ConfigPath); statErr == nil {
		if info.IsDir() {
			return Detection{}, fmt.Errorf("harness: %s config path %s is a directory", harness, d.ConfigPath)
		}
		d.ConfigExists = true
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return Detection{}, fmt.Errorf("harness: stat %s: %w", d.ConfigPath, statErr)
	}

	if found, lookErr := l.lookPath(binary); lookErr == nil {
		d.BinaryPath = found
	}

	d.Installed = d.ConfigExists || d.BinaryPath != ""
	if !d.Installed {
		d.Reason = fmt.Sprintf("no %s executable on PATH and no configuration at %s", binary, d.ConfigPath)
		return d, nil
	}
	d.NeverLaunched = d.BinaryPath != "" && !d.ConfigExists
	if d.NeverLaunched {
		d.Reason = fmt.Sprintf("%s is installed and has never been launched (no configuration at %s yet); "+
			"configuring it creates the file", binary, d.ConfigPath)
	}

	if harness == Grok {
		d.Version, d.Support, d.SupportReason = l.grokSupport(d.BinaryPath)
		d.CompatSources = grokCompatSources(d.ConfigPath)
	}
	return d, nil
}

// grokSupport observes grok's version and judges it against the captured
// contract. The binary path may be empty — a machine whose grok config exists
// but whose CLI is not on PATH — and that is UNKNOWN, never unsupported: a
// version we could not observe is not evidence of drift, and refusing would
// strand a repairable config behind a PATH problem.
func (l Locator) grokSupport(binaryPath string) (version, support, reason string) {
	if binaryPath == "" {
		return "", SupportUnknown,
			"grok's version could not be observed (no grok executable on PATH), so the CLI contract could not be checked; " +
				"the write is still verified by re-parsing the configuration"
	}
	raw, err := l.probeVersion(binaryPath)
	if err != nil {
		return "", SupportUnknown, fmt.Sprintf("grok's version could not be observed (%v), so the CLI contract could not be checked", err)
	}
	version = parseGrokVersion(raw)
	if version == "" {
		return "", SupportUnknown, fmt.Sprintf("grok reported a version this build cannot read (%q), so the CLI contract could not be checked",
			truncateForMessage(raw, 80))
	}
	support, reason = judgeGrokVersion(version)
	if support != SupportDrifted {
		return version, support, reason
	}

	// A same-major release is not automatically a release that still has the
	// surface the contract describes. The version comparison says "probably the
	// same shape"; nobody has observed THIS build. So the one surface everything
	// here depends on is checked directly, before the drift verdict is allowed
	// to authorise a write — otherwise a release that dropped `mcp` would
	// supersede a working grant and then receive a configuration it cannot read.
	//
	// `mcp list --json` is the check because it is the READ verb the capture
	// pins: on a never-launched home it prints `[]` and exits 0, so a clean exit
	// means the surface is there and nothing was mutated. Its OUTPUT is
	// discarded unread — `mcp list` echoes header values verbatim, and that
	// includes a bearer token.
	if err := l.probeSurface(binaryPath, "mcp", "list", "--json"); err != nil {
		return version, SupportUnsupported, fmt.Sprintf(
			"grok %s differs from the captured contract (grok %s) AND does not answer `grok mcp list --json` (%v), so the "+
				"configuration surface this build writes is not there. Re-run scripts/capture-grok-contract.sh against this release",
			version, GrokContractVersion, err)
	}
	return version, support, reason
}

func (l Locator) probeSurface(binary string, args ...string) error {
	if l.Surface != nil {
		return l.Surface(binary, args...)
	}
	return runSurfaceProbe(binary, args...)
}

// runSurfaceProbe runs a READ-ONLY harness verb and reports only its exit
// status. The output is deliberately thrown away: this asks "does the verb
// exist", and the answer must not carry a credential into a log.
func runSurfaceProbe(binary string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), versionProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.WaitDelay = versionProbeWaitDelay
	return cmd.Run()
}

func (l Locator) probeVersion(binary string) (string, error) {
	if l.Version != nil {
		return l.Version(binary)
	}
	return runVersion(binary)
}

// runVersion asks a CLI what it is. Timed out rather than trusted: a harness
// binary is a third-party program, and `--version` hanging must not hang a
// status call.
func runVersion(binary string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), versionProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--version")
	cmd.WaitDelay = versionProbeWaitDelay
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// grokVersionRE reads the version out of grok's `--version` line, captured
// verbatim as `grok 1.0.3 (1a29d5bc12d4)`. The build hash is deliberately not
// captured: it identifies a build, and the config contract is a property of the
// release.
var grokVersionRE = regexp.MustCompile(`(?m)^\s*grok\s+v?(\d+\.\d+\.\d+)`)

func parseGrokVersion(raw string) string {
	m := grokVersionRE.FindStringSubmatch(raw)
	if m == nil {
		return ""
	}
	return m[1]
}

// judgeGrokVersion is the whole version policy, in one place so the reason an
// operator reads and the gate configure applies can never disagree.
func judgeGrokVersion(version string) (support, reason string) {
	got, ok := parseSemver(version)
	if !ok {
		return SupportUnknown, fmt.Sprintf("grok %s is not a version this build can compare against the captured contract (grok %s)",
			version, GrokContractVersion)
	}
	contract, _ := parseSemver(GrokContractVersion)
	minimum, _ := parseSemver(GrokMinVersion)

	if got[0] != contract[0] {
		return SupportUnsupported, fmt.Sprintf(
			"grok %s is a different major version than the captured contract (grok %s): its configuration surface has not been "+
				"observed, so Homeplane refuses to write it. Re-run scripts/capture-grok-contract.sh and re-ratify "+
				"docs/decisions/fn3-grok-surfaces.md to support it", version, GrokContractVersion)
	}
	if compareSemver(got, minimum) < 0 {
		return SupportUnsupported, fmt.Sprintf(
			"grok %s is older than the oldest release this build was verified against (grok %s), so Homeplane refuses to write it",
			version, GrokMinVersion)
	}
	if got == contract {
		return SupportSupported, ""
	}
	return SupportDrifted, fmt.Sprintf(
		"grok %s differs from the captured contract (grok %s) within the same major line: the entry shape is written as captured "+
			"and verified by re-parsing, but nobody has observed THIS release — re-run scripts/capture-grok-contract.sh if it misbehaves",
		version, GrokContractVersion)
}

func parseSemver(s string) ([3]int, bool) {
	var out [3]int
	parts := strings.SplitN(strings.TrimSpace(s), ".", 3)
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func compareSemver(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

func truncateForMessage(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// DetectAll reports every known harness, in Known() order.
func (l Locator) DetectAll() ([]Detection, error) {
	out := make([]Detection, 0, len(Known()))
	for _, h := range Known() {
		d, err := l.Detect(h)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// projectScopedNames are file names that are, by convention, checked into a
// repository. A grant token written into one is a token in git history.
var projectScopedNames = map[string]bool{
	".mcp.json": true,
	"mcp.json":  true,
}

// assertUserScope refuses a path a grant token must not reach.
//
// The name check alone is not enough, because the DIRECTORY is attacker- or
// accident-controlled: `CODEX_HOME` is an environment variable and `~/.codex`
// can be a symlink. Either can land `config.toml` — with its inline bearer
// token — and its timestamped backups inside a git working tree, where 0600 does
// nothing to stop `git add`. So the destination is resolved through symlinks and
// then checked for a repository ABOVE it, all the way to the filesystem root.
// A home directory that is itself a dotfiles repository is not exempt: R5 says
// a token never lands in a git-shared file, and "the user chose to version their
// home" does not make the token less committable.
//
// The one thing that DOES make it safe is the file being ignored, so that is
// what gets asked — of git itself, via `check-ignore`, rather than by
// reimplementing ignore precedence. A dotfiles user who already ignores their
// secrets is not blocked; one who does not is told exactly what to add. When
// git cannot answer (not installed, an error), the answer is refusal: we cannot
// prove the file is safe, and an unprovable secret is treated as exposed.
func assertUserScope(path string) error {
	if projectScopedNames[filepath.Base(path)] {
		return fmt.Errorf("%w: %s", ErrProjectScope, path)
	}

	resolved := filepath.Join(resolveExisting(filepath.Dir(path)), filepath.Base(path))
	for cur := filepath.Dir(resolved); ; {
		if isRepositoryRoot(cur) {
			if gitIgnores(cur, resolved) {
				return nil
			}
			return fmt.Errorf("%w: %s is inside the git repository at %s and is not ignored there "+
				"(add it to .gitignore, or point the harness's config directory outside the checkout)",
				ErrProjectScope, path, cur)
		}
		parent := filepath.Dir(cur)
		if parent == cur { // filesystem root
			return nil
		}
		cur = parent
	}
}

// gitIgnores asks git whether path is ignored in the repository at root.
//
// Exit 0 means ignored, 1 means not ignored, anything else is an error — and an
// error is NOT ignored, because this answer is used to permit a secret to be
// written.
//
// `--no-index` is deliberately NOT passed. Without it, git refuses to call a
// TRACKED file ignored even when an ignore rule matches it — which is exactly
// the answer we want, because a file already in the index is already
// committable no matter what `.gitignore` says. Passing the flag would turn a
// tracked, force-added config into a permitted destination.
func gitIgnores(root, path string) bool {
	git, err := exec.LookPath("git")
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitCheckTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, git, "-C", root, "check-ignore", "--quiet", "--", path)
	return cmd.Run() == nil
}

// gitCheckTimeout bounds the ignore check. It consults local files only, so a
// slow answer means something is wrong and refusing beats hanging a CLI.
const gitCheckTimeout = 5 * time.Second

// isRepositoryRoot reports whether dir holds a `.git` entry. Both shapes count:
// a directory for an ordinary clone, and a file for a worktree or submodule —
// a linked worktree is every bit as committable as a normal one.
func isRepositoryRoot(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, ".git"))
	return err == nil
}

// resolveExisting resolves symlinks as far up the path as actually exists, so a
// destination that does not exist YET is still judged by where it would land.
// An unresolvable path is returned cleaned rather than rejected: failing to
// resolve is not evidence of a repository, and the caller's other checks stand.
func resolveExisting(path string) string {
	cleaned := filepath.Clean(path)
	for cur := cleaned; ; {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			rest, relErr := filepath.Rel(cur, cleaned)
			if relErr != nil {
				return resolved
			}
			return filepath.Clean(filepath.Join(resolved, rest))
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return cleaned
		}
		cur = parent
	}
}
