package harness

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
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
	// LookPath finds an executable. Empty means exec.LookPath.
	LookPath func(string) (string, error)
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
	// Reason explains a negative detection in the operator's words.
	Reason string `json:"reason,omitempty"`
}

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

// Detect reports what the machine says about one harness.
func (l Locator) Detect(harness string) (Detection, error) {
	d := Detection{Harness: harness}
	var binary string
	var err error

	switch harness {
	case ClaudeCode:
		d.ConfigPath, err = l.ClaudeConfigPath()
		binary = "claude"
	case Codex:
		d.ConfigPath, err = l.CodexConfigPath()
		binary = "codex"
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
	}
	return d, nil
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
