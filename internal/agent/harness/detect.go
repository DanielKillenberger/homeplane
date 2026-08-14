package harness

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	home, homeErr := l.home()
	if homeErr != nil {
		home = ""
	}
	if err := assertUserScope(d.ConfigPath, home); err != nil {
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
// accident-controlled: `CODEX_HOME` is an environment variable, and `~/.codex`
// can be a symlink. Either can land `config.toml` — with its inline bearer
// token — and its timestamped backups inside a git working tree, where 0600 does
// nothing to stop `git add`. So the destination is resolved through symlinks
// and then checked for a repository above it.
//
// The walk stops AT the home directory rather than at the filesystem root. A
// home directory that is itself a dotfiles repository is a deliberate choice by
// its owner about their own home, and refusing to configure any harness on such
// a machine would be a false positive that breaks the normal case; a config
// path nested inside a PROJECT checkout is the actual hazard, and it is always
// found strictly below home.
func assertUserScope(path, home string) error {
	if projectScopedNames[filepath.Base(path)] {
		return fmt.Errorf("%w: %s", ErrProjectScope, path)
	}

	dir := resolveExisting(filepath.Dir(path))
	stop := ""
	if home != "" {
		stop = resolveExisting(home)
	}

	for cur := dir; ; {
		if cur == stop {
			return nil
		}
		if isRepositoryRoot(cur) {
			return fmt.Errorf("%w: %s is inside the repository at %s", ErrProjectScope, path, cur)
		}
		parent := filepath.Dir(cur)
		if parent == cur { // filesystem root
			return nil
		}
		cur = parent
	}
}

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
