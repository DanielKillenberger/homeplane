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
	home, err := l.home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude.json"), nil
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
// The primary guarantee is structural — the only paths this package writes are
// the ones Locator derives, and Locator has no project-scope branch. This check
// is the second lock: it makes "someone passed a project config path" a
// refusal rather than a leak, including when that someone is a future caller of
// this package.
func assertUserScope(path string) error {
	if projectScopedNames[filepath.Base(path)] {
		return fmt.Errorf("%w: %s", ErrProjectScope, path)
	}
	return nil
}
