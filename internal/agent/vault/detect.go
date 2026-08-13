// Package vault finds the Daniel-OS Obsidian vault on a machine, retrieves it
// when it is absent, and keeps it synchronized under supervision.
//
// Three rules shape this package, and each one exists because getting it wrong
// destroys data rather than merely failing:
//
//   - Never guess which vault. A machine with two candidate vaults gets an
//     explicit-selection error listing both (R3). Picking "the most recently
//     opened one" would be a silent, unrecoverable choice about where an agent
//     writes.
//   - Never sync an unverified CLI. The obsidian-headless releases are pinned
//     by version AND SHA-256; an unpinned, unmatched, or unverifiable binary
//     refuses to run rather than syncing through it (upstream reported data
//     loss against 0.0.12).
//   - Never sync through a destructive diff. The real vault is snapshotted
//     before first activation, and a sync pass that deletes or rewrites more
//     than the guard policy allows aborts activation with the diff attached.
//
// Secrets: the Obsidian Sync credential is the spec's named custody exception.
// It lives 0600 inside the agent state directory, is passed to the CLI through
// the environment, and never appears in argv, logs, or state.json.
package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// ConfigDirName is the marker directory every Obsidian vault carries.
const ConfigDirName = ".obsidian"

// Candidate sources, reported so a human can see WHY a directory was offered.
const (
	SourceExplicit = "explicit"
	SourceRegistry = "obsidian-registry"
	SourceScan     = "filesystem-scan"
)

// Candidate is one directory that looks like an Obsidian vault.
type Candidate struct {
	Path   string `json:"path"`
	Name   string `json:"name"`
	Source string `json:"source"`
}

// ErrNoVault means no vault was found. It is deliberately distinct from an
// authentication failure: `status` must be able to tell "this machine has no
// vault yet" from "this machine could not log in to fetch one" (R3).
var ErrNoVault = errors.New("vault: no Obsidian vault found on this machine")

// ErrNotAVault means a path exists but carries no .obsidian directory.
var ErrNotAVault = errors.New("vault: path is not an Obsidian vault")

// AmbiguousError reports multiple candidate vaults. Detection returns this
// instead of choosing; the caller must pass an explicit path.
type AmbiguousError struct {
	Candidates []Candidate
}

func (e *AmbiguousError) Error() string {
	paths := make([]string, 0, len(e.Candidates))
	for _, c := range e.Candidates {
		paths = append(paths, c.Path)
	}
	return fmt.Sprintf("vault: %d candidate vaults found (%s) — re-run with -vault-path to choose one",
		len(e.Candidates), strings.Join(paths, ", "))
}

// DetectOptions describes one detection. Every environment-derived input is
// overridable so the whole matrix is testable against temporary directories —
// no test ever reads a real vault or a real Obsidian configuration.
type DetectOptions struct {
	// ExplicitPath, when set, is the only candidate considered.
	ExplicitPath string
	// Name, when set, keeps only candidates whose directory base name matches
	// (case-insensitively). This is how "the Daniel-OS vault" is expressed.
	Name string
	// Home overrides the user's home directory.
	Home string
	// GOOS overrides the platform used to locate Obsidian's own config.
	GOOS string
	// RegistryPath overrides the location of Obsidian's obsidian.json.
	RegistryPath string
	// ScanRoots overrides the directories whose immediate children are scanned.
	ScanRoots []string
}

// Detect finds the vault, or explains precisely why it cannot.
func Detect(opts DetectOptions) (Candidate, error) {
	if p := strings.TrimSpace(opts.ExplicitPath); p != "" {
		abs, err := filepath.Abs(p)
		if err != nil {
			return Candidate{}, fmt.Errorf("vault: resolve %s: %w", p, err)
		}
		if !IsVault(abs) {
			return Candidate{}, fmt.Errorf("%w: %s (no %s directory)", ErrNotAVault, abs, ConfigDirName)
		}
		return Candidate{Path: abs, Name: filepath.Base(abs), Source: SourceExplicit}, nil
	}

	candidates, err := Candidates(opts)
	if err != nil {
		return Candidate{}, err
	}
	switch len(candidates) {
	case 0:
		return Candidate{}, ErrNoVault
	case 1:
		return candidates[0], nil
	default:
		return Candidate{}, &AmbiguousError{Candidates: candidates}
	}
}

// Candidates lists every vault-looking directory this machine offers, from
// Obsidian's own registry first and a bounded filesystem scan second.
func Candidates(opts DetectOptions) ([]Candidate, error) {
	home := opts.Home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("vault: locate home directory: %w", err)
		}
		home = h
	}
	goos := opts.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}

	seen := map[string]bool{}
	var out []Candidate
	add := func(path, source string) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			abs = resolved
		}
		if seen[abs] || !IsVault(abs) {
			return
		}
		name := filepath.Base(abs)
		if opts.Name != "" && !strings.EqualFold(name, opts.Name) {
			return
		}
		seen[abs] = true
		out = append(out, Candidate{Path: abs, Name: name, Source: source})
	}

	for _, p := range registryVaults(registryPath(opts, home, goos)) {
		add(p, SourceRegistry)
	}
	for _, root := range scanRoots(opts, home, goos) {
		for _, p := range scanChildren(root) {
			add(p, SourceScan)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// IsVault reports whether dir carries an Obsidian configuration directory.
func IsVault(dir string) bool {
	if dir == "" {
		return false
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	cfg, err := os.Stat(filepath.Join(dir, ConfigDirName))
	return err == nil && cfg.IsDir()
}

// registryPath locates Obsidian's obsidian.json, which records every vault the
// desktop app knows about.
func registryPath(opts DetectOptions, home, goos string) string {
	if opts.RegistryPath != "" {
		return opts.RegistryPath
	}
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "obsidian", "obsidian.json")
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "obsidian", "obsidian.json")
	default:
		if xdg := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(xdg) {
			return filepath.Join(xdg, "obsidian", "obsidian.json")
		}
		return filepath.Join(home, ".config", "obsidian", "obsidian.json")
	}
}

// registryVaults reads obsidian.json. A missing or malformed registry is not an
// error — it just contributes no candidates, and the filesystem scan still runs.
func registryVaults(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Vaults map[string]struct {
			Path string `json:"path"`
		} `json:"vaults"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	paths := make([]string, 0, len(doc.Vaults))
	for _, v := range doc.Vaults {
		if strings.TrimSpace(v.Path) != "" {
			paths = append(paths, v.Path)
		}
	}
	sort.Strings(paths)
	return paths
}

// scanRoots are the directories whose IMMEDIATE children are examined. The scan
// is deliberately one level deep: a recursive walk of $HOME is slow, and it
// would surface vaults nested inside backups or clones that nobody meant to use.
func scanRoots(opts DetectOptions, home, goos string) []string {
	if opts.ScanRoots != nil {
		return opts.ScanRoots
	}
	roots := []string{
		home,
		filepath.Join(home, "Documents"),
		filepath.Join(home, "Obsidian"),
		filepath.Join(home, "vaults"),
	}
	if goos == "darwin" {
		roots = append(roots,
			filepath.Join(home, "Library", "Mobile Documents", "iCloud~md~obsidian", "Documents"))
	}
	return roots
}

func scanChildren(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		out = append(out, filepath.Join(root, e.Name()))
	}
	return out
}

// ValidatePath checks a recorded vault path is still usable, phrasing each
// failure the way `status` should report it.
func ValidatePath(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("vault: no vault path recorded")
	}
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("vault: %s does not exist", path)
	case err != nil:
		return fmt.Errorf("vault: %s is unreadable: %w", path, err)
	case !info.IsDir():
		return fmt.Errorf("vault: %s is not a directory", path)
	}
	if !IsVault(path) {
		return fmt.Errorf("%w: %s (no %s directory)", ErrNotAVault, path, ConfigDirName)
	}
	return nil
}
