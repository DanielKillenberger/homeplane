package gno

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/DanielKillenberger/homeplane/internal/agent/vault"
)

// The disposable-index contract (R14).
//
// Vault FILES sync between machines. The GNO index must not: it is derived
// state, it is machine-local, it is large, and two machines writing the same
// SQLite file through a file-sync product is a corruption engine. So the index
// lives in the agent's own state directory, and three things are asserted
// before anything is written there:
//
//  1. it is not inside the vault (vault.EnsureOutsideVault, the contract task
//     .5 left here for this task),
//  2. it is not inside any KNOWN synchronized root (iCloud, Dropbox, Drive,
//     OneDrive, Syncthing, Nextcloud) — the vault is not the only synced tree
//     on a real machine,
//  3. deleting it is safe, because the agent can rebuild it from the vault.
//
// The third one is not a comment: Discard + Rebuild is the self-heal path, and
// it is exercised end-to-end against a real GNO in the live test.

const (
	// dirPerm keeps the index owner-only. It is derived from vault content.
	dirPerm fs.FileMode = 0o700
	// filePerm is used for every record this package writes.
	filePerm fs.FileMode = 0o600
)

// Paths are GNO's three directories, pinned per machine.
type Paths struct {
	Config string `json:"config_dir"`
	Data   string `json:"data_dir"`
	Cache  string `json:"cache_dir"`
}

// DefaultPaths puts every GNO directory under the agent's own state directory.
//
// That single decision is what makes the index disposable: the agent state
// directory is machine-local by construction (it holds the machine credential),
// so no index can end up in a synchronized tree by default — and the assertions
// below still run, because "by default" is not the same as "always".
func DefaultPaths(stateDir string) Paths {
	root := filepath.Join(stateDir, "gno")
	return Paths{
		Config: filepath.Join(root, "config"),
		Data:   filepath.Join(root, "data"),
		Cache:  filepath.Join(root, "cache"),
	}
}

// All returns the three directories in a stable order.
func (p Paths) All() []string { return []string{p.Config, p.Data, p.Cache} }

// Complete reports whether all three directories are set.
func (p Paths) Complete() bool {
	return p.Config != "" && p.Data != "" && p.Cache != ""
}

// Create makes the directories 0700.
func (p Paths) Create() error {
	if !p.Complete() {
		return errors.New("gno: config, data, and cache directories are all required")
	}
	for _, dir := range p.All() {
		if err := os.MkdirAll(dir, dirPerm); err != nil {
			return fmt.Errorf("gno: create %s: %w", dir, err)
		}
	}
	return nil
}

// ConfigFile is GNO's own config file inside the pinned config directory.
func (p Paths) ConfigFile() string { return filepath.Join(p.Config, "index.yml") }

// IndexDBPath is the SQLite index for a named index, following upstream's own
// `<dataDir>/index-<name>.sqlite` layout.
func (p Paths) IndexDBPath(index string) string {
	if strings.TrimSpace(index) == "" {
		index = DefaultIndexName
	}
	return filepath.Join(p.Data, "index-"+index+".sqlite")
}

// ErrIndexInSyncedPath means an index directory resolves inside a tree that a
// file-sync product replicates between machines.
var ErrIndexInSyncedPath = errors.New("gno: the index must not live inside a synchronized path")

// syncedMarkers are path segments that identify a synchronized tree on macOS or
// Linux. They are matched as whole path SEGMENTS, so a vault called
// "Dropbox notes" is not mistaken for Dropbox itself.
var syncedMarkers = []string{
	"Library/Mobile Documents", // iCloud Drive
	"Library/CloudStorage",     // macOS: Dropbox/Drive/OneDrive/Box mounts
	"Dropbox",
	"Google Drive",
	"GoogleDrive",
	"OneDrive",
	"Nextcloud",
	"ownCloud",
	"Syncthing",
	"pCloud Drive",
	"Sync",
}

// EnsureDisposable asserts an index location is machine-local: outside the
// vault, and outside every known synchronized root.
//
// extraSyncedRoots lets a caller name machine-specific synced trees the marker
// list cannot know about. Passing none is normal; passing the vault twice is
// harmless.
func EnsureDisposable(p Paths, vaultPath string, extraSyncedRoots ...string) error {
	if !p.Complete() {
		return errors.New("gno: config, data, and cache directories are all required")
	}
	for _, dir := range p.All() {
		abs, err := absClean(dir)
		if err != nil {
			return err
		}
		if strings.TrimSpace(vaultPath) != "" {
			if err := vault.EnsureOutsideVault(abs, vaultPath); err != nil {
				return err
			}
		}
		for _, root := range extraSyncedRoots {
			if strings.TrimSpace(root) == "" {
				continue
			}
			inside, err := withinRoot(abs, root)
			if err != nil {
				return err
			}
			if inside {
				return fmt.Errorf("%w: %s is inside %s", ErrIndexInSyncedPath, abs, root)
			}
		}
		if marker, ok := matchesSyncedMarker(abs); ok {
			return fmt.Errorf("%w: %s looks like it is inside a %s tree", ErrIndexInSyncedPath, abs, marker)
		}
	}
	return nil
}

// matchesSyncedMarker reports whether a path contains a known synced-tree
// segment. Matching is on whole segments (and, for two-part markers, on
// consecutive segments) so a note directory merely NAMED after a sync product
// is not refused.
func matchesSyncedMarker(abs string) (string, bool) {
	segments := strings.Split(filepath.ToSlash(abs), "/")
	for _, marker := range syncedMarkers {
		parts := strings.Split(marker, "/")
		for i := 0; i+len(parts) <= len(segments); i++ {
			match := true
			for j, want := range parts {
				if !strings.EqualFold(segments[i+j], want) {
					match = false
					break
				}
			}
			if match {
				return marker, true
			}
		}
	}
	return "", false
}

func absClean(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("gno: path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("gno: resolve %s: %w", path, err)
	}
	// Resolve symlinks: a symlinked state directory pointing into a synced tree
	// would otherwise pass every check.
	//
	// The path usually does NOT exist yet — it is about to be created — so the
	// LONGEST EXISTING ANCESTOR is resolved and the remainder re-appended.
	// Resolving only fully existing paths would silently compare a /var path
	// against a /private/var one on macOS and conclude they are unrelated.
	return resolveExistingPrefix(filepath.Clean(abs)), nil
}

func resolveExistingPrefix(abs string) string {
	remainder := ""
	current := abs
	for {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			return filepath.Join(resolved, remainder)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return abs
		}
		remainder = filepath.Join(filepath.Base(current), remainder)
		current = parent
	}
}

func withinRoot(path, root string) (bool, error) {
	rootAbs, err := absClean(root)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(rootAbs, path)
	if err != nil {
		return false, nil
	}
	if rel == "." {
		return true, nil
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..", nil
}

// IndexExists reports whether an index database is present.
func IndexExists(p Paths, index string) bool {
	info, err := os.Stat(p.IndexDBPath(index))
	return err == nil && !info.IsDir() && info.Size() > 0
}

// Discard deletes the machine-local index, keeping GNO's configuration.
//
// This is the operation the disposable contract exists to make safe, and it is
// deliberately narrow: it removes the DATA directory (index, WAL, receipts) and
// leaves config and cache alone, so a rebuild does not have to re-download
// anything or re-derive which folder was bound to which collection.
func Discard(p Paths) error {
	if strings.TrimSpace(p.Data) == "" {
		return errors.New("gno: no data directory to discard")
	}
	abs, err := absClean(p.Data)
	if err != nil {
		return err
	}
	// A guard against catastrophe: refuse to recursively delete a root or a home
	// directory if a caller ever hands us a truncated path.
	if abs == "/" || abs == filepath.Dir(abs) {
		return fmt.Errorf("gno: refusing to discard %s", abs)
	}
	if home, err := os.UserHomeDir(); err == nil && abs == filepath.Clean(home) {
		return fmt.Errorf("gno: refusing to discard the home directory %s", abs)
	}
	if err := os.RemoveAll(abs); err != nil {
		return fmt.Errorf("gno: discard index at %s: %w", abs, err)
	}
	return os.MkdirAll(abs, dirPerm)
}

// KnownSyncedRoots names the synchronized trees that exist on THIS machine, for
// an operator reading `status` and for the activation record's evidence.
func KnownSyncedRoots() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	candidates := []string{
		filepath.Join(home, "Library", "Mobile Documents"),
		filepath.Join(home, "Library", "CloudStorage"),
		filepath.Join(home, "Dropbox"),
		filepath.Join(home, "Google Drive"),
		filepath.Join(home, "OneDrive"),
		filepath.Join(home, "Nextcloud"),
		filepath.Join(home, "Syncthing"),
	}
	if runtime.GOOS != "darwin" {
		candidates = candidates[2:]
	}
	var out []string
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			out = append(out, c)
		}
	}
	return out
}
