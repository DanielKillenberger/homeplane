package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// A snapshot is the answer to "what if the first sync eats the vault".
//
// Before Obsidian Sync is ever pointed at Daniel's real vault, the whole vault
// is copied aside and a content manifest is recorded. The manifest is also what
// the destructive-diff guard compares against, so the snapshot pays for itself
// twice: it is both the undo and the evidence.

// ManifestFileName is the manifest written beside a snapshot's file tree.
const ManifestFileName = "manifest.json"

// SnapshotTreeDirName holds the copied files inside a snapshot directory.
const SnapshotTreeDirName = "tree"

// FileEntry is one file's identity in a manifest.
type FileEntry struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

// Manifest is the content identity of a vault at one instant.
type Manifest struct {
	SchemaVersion int                  `json:"schema_version"`
	Root          string               `json:"root"`
	TakenAt       time.Time            `json:"taken_at"`
	Files         map[string]FileEntry `json:"files"`
}

// ManifestSchemaVersion is bumped when the on-disk manifest shape changes.
const ManifestSchemaVersion = 1

// Paths returns the manifest's file paths, sorted.
func (m Manifest) Paths() []string {
	out := make([]string, 0, len(m.Files))
	for p := range m.Files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Scan records every regular file under root, keyed by slash-separated path
// relative to root.
//
// `.obsidian` IS included: a sync that wipes the vault's own configuration is
// exactly as destructive as one that wipes the notes, and the guard should see
// it. Symlinks are recorded as skipped rather than followed — a vault that
// links outside itself must not drag unrelated trees into a snapshot.
func Scan(root string) (Manifest, error) {
	// A symlink root walks as a single non-directory entry and yields an empty
	// manifest. Resolving it here means every caller — snapshot, guard, and the
	// post-sync rescan — agrees on which directory the vault actually is.
	resolved, err := Canonicalize(root)
	if err != nil {
		return Manifest{}, err
	}
	root = resolved
	m := Manifest{
		SchemaVersion: ManifestSchemaVersion,
		Root:          root,
		TakenAt:       time.Now().UTC(),
		Files:         map[string]FileEntry{},
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		m.Files[filepath.ToSlash(rel)] = FileEntry{
			Size:   info.Size(),
			SHA256: sum,
			Mode:   uint32(info.Mode().Perm()),
		}
		return nil
	})
	if err != nil {
		return Manifest{}, fmt.Errorf("vault: scan %s: %w", root, err)
	}
	return m, nil
}

// Snapshot copies the vault under destDir/tree and writes destDir/manifest.json.
//
// destDir must not be inside the vault — a snapshot written into the vault
// would be synced to every other machine and would then be compared against
// itself on the next pass.
func Snapshot(vaultDir, destDir string) (Manifest, error) {
	// Canonicalize first: WalkDir does not follow a symlink root, so a
	// symlinked vault would otherwise produce an empty snapshot AND an empty
	// manifest, and the guard would then compare nothing against nothing.
	vaultDir, err := ValidatePath(vaultDir)
	if err != nil {
		return Manifest{}, err
	}
	inside, err := isInside(destDir, vaultDir)
	if err != nil {
		return Manifest{}, err
	}
	if inside {
		return Manifest{}, fmt.Errorf("vault: refusing to snapshot %s into itself (%s)", vaultDir, destDir)
	}
	if entries, err := os.ReadDir(destDir); err == nil && len(entries) > 0 {
		return Manifest{}, fmt.Errorf("vault: snapshot destination %s is not empty", destDir)
	}
	tree := filepath.Join(destDir, SnapshotTreeDirName)
	if err := os.MkdirAll(tree, credDirPerm); err != nil {
		return Manifest{}, fmt.Errorf("vault: create snapshot dir: %w", err)
	}
	if err := copyTree(vaultDir, tree); err != nil {
		return Manifest{}, err
	}
	m, err := Scan(vaultDir)
	if err != nil {
		return Manifest{}, err
	}
	// Verify the copy is byte-identical to what was scanned. A snapshot nobody
	// checked is a backup nobody has restored.
	copied, err := Scan(tree)
	if err != nil {
		return Manifest{}, err
	}
	if d := Compare(m, copied); len(d.Added)+len(d.Modified)+len(d.Deleted) > 0 {
		return Manifest{}, fmt.Errorf("vault: snapshot of %s does not match the source (%d added, %d modified, %d missing)",
			vaultDir, len(d.Added), len(d.Modified), len(d.Deleted))
	}
	if err := WriteManifest(filepath.Join(destDir, ManifestFileName), m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// WriteManifest persists a manifest atomically.
func WriteManifest(path string, m Manifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("vault: encode manifest: %w", err)
	}
	return writeFileAtomic(path, append(raw, '\n'), credFilePerm)
}

// ReadManifest loads a manifest written by WriteManifest.
func ReadManifest(path string) (Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("vault: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("vault: parse manifest %s: %w", path, err)
	}
	if m.Files == nil {
		m.Files = map[string]FileEntry{}
	}
	return m, nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(target, info.Mode().Perm()|0o700)
		case d.Type().IsRegular():
			return copyFile(path, target)
		default:
			// Symlinks, sockets, devices: recorded by neither Scan nor the copy.
			return nil
		}
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), credDirPerm); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// isInside reports whether candidate resolves to a path under root.
func isInside(candidate, root string) (bool, error) {
	if candidate == "" {
		return false, errors.New("vault: empty path")
	}
	absCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return false, err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	if resolved, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = resolved
	}
	// The candidate may not exist yet; resolve the deepest existing ancestor.
	probe := absCandidate
	for {
		if resolved, err := filepath.EvalSymlinks(probe); err == nil {
			absCandidate = filepath.Join(resolved, relSuffix(probe, absCandidate))
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}
	rel, err := filepath.Rel(absRoot, absCandidate)
	if err != nil {
		return false, err
	}
	return rel != ".." && !hasDotDotPrefix(rel), nil
}

func relSuffix(prefix, full string) string {
	rel, err := filepath.Rel(prefix, full)
	if err != nil {
		return ""
	}
	if rel == "." {
		return ""
	}
	return rel
}

func hasDotDotPrefix(rel string) bool {
	return rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator)
}

func writeFileAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, credDirPerm); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
