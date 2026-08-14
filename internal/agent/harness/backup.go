package harness

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// BackupSuffix marks the copies this package takes. It is distinctive enough
// that an operator scanning a directory can tell at a glance which files
// Homeplane put there — and, more importantly, which ones hold a grant token.
const BackupSuffix = ".homeplane-backup-"

// backupClock is a test seam. Two writes inside the same second must not land
// on the same backup name, so the timestamp is second-resolution plus a
// uniquifying suffix chosen by the filesystem (O_EXCL) rather than by a clock
// nobody can control.
var backupClock = time.Now

// backupFile copies path to a timestamped sibling before it is written.
//
// A backup is taken BEFORE parsing, not after: a config too malformed to parse
// is exactly the one whose original bytes an operator will want back, and R5
// requires the skip path to leave a backup intact. The copy carries 0600
// whatever the original's mode was — a backup of a file holding a grant token
// holds one too.
//
// A missing original is not an error and produces no backup: there is nothing
// to preserve, and inventing an empty file to "back up" would be a lie.
func backupFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	stamp := backupClock().UTC().Format("20060102T150405Z")
	base := path + BackupSuffix + stamp

	for attempt := 0; ; attempt++ {
		candidate := base
		if attempt > 0 {
			candidate = fmt.Sprintf("%s-%d", base, attempt)
		}
		f, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
		if errors.Is(err, fs.ErrExist) {
			if attempt > 100 {
				return "", fmt.Errorf("could not find a free backup name beside %s", path)
			}
			continue
		}
		if err != nil {
			return "", fmt.Errorf("create backup %s: %w", candidate, err)
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return "", fmt.Errorf("write backup %s: %w", candidate, err)
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return "", fmt.Errorf("sync backup %s: %w", candidate, err)
		}
		if err := f.Close(); err != nil {
			return "", fmt.Errorf("close backup %s: %w", candidate, err)
		}
		return candidate, nil
	}
}

// ensureBackup reuses a backup that still holds the file's CURRENT bytes, and
// takes a fresh one otherwise.
//
// The two-phase write backs the file up in phase one, before a grant is minted,
// and commits in phase two. Re-copying an unchanged file would litter the
// directory with a second identical copy on every run; reusing a copy of bytes
// that have since changed would be worse — the rollback would restore someone
// else's overwritten edit. So the reuse is CONDITIONAL on the bytes still
// matching, which is exactly the condition under which the copy is still a
// faithful "what was there before we wrote".
func ensureBackup(path, existing string) (string, error) {
	if existing == "" {
		return backupFile(path)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The file has been deleted since phase one. The existing copy is
			// still what was there, and there is nothing new to copy.
			return existing, nil
		}
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	saved, err := os.ReadFile(existing)
	if err != nil {
		return "", fmt.Errorf("read backup %s: %w", existing, err)
	}
	if bytes.Equal(current, saved) {
		return existing, nil
	}
	return backupFile(path)
}

// restoreFromBackup puts the original bytes back. It is the rollback half of
// every verified write: a write whose preservation check fails has already
// touched the file, and leaving it there would be worse than never having
// tried.
func restoreFromBackup(path, backup string) error {
	if backup == "" {
		// There was no original: the correct rollback is to remove what we made.
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		return nil
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		return fmt.Errorf("read backup %s: %w", backup, err)
	}
	return writeFileAtomic(path, data, filePerm)
}

// writeFileAtomic writes data through a same-directory temporary file, fsynced
// and renamed, so no reader (and no crash) ever observes a half-written config.
func writeFileAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".homeplane-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName) // a no-op once the rename succeeded
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
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}
