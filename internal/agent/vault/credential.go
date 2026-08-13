package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The Obsidian Sync credential is the spec's NAMED custody exception (D4): it
// is the one remote-service secret that must live on the machine, because the
// sync process runs there. Everything about how it is stored follows from that
// being an exception rather than a precedent:
//
//   - own 0600 file in the 0700 agent state directory, beside machine.cred
//   - never in state.json, never in argv, never in a log line, never in a
//     rendered supervision unit (the unit reads the same file)
//   - written atomically, so a crash cannot leave a truncated secret
const (
	// CredentialFileName holds the Obsidian Sync credential.
	CredentialFileName = "obsidian-sync.cred"

	credFilePerm fs.FileMode = 0o600
	credDirPerm  fs.FileMode = 0o700
)

// ErrNoCredential means no sync credential has been stored on this machine.
var ErrNoCredential = errors.New("vault: no Obsidian Sync credential stored")

// CredentialPath is where the sync credential lives for a given state dir.
func CredentialPath(stateDir string) string {
	return filepath.Join(stateDir, CredentialFileName)
}

// SaveCredential stores the sync credential 0600, atomically.
func SaveCredential(stateDir, credential string) error {
	if strings.TrimSpace(stateDir) == "" {
		return errors.New("vault: state directory is required")
	}
	if strings.TrimSpace(credential) == "" {
		return errors.New("vault: refusing to store an empty sync credential")
	}
	if err := os.MkdirAll(stateDir, credDirPerm); err != nil {
		return fmt.Errorf("vault: create state dir: %w", err)
	}
	return writeFileAtomic(CredentialPath(stateDir), []byte(credential+"\n"), credFilePerm)
}

// LoadCredential reads the sync credential, distinguishing "absent" from
// "unreadable" and refusing to read one whose permissions have loosened.
func LoadCredential(stateDir string) (string, error) {
	path := CredentialPath(stateDir)
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", ErrNoCredential
		}
		return "", fmt.Errorf("vault: stat sync credential: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("vault: sync credential %s is mode %o; it must be 0600", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("vault: read sync credential: %w", err)
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}
