package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The Obsidian credentials are the spec's NAMED custody exception (D4): they
// are the remote-service secrets that must live on the machine, because the
// sync process runs there.
//
// There are TWO of them, and conflating them would be a real hazard:
//
//	auth token     authenticates the ACCOUNT to Obsidian. Obtained once by
//	               `login`, revocable server-side, and handed to the CLI through
//	               OBSIDIAN_AUTH_TOKEN.
//	E2E password   decrypts an end-to-end encrypted VAULT. It is not derivable
//	               from the account and not recoverable if lost; it is answered
//	               at upstream's interactive prompt on stdin.
//
// Both are stored in their own 0600 file in the 0700 agent state directory,
// written atomically, kept out of state.json, argv, logs, and supervision
// units, and refused outright if their permissions have loosened.
const (
	// AuthTokenFileName holds the Obsidian account auth token.
	AuthTokenFileName = "obsidian-auth.token"
	// E2EPasswordFileName holds the end-to-end vault encryption password.
	E2EPasswordFileName = "obsidian-e2e.pass"

	credFilePerm fs.FileMode = 0o600
	credDirPerm  fs.FileMode = 0o700
)

// ErrNoAuthToken means no Obsidian account token is stored on this machine.
var ErrNoAuthToken = errors.New("vault: no Obsidian auth token stored — run `homeplane-agent vault login`")

// ErrNoE2EPassword means no end-to-end encryption password is stored.
var ErrNoE2EPassword = errors.New("vault: no Obsidian end-to-end encryption password stored")

// AuthTokenPath is where the account token lives for a given state dir.
func AuthTokenPath(stateDir string) string { return filepath.Join(stateDir, AuthTokenFileName) }

// E2EPasswordPath is where the vault encryption password lives.
func E2EPasswordPath(stateDir string) string { return filepath.Join(stateDir, E2EPasswordFileName) }

// SaveAuthToken stores the account token 0600, atomically.
func SaveAuthToken(stateDir, token string) error {
	return saveSecret(stateDir, AuthTokenPath(stateDir), token, "Obsidian auth token")
}

// LoadAuthToken reads the account token.
func LoadAuthToken(stateDir string) (string, error) {
	return loadSecret(AuthTokenPath(stateDir), ErrNoAuthToken)
}

// SaveE2EPassword stores the vault encryption password 0600, atomically.
func SaveE2EPassword(stateDir, password string) error {
	return saveSecret(stateDir, E2EPasswordPath(stateDir), password, "Obsidian E2E password")
}

// LoadE2EPassword reads the vault encryption password. Its absence is NOT an
// error for a vault that is not end-to-end encrypted, so callers decide.
func LoadE2EPassword(stateDir string) (string, error) {
	return loadSecret(E2EPasswordPath(stateDir), ErrNoE2EPassword)
}

// LoadSecrets gathers whatever is stored. A missing E2E password is tolerated
// (standard-encryption vaults do not have one); a missing auth token is not,
// because nothing can be done without it.
func LoadSecrets(stateDir string) (Secrets, error) {
	token, err := LoadAuthToken(stateDir)
	if err != nil {
		return Secrets{}, err
	}
	s := Secrets{AuthToken: token}
	switch pw, err := LoadE2EPassword(stateDir); {
	case err == nil:
		s.E2EPassword = pw
	case errors.Is(err, ErrNoE2EPassword):
		// Fine: not every vault is end-to-end encrypted.
	default:
		return Secrets{}, err
	}
	return s, nil
}

func saveSecret(stateDir, path, value, label string) error {
	if strings.TrimSpace(stateDir) == "" {
		return errors.New("vault: state directory is required")
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("vault: refusing to store an empty %s", label)
	}
	if err := os.MkdirAll(stateDir, credDirPerm); err != nil {
		return fmt.Errorf("vault: create state dir: %w", err)
	}
	return writeFileAtomic(path, []byte(value+"\n"), credFilePerm)
}

func loadSecret(path string, absent error) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", absent
		}
		return "", fmt.Errorf("vault: stat %s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("vault: %s is mode %o; it must be 0600", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("vault: read %s: %w", path, err)
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

// CLIConfigDir is where the agent confines obsidian-headless's OWN state (its
// token file and local vault registry), so the agent can never read or clobber
// a human's interactive `ob login` session — nor be silently authenticated by
// one.
func CLIConfigDir(stateDir string) string { return filepath.Join(stateDir, "obsidian-cli") }
