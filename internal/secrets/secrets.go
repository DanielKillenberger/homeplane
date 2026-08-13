// Package secrets implements D3's at-rest protection for provider credentials:
// age (X25519) encryption under a server-local key file that is provisioned out
// of band (systemd LoadCredential / 0600 file) and never lives in the database.
//
// Consequence: a stolen SQLite file alone does not yield provider credentials,
// and the store layer only ever handles opaque ciphertext.
package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// ErrKeyFilePermissions is returned when the age key file is group- or
// world-accessible. Refusing to read a loose key file is the point: a
// credential store is only as private as the key protecting it.
var ErrKeyFilePermissions = errors.New("secrets: age key file must not be group- or world-accessible (want 0600)")

// Keyring holds the server's age identity and encrypts/decrypts provider
// secrets with it.
type Keyring struct {
	identity *age.X25519Identity
}

// GenerateKeyFile writes a fresh age identity to path with 0600 permissions,
// refusing to clobber an existing file (regenerating a key would orphan every
// secret already encrypted under the old one).
//
// The write is atomic: the identity is written, fsynced, and closed in a
// temporary 0600 file alongside the target, and only then linked into place.
// The failure this avoids is nasty and silent — a disk-full or interrupted
// first run leaving a truncated key at the final path, which every later run
// then refuses to replace, locking the operator out of a store they cannot yet
// have populated.
func GenerateKeyFile(path string) (*Keyring, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("secrets: generate identity: %w", err)
	}
	contents := "# Homeplane provider-secret key (age X25519). Keep 0600, back up offline.\n" +
		"# public key: " + id.Recipient().String() + "\n" +
		id.String() + "\n"

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".age-key-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("secrets: create temporary key file: %w", err)
	}
	tmpName := tmp.Name()
	// From here on, every failure path removes the temporary file.
	cleanup := func() { _ = os.Remove(tmpName) }

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return nil, fmt.Errorf("secrets: chmod temporary key file: %w", err)
	}
	if _, err := io.WriteString(tmp, contents); err != nil {
		_ = tmp.Close()
		cleanup()
		return nil, fmt.Errorf("secrets: write key file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return nil, fmt.Errorf("secrets: sync key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return nil, fmt.Errorf("secrets: close key file: %w", err)
	}

	// Link rather than rename: rename would silently overwrite an existing key,
	// destroying access to every secret already sealed under it. Link fails if
	// the target exists, which is exactly the behavior wanted.
	if err := os.Link(tmpName, path); err != nil {
		cleanup()
		return nil, fmt.Errorf("secrets: publish key file: %w", err)
	}
	cleanup()
	return &Keyring{identity: id}, nil
}

// LoadKeyFile reads an age identity from path, enforcing 0600-style
// permissions.
func LoadKeyFile(path string) (*Keyring, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("secrets: open key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("secrets: key file %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %#o", ErrKeyFilePermissions, path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secrets: read key file: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, err := age.ParseX25519Identity(line)
		if err != nil {
			return nil, fmt.Errorf("secrets: parse key file %s: %w", path, err)
		}
		return &Keyring{identity: id}, nil
	}
	return nil, fmt.Errorf("secrets: key file %s contains no identity", path)
}

// Recipient returns the public key of this keyring.
func (k *Keyring) Recipient() string { return k.identity.Recipient().String() }

// Encrypt seals plaintext for this keyring.
func (k *Keyring) Encrypt(plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, k.identity.Recipient())
	if err != nil {
		return nil, fmt.Errorf("secrets: encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("secrets: encrypt write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("secrets: encrypt close: %w", err)
	}
	return buf.Bytes(), nil
}

// ageHeader begins every age message (binary format, which Encrypt produces).
const ageHeader = "age-encryption.org/v1"

// LooksEncrypted reports whether b is an age message.
//
// It is a STRUCTURAL check, not a cryptographic one: it answers "were these
// bytes produced by Encrypt?" without a key, which is what an operator asking
// "is my credential store actually encrypted at rest?" needs — and it cannot,
// by construction, reveal anything about the plaintext. Anything that has to
// know the value must Decrypt and hold the key.
func LooksEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte(ageHeader))
}

// Decrypt opens ciphertext sealed by Encrypt.
func (k *Keyring) Decrypt(ciphertext []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), k.identity)
	if err != nil {
		return nil, fmt.Errorf("secrets: decrypt: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("secrets: decrypt read: %w", err)
	}
	return plaintext, nil
}
