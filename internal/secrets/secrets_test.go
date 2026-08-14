package secrets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.age-key")
	kr, err := GenerateKeyFile(path)
	if err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %#o, want 0600", info.Mode().Perm())
	}

	plaintext := []byte("google-oauth-client-secret")
	ciphertext, err := kr.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("ciphertext contains the plaintext")
	}

	loaded, err := LoadKeyFile(path)
	if err != nil {
		t.Fatalf("LoadKeyFile: %v", err)
	}
	got, err := loaded.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted = %q, want %q", got, plaintext)
	}
}

func TestLoadKeyFileRefusesLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.age-key")
	if _, err := GenerateKeyFile(path); err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadKeyFile(path); !errors.Is(err, ErrKeyFilePermissions) {
		t.Fatalf("err = %v, want ErrKeyFilePermissions", err)
	}
}

// TestGenerateKeyFileRefusesToClobber protects every already-stored secret:
// silently minting a new key would make them permanently undecryptable.
func TestGenerateKeyFileRefusesToClobber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.age-key")
	if _, err := GenerateKeyFile(path); err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	if _, err := GenerateKeyFile(path); err == nil {
		t.Fatal("GenerateKeyFile overwrote an existing key file")
	}
}

func TestDecryptFailsWithAnotherKey(t *testing.T) {
	dir := t.TempDir()
	a, err := GenerateKeyFile(filepath.Join(dir, "a.key"))
	if err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	b, err := GenerateKeyFile(filepath.Join(dir, "b.key"))
	if err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	ciphertext, err := a.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := b.Decrypt(ciphertext); err == nil {
		t.Fatal("a foreign key decrypted the ciphertext")
	}
}

func TestLoadKeyFileRejectsMissingAndEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadKeyFile(filepath.Join(dir, "absent.key")); err == nil {
		t.Error("missing key file accepted")
	}
	empty := filepath.Join(dir, "empty.key")
	if err := os.WriteFile(empty, []byte("# only a comment\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadKeyFile(empty); err == nil {
		t.Error("key file without an identity accepted")
	}
}

// TestGenerateKeyFileLeavesNoDebrisOnSuccess checks the atomic-publish path
// cleans up after itself: a stray readable temp copy of the key would defeat
// the point of the 0600 target.
func TestGenerateKeyFileLeavesNoDebrisOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.age-key")
	if _, err := GenerateKeyFile(path); err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "secrets.age-key" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory contains %v, want only the key file", names)
	}
}

// TestGenerateKeyFileDoesNotDisturbAnExistingKey pins the refusal semantics on
// the atomic path: the existing key (and everything encrypted under it) must
// survive a second init attempt untouched.
func TestGenerateKeyFileDoesNotDisturbAnExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.age-key")
	kr, err := GenerateKeyFile(path)
	if err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	ciphertext, err := kr.Encrypt([]byte("provider-secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := GenerateKeyFile(path); err == nil {
		t.Fatal("second GenerateKeyFile succeeded")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("the existing key file was modified by a refused regeneration")
	}
	reloaded, err := LoadKeyFile(path)
	if err != nil {
		t.Fatalf("LoadKeyFile: %v", err)
	}
	if _, err := reloaded.Decrypt(ciphertext); err != nil {
		t.Fatalf("previously sealed secret is no longer decryptable: %v", err)
	}
	// No temp debris from the failed attempt either.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("failed regeneration left %d files behind", len(entries)-1)
	}
}
