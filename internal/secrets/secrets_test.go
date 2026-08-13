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
