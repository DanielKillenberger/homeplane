package vault

import (
	"errors"
	"os"
	"testing"
)

func TestCredentialRoundTripIs0600(t *testing.T) {
	dir := tempDir(t)
	const secret = "obsidian-sync-password"

	if err := SaveCredential(dir, secret); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	info, err := os.Stat(CredentialPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credential mode = %o, want 0600", perm)
	}
	got, err := LoadCredential(dir)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if got != secret {
		t.Fatalf("credential = %q, want %q", got, secret)
	}
}

func TestLoadCredentialDistinguishesAbsentFromUnreadable(t *testing.T) {
	dir := tempDir(t)
	if _, err := LoadCredential(dir); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("err = %v, want ErrNoCredential", err)
	}
}

// A credential whose permissions loosened is refused rather than used: the
// custody exception is only acceptable while the file is actually protected.
func TestLoadCredentialRefusesLoosePermissions(t *testing.T) {
	dir := tempDir(t)
	if err := SaveCredential(dir, "pw"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(CredentialPath(dir), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(dir); err == nil {
		t.Fatal("a world-readable credential was accepted")
	}
}

func TestSaveCredentialRefusesEmpty(t *testing.T) {
	if err := SaveCredential(tempDir(t), "   "); err == nil {
		t.Fatal("an empty credential was stored")
	}
}

// Rewriting the credential must replace it atomically, never append or leave a
// half-written secret behind.
func TestSaveCredentialReplaces(t *testing.T) {
	dir := tempDir(t)
	if err := SaveCredential(dir, "first"); err != nil {
		t.Fatal(err)
	}
	if err := SaveCredential(dir, "second"); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCredential(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "second" {
		t.Fatalf("credential = %q, want %q", got, "second")
	}
}
