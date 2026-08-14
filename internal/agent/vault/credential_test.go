package vault

import (
	"errors"
	"os"
	"testing"
)

// The two credentials are distinct and must stay distinct: the account token
// authenticates to Obsidian and is revocable server-side; the E2E password
// decrypts vault content and cannot be recovered from the account.

func TestAuthTokenRoundTripIs0600(t *testing.T) {
	dir := tempDir(t)
	const token = "tok-abcdef"

	if err := SaveAuthToken(dir, token); err != nil {
		t.Fatalf("SaveAuthToken: %v", err)
	}
	info, err := os.Stat(AuthTokenPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("token mode = %o, want 0600", perm)
	}
	got, err := LoadAuthToken(dir)
	if err != nil {
		t.Fatalf("LoadAuthToken: %v", err)
	}
	if got != token {
		t.Fatalf("token = %q, want %q", got, token)
	}
}

func TestE2EPasswordRoundTripIs0600(t *testing.T) {
	dir := tempDir(t)
	const pw = "correct horse battery staple"

	if err := SaveE2EPassword(dir, pw); err != nil {
		t.Fatalf("SaveE2EPassword: %v", err)
	}
	info, err := os.Stat(E2EPasswordPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("password mode = %o, want 0600", perm)
	}
	got, err := LoadE2EPassword(dir)
	if err != nil {
		t.Fatalf("LoadE2EPassword: %v", err)
	}
	if got != pw {
		t.Fatalf("password = %q", got)
	}
}

// The two secrets live in different files: storing one must never be mistaken
// for storing the other.
func TestTheTwoSecretsAreSeparate(t *testing.T) {
	dir := tempDir(t)
	if err := SaveAuthToken(dir, "tok"); err != nil {
		t.Fatal(err)
	}
	if AuthTokenPath(dir) == E2EPasswordPath(dir) {
		t.Fatal("both credentials share a path")
	}
	if _, err := LoadE2EPassword(dir); !errors.Is(err, ErrNoE2EPassword) {
		t.Fatalf("storing the token also produced an E2E password: %v", err)
	}
}

func TestLoadSecretsRequiresTheTokenButToleratesNoE2EPassword(t *testing.T) {
	dir := tempDir(t)
	if _, err := LoadSecrets(dir); !errors.Is(err, ErrNoAuthToken) {
		t.Fatalf("err = %v, want ErrNoAuthToken", err)
	}
	if err := SaveAuthToken(dir, "tok"); err != nil {
		t.Fatal(err)
	}
	// A standard-encryption vault has no E2E password, and that is fine.
	s, err := LoadSecrets(dir)
	if err != nil {
		t.Fatalf("LoadSecrets: %v", err)
	}
	if s.AuthToken != "tok" || s.E2EPassword != "" {
		t.Fatalf("secrets = %+v", s)
	}
	if err := SaveE2EPassword(dir, "pw"); err != nil {
		t.Fatal(err)
	}
	if s, err = LoadSecrets(dir); err != nil || s.E2EPassword != "pw" {
		t.Fatalf("secrets = %+v, err = %v", s, err)
	}
}

// A credential whose permissions loosened is refused rather than used: the
// custody exception is only acceptable while the file is actually protected.
func TestLoadRefusesLoosePermissions(t *testing.T) {
	dir := tempDir(t)
	if err := SaveAuthToken(dir, "tok"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(AuthTokenPath(dir), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthToken(dir); err == nil {
		t.Fatal("a world-readable token was accepted")
	}
}

func TestSaveRefusesEmptySecrets(t *testing.T) {
	dir := tempDir(t)
	if err := SaveAuthToken(dir, "  "); err == nil {
		t.Fatal("an empty token was stored")
	}
	if err := SaveE2EPassword(dir, ""); err == nil {
		t.Fatal("an empty password was stored")
	}
}

func TestSaveReplacesAtomically(t *testing.T) {
	dir := tempDir(t)
	if err := SaveAuthToken(dir, "first"); err != nil {
		t.Fatal(err)
	}
	if err := SaveAuthToken(dir, "second"); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAuthToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "second" {
		t.Fatalf("token = %q, want %q", got, "second")
	}
}

func TestSecretsAll(t *testing.T) {
	s := Secrets{AuthToken: "a", E2EPassword: "", AccountPassword: "c", MFACode: " "}
	got := s.all()
	if len(got) != 2 {
		t.Fatalf("all() = %v, want the two non-empty secrets", got)
	}
}
