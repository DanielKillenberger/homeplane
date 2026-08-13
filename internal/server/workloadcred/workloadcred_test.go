package workloadcred

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testCredential() Credential {
	return Credential{
		AccessToken:  "access-token-value",
		RefreshToken: "refresh-token-value",
		TokenURI:     "https://oauth2.googleapis.com/token",
		ClientID:     "client-id-value",
		ClientSecret: "client-secret-value",
		Scopes: []string{
			"https://www.googleapis.com/auth/drive.readonly",
			"https://www.googleapis.com/auth/calendar.events",
		},
		ExpiresAt: time.Date(2026, 8, 14, 9, 30, 0, 0, time.UTC),
	}
}

func TestMaterializeWritesTheConnectorsShape(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "creds")
	path, err := Materialize("google-oauth-user-file", dir, "daniel@example.test", testCredential())
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if got, want := filepath.Base(path), "daniel@example.test.json"; got != want {
		t.Fatalf("filename %q, want %q — the connector looks the file up by this exact name", got, want)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("the written credential is not JSON: %v", err)
	}
	for field, want := range map[string]string{
		"token":         "access-token-value",
		"refresh_token": "refresh-token-value",
		"token_uri":     "https://oauth2.googleapis.com/token",
		"client_id":     "client-id-value",
		"client_secret": "client-secret-value",
		// Timezone-naive: the connector's auth library compares this against a
		// naive UTC clock.
		"expiry": "2026-08-14T09:30:00.000000",
	} {
		if got[field] != want {
			t.Errorf("%s = %v, want %q", field, got[field], want)
		}
	}
	scopes, _ := got["scopes"].([]any)
	if len(scopes) != 2 {
		t.Errorf("scopes = %v, want the granted set written truthfully", got["scopes"])
	}
}

// TestMaterializeIsNotWorldReadable — the file holds a live refresh token, and a
// mode fixed up after creation leaves a window where it is not.
func TestMaterializeIsNotWorldReadable(t *testing.T) {
	old := syscall.Umask(0o000) // the default test umask would hide the bug
	defer syscall.Umask(old)

	dir := filepath.Join(t.TempDir(), "creds")
	path, err := Materialize("google-oauth-user-file", dir, "daniel@example.test", testCredential())
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != FileMode {
		t.Errorf("credential file mode %o, want %o", got, FileMode)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := di.Mode().Perm(); got != DirMode {
		t.Errorf("credential dir mode %o, want %o", got, DirMode)
	}

	// No temp file survives: a leftover .tmp would hold the same token at
	// whatever mode it was abandoned in.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("credential dir holds %d entries, want exactly the credential", len(entries))
	}
}

// TestMaterializeReplacesAtomically covers R13's replacement case: a re-auth
// overwrites the credential while the workload is running, and must never leave
// a partial file where a whole one was.
func TestMaterializeReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	first := testCredential()
	if _, err := Materialize("google-oauth-user-file", dir, "daniel@example.test", first); err != nil {
		t.Fatalf("first Materialize: %v", err)
	}
	second := testCredential()
	second.RefreshToken = "rotated-refresh-token"
	path, err := Materialize("google-oauth-user-file", dir, "daniel@example.test", second)
	if err != nil {
		t.Fatalf("second Materialize: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(body), "rotated-refresh-token") {
		t.Fatal("the replacement did not take effect")
	}
	if strings.Contains(string(body), "refresh-token-value") {
		t.Fatal("the superseded credential is still in the file")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("dir holds %d entries after a replacement, want 1", len(entries))
	}
}

func TestMaterializeRefusesWhatItCannotDeliver(t *testing.T) {
	dir := t.TempDir()
	if _, err := Materialize("some-other-shape", dir, "daniel@example.test", testCredential()); !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("unknown format: %v, want ErrUnsupportedFormat", err)
	}
	for name, account := range map[string]string{
		"empty":          "  ",
		"path traversal": "../../etc/passwd",
		"separator":      "a/b@example.test",
		"space":          "daniel k@example.test",
		"nul":            "daniel\x00@example.test",
	} {
		if _, err := Materialize("google-oauth-user-file", dir, account, testCredential()); !errors.Is(err, ErrInvalidAccount) {
			t.Errorf("%s account: %v, want ErrInvalidAccount", name, err)
		}
	}
	if _, err := Materialize("google-oauth-user-file", "", "daniel@example.test", testCredential()); err == nil {
		t.Error("an empty destination directory was accepted")
	}
	empty := Credential{TokenURI: "https://oauth2.googleapis.com/token"}
	if _, err := Materialize("google-oauth-user-file", dir, "daniel@example.test", empty); err == nil {
		t.Error("a credential with no tokens at all was written")
	}
	// Nothing above may have written anything.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("refused deliveries left %d files behind: %v", len(entries), entries)
	}
}

// TestMaterializeOmitsAnUnknownExpiry — a zero expiry written as a literal date
// would tell the connector the token expired in year one and force a refresh on
// every call.
func TestMaterializeOmitsAnUnknownExpiry(t *testing.T) {
	dir := t.TempDir()
	c := testCredential()
	c.ExpiresAt = time.Time{}
	path, err := Materialize("google-oauth-user-file", dir, "daniel@example.test", c)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["expiry"] != nil {
		t.Fatalf("expiry = %v, want null for an unknown expiry", got["expiry"])
	}
}
