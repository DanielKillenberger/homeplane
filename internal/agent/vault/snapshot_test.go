package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotCopiesAndManifestsTheVault(t *testing.T) {
	v := makeVault(t, map[string]string{
		"a.md":             "alpha\n",
		"nested/b.md":      "beta\n",
		"nested/deep/c.md": "gamma\n",
	})
	dest := filepath.Join(tempDir(t), "snap")

	m, err := Snapshot(v, dest)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// .obsidian/app.json plus three notes.
	if len(m.Files) != 4 {
		t.Fatalf("manifest has %d files, want 4: %v", len(m.Files), m.Paths())
	}
	for _, rel := range []string{"a.md", "nested/b.md", "nested/deep/c.md", ".obsidian/app.json"} {
		if _, ok := m.Files[rel]; !ok {
			t.Fatalf("manifest is missing %s: %v", rel, m.Paths())
		}
		copied := filepath.Join(dest, SnapshotTreeDirName, filepath.FromSlash(rel))
		if _, err := os.Stat(copied); err != nil {
			t.Fatalf("snapshot is missing %s: %v", rel, err)
		}
	}

	// The snapshot must be restorable, which means its bytes must match.
	got, err := os.ReadFile(filepath.Join(dest, SnapshotTreeDirName, "nested", "b.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "beta\n" {
		t.Fatalf("snapshot content = %q", got)
	}

	reread, err := ReadManifest(filepath.Join(dest, ManifestFileName))
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if len(reread.Files) != len(m.Files) {
		t.Fatalf("re-read manifest has %d files, want %d", len(reread.Files), len(m.Files))
	}
}

// A snapshot written inside the vault would be synced to every other machine
// and would then be compared against itself.
func TestSnapshotRefusesToWriteIntoTheVault(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	_, err := Snapshot(v, filepath.Join(v, "backup"))
	if err == nil || !strings.Contains(err.Error(), "into itself") {
		t.Fatalf("err = %v, want a refusal to snapshot into the vault", err)
	}
}

func TestSnapshotRefusesANonEmptyDestination(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	dest := filepath.Join(tempDir(t), "snap")
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "stale"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Snapshot(v, dest); err == nil {
		t.Fatal("a non-empty snapshot destination was accepted")
	}
}

func TestSnapshotRefusesANonVault(t *testing.T) {
	if _, err := Snapshot(tempDir(t), filepath.Join(tempDir(t), "snap")); err == nil {
		t.Fatal("a non-vault directory was snapshotted")
	}
}

func TestScanIsContentAddressed(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "alpha\n"})
	before, err := Scan(v)
	if err != nil {
		t.Fatal(err)
	}
	// Same size, different content: a size-only manifest would miss this, and
	// so would a guard built on it.
	if err := os.WriteFile(filepath.Join(v, "a.md"), []byte("alpin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := Scan(v)
	if err != nil {
		t.Fatal(err)
	}
	d := Compare(before, after)
	if len(d.Modified) != 1 || d.Modified[0] != "a.md" {
		t.Fatalf("diff = %+v, want a.md modified", d)
	}
}

func TestScanIgnoresSymlinks(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	outside := filepath.Join(tempDir(t), "outside.md")
	if err := os.WriteFile(outside, []byte("not mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(v, "link.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	m, err := Scan(v)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Files["link.md"]; ok {
		t.Fatal("a symlink was followed into the manifest")
	}
}
