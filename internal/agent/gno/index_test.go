package gno

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/agent/vault"
)

func TestDefaultPathsAreUnderTheAgentStateDirectory(t *testing.T) {
	state := t.TempDir()
	p := DefaultPaths(state)
	for _, dir := range p.All() {
		if !strings.HasPrefix(dir, state) {
			t.Fatalf("%s is not under the agent state directory %s", dir, state)
		}
	}
	if filepath.Base(p.IndexDBPath("")) != "index-default.sqlite" {
		t.Fatalf("the index db path does not follow upstream's layout: %s", p.IndexDBPath(""))
	}
	if filepath.Dir(p.IndexDBPath("")) != p.Data {
		t.Fatalf("the index db is not in the data directory: %s", p.IndexDBPath(""))
	}
}

// The R14 contract: an index inside the vault would be replicated to every
// other machine, and two machines writing the same SQLite file through a sync
// product corrupt it.
func TestEnsureDisposableRefusesAnIndexInsideTheVault(t *testing.T) {
	root := t.TempDir()
	vaultPath := filepath.Join(root, "Daniel-OS")
	if err := os.MkdirAll(vaultPath, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := Paths{
		Config: filepath.Join(vaultPath, ".gno", "config"),
		Data:   filepath.Join(vaultPath, ".gno", "data"),
		Cache:  filepath.Join(vaultPath, ".gno", "cache"),
	}
	err := EnsureDisposable(inside, vaultPath)
	if err == nil {
		t.Fatal("an index inside the vault was accepted")
	}
	if !errors.Is(err, vault.ErrIndexInsideVault) {
		t.Fatalf("expected the R14 in-vault refusal, got %v", err)
	}
}

func TestEnsureDisposableRefusesKnownSyncedTrees(t *testing.T) {
	root := t.TempDir()
	vaultPath := filepath.Join(root, "vault")
	if err := os.MkdirAll(vaultPath, 0o755); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"iCloud":   filepath.Join(root, "Library", "Mobile Documents", "com~apple~CloudDocs", "gno"),
		"Dropbox":  filepath.Join(root, "Dropbox", "gno"),
		"Drive":    filepath.Join(root, "Google Drive", "gno"),
		"OneDrive": filepath.Join(root, "OneDrive", "state", "gno"),
	}
	for name, base := range cases {
		p := Paths{Config: base + "/config", Data: base + "/data", Cache: base + "/cache"}
		err := EnsureDisposable(p, vaultPath)
		if !errors.Is(err, ErrIndexInSyncedPath) {
			t.Fatalf("%s: a synchronized location was accepted: %v", name, err)
		}
	}
}

// A directory merely NAMED after a sync product is not a synced tree. Refusing
// it would be a false positive that blocks a legitimate machine.
func TestEnsureDisposableAllowsALookalikeName(t *testing.T) {
	root := t.TempDir()
	vaultPath := filepath.Join(root, "vault")
	if err := os.MkdirAll(vaultPath, 0o755); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "Dropbox-notes-archive", "gno")
	p := Paths{Config: base + "/config", Data: base + "/data", Cache: base + "/cache"}
	if err := EnsureDisposable(p, vaultPath); err != nil {
		t.Fatalf("a lookalike directory name was refused: %v", err)
	}
}

// A caller can name machine-specific synced trees the marker list cannot know.
func TestEnsureDisposableHonoursExtraSyncedRoots(t *testing.T) {
	root := t.TempDir()
	vaultPath := filepath.Join(root, "vault")
	extra := filepath.Join(root, "company-sync")
	for _, d := range []string{vaultPath, extra} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p := Paths{
		Config: filepath.Join(extra, "gno", "config"),
		Data:   filepath.Join(extra, "gno", "data"),
		Cache:  filepath.Join(extra, "gno", "cache"),
	}
	if err := EnsureDisposable(p, vaultPath, extra); !errors.Is(err, ErrIndexInSyncedPath) {
		t.Fatalf("an operator-declared synced root was accepted: %v", err)
	}
}

// A symlinked state directory pointing into a synced tree must not slip past.
func TestEnsureDisposableResolvesSymlinks(t *testing.T) {
	root := t.TempDir()
	vaultPath := filepath.Join(root, "vault")
	real := filepath.Join(root, "Dropbox", "hidden")
	for _, d := range []string{vaultPath, real} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "state")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p := Paths{Config: link + "/config", Data: link, Cache: link + "/cache"}
	if err := EnsureDisposable(p, vaultPath); !errors.Is(err, ErrIndexInSyncedPath) {
		t.Fatalf("a symlink into a synchronized tree was accepted: %v", err)
	}
}

func TestDiscardRemovesTheIndexAndKeepsTheDirectory(t *testing.T) {
	state := t.TempDir()
	p := DefaultPaths(state)
	if err := p.Create(); err != nil {
		t.Fatal(err)
	}
	db := p.IndexDBPath("")
	if err := os.WriteFile(db, []byte("index"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.ConfigFile(), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !IndexExists(p, "") {
		t.Fatal("IndexExists did not see the index")
	}

	if err := Discard(p); err != nil {
		t.Fatalf("discard: %v", err)
	}
	if IndexExists(p, "") {
		t.Fatal("the index survived being discarded")
	}
	if _, err := os.Stat(p.Data); err != nil {
		t.Fatalf("the data directory was not recreated: %v", err)
	}
	// Config survives: a rebuild must not have to re-derive which folder was
	// bound to which collection.
	if _, err := os.Stat(p.ConfigFile()); err != nil {
		t.Fatalf("discard deleted the configuration: %v", err)
	}
}

func TestDiscardRefusesAHomeOrRootDirectory(t *testing.T) {
	if err := Discard(Paths{Config: "/x", Data: "/", Cache: "/y"}); err == nil {
		t.Fatal("discarding the filesystem root was accepted")
	}
	if home, err := os.UserHomeDir(); err == nil {
		if err := Discard(Paths{Config: "/x", Data: home, Cache: "/y"}); err == nil {
			t.Fatal("discarding the home directory was accepted")
		}
	}
}
