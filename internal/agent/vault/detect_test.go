package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDetectExplicitPathWins(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	got, err := Detect(DetectOptions{ExplicitPath: v})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got.Source != SourceExplicit {
		t.Fatalf("source = %q, want %q", got.Source, SourceExplicit)
	}
	if got.Path != v {
		t.Fatalf("path = %q, want %q", got.Path, v)
	}
}

func TestDetectExplicitPathRejectsNonVault(t *testing.T) {
	dir := t.TempDir()
	_, err := Detect(DetectOptions{ExplicitPath: dir})
	if !errors.Is(err, ErrNotAVault) {
		t.Fatalf("err = %v, want ErrNotAVault", err)
	}
}

func TestDetectFindsRegisteredVault(t *testing.T) {
	home := tempDir(t)
	v := filepath.Join(home, "Daniel-OS")
	mustVault(t, v)

	registry := filepath.Join(home, "obsidian.json")
	writeRegistry(t, registry, v)

	got, err := Detect(DetectOptions{Home: home, RegistryPath: registry, ScanRoots: []string{}})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got.Path != v || got.Source != SourceRegistry {
		t.Fatalf("got %+v, want %s via registry", got, v)
	}
}

func TestDetectFindsVaultByScan(t *testing.T) {
	home := tempDir(t)
	v := filepath.Join(home, "Documents", "Daniel-OS")
	mustVault(t, v)

	got, err := Detect(DetectOptions{
		Home:         home,
		RegistryPath: filepath.Join(home, "absent.json"),
		ScanRoots:    []string{filepath.Join(home, "Documents")},
	})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got.Path != v || got.Source != SourceScan {
		t.Fatalf("got %+v, want %s via scan", got, v)
	}
}

// The load-bearing R3 case: two candidates must produce an explicit-selection
// error listing both, never a silent pick.
func TestDetectRefusesToGuessBetweenCandidates(t *testing.T) {
	home := tempDir(t)
	a := filepath.Join(home, "Documents", "Daniel-OS")
	b := filepath.Join(home, "Documents", "Daniel-OS-old")
	mustVault(t, a)
	mustVault(t, b)

	_, err := Detect(DetectOptions{
		Home:         home,
		RegistryPath: filepath.Join(home, "absent.json"),
		ScanRoots:    []string{filepath.Join(home, "Documents")},
	})
	var ambiguous *AmbiguousError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("err = %v, want *AmbiguousError", err)
	}
	if len(ambiguous.Candidates) != 2 {
		t.Fatalf("candidates = %d, want 2", len(ambiguous.Candidates))
	}
	for _, want := range []string{a, b} {
		if !containsCandidate(ambiguous.Candidates, want) {
			t.Fatalf("candidates %+v missing %s", ambiguous.Candidates, want)
		}
	}
}

// A name filter resolves ambiguity WITHOUT the code choosing for the user.
func TestDetectNameFilterResolvesAmbiguity(t *testing.T) {
	home := tempDir(t)
	mustVault(t, filepath.Join(home, "Documents", "Daniel-OS"))
	mustVault(t, filepath.Join(home, "Documents", "Scratch"))

	got, err := Detect(DetectOptions{
		Home:         home,
		Name:         "Daniel-OS",
		RegistryPath: filepath.Join(home, "absent.json"),
		ScanRoots:    []string{filepath.Join(home, "Documents")},
	})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if filepath.Base(got.Path) != "Daniel-OS" {
		t.Fatalf("got %s, want the Daniel-OS vault", got.Path)
	}
}

func TestDetectNoVault(t *testing.T) {
	home := tempDir(t)
	_, err := Detect(DetectOptions{
		Home:         home,
		RegistryPath: filepath.Join(home, "absent.json"),
		ScanRoots:    []string{home},
	})
	if !errors.Is(err, ErrNoVault) {
		t.Fatalf("err = %v, want ErrNoVault", err)
	}
}

// The same vault reached through the registry AND the scan is one candidate,
// not an ambiguity — otherwise every normal machine would refuse to detect.
func TestDetectDeduplicatesRegistryAndScan(t *testing.T) {
	home := tempDir(t)
	v := filepath.Join(home, "Documents", "Daniel-OS")
	mustVault(t, v)
	registry := filepath.Join(home, "obsidian.json")
	writeRegistry(t, registry, v)

	got, err := Detect(DetectOptions{
		Home:         home,
		RegistryPath: registry,
		ScanRoots:    []string{filepath.Join(home, "Documents")},
	})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got.Path != v {
		t.Fatalf("got %s, want %s", got.Path, v)
	}
}

// A registry naming a directory that has since been deleted must not create a
// phantom candidate.
func TestDetectIgnoresStaleRegistryEntries(t *testing.T) {
	home := tempDir(t)
	live := filepath.Join(home, "Documents", "Daniel-OS")
	mustVault(t, live)
	registry := filepath.Join(home, "obsidian.json")
	writeRegistry(t, registry, live, filepath.Join(home, "gone", "Deleted-Vault"))

	got, err := Detect(DetectOptions{
		Home:         home,
		RegistryPath: registry,
		ScanRoots:    []string{},
	})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got.Path != live {
		t.Fatalf("got %s, want %s", got.Path, live)
	}
}

func TestDetectSurvivesMalformedRegistry(t *testing.T) {
	home := tempDir(t)
	registry := filepath.Join(home, "obsidian.json")
	if err := os.WriteFile(registry, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := filepath.Join(home, "Documents", "Daniel-OS")
	mustVault(t, v)

	got, err := Detect(DetectOptions{
		Home:         home,
		RegistryPath: registry,
		ScanRoots:    []string{filepath.Join(home, "Documents")},
	})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got.Path != v {
		t.Fatalf("got %s, want %s", got.Path, v)
	}
}

func TestValidatePath(t *testing.T) {
	v := makeVault(t, nil)
	got, err := ValidatePath(v)
	if err != nil {
		t.Fatalf("ValidatePath(vault): %v", err)
	}
	if got != v {
		t.Fatalf("ValidatePath returned %q, want the canonical %q", got, v)
	}
	if _, err := ValidatePath(""); err == nil {
		t.Fatal("ValidatePath(\"\") = nil, want an error")
	}
	if _, err := ValidatePath(filepath.Join(v, "nope")); err == nil {
		t.Fatal("ValidatePath(missing) = nil, want an error")
	}
	plain := tempDir(t)
	if _, err := ValidatePath(plain); !errors.Is(err, ErrNotAVault) {
		t.Fatalf("ValidatePath(non-vault) = %v, want ErrNotAVault", err)
	}
	file := filepath.Join(plain, "f")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePath(file); err == nil {
		t.Fatal("ValidatePath(file) = nil, want an error")
	}
}

func TestCanonicalize(t *testing.T) {
	v := makeVault(t, nil)
	link := filepath.Join(tempDir(t), "link")
	if err := os.Symlink(v, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got, err := Canonicalize(link)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if got != v {
		t.Fatalf("Canonicalize(%q) = %q, want %q", link, got, v)
	}
	if _, err := Canonicalize(""); err == nil {
		t.Fatal("an empty path was canonicalized")
	}
	if _, err := Canonicalize(filepath.Join(v, "absent")); err == nil {
		t.Fatal("a missing path was canonicalized")
	}
}

func mustVault(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ConfigDirName), 0o700); err != nil {
		t.Fatalf("create vault %s: %v", dir, err)
	}
}

func writeRegistry(t *testing.T, path string, vaults ...string) {
	t.Helper()
	doc := map[string]any{"vaults": map[string]any{}}
	for i, v := range vaults {
		doc["vaults"].(map[string]any)[itoa(i)] = map[string]any{"path": v}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func containsCandidate(cs []Candidate, path string) bool {
	for _, c := range cs {
		if c.Path == path {
			return true
		}
	}
	return false
}
