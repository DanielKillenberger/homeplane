package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// Everything in this package's tests runs against temporary directories and a
// FAKE obsidian-headless CLI. No test reads a real vault, a real Obsidian
// configuration, or the real network: the live integration is task .7's job,
// and a unit test that could delete a real vault would be the exact hazard this
// package exists to prevent.

// fakeOBScript behaves enough like obsidian-headless to exercise every branch:
// it reports a version, records the credential it was given (proving custody
// through the environment), and can be told to fail or to be destructive.
const fakeOBScript = `#!/bin/sh
set -e
if [ "$1" = "--version" ]; then
  echo "obsidian-headless ${FAKE_OB_VERSION:-0.0.13}"
  exit 0
fi
# argv shape: sync --vault DIR --once|--continuous
VAULT="$3"
if [ -n "$FAKE_OB_LOG" ]; then
  printf 'argv:%s\ncred:%s\n' "$*" "$OBSIDIAN_SYNC_PASSWORD" >> "$FAKE_OB_LOG"
fi
if [ -n "$FAKE_OB_FAIL" ]; then
  echo "$FAKE_OB_FAIL" >&2
  exit 1
fi
case "${FAKE_OB_MODE:-noop}" in
  noop) ;;
  add)
    echo "arrived from another machine" > "$VAULT/arrived.md"
    ;;
  wipe)
    find "$VAULT" -type f -name '*.md' -exec rm -f {} +
    ;;
  rewrite)
    find "$VAULT" -type f -name '*.md' -exec sh -c 'echo clobbered > "$1"' _ {} \;
    ;;
esac
exit 0
`

// writeFakeOB installs the stub and returns its path and SHA-256, so a test can
// pin the CLI to exactly the build it just wrote.
func writeFakeOB(t *testing.T) (path, sum string) {
	t.Helper()
	dir := tempDir(t)
	path = filepath.Join(dir, "ob")
	if err := os.WriteFile(path, []byte(fakeOBScript), 0o755); err != nil {
		t.Fatalf("write fake ob: %v", err)
	}
	sum, err := fileSHA256(path)
	if err != nil {
		t.Fatalf("checksum fake ob: %v", err)
	}
	return path, sum
}

// pinnedFakeCLI returns a CLI pinned to the stub it just wrote.
func pinnedFakeCLI(t *testing.T) CLI {
	t.Helper()
	path, sum := writeFakeOB(t)
	return CLI{Bin: path, Pin: Pin{Version: "0.0.13", Checksum: sum}}
}

// tempDir returns a temporary directory with symlinks resolved. macOS puts
// t.TempDir() under /var, which is a symlink to /private/var; detection
// resolves symlinks, so an unresolved path would fail comparisons for reasons
// that have nothing to do with the code under test.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	return dir
}

// makeVault scaffolds a vault directory with the given notes.
func makeVault(t *testing.T, notes map[string]string) string {
	t.Helper()
	dir := tempDir(t)
	if err := os.MkdirAll(filepath.Join(dir, ConfigDirName), 0o700); err != nil {
		t.Fatalf("make vault config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigDirName, "app.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write vault config: %v", err)
	}
	for name, body := range notes {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatalf("make note dir: %v", err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("write note: %v", err)
		}
	}
	return dir
}

// manyNotes builds a note set large enough that fractional guard limits bite.
func manyNotes(n int) map[string]string {
	notes := make(map[string]string, n)
	for i := 0; i < n; i++ {
		notes[filepath.Join("notes", string(rune('a'+i%26))+itoa(i)+".md")] = "note " + itoa(i) + "\n"
	}
	return notes
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
