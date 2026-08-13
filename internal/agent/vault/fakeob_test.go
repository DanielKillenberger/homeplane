package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// Everything in this package's tests runs against temporary directories and a
// FAKE obsidian-headless CLI. No test reads a real vault, a real Obsidian
// configuration, or the real network.
//
// The stub implements the REAL 0.0.13 command surface — `login`,
// `sync-list-remote`, `sync-setup`, `sync-config`, `sync-status`, and
// `sync [--path] [--continuous]` — and TestArgvMatchesThePinnedContract
// independently asserts that the argv this package emits is accepted by the
// real build's own parser, captured in testdata/. A stub that agreed with the
// code but not with upstream is exactly the failure mode that pair of checks
// exists to prevent.
//
// The stub is also STATEFUL, and that is load-bearing rather than decorative:
// upstream refuses `sync`, `sync-config`, and `sync-status` on a directory that
// was never bound by `sync-setup`. An accommodating stub that synced any
// directory with a `.obsidian` folder is precisely what let an invalid
// lifecycle pass its tests once already, so this one refuses the same way
// upstream does.

const fakeOBScript = `#!/bin/sh
set -e

log() {
  if [ -n "$FAKE_OB_LOG" ]; then
    printf '%s\n' "$1" >> "$FAKE_OB_LOG"
  fi
}

log "argv:$*"
log "token:${OBSIDIAN_AUTH_TOKEN}"

case "$1" in
  --version|-V)
    echo "${FAKE_OB_VERSION:-0.0.13}"
    exit 0
    ;;
  login)
    # The password arrives on stdin, at upstream's prompt.
    read -r PASSWORD || PASSWORD=""
    log "password:${PASSWORD}"
    if [ -n "$FAKE_OB_AUTH_FAIL" ]; then
      echo "error: unauthorized - invalid credentials" >&2
      exit 1
    fi
    CFG="${XDG_CONFIG_HOME:-$HOME/.config}/obsidian-headless"
    mkdir -p "$CFG"
    printf '%s' "${FAKE_OB_TOKEN:-fake-auth-token}" > "$CFG/auth_token"
    chmod 600 "$CFG/auth_token"
    echo "Logged in"
    exit 0
    ;;
  sync-list-remote)
    if [ -z "$OBSIDIAN_AUTH_TOKEN" ] || [ -n "$FAKE_OB_AUTH_FAIL" ]; then
      echo "error: unauthorized - please log in" >&2
      exit 1
    fi
    if [ -n "$FAKE_OB_NET_FAIL" ]; then
      echo "error: connection refused" >&2
      exit 1
    fi
    echo "Remote vaults:"
    printf '%s\n' ${FAKE_OB_REMOTES:-Daniel-OS}
    exit 0
    ;;
  sync-create-remote)
    if [ -z "$OBSIDIAN_AUTH_TOKEN" ]; then
      echo "error: unauthorized - please log in" >&2
      exit 1
    fi
    exit 0
    ;;
  sync-setup)
    # sync-setup --vault NAME --path DIR [--device-name N]
    shift
    VAULT=""; DIR="$PWD"
    while [ $# -gt 0 ]; do
      case "$1" in
        --vault) VAULT="$2"; shift 2 ;;
        --path) DIR="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    read -r E2E || E2E=""
    log "e2e:${E2E}"
    if [ -z "$OBSIDIAN_AUTH_TOKEN" ] || [ -n "$FAKE_OB_AUTH_FAIL" ]; then
      echo "error: unauthorized - please log in" >&2
      exit 1
    fi
    if [ -n "$FAKE_OB_SETUP_FAIL" ]; then
      echo "$FAKE_OB_SETUP_FAIL" >&2
      exit 1
    fi
    mkdir -p "$DIR/.obsidian"
    printf '{}\n' > "$DIR/.obsidian/app.json"
    # THE state marker: upstream stores a sync configuration here, and every
    # command below refuses without it.
    printf 'remote=%s\nmode=bidirectional\n' "$VAULT" > "$DIR/.obsidian/sync-config"
    exit 0
    ;;
  sync-status)
    shift
    DIR="$PWD"
    while [ $# -gt 0 ]; do
      case "$1" in --path) DIR="$2"; shift 2 ;; *) shift ;; esac
    done
    if [ ! -f "$DIR/.obsidian/sync-config" ]; then
      echo "error: this vault is not configured for sync - run sync-setup first" >&2
      exit 1
    fi
    cat "$DIR/.obsidian/sync-config"
    exit 0
    ;;
  sync-config)
    shift
    DIR="$PWD"; MODE=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --path) DIR="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    log "mode:${MODE}"
    if [ ! -f "$DIR/.obsidian/sync-config" ]; then
      echo "error: this vault is not configured for sync - run sync-setup first" >&2
      exit 1
    fi
    if [ -n "$FAKE_OB_CONFIG_FAIL" ]; then
      echo "$FAKE_OB_CONFIG_FAIL" >&2
      exit 1
    fi
    if [ -n "$FAKE_OB_BIDI_FAIL" ] && [ "$MODE" = "bidirectional" ]; then
      echo "$FAKE_OB_BIDI_FAIL" >&2
      exit 1
    fi
    printf 'remote=unknown\nmode=%s\n' "$MODE" > "$DIR/.obsidian/sync-config"
    exit 0
    ;;
  sync)
    shift
    DIR="$PWD"; CONTINUOUS=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --path) DIR="$2"; shift 2 ;;
        --continuous) CONTINUOUS=1; shift ;;
        *) shift ;;
      esac
    done
    # Upstream refuses to sync a directory that was never bound to a remote
    # vault. An .obsidian folder alone is NOT a sync configuration.
    if [ ! -f "$DIR/.obsidian/sync-config" ]; then
      echo "error: this vault is not configured for sync - run sync-setup first" >&2
      exit 1
    fi
    if [ -n "$FAKE_OB_FAIL" ]; then
      echo "$FAKE_OB_FAIL" >&2
      exit 1
    fi
    case "${FAKE_OB_MODE:-noop}" in
      noop) ;;
      add)     echo "arrived from another machine" > "$DIR/arrived.md" ;;
      pull)    mkdir -p "$DIR/.obsidian"; printf '{}\n' > "$DIR/.obsidian/app.json"
               echo "# pulled" > "$DIR/pulled.md" ;;
      wipe)    find "$DIR" -type f -name '*.md' -exec rm -f {} + ;;
      rewrite) find "$DIR" -type f -name '*.md' -exec sh -c 'echo clobbered > "$1"' _ {} \; ;;
    esac
    if [ -n "$CONTINUOUS" ]; then
      # A real continuous sync runs until it is stopped. Sleeping in short
      # bursts keeps the stub responsive to context cancellation.
      i=0
      while [ $i -lt 600 ]; do
        echo "watching"
        sleep 0.1
        i=$((i+1))
      done
    fi
    exit 0
    ;;
esac
echo "error: unknown command $1" >&2
exit 1
`

// writeFakeOB installs the stub and returns its path and SHA-256.
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
// t.TempDir() under /var, which is a symlink to /private/var; the vault paths
// are canonicalized, so an unresolved path would fail comparisons for reasons
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
//
// It writes the sync-configuration marker too: an existing Daniel-OS vault on a
// machine has already been bound to a remote vault, which is exactly why
// `sync --path` is valid against it and NOT valid against a bare directory.
func makeVault(t *testing.T, notes map[string]string) string {
	t.Helper()
	dir := tempDir(t)
	if err := os.MkdirAll(filepath.Join(dir, ConfigDirName), 0o700); err != nil {
		t.Fatalf("make vault config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigDirName, "app.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write vault config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigDirName, "sync-config"),
		[]byte("remote=Daniel-OS\nmode=bidirectional\n"), 0o600); err != nil {
		t.Fatalf("write sync config: %v", err)
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

// testSecrets is a stored-credential set for tests.
func testSecrets() Secrets {
	return Secrets{AuthToken: "fake-auth-token", E2EPassword: "fake-e2e-password"}
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
