package gno

import (
	"os"
	"path/filepath"
	"testing"
)

// Everything in this package's tests runs against temporary directories and a
// FAKE gno CLI. No test reads Daniel's vault, his real GNO index, or the
// network.
//
// The stub implements the REAL 1.29.6 surface — `--version`, `setup`, `doctor`,
// `search`, `mcp install --dry-run`, the stdio `mcp` server, and `daemon` — and
// TestArgvMatchesThePinnedContract independently asserts that the argv this
// package emits is accepted by the real build's own parser, captured in
// testdata/. A stub that agreed with the code but not with upstream is exactly
// the failure mode that pair of checks exists to prevent (the task .5 review
// lesson, applied structurally).
//
// The stub is STATEFUL where upstream is: `search` and `doctor` fail if `setup`
// never ran, and the index database only exists once `setup` has created it —
// which is what makes the delete-the-index self-heal test meaningful rather
// than a no-op against an accommodating fake.

const fakeGNOScript = `#!/bin/sh
set -e

log() {
  if [ -n "$FAKE_GNO_LOG" ]; then
    printf '%s\n' "$1" >> "$FAKE_GNO_LOG"
  fi
}

log "argv:$*"
log "config:${GNO_CONFIG_DIR}"
log "data:${GNO_DATA_DIR}"
log "cache:${GNO_CACHE_DIR}"

CONFIG_FILE="${GNO_CONFIG_DIR}/index.yml"
DB="${GNO_DATA_DIR}/index-default.sqlite"

# Global options come first, exactly as upstream's parser expects.
OFFLINE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --offline) OFFLINE=1; shift ;;
    --index) shift 2 ;;
    --config) shift 2 ;;
    *) break ;;
  esac
done

case "$1" in
  --version|-V)
    echo "${FAKE_GNO_VERSION:-1.29.6}"
    exit 0
    ;;
  setup)
    shift
    FOLDER="$1"; shift
    NAME="collection"
    while [ $# -gt 0 ]; do
      case "$1" in
        --name|-n) NAME="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    if [ -n "$FAKE_GNO_SETUP_FAIL" ]; then
      echo "error: setup failed" >&2
      exit 1
    fi
    if [ ! -d "$FOLDER" ]; then
      echo "error: folder not found: $FOLDER" >&2
      exit 1
    fi
    mkdir -p "$GNO_CONFIG_DIR" "$GNO_DATA_DIR" "$GNO_CACHE_DIR"
    printf 'version: 1\ncollections:\n  - name: %s\n    path: %s\n' "$NAME" "$FOLDER" > "$CONFIG_FILE"
    # A real setup only reports success after a lexical retrieval hits, so the
    # stub refuses an empty folder the same way.
    if [ -z "$(ls -A "$FOLDER" 2>/dev/null)" ]; then
      echo "error: verification failed - no documents indexed" >&2
      exit 1
    fi
    printf 'fake index for %s\n' "$FOLDER" > "$DB"
    printf '{"schemaVersion":"1.0","collection":"%s","verified":true}\n' "$NAME"
    exit 0
    ;;
  doctor)
    if [ ! -f "$CONFIG_FILE" ]; then
      printf '{"healthy":false,"checks":[{"name":"config","status":"error","message":"Config file not found: %s"}]}\n' "$CONFIG_FILE"
      exit 1
    fi
    if [ -n "$FAKE_GNO_DOCTOR_ERROR" ]; then
      printf '{"healthy":false,"checks":[{"name":"database","status":"error","message":"Database missing"}]}\n'
      exit 1
    fi
    printf '{"healthy":true,"checks":[{"name":"config","status":"ok","message":"Config loaded: %s"},{"name":"database","status":"ok","message":"Database found: %s"},{"name":"embed-model","status":"warn","message":"embed model not cached. Run: gno models pull --embed"}]}\n' "$CONFIG_FILE" "$DB"
    exit 0
    ;;
  search)
    shift
    QUERY="$1"
    if [ ! -f "$DB" ]; then
      echo "error: no config. run gno init" >&2
      exit 1
    fi
    if [ -n "$FAKE_GNO_NO_RESULTS" ]; then
      printf '{"results":[]}\n'
      exit 0
    fi
    printf '{"results":[{"docid":"#abc","score":1,"uri":"%s","title":"note","snippet":"%s"}]}\n' \
      "${FAKE_GNO_CALL_URI:-gno://c/note.md}" "$QUERY"
    exit 0
    ;;
  mcp)
    shift
    case "$1" in
      install)
        shift
        TARGET="claude-desktop"
        DRY=0
        while [ $# -gt 0 ]; do
          case "$1" in
            --target|-t) TARGET="$2"; shift 2 ;;
            --scope|-s) shift 2 ;;
            --dry-run) DRY=1; shift ;;
            *) shift ;;
          esac
        done
        case "$TARGET" in
          claude-code|codex|claude-desktop) : ;;
          *) printf '{"error":{"code":"VALIDATION","message":"Invalid target: %s."}}\n' "$TARGET"; exit 1 ;;
        esac
        ACTION="create"
        [ "$DRY" -eq 1 ] && ACTION="dry_run_create"
        printf '{"installed":{"target":"%s","scope":"user","configPath":"/dev/null","action":"%s","serverEntry":{"command":"%s","args":["--config","%s","mcp"],"env":{"GNO_DATA_DIR":"%s","GNO_CACHE_DIR":"%s"}}}}\n' \
          "$TARGET" "$ACTION" "${FAKE_GNO_LAUNCH_COMMAND:-$0}" "$CONFIG_FILE" "$GNO_DATA_DIR" "$GNO_CACHE_DIR"
        exit 0
        ;;
      uninstall|status)
        printf '{"ok":true}\n'
        exit 0
        ;;
      *)
        # No subcommand: the stdio MCP server, which is upstream's default.
        echo "[MCP] fake gno ready on stdio" >&2
        while IFS= read -r line; do
          case "$line" in
            *'"method":"initialize"'*)
              printf '{"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"gno","version":"%s"}},"jsonrpc":"2.0","id":1}\n' "${FAKE_GNO_VERSION:-1.29.6}"
              ;;
            *'"method":"tools/list"'*)
              printf '{"result":{"tools":[{"name":"gno_search"},{"name":"gno_get"}]},"jsonrpc":"2.0","id":2}\n'
              ;;
            *'"method":"tools/call"'*)
              if [ -n "$FAKE_GNO_CALL_FAIL" ]; then
                printf '{"error":{"code":-32000,"message":"tool failed"},"jsonrpc":"2.0","id":3}\n'
              else
                # Upstream renders the document URI into the result text, and the
                # probe holds the endpoint to exactly that: a stub that answered
                # without it would let an endpoint serving a different index pass.
                printf '{"result":{"content":[{"type":"text","text":"Found 1 results for query: [#abc] %s -- %s"}]},"jsonrpc":"2.0","id":3}\n' \
                  "${FAKE_GNO_CALL_URI:-gno://c/note.md}" "${FAKE_GNO_CALL_TEXT:-zarquon-7742-homeplane}"
              fi
              ;;
            *'"method":"notifications/'*) : ;;
          esac
        done
        exit 0
        ;;
    esac
    ;;
  daemon)
    if [ -n "$FAKE_GNO_DAEMON_FAIL" ]; then
      echo "error: daemon failed to start" >&2
      exit 1
    fi
    echo "GNO daemon started (offline=$OFFLINE)"
    # Sleep in short bursts so a cancelled context kills it promptly.
    i=0
    while [ $i -lt 600 ]; do
      sleep 1
      i=$((i + 1))
    done
    exit 0
    ;;
  *)
    echo "error: unknown command $1" >&2
    exit 1
    ;;
esac
`

// writeFakeGNO installs the stub and returns its path.
func writeFakeGNO(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "gno")
	if err := os.WriteFile(path, []byte(fakeGNOScript), 0o755); err != nil {
		t.Fatalf("write fake gno: %v", err)
	}
	return path
}

// testPin is the pin the stub satisfies.
func testPin() Pin {
	return Pin{Version: "1.29.6", Package: "@gmickel/gno", Tarball: "deadbeef"}
}

// newTestCLI builds a CLI over the stub with isolated directories.
func newTestCLI(t *testing.T, stateDir string) CLI {
	t.Helper()
	paths := DefaultPaths(stateDir)
	if err := paths.Create(); err != nil {
		t.Fatalf("create gno dirs: %v", err)
	}
	return CLI{Bin: writeFakeGNO(t), Pin: testPin(), Dirs: paths}
}
