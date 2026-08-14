#!/usr/bin/env bash
# capture-gno-contract.sh — capture the pinned GNO build's own parser output.
#
# The Go wrapper in internal/agent/gno builds argv for a CLI it does not own. A
# stub can only prove the wrapper agrees with itself, so the argv is also
# asserted against the REAL build's help text, captured here verbatim and
# committed as testdata. An invented flag (`--vault`, `--once`, `--target` on
# the wrong subcommand) cannot survive that assertion.
#
# GNO's nested subcommands (`gno mcp serve --help`) fall back to the ROOT help
# in 1.29.x — commander does not route `--help` past the first level. So the
# nested groups are captured through their PARENT (`gno mcp --help`), which does
# list every child, and the child flags are captured where upstream exposes them.
#
# Usage: scripts/capture-gno-contract.sh [path-to-gno]
# Writes: internal/agent/gno/testdata/gno-<version>-contract.txt
set -euo pipefail

GNO_BIN="${1:-gno}"
command -v "$GNO_BIN" >/dev/null 2>&1 || { echo "capture-gno-contract.sh: $GNO_BIN not found" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUT_DIR="$REPO_ROOT/internal/agent/gno/testdata"
mkdir -p "$OUT_DIR"

VERSION="$("$GNO_BIN" --version | tr -d '[:space:]')"
OUT="$OUT_DIR/gno-$VERSION-contract.txt"

# A captured contract must describe the machine's own environment as little as
# possible: run every probe with isolated GNO dirs so no personal collection
# name, index path, or home directory can leak into a committed file.
WORK="$(mktemp -d)"
trap 'command rm -rf "$WORK"' EXIT
export GNO_CONFIG_DIR="$WORK/config" GNO_DATA_DIR="$WORK/data" GNO_CACHE_DIR="$WORK/cache"

{
  echo "# Captured from gno $VERSION by scripts/capture-gno-contract.sh."
  echo "# Verbatim upstream --help output. Do not hand-edit."
  echo
  for cmd in "" "setup" "search" "status" "doctor" "index" "update" "reset" \
             "daemon" "serve" "mcp" "collection"; do
    if [[ -z "$cmd" ]]; then
      echo "=== gno --help ==="
      "$GNO_BIN" --help 2>&1 || true
    else
      echo "=== gno $cmd --help ==="
      # shellcheck disable=SC2086
      "$GNO_BIN" $cmd --help 2>&1 || true
    fi
    echo
  done

  # The MCP launch template, straight from upstream. `gno mcp install --dry-run
  # --json` prints the exact stdio server entry it would write into a client
  # config, which is what the endpoint descriptor carries — so this is the one
  # contract the descriptor is derived from rather than invented against.
  #
  # Two targets are captured on purpose: the descriptor is harness-AGNOSTIC
  # (D16), and that only holds if upstream emits the same entry for both.
  for target in claude-code codex; do
    echo "=== gno mcp install -t $target -s user --dry-run --json ==="
    "$GNO_BIN" mcp install -t "$target" -s user --dry-run --json 2>&1 || true
    echo
  done

  # The refusal names upstream's full target list, which is the only place the
  # supported targets are machine-readable.
  echo "=== gno mcp install -t <invalid> --dry-run --json ==="
  "$GNO_BIN" mcp install -t homeplane-not-a-target -s user --dry-run --json 2>&1 || true
  echo
} | sed -e "s|$WORK|<gno-dirs>|g" -e "s|$HOME|<home>|g" >"$OUT"

echo "wrote $OUT"
