#!/usr/bin/env bash
# capture-ob-contract.sh — record the pinned obsidian-headless CLI's own parser
# output as golden testdata.
#
# The agent builds argv for a third-party CLI it does not own. The only honest
# way to know that argv is right is to ask the real binary what it accepts, and
# to keep that answer in the repository so a test can enforce it on every run —
# not just on the machine where someone once tried it by hand.
#
# Usage: scripts/capture-ob-contract.sh <path-to-ob> [version]
# The output path is derived from the version the binary reports.
set -euo pipefail

OB="${1:-}"
if [[ -z "$OB" ]]; then
  echo "usage: scripts/capture-ob-contract.sh <path-to-ob> [version]" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION="${2:-$("$OB" --version)}"
OUT="$REPO_ROOT/internal/agent/vault/testdata/ob-$VERSION-contract.txt"
mkdir -p "$(dirname "$OUT")"

SUBCOMMANDS=(
  login
  logout
  sync-list-remote
  sync-list-local
  sync-create-remote
  sync-setup
  sync-config
  sync-status
  sync
)

{
  echo "# obsidian-headless $VERSION — captured verbatim from the pinned build."
  echo "# Regenerate with: scripts/capture-ob-contract.sh <path-to-ob>"
  echo "# internal/agent/vault asserts every argv it emits against this file."
  echo ""
  echo "=== ob --help ==="
  "$OB" --help 2>&1
  for cmd in "${SUBCOMMANDS[@]}"; do
    echo ""
    echo "=== ob $cmd --help ==="
    "$OB" "$cmd" --help 2>&1
  done
  echo ""
  echo "=== ob --version ==="
  "$OB" --version 2>&1
} >"$OUT"

echo "wrote $OUT ($(wc -l <"$OUT" | tr -d ' ') lines) from $OB"
