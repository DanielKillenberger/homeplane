#!/usr/bin/env bash
# fetch-obsidian-headless.sh — download and verify the pinned obsidian-headless
# CLI, then install it into a prefix.
#
# Order matters and is the whole point: the tarball is checksum-verified BEFORE
# anything is installed, and the installed entrypoint is checksum-verified after
# — so neither a tampered registry mirror nor a post-install swap can put an
# unattested sync binary on the machine.
#
# Usage:
#   scripts/fetch-obsidian-headless.sh --prefix DIR      install the pinned build
#   scripts/fetch-obsidian-headless.sh --record          print checksums only
#   scripts/fetch-obsidian-headless.sh --version X ...   override the version
#
# Requires: npm, node 22+, shasum (or sha256sum).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PIN_FILE="$REPO_ROOT/internal/agent/vault/obsidian-headless-pinned.sha256"

pin_value() {
  # `key = value`, comments ignored.
  awk -v k="$1" -F= '
    /^[[:space:]]*#/ { next }
    {
      key = $1; sub(/^[[:space:]]+/, "", key); sub(/[[:space:]]+$/, "", key)
      if (key == k) {
        val = substr($0, index($0, "=") + 1)
        sub(/^[[:space:]]+/, "", val); sub(/[[:space:]]+$/, "", val)
        print val
      }
    }' "$PIN_FILE"
}

sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

VERSION="$(pin_value version)"
WANT_TARBALL="$(pin_value tarball)"
WANT_ENTRYPOINT="$(pin_value checksum)"
PREFIX=""
RECORD_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --version) VERSION="$2"; WANT_TARBALL=""; WANT_ENTRYPOINT=""; shift 2 ;;
    --record) RECORD_ONLY=1; shift ;;
    -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "fetch-obsidian-headless.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done

WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; command rm -rf "$WORK"' EXIT

echo "fetching obsidian-headless@$VERSION" >&2
(cd "$WORK" && npm pack "obsidian-headless@$VERSION" --silent >/dev/null)
TARBALL="$(find "$WORK" -maxdepth 1 -name '*.tgz' -print -quit)"
if [[ -z "$TARBALL" ]]; then
  echo "fetch-obsidian-headless.sh: npm pack produced no tarball" >&2
  exit 1
fi

GOT_TARBALL="$(sha256 "$TARBALL")"
if [[ -n "$WANT_TARBALL" && "$GOT_TARBALL" != "$WANT_TARBALL" ]]; then
  echo "fetch-obsidian-headless.sh: TARBALL CHECKSUM MISMATCH — refusing to install" >&2
  echo "  expected $WANT_TARBALL" >&2
  echo "  got      $GOT_TARBALL" >&2
  exit 1
fi

mkdir -p "$WORK/x"
tar xzf "$TARBALL" -C "$WORK/x"
GOT_ENTRYPOINT="$(sha256 "$WORK/x/package/cli.js")"
if [[ -n "$WANT_ENTRYPOINT" && "$WANT_ENTRYPOINT" != "PENDING" && "$GOT_ENTRYPOINT" != "$WANT_ENTRYPOINT" ]]; then
  echo "fetch-obsidian-headless.sh: ENTRYPOINT CHECKSUM MISMATCH — refusing to install" >&2
  echo "  expected $WANT_ENTRYPOINT" >&2
  echo "  got      $GOT_ENTRYPOINT" >&2
  exit 1
fi

if [[ $RECORD_ONLY -eq 1 || -z "$PREFIX" ]]; then
  echo "version = $VERSION"
  echo "tarball = $GOT_TARBALL"
  echo "checksum = $GOT_ENTRYPOINT"
  exit 0
fi

mkdir -p "$PREFIX"
npm install --prefix "$PREFIX" "$TARBALL" --no-audit --no-fund --silent >/dev/null
OB="$PREFIX/node_modules/.bin/ob"
ENTRY="$PREFIX/node_modules/obsidian-headless/cli.js"
INSTALLED="$(sha256 "$ENTRY")"
if [[ "$INSTALLED" != "$GOT_ENTRYPOINT" ]]; then
  echo "fetch-obsidian-headless.sh: the installed entrypoint does not match the tarball's" >&2
  exit 1
fi
REPORTED="$("$OB" --version)"
if [[ "$REPORTED" != "$VERSION" ]]; then
  echo "fetch-obsidian-headless.sh: installed build reports $REPORTED, expected $VERSION" >&2
  exit 1
fi

echo "$OB"
