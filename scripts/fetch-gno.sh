#!/usr/bin/env bash
# fetch-gno.sh — download and verify the pinned GNO package, then install it.
#
# Order matters and is the whole point: the npm tarball is checksum-verified
# BEFORE anything is installed, so a tampered registry mirror cannot put an
# unattested retrieval engine on the machine.
#
# The post-install check is a VERSION probe rather than a file checksum. That is
# a deliberate difference from fetch-obsidian-headless.sh and it is explained in
# internal/agent/gno/gno-pinned.sha256: obsidian-headless executes one file,
# GNO's entrypoint imports a whole package tree, so hashing the entrypoint would
# be theatre. What actually protects the install is verifying the tarball before
# extraction.
#
# Usage:
#   scripts/fetch-gno.sh --prefix DIR       install the pinned build
#   scripts/fetch-gno.sh --record           print the checksum only
#   scripts/fetch-gno.sh --version X ...    override the version (records only)
#
# Requires: bun >= 1.3, curl, shasum (or sha256sum).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PIN_FILE="$REPO_ROOT/internal/agent/gno/gno-pinned.sha256"
REGISTRY="${HOMEPLANE_NPM_REGISTRY:-https://registry.npmjs.org}"

die() { echo "fetch-gno.sh: $*" >&2; exit 1; }

pin_value() {
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
PACKAGE="$(pin_value package)"
WANT_TARBALL="$(pin_value tarball)"
PREFIX=""
RECORD_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --version) VERSION="$2"; WANT_TARBALL=""; shift 2 ;;
    --record) RECORD_ONLY=1; shift ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument $1" ;;
  esac
done

[[ -n "$VERSION" && -n "$PACKAGE" ]] || die "$PIN_FILE is missing a version or package name"

WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; command rm -rf "$WORK"' EXIT

# The scoped package's tarball path: @scope/name → .../@scope/name/-/name-VER.tgz
NAME_ONLY="${PACKAGE##*/}"
URL="$REGISTRY/$PACKAGE/-/$NAME_ONLY-$VERSION.tgz"

echo "fetching $PACKAGE@$VERSION" >&2
command -v curl >/dev/null 2>&1 || die "curl is required"
curl -fsSL --retry 2 -o "$WORK/pkg.tgz" "$URL" || die "could not download $URL"

GOT_TARBALL="$(sha256 "$WORK/pkg.tgz")"
if [[ -n "$WANT_TARBALL" && "$GOT_TARBALL" != "$WANT_TARBALL" ]]; then
  die "TARBALL CHECKSUM MISMATCH — refusing to install
  expected $WANT_TARBALL
  got      $GOT_TARBALL"
fi

if [[ $RECORD_ONLY -eq 1 || -z "$PREFIX" ]]; then
  echo "version = $VERSION"
  echo "package = $PACKAGE"
  echo "tarball = $GOT_TARBALL"
  exit 0
fi

command -v bun >/dev/null 2>&1 || die "bun >= 1.3 is required to install GNO (install.sh provisions it)"

mkdir -p "$PREFIX"
# Install the VERIFIED local tarball, never the registry name: re-resolving the
# name here would discard the check that was just performed.
(cd "$PREFIX" && bun add --no-save "$WORK/pkg.tgz" >/dev/null 2>&1) \
  || (cd "$PREFIX" && bun install "$WORK/pkg.tgz" >/dev/null) \
  || die "bun could not install the verified tarball"

GNO_BIN="$PREFIX/node_modules/.bin/gno"
[[ -x "$GNO_BIN" || -L "$GNO_BIN" ]] || die "the install produced no gno executable at $GNO_BIN"

REPORTED="$("$GNO_BIN" --version 2>/dev/null | tr -d '[:space:]')"
[[ "$REPORTED" == "$VERSION" ]] || die "installed build reports '$REPORTED', expected '$VERSION'"

echo "$GNO_BIN"
