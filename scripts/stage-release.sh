#!/usr/bin/env bash
# stage-release.sh — build release-form artifacts and their checksum manifest
# into a staging directory that install.sh can consume.
#
# It stages BOTH halves of an installable release:
#
#   * the cross-compiled homeplane-agent binary for every supported platform;
#   * the pinned Node 22 runtime for every supported platform, verified against
#     the upstream checksums in scripts/node-pinned.sha256.
#
# The Node half is not optional decoration: install.sh provisions Node from the
# staged tarball, and macOS has no package-manager fallback, so a staging
# directory without Node cannot install onto a fresh Mac at all.
#
# This is the local stand-in for the published release pipeline (deferred per
# the spec's Boundaries). It exists so that "one command installs the agent" is
# a claim about real, checksummed artifacts.
#
# Usage:
#   scripts/stage-release.sh [output-dir] [--skip-node]
#
# Environment:
#   HOMEPLANE_NODE_CACHE       where downloaded Node archives are cached
#                              (default ~/.cache/homeplane/node)
#   HOMEPLANE_STAGE_PLATFORMS  newline-separated "<goos> <goarch>" pairs to
#                              stage instead of the full supported matrix
#   HOMEPLANE_NODE_DIST_URL    Node distribution root (default nodejs.org/dist)
#   HOMEPLANE_NODE_PIN_FILE    checksum pin file (default scripts/node-pinned.sha256)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"

readonly PROGRAM="stage-release.sh"

die() { echo "$PROGRAM: $*" >&2; exit 1; }
info() { echo "$PROGRAM: $*"; }

OUT_DIR="dist"
SKIP_NODE=0
for arg in "$@"; do
  case "$arg" in
    --skip-node) SKIP_NODE=1 ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "unknown option $arg" ;;
    *) OUT_DIR="$arg" ;;
  esac
done
mkdir -p "$OUT_DIR"

NODE_PIN_FILE="${HOMEPLANE_NODE_PIN_FILE:-$REPO_ROOT/scripts/node-pinned.sha256}"
NODE_DIST_URL="${HOMEPLANE_NODE_DIST_URL:-https://nodejs.org/dist}"
NODE_CACHE="${HOMEPLANE_NODE_CACHE:-$HOME/.cache/homeplane/node}"

# The supported matrix, and only the supported matrix: install.sh rejects
# anything outside it, so shipping other artifacts would be misleading.
DEFAULT_PLATFORMS="darwin arm64
darwin amd64
linux amd64
linux arm64"
PLATFORMS="${HOMEPLANE_STAGE_PLATFORMS:-$DEFAULT_PLATFORMS}"

VERSION="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# node_version_from_pins derives the Node version from the pin file rather than
# repeating the literal here: one place to change when bumping, and no way for
# the staged archive and the pinned checksum to describe different versions.
node_version_from_pins() {
  local versions
  versions="$(awk '!/^#/ && NF == 2 { name = $2; sub(/^node-v/, "", name); sub(/-.*$/, "", name); print name }' \
    "$NODE_PIN_FILE" | sort -u)"
  [[ -n "$versions" ]] || die "no Node checksums pinned in $NODE_PIN_FILE"
  [[ "$(echo "$versions" | wc -l | tr -d ' ')" == "1" ]] \
    || die "$NODE_PIN_FILE pins more than one Node version: $(echo "$versions" | tr '\n' ' ')"
  echo "$versions"
}

pinned_sha() {
  local name="$1"
  awk -v want="$name" '$2 == want { print $1; found=1 } END { if (!found) exit 1 }' "$NODE_PIN_FILE" \
    || die "no pinned checksum for '$name' in $NODE_PIN_FILE; refusing to stage an unverified runtime"
}

node_archive_name() {
  local goos="$1" goarch="$2" node_arch
  case "$goarch" in
    arm64) node_arch=arm64 ;;
    amd64) node_arch=x64 ;;
    *) die "unsupported architecture $goarch" ;;
  esac
  echo "node-v${NODE_VERSION}-${goos}-${node_arch}.tar.gz"
}

# fetch_node downloads (or reuses a cached) Node archive and verifies it against
# the pinned upstream checksum BEFORE it is allowed near the staging directory.
# A mismatched download is deleted rather than cached, so a poisoned cache
# cannot survive to the next run.
#
# The result is returned in FETCHED_ARCHIVE rather than on stdout: this function
# also logs progress, and a caller capturing stdout would otherwise splice the
# log lines into the path.
FETCHED_ARCHIVE=""

fetch_node() {
  local archive="$1"
  local cached="$NODE_CACHE/$archive"
  mkdir -p "$NODE_CACHE"
  FETCHED_ARCHIVE=""

  local want
  want="$(pinned_sha "$archive")"

  if [[ -f "$cached" ]]; then
    if [[ "$(sha256_of "$cached")" == "$want" ]]; then
      FETCHED_ARCHIVE="$cached"
      return
    fi
    info "cached $archive does not match its pinned checksum; re-downloading"
    rm -f "$cached"
  fi

  local url="$NODE_DIST_URL/v$NODE_VERSION/$archive"
  info "downloading $url"
  command -v curl >/dev/null 2>&1 || die "curl is required to fetch the Node runtime"
  if ! curl -fsSL --retry 2 -o "$cached.part" "$url"; then
    rm -f "$cached.part"
    die "could not download $url (stage with --skip-node only if every target machine already has Node $NODE_MAJOR)"
  fi

  local got
  got="$(sha256_of "$cached.part")"
  if [[ "$got" != "$want" ]]; then
    rm -f "$cached.part"
    die "checksum mismatch for $archive
  expected (pinned): $want
  actual (download): $got
Nothing has been staged. Either the mirror is compromised or $NODE_PIN_FILE is stale."
  fi
  mv "$cached.part" "$cached"
  FETCHED_ARCHIVE="$cached"
}

# --- build -------------------------------------------------------------------

while read -r goos goarch; do
  [[ -n "$goos" ]] || continue
  out="$OUT_DIR/homeplane-agent-${goos}-${goarch}"
  info "building $out"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$out" ./cmd/homeplane-agent
done <<<"$PLATFORMS"

if [[ $SKIP_NODE -eq 0 ]]; then
  [[ -f "$NODE_PIN_FILE" ]] || die "$NODE_PIN_FILE not found; cannot stage a verified Node runtime"
  NODE_VERSION="$(node_version_from_pins)"
  NODE_MAJOR="${NODE_VERSION%%.*}"
  info "staging node v$NODE_VERSION (pinned in $NODE_PIN_FILE)"
  while read -r goos goarch; do
    [[ -n "$goos" ]] || continue
    archive="$(node_archive_name "$goos" "$goarch")"
    fetch_node "$archive"
    cp "$FETCHED_ARCHIVE" "$OUT_DIR/$archive"
    info "staged $archive"
  done <<<"$PLATFORMS"
else
  info "skipping Node staging (--skip-node): the resulting directory only installs onto machines that already have Node 22"
fi

# The manifest is regenerated wholesale so a stale entry can never survive a
# rebuild. install.sh verifies every artifact it touches against it.
(
  cd "$OUT_DIR"
  artifacts=()
  for f in homeplane-agent-* node-v*.tar.gz; do
    # An unmatched glob comes through as its own literal pattern; skipping
    # non-files is what keeps `--skip-node` from manifesting a phantom archive.
    if [[ -f "$f" ]]; then
      artifacts+=("$f")
    fi
  done
  [[ ${#artifacts[@]} -gt 0 ]] || { echo "$PROGRAM: nothing staged" >&2; exit 1; }
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${artifacts[@]}" > SHA256SUMS
  else
    shasum -a 256 "${artifacts[@]}" > SHA256SUMS
  fi
)

echo
info "staged $OUT_DIR (agent version $VERSION):"
cat "$OUT_DIR/SHA256SUMS"
echo
echo "install with: ./install.sh --stage-dir $OUT_DIR"
