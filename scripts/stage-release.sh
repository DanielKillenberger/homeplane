#!/usr/bin/env bash
# stage-release.sh — build release-form artifacts and their checksum manifest
# into a staging directory that install.sh can consume.
#
# It stages the halves of an installable release:
#
#   * the cross-compiled homeplane-agent binary for every supported platform;
#   * the cross-compiled homeplane-server binary for every supported LINUX
#     platform (the server is deployed on Linux only — deploy/server/README.md);
#   * the pinned Node 22 runtime for every supported platform, verified against
#     the upstream checksums in scripts/node-pinned.sha256;
#   * the pinned Bun runtime for every supported platform, verified against the
#     upstream checksums in scripts/bun-pinned.sha256. GNO (D8) runs on Bun, so
#     the retrieval engine is as unrunnable without it as vault sync is without
#     Node.
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
#   scripts/stage-release.sh [output-dir] [--skip-node] [--skip-bun]
#
# Environment:
#   HOMEPLANE_NODE_CACHE       where downloaded Node archives are cached
#                              (default ~/.cache/homeplane/node)
#   HOMEPLANE_STAGE_PLATFORMS  newline-separated "<goos> <goarch>" pairs to
#                              stage instead of the full supported matrix
#   HOMEPLANE_NODE_DIST_URL    Node distribution root (default nodejs.org/dist)
#   HOMEPLANE_NODE_PIN_FILE    checksum pin file (default scripts/node-pinned.sha256)
#   HOMEPLANE_BUN_CACHE        where downloaded Bun archives are cached
#                              (default ~/.cache/homeplane/bun)
#   HOMEPLANE_BUN_DIST_URL     Bun release root (default github.com/oven-sh/bun)
#   HOMEPLANE_BUN_PIN_FILE     checksum pin file (default scripts/bun-pinned.sha256)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"

readonly PROGRAM="stage-release.sh"

die() { echo "$PROGRAM: $*" >&2; exit 1; }
info() { echo "$PROGRAM: $*"; }

OUT_DIR="dist"
SKIP_NODE=0
SKIP_BUN=0
for arg in "$@"; do
  case "$arg" in
    --skip-node) SKIP_NODE=1 ;;
    --skip-bun) SKIP_BUN=1 ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "unknown option $arg" ;;
    *) OUT_DIR="$arg" ;;
  esac
done
mkdir -p "$OUT_DIR"

NODE_PIN_FILE="${HOMEPLANE_NODE_PIN_FILE:-$REPO_ROOT/scripts/node-pinned.sha256}"
NODE_DIST_URL="${HOMEPLANE_NODE_DIST_URL:-https://nodejs.org/dist}"
NODE_CACHE="${HOMEPLANE_NODE_CACHE:-$HOME/.cache/homeplane/node}"
BUN_PIN_FILE="${HOMEPLANE_BUN_PIN_FILE:-$REPO_ROOT/scripts/bun-pinned.sha256}"
BUN_DIST_URL="${HOMEPLANE_BUN_DIST_URL:-https://github.com/oven-sh/bun/releases/download}"
BUN_CACHE="${HOMEPLANE_BUN_CACHE:-$HOME/.cache/homeplane/bun}"

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

# Bun's release assets carry no version in their names, so the version is stated
# explicitly in the pin file and the STAGED copy is renamed to include it — a
# staging directory whose file names do not say what they are is how a stale
# runtime survives a bump unnoticed.
bun_version_from_pins() {
  local version
  version="$(awk -F= '/^[[:space:]]*version[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); print $2 }' "$BUN_PIN_FILE")"
  [[ -n "$version" ]] || die "no Bun version pinned in $BUN_PIN_FILE"
  echo "$version"
}

bun_pinned_sha() {
  local name="$1"
  awk -v want="$name" '$2 == want { print $1; found=1 } END { if (!found) exit 1 }' "$BUN_PIN_FILE" \
    || die "no pinned checksum for '$name' in $BUN_PIN_FILE; refusing to stage an unverified runtime"
}

# bun_asset_name is the name upstream publishes; bun_archive_name is what we
# stage it as.
bun_asset_name() {
  local goos="$1" goarch="$2" bun_arch
  case "$goarch" in
    arm64) bun_arch=aarch64 ;;
    amd64) bun_arch=x64 ;;
    *) die "unsupported architecture $goarch" ;;
  esac
  echo "bun-${goos}-${bun_arch}.zip"
}

bun_archive_name() {
  local goos="$1" goarch="$2"
  echo "bun-v${BUN_VERSION}-$(bun_asset_name "$goos" "$goarch" | sed 's/^bun-//')"
}

fetch_bun() {
  local asset="$1"
  local cached="$BUN_CACHE/bun-v$BUN_VERSION-$asset"
  mkdir -p "$BUN_CACHE"
  FETCHED_ARCHIVE=""

  local want
  want="$(bun_pinned_sha "$asset")"

  if [[ -f "$cached" ]]; then
    if [[ "$(sha256_of "$cached")" == "$want" ]]; then
      FETCHED_ARCHIVE="$cached"
      return
    fi
    info "cached $asset does not match its pinned checksum; re-downloading"
    rm -f "$cached"
  fi

  local url="$BUN_DIST_URL/bun-v$BUN_VERSION/$asset"
  info "downloading $url"
  command -v curl >/dev/null 2>&1 || die "curl is required to fetch the Bun runtime"
  if ! curl -fsSL --retry 2 -o "$cached.part" "$url"; then
    rm -f "$cached.part"
    die "could not download $url (stage with --skip-bun only if every target machine already has Bun $BUN_VERSION)"
  fi

  local got
  got="$(sha256_of "$cached.part")"
  if [[ "$got" != "$want" ]]; then
    rm -f "$cached.part"
    die "checksum mismatch for $asset
  expected (pinned): $want
  actual (download): $got
Nothing has been staged. Either the mirror is compromised or $BUN_PIN_FILE is stale."
  fi
  mv "$cached.part" "$cached"
  FETCHED_ARCHIVE="$cached"
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

  # The server ships for Linux only. Building it for darwin would stage an
  # artifact no deployment path installs, and deploy/server/install-server.sh
  # would have no way to tell a supported target from a decorative one.
  if [[ "$goos" == "linux" ]]; then
    srv="$OUT_DIR/homeplane-server-${goos}-${goarch}"
    info "building $srv"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$srv" ./cmd/homeplane-server
  fi
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

if [[ $SKIP_BUN -eq 0 ]]; then
  [[ -f "$BUN_PIN_FILE" ]] || die "$BUN_PIN_FILE not found; cannot stage a verified Bun runtime"
  BUN_VERSION="$(bun_version_from_pins)"
  info "staging bun v$BUN_VERSION (pinned in $BUN_PIN_FILE)"
  while read -r goos goarch; do
    [[ -n "$goos" ]] || continue
    asset="$(bun_asset_name "$goos" "$goarch")"
    fetch_bun "$asset"
    staged="$(bun_archive_name "$goos" "$goarch")"
    cp "$FETCHED_ARCHIVE" "$OUT_DIR/$staged"
    info "staged $staged"
  done <<<"$PLATFORMS"
else
  info "skipping Bun staging (--skip-bun): the resulting directory only installs onto machines that already have Bun 1.3+"
fi

# The manifest is regenerated wholesale so a stale entry can never survive a
# rebuild. install.sh verifies every artifact it touches against it.
(
  cd "$OUT_DIR"
  artifacts=()
  for f in homeplane-agent-* homeplane-server-* node-v*.tar.gz bun-v*.zip; do
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
