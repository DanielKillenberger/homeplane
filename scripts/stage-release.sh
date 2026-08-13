#!/usr/bin/env bash
# stage-release.sh — build release-form agent artifacts and their checksum
# manifest into a staging directory that install.sh can consume.
#
# This is the local stand-in for the published release pipeline (deferred per
# the spec's Boundaries). It exists so that "one command installs the agent" is
# a claim about real, checksummed, cross-compiled artifacts rather than about a
# binary someone happened to have lying around.
#
# Usage: scripts/stage-release.sh [output-dir]   (default: dist)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"

OUT_DIR="${1:-dist}"
mkdir -p "$OUT_DIR"

# The supported matrix, and only the supported matrix: install.sh rejects
# anything outside it, so shipping other artifacts would be misleading.
PLATFORMS=(
  "darwin arm64"
  "darwin amd64"
  "linux amd64"
  "linux arm64"
)

VERSION="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

for platform in "${PLATFORMS[@]}"; do
  read -r goos goarch <<<"$platform"
  out="$OUT_DIR/homeplane-agent-${goos}-${goarch}"
  echo "building $out"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$out" ./cmd/homeplane-agent
done

# The manifest is what install.sh verifies against; it is regenerated wholesale
# so a stale entry can never survive a rebuild.
(
  cd "$OUT_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum homeplane-agent-* > SHA256SUMS
  else
    shasum -a 256 homeplane-agent-* > SHA256SUMS
  fi
)

echo
echo "staged $OUT_DIR (version $VERSION):"
cat "$OUT_DIR/SHA256SUMS"
echo
echo "install with: ./install.sh --stage-dir $OUT_DIR"
