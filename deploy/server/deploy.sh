#!/usr/bin/env bash
# deploy.sh — stage, upload and install the Homeplane server on a remote host.
#
# This is a thin driver, deliberately: everything that decides what the
# deployment looks like lives in install-server.sh (which runs on the host) and
# in server.env. This script only builds the artifacts, copies them, and runs
# the installer over SSH — so an operator with no SSH access can do exactly the
# same thing by copying the staging directory across by hand.
#
# Usage:
#   deploy/server/deploy.sh --host clawniel [--config deploy/server/server.env]
#                           [--authkey-file PATH_ON_HOST] [--prefix DIR]
#                           [--skip-build] [--no-start]
#
# --authkey-file names a path ON THE TARGET HOST (e.g. ~/.homeplane/authkey).
# The key is never read here, never passed as an argument to anything, and never
# printed: it is the host's own file, and the installer copies it into a 0600
# EnvironmentFile.
set -euo pipefail

readonly PROGRAM="deploy.sh"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly DEPLOY_DIR="$REPO_ROOT/deploy/server"

HOST=""
CONFIG="$DEPLOY_DIR/server.env"
PREFIX=""
AUTHKEY_FILE=""
SKIP_BUILD=0
INSTALL_ARGS=()

die() { echo "$PROGRAM: $*" >&2; exit 1; }
info() { echo "$PROGRAM: $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --authkey-file) AUTHKEY_FILE="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --no-start) INSTALL_ARGS+=(--no-start); shift ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

[[ -n "$HOST" ]] || die "--host is required"
[[ -f "$CONFIG" ]] || die "config $CONFIG not found (copy server.env.example)"

# The remote staging directory is INSIDE the prefix: one place to look at, and
# an operator inspecting the host can see exactly which artifacts produced the
# running deployment.
#
# The remote home is resolved with a shell on the far side rather than written
# as "$HOME": scp speaks SFTP, which does no shell expansion, so a literal
# $HOME in a destination path becomes a directory called '$HOME'.
if [[ -n "$PREFIX" ]]; then
  REMOTE_PREFIX="$PREFIX"
else
  REMOTE_HOME="$(ssh -o BatchMode=yes "$HOST" 'printf %s "$HOME"')" \
    || die "cannot resolve the remote home directory on $HOST"
  REMOTE_PREFIX="$REMOTE_HOME/homeplane"
fi
REMOTE_STAGE="$REMOTE_PREFIX/stage"

if [[ $SKIP_BUILD -eq 0 ]]; then
  info "staging release artifacts (agent + linux server binaries)"
  # --skip-node: the server half of a release needs no Node runtime, and pulling
  # four Node tarballs to deploy one binary would be wasteful.
  "$REPO_ROOT/scripts/stage-release.sh" "$REPO_ROOT/dist" --skip-node >/dev/null
fi
[[ -f "$REPO_ROOT/dist/SHA256SUMS" ]] || die "no dist/SHA256SUMS; run scripts/stage-release.sh"

info "uploading to $HOST:$REMOTE_STAGE"
# shellcheck disable=SC2029  # remote expansion of $HOME is intended
ssh "$HOST" "mkdir -p $REMOTE_STAGE/units"
scp -q "$REPO_ROOT/dist/SHA256SUMS" \
       "$REPO_ROOT"/dist/homeplane-server-linux-* \
       "$DEPLOY_DIR/install-server.sh" \
       "$DEPLOY_DIR/verify.sh" \
       "$DEPLOY_DIR/manifest.json" \
       "$DEPLOY_DIR/toolhive-pinned.sha256" \
       "$DEPLOY_DIR/README.md" \
       "$CONFIG" \
       "$HOST:$REMOTE_STAGE/"
scp -q "$DEPLOY_DIR"/units/*.tmpl "$HOST:$REMOTE_STAGE/units/"
# The uploaded copy of the config keeps its canonical name whatever the local
# file was called; install-server.sh looks for exactly server.env.
if [[ "$(basename "$CONFIG")" != "server.env" ]]; then
  ssh "$HOST" "mv $REMOTE_STAGE/$(basename "$CONFIG") $REMOTE_STAGE/server.env"
fi

remote_cmd="chmod +x $REMOTE_STAGE/install-server.sh $REMOTE_STAGE/verify.sh && $REMOTE_STAGE/install-server.sh --stage-dir $REMOTE_STAGE"
if [[ -n "$PREFIX" ]]; then remote_cmd+=" --prefix $PREFIX"; fi
if [[ -n "$AUTHKEY_FILE" ]]; then remote_cmd+=" --authkey-file $AUTHKEY_FILE"; fi
for arg in ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}; do remote_cmd+=" $arg"; done

info "running the installer on $HOST"
ssh "$HOST" "$remote_cmd"
