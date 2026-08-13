#!/usr/bin/env bash
# install.sh — install the Homeplane agent onto this machine.
#
# The installer's contract, in order:
#
#   1. Decide whether this machine is SUPPORTED (OS, architecture, init system)
#      and refuse clearly if it is not — before touching the filesystem.
#   2. Verify every artifact against a checksum manifest. A mismatch aborts and
#      leaves nothing behind: a tampered or truncated download must never become
#      a half-installed agent.
#   3. Provision the Node 22 prerequisite DETERMINISTICALLY (a checksummed
#      vendored tarball, or a distro package explicitly opted into). A supported
#      machine that cannot get Node is an installation failure, not a degraded
#      success.
#   4. Only then place the binary — atomically, and idempotently, so re-running
#      the installer refreshes the agent without disturbing enrolment state.
#
# Supported platforms: macOS (launchd) and systemd-based Linux with
# `systemctl --user`. Everything else is rejected in step 1.
#
# Artifacts are consumed from a locally staged, checksummed release-form
# directory (spec Boundaries: the published CI release pipeline is deferred).
#
# Usage:
#   ./install.sh [--stage-dir DIR] [--prefix DIR] [--help]
#
# Environment:
#   HOMEPLANE_STAGE_DIR      staged artifact directory (default ./dist)
#   HOMEPLANE_PREFIX         install root (default ~/.homeplane)
#   HOMEPLANE_NODE_PACKAGE   set to 1 to allow distro-package Node provisioning
#
# Test hooks (documented because the installer is exercised by the test suite;
# they let a test drive the platform matrix without a fleet of machines):
#   HOMEPLANE_UNAME_S / HOMEPLANE_UNAME_M   override detected OS / architecture
#   HOMEPLANE_INIT_OVERRIDE                 override detected init system
#   HOMEPLANE_NODE_BIN                      node binary to probe

set -euo pipefail

readonly PROGRAM="install.sh"

# Node prerequisite. Pinning the exact version is what makes provisioning
# deterministic: two machines installed a month apart get the same runtime.
readonly NODE_MIN_MAJOR=22
readonly NODE_VERSION="${HOMEPLANE_NODE_VERSION:-22.11.0}"

readonly MANIFEST_NAME="SHA256SUMS"

STAGE_DIR="${HOMEPLANE_STAGE_DIR:-./dist}"
PREFIX="${HOMEPLANE_PREFIX:-$HOME/.homeplane}"

die() {
  echo "$PROGRAM: $*" >&2
  exit 1
}

info() { echo "$PROGRAM: $*"; }

usage() {
  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
}

# --- argument parsing --------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage-dir)
      [[ $# -ge 2 ]] || die "--stage-dir needs a directory"
      STAGE_DIR="$2"; shift 2 ;;
    --stage-dir=*) STAGE_DIR="${1#*=}"; shift ;;
    --prefix)
      [[ $# -ge 2 ]] || die "--prefix needs a directory"
      PREFIX="$2"; shift 2 ;;
    --prefix=*) PREFIX="${1#*=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option $1 (try --help)" ;;
  esac
done

readonly BIN_DIR="$PREFIX/bin"
readonly NODE_DIR="$PREFIX/node"

# --- step 1: platform support ------------------------------------------------

detect_os() {
  local uname_s="${HOMEPLANE_UNAME_S:-$(uname -s)}"
  case "$uname_s" in
    Darwin) echo darwin ;;
    Linux)  echo linux ;;
    *) die "unsupported operating system '$uname_s'. Homeplane supports macOS and systemd-based Linux." ;;
  esac
}

detect_arch() {
  local uname_m="${HOMEPLANE_UNAME_M:-$(uname -m)}"
  case "$uname_m" in
    arm64|aarch64) echo arm64 ;;
    x86_64|amd64)  echo amd64 ;;
    *) die "unsupported architecture '$uname_m'. Homeplane supports arm64 and amd64." ;;
  esac
}

# detect_init resolves the supervisor this machine actually has.
#
# This is the gate that keeps a non-systemd Linux from getting a
# half-functional install: Homeplane supervises the vault sync and GNO through
# a user-level service manager, so a machine without one cannot run the plane
# and is told so before anything is written.
detect_init() {
  local os="$1"
  if [[ -n "${HOMEPLANE_INIT_OVERRIDE:-}" ]]; then
    echo "$HOMEPLANE_INIT_OVERRIDE"
    return
  fi
  case "$os" in
    darwin)
      if command -v launchctl >/dev/null 2>&1; then
        echo launchd
      else
        echo none
      fi
      ;;
    linux)
      if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        echo systemd
      else
        echo none
      fi
      ;;
  esac
}

require_supported_init() {
  local os="$1" init="$2"
  case "$os:$init" in
    darwin:launchd) : ;;
    linux:systemd)
      # `systemctl --user` plus linger is what lets Homeplane's services run
      # without an interactive login session. Absent tooling is reported now,
      # not discovered later by a service that silently never starts.
      if ! command -v loginctl >/dev/null 2>&1; then
        die "this Linux machine has systemd but no loginctl, so 'systemctl --user' services cannot be made to survive logout. Homeplane needs a user service manager with lingering."
      fi
      ;;
    darwin:*)
      die "launchd was not found on this macOS machine; Homeplane cannot supervise its services here." ;;
    linux:*)
      die "unsupported init system on this Linux machine (systemd with 'systemctl --user' is required). Homeplane supervises vault sync and GNO through a user service manager; a non-systemd Linux is not supported." ;;
    *)
      die "unsupported platform $os/$init" ;;
  esac
}

# --- step 2: checksummed artifacts -------------------------------------------

sha256_of() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    die "no sha256 tool found (need sha256sum or shasum); refusing to install unverified artifacts"
  fi
}

# expected_sha reads a filename's checksum out of the staged manifest. A file
# that is not IN the manifest is treated exactly like a mismatch: unverifiable
# and therefore not installable.
expected_sha() {
  local name="$1" manifest="$STAGE_DIR/$MANIFEST_NAME"
  awk -v want="$name" '$2 == want || $2 == "*" want { print $1; found=1 } END { if (!found) exit 1 }' "$manifest" 2>/dev/null \
    || die "artifact '$name' has no entry in $manifest; refusing to install an unverified artifact"
}

verify_artifact() {
  local name="$1" path="$STAGE_DIR/$1"
  [[ -f "$path" ]] || die "staged artifact '$name' not found in $STAGE_DIR"
  local want got
  want="$(expected_sha "$name")"
  got="$(sha256_of "$path")"
  if [[ "$want" != "$got" ]]; then
    die "checksum mismatch for '$name'
  expected: $want
  actual:   $got
Nothing has been installed. The staged artifact is corrupt or has been tampered with; re-stage it and run $PROGRAM again."
  fi
  info "verified $name ($got)"
}

# --- step 3: Node 22 ---------------------------------------------------------

node_major() {
  local bin="$1" version
  version="$("$bin" --version 2>/dev/null)" || return 1
  version="${version#v}"
  echo "${version%%.*}"
}

# have_node_22 reports whether a usable Node is ALREADY on this machine.
have_node_22() {
  local bin="${HOMEPLANE_NODE_BIN:-}"
  if [[ -z "$bin" ]]; then
    bin="$(command -v node 2>/dev/null || true)"
  fi
  [[ -n "$bin" && -x "$bin" ]] || return 1
  local major
  major="$(node_major "$bin")" || return 1
  [[ -n "$major" && "$major" -ge "$NODE_MIN_MAJOR" ]]
}

node_archive_name() {
  local os="$1" arch="$2" node_os node_arch
  case "$os" in
    darwin) node_os=darwin ;;
    linux)  node_os=linux ;;
  esac
  case "$arch" in
    arm64) node_arch=arm64 ;;
    amd64) node_arch=x64 ;;
  esac
  echo "node-v${NODE_VERSION}-${node_os}-${node_arch}.tar.gz"
}

# provision_node installs the Node prerequisite, or fails the installation.
#
# There is deliberately no "carry on without Node" branch: the vault sync and
# GNO this machine exists to run are Node programs, and an installer that
# quietly produced a machine which cannot run them would be reporting success
# for a machine that does not work.
provision_node() {
  local os="$1" arch="$2"
  if have_node_22; then
    info "node $NODE_MIN_MAJOR+ already present"
    return
  fi

  local archive
  archive="$(node_archive_name "$os" "$arch")"
  if [[ -f "$STAGE_DIR/$archive" ]]; then
    verify_artifact "$archive"
    local tmp
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/homeplane-node.XXXXXX")"
    # Extract into a temporary root first: a failed or partial extraction never
    # becomes the machine's Node installation.
    tar -xzf "$STAGE_DIR/$archive" -C "$tmp" || die "could not extract $archive"
    local extracted
    extracted="$(find "$tmp" -maxdepth 1 -mindepth 1 -type d | head -n 1)"
    [[ -n "$extracted" && -x "$extracted/bin/node" ]] || die "$archive does not contain bin/node"
    mkdir -p "$PREFIX"
    rm -rf "$NODE_DIR.incoming" "$NODE_DIR.previous"
    mv "$extracted" "$NODE_DIR.incoming"
    # Move the previous runtime aside rather than deleting it first, so a failed
    # swap leaves a working Node in place instead of no Node at all.
    if [[ -d "$NODE_DIR" ]]; then
      mv "$NODE_DIR" "$NODE_DIR.previous"
    fi
    mv "$NODE_DIR.incoming" "$NODE_DIR"
    rm -rf "$NODE_DIR.previous" "$tmp"

    local major
    major="$(node_major "$NODE_DIR/bin/node")" || die "provisioned node is not runnable"
    [[ "$major" -ge "$NODE_MIN_MAJOR" ]] || die "vendored node reports major version $major, need >= $NODE_MIN_MAJOR"
    mkdir -p "$BIN_DIR"
    ln -sf "$NODE_DIR/bin/node" "$BIN_DIR/node"
    if [[ -x "$NODE_DIR/bin/npm" ]]; then
      ln -sf "$NODE_DIR/bin/npm" "$BIN_DIR/npm"
    fi
    info "provisioned node v$NODE_VERSION from the staged tarball into $NODE_DIR"
    return
  fi

  if [[ "${HOMEPLANE_NODE_PACKAGE:-0}" == "1" ]]; then
    provision_node_package "$os"
    have_node_22 || die "the distro package did not produce node >= $NODE_MIN_MAJOR"
    info "provisioned node from the distribution package manager"
    return
  fi

  die "node >= $NODE_MIN_MAJOR is required and was not found.
Stage the checksummed tarball '$archive' in $STAGE_DIR (with its $MANIFEST_NAME entry), or re-run with HOMEPLANE_NODE_PACKAGE=1 to install it from this distribution's package manager.
Nothing has been installed."
}

provision_node_package() {
  local os="$1"
  [[ "$os" == "linux" ]] || die "package-manager Node provisioning is only supported on Linux"
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y nodejs
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y "nodejs$NODE_MIN_MAJOR" || sudo dnf install -y nodejs
  else
    die "no supported package manager (apt-get or dnf) found for Node provisioning"
  fi
}

# --- step 4: place the agent -------------------------------------------------

install_agent() {
  local artifact="$1"
  mkdir -p "$BIN_DIR"
  local target="$BIN_DIR/homeplane-agent"
  local staging="$target.incoming.$$"
  cp "$STAGE_DIR/$artifact" "$staging"
  chmod 0755 "$staging"
  # Verify the artifact RUNS on this machine before it becomes the installed
  # agent. A checksum only proves the bytes are the intended ones; this catches
  # the intended bytes for the wrong platform. Failing here leaves any
  # previously installed agent untouched.
  if ! "$staging" version >/dev/null 2>&1; then
    rm -f "$staging"
    die "the staged artifact '$artifact' did not run on this machine. It is checksum-valid, so it is probably built for a different platform. Nothing has been changed."
  fi
  # A rename is atomic, so a concurrent `homeplane-agent status` either sees the
  # old binary or the new one, never a half-copied file. This is also what makes
  # a re-run a refresh rather than a second installation.
  mv -f "$staging" "$target"
  info "installed $target"
}

# --- main --------------------------------------------------------------------

main() {
  local os arch init artifact
  os="$(detect_os)"
  arch="$(detect_arch)"
  init="$(detect_init "$os")"
  require_supported_init "$os" "$init"
  info "platform $os/$arch supervised by $init"

  [[ -d "$STAGE_DIR" ]] || die "staged artifact directory $STAGE_DIR does not exist (pass --stage-dir)"
  [[ -f "$STAGE_DIR/$MANIFEST_NAME" ]] || die "no $MANIFEST_NAME in $STAGE_DIR; refusing to install unverified artifacts"

  artifact="homeplane-agent-${os}-${arch}"
  verify_artifact "$artifact"

  provision_node "$os" "$arch"
  install_agent "$artifact"

  cat <<EOF

Homeplane agent installed.

  $BIN_DIR/homeplane-agent

Next:
  1. add $BIN_DIR to your PATH
  2. enrol this machine:  homeplane-agent enrol -server https://<server>.ts.net
  3. check it:            homeplane-agent status

Enrolment state lives in ~/.homeplane and is untouched by re-running this
installer.
EOF
}

main "$@"
