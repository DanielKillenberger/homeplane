#!/usr/bin/env bash
# install.sh — install the Homeplane agent onto this machine.
#
# The installer is split into a VALIDATE phase and a COMMIT phase, and it never
# interleaves them:
#
#   validate  1. Is this machine supported (OS, architecture, init system)?
#             2. Does every staged artifact match the checksum manifest?
#             3. Does the agent binary actually run here?
#             4. Can the Node 22 and Bun 1.3 prerequisites be satisfied, and do
#                the extracted runtimes run and report the required versions?
#   commit    5. Move the validated runtimes into the prefix, keeping the
#             6. previous ones aside, then place the agent atomically.
#
# Both runtimes are prerequisites, not alternatives: vault sync runs on Node
# (obsidian-headless) and the retrieval engine runs on Bun (GNO).
#
# Nothing under the install prefix is touched until every check above has
# passed, and the previous runtimes are retained until the WHOLE install
# succeeds — a failure at any point restores them. A checksum-valid but malformed
# release therefore cannot destroy a working machine, and it cannot leave a
# machine with a new runtime and no agent.
#
# Supported platforms: macOS 13+ (launchd) and systemd-based Linux whose user
# service manager is actually running and can linger. Everything else is
# rejected before step 2.
#
# Artifacts are consumed from a locally staged, checksummed release-form
# directory produced by scripts/stage-release.sh (spec Boundaries: the
# published CI release pipeline is deferred).
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
#   HOMEPLANE_BUN_BIN                       bun binary to probe
#   HOMEPLANE_MACOS_VERSION                 override the detected macOS version
#   HOMEPLANE_USER_MANAGER_STATE            override `systemctl --user` state
#   HOMEPLANE_LINGER_STATE                  override the logind lingering state

set -euo pipefail

readonly PROGRAM="install.sh"

# Node prerequisite. Pinning the exact version is what makes provisioning
# deterministic: two machines installed a month apart get the same runtime.
# scripts/node-pinned.sha256 must pin this same version (asserted by the tests).
readonly NODE_MIN_MAJOR=22
readonly NODE_VERSION="${HOMEPLANE_NODE_VERSION:-22.11.0}"

# Bun prerequisite, pinned the same way and for the same reason. GNO (D8) is a
# Bun program, so a machine without Bun cannot run the retrieval engine at all.
# scripts/bun-pinned.sha256 must pin this same version (asserted by the tests).
readonly BUN_MIN_MAJOR=1
readonly BUN_MIN_MINOR=3
readonly BUN_VERSION="${HOMEPLANE_BUN_VERSION:-1.3.11}"

readonly MANIFEST_NAME="SHA256SUMS"

STAGE_DIR="${HOMEPLANE_STAGE_DIR:-./dist}"
PREFIX="${HOMEPLANE_PREFIX:-$HOME/.homeplane}"

die() {
  echo "$PROGRAM: $*" >&2
  exit 1
}

info() { echo "$PROGRAM: $*"; }

usage() {
  sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'
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
readonly BUN_DIR="$PREFIX/bun"

# --- failure handling --------------------------------------------------------
#
# INSTALL_COMPLETE flips to 1 only when the whole install has landed. Until
# then, exiting for ANY reason (a `die`, a failed command under `set -e`, a
# signal) rolls the prefix back to the runtime it had on entry.

TMP_ROOT=""
INSTALL_COMPLETE=0
NODE_RESTORE_NEEDED=0
NODE_DIR_CREATED=0
BUN_RESTORE_NEEDED=0
BUN_DIR_CREATED=0

on_exit() {
  if [[ $INSTALL_COMPLETE -eq 0 && $NODE_RESTORE_NEEDED -eq 1 && -d "$NODE_DIR.previous" ]]; then
    rm -rf "$NODE_DIR"
    mv "$NODE_DIR.previous" "$NODE_DIR"
    echo "$PROGRAM: install failed; restored the previous node runtime at $NODE_DIR" >&2
  elif [[ $INSTALL_COMPLETE -eq 0 && $NODE_DIR_CREATED -eq 1 ]]; then
    # There was no previous runtime to restore, so the honest rollback is to
    # remove the one this run was in the middle of placing.
    rm -rf "$NODE_DIR"
    echo "$PROGRAM: install failed; removed the partially placed node runtime" >&2
  fi
  if [[ $INSTALL_COMPLETE -eq 0 && $BUN_RESTORE_NEEDED -eq 1 && -d "$BUN_DIR.previous" ]]; then
    rm -rf "$BUN_DIR"
    mv "$BUN_DIR.previous" "$BUN_DIR"
    echo "$PROGRAM: install failed; restored the previous bun runtime at $BUN_DIR" >&2
  elif [[ $INSTALL_COMPLETE -eq 0 && $BUN_DIR_CREATED -eq 1 ]]; then
    rm -rf "$BUN_DIR"
    echo "$PROGRAM: install failed; removed the partially placed bun runtime" >&2
  fi
  if [[ -n "$TMP_ROOT" && -d "$TMP_ROOT" ]]; then
    rm -rf "$TMP_ROOT"
  fi
  return 0
}
trap on_exit EXIT

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

# MIN_MACOS_MAJOR is R1's supported floor: macOS 13 (Ventura). An older macOS
# is rejected rather than half-installed — its launchd, its TLS stack and its
# Node builds are not what the agent is built against.
MIN_MACOS_MAJOR=13

# macos_version echoes the running product version ("14.6.1"), or nothing when
# it cannot be read. The override exists for the installer tests, which have to
# exercise the gate on whatever machine they run on.
macos_version() {
  if [[ -n "${HOMEPLANE_MACOS_VERSION:-}" ]]; then
    echo "$HOMEPLANE_MACOS_VERSION"
    return
  fi
  command -v sw_vers >/dev/null 2>&1 || return 0
  sw_vers -productVersion 2>/dev/null || return 0
}

# require_supported_macos enforces the version floor.
#
# An unreadable version is a REFUSAL, not a pass: "we could not tell" must never
# resolve to "supported", or an unsupported machine gets a binary it cannot run.
require_supported_macos() {
  local version major
  version="$(macos_version)"
  if [[ -z "$version" ]]; then
    die "could not determine this machine's macOS version (sw_vers did not answer). Homeplane requires macOS $MIN_MACOS_MAJOR or newer; nothing has been installed."
  fi
  major="${version%%.*}"
  if [[ ! "$major" =~ ^[0-9]+$ ]]; then
    die "could not read this machine's macOS version (sw_vers said '$version'). Homeplane requires macOS $MIN_MACOS_MAJOR or newer; nothing has been installed."
  fi
  if (( major < MIN_MACOS_MAJOR )); then
    die "macOS $version is not supported. Homeplane requires macOS $MIN_MACOS_MAJOR (Ventura) or newer; nothing has been installed."
  fi
}

# user_manager_state echoes what `systemctl --user is-system-running` says about
# THIS user's service manager: `running`, `degraded`, `offline`, `starting`, and
# so on. The command exits non-zero for every state but `running`, so its exit
# code is deliberately ignored — the state word is the answer. An empty answer
# means the user bus could not be reached at all.
user_manager_state() {
  if [[ -n "${HOMEPLANE_USER_MANAGER_STATE+x}" ]]; then
    echo "$HOMEPLANE_USER_MANAGER_STATE"
    return
  fi
  systemctl --user is-system-running 2>/dev/null || true
}

# linger_state echoes `yes`, `no`, or nothing when logind could not answer for
# this user. Nothing is the interesting case: it means lingering can neither be
# read nor enabled here, which is the condition R1 excludes.
linger_state() {
  if [[ -n "${HOMEPLANE_LINGER_STATE+x}" ]]; then
    echo "$HOMEPLANE_LINGER_STATE"
    return
  fi
  command -v loginctl >/dev/null 2>&1 || return 0
  loginctl show-user "$(id -un)" --property=Linger --value 2>/dev/null || true
}

# require_user_service_manager proves — without changing anything — that this
# Linux machine can actually run per-user services that survive logout.
#
# The presence of the binaries is not the property that matters: a container, a
# chroot or a session without a user bus all have `systemctl` on PATH and no
# user manager behind it. So the manager is asked whether it is running, and
# logind is asked whether it knows this user, before anything is written.
require_user_service_manager() {
  # The probes below are seams (see linger_state); the binary check applies to
  # the machine that will actually be asked.
  if [[ -z "${HOMEPLANE_LINGER_STATE+x}" ]] && ! command -v loginctl >/dev/null 2>&1; then
    die "this Linux machine has systemd but no loginctl, so 'systemctl --user' services cannot be made to survive logout. Homeplane needs a user service manager with lingering."
  fi

  local state
  state="$(user_manager_state)"
  case "$state" in
    # `degraded` means some unrelated user unit failed; the manager itself is up
    # and can run Homeplane's units, so it is accepted rather than refused.
    running|degraded) : ;;
    "")
      die "'systemctl --user' could not reach a user service manager for $(id -un). Homeplane supervises the vault sync and the retrieval engine as user services, so this machine cannot run the plane. Have an administrator run 'loginctl enable-linger $(id -un)' (and log in once) and re-run $PROGRAM. Nothing has been installed." ;;
    *)
      die "this machine's user service manager is '$state', not running. Homeplane supervises the vault sync and the retrieval engine as user services, so it cannot install here yet. Fix the user session (an administrator may need 'loginctl enable-linger $(id -un)') and re-run $PROGRAM. Nothing has been installed." ;;
  esac

  # Lingering is what keeps those units alive when nobody is logged in. The
  # agent enables it at activation, so `no` is not a refusal — but a logind that
  # cannot answer for this user at all is: enable-linger would fail later, and
  # the services would silently stop at logout.
  local linger
  linger="$(linger_state)"
  if [[ -z "$linger" ]]; then
    die "logind could not report the lingering state for $(id -un), so 'loginctl enable-linger' cannot be relied on here and Homeplane's services would stop at logout. Nothing has been installed."
  fi
  if [[ "$linger" != "yes" ]]; then
    info "lingering is off for $(id -un); the agent enables it when it activates its services (or run 'sudo loginctl enable-linger $(id -un)' yourself)"
  fi
}

require_supported_init() {
  local os="$1" init="$2"
  case "$os:$init" in
    darwin:launchd)
      require_supported_macos ;;
    linux:systemd)
      # `systemctl --user` plus linger is what lets Homeplane's services run
      # without an interactive login session. A machine that only LOOKS like it
      # has them is caught now, not later by a service that never starts.
      require_user_service_manager
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

# --- step 3: validate the agent binary ---------------------------------------

# VALIDATED_AGENT is the path of an agent binary that has been checksum-verified
# AND observed to run on this machine. Only this file is ever installed.
VALIDATED_AGENT=""

prepare_agent() {
  local artifact="$1"
  verify_artifact "$artifact"

  local candidate="$TMP_ROOT/homeplane-agent"
  cp "$STAGE_DIR/$artifact" "$candidate"
  chmod 0755 "$candidate"
  # A checksum only proves the bytes are the intended ones; running the binary
  # is what catches the intended bytes for the wrong platform. This happens
  # entirely outside the prefix, so a wrong-platform artifact can neither
  # replace a working agent nor leave one behind.
  if ! "$candidate" version >/dev/null 2>&1; then
    die "the staged artifact '$artifact' did not run on this machine. It is checksum-valid, so it is probably built for a different platform. Nothing has been changed."
  fi
  VALIDATED_AGENT="$candidate"
}

# --- step 4: validate the Node 22 prerequisite -------------------------------

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

# NODE_ACTION is decided during validation and carried out during commit.
#   none      a usable Node is already installed
#   vendored  VALIDATED_NODE holds an extracted, runnable Node >= 22
#   package   the distro package manager will be asked (opted into explicitly)
NODE_ACTION="none"
VALIDATED_NODE=""

# prepare_node decides how the prerequisite will be met and PROVES it, without
# writing anything into the prefix.
#
# There is deliberately no "carry on without Node" branch: the vault sync and
# GNO this machine exists to run are Node programs, and an installer that
# quietly produced a machine which cannot run them would be reporting success
# for a machine that does not work.
prepare_node() {
  local os="$1" arch="$2"
  if have_node_22; then
    NODE_ACTION="none"
    info "node $NODE_MIN_MAJOR+ already present"
    return
  fi

  local archive
  archive="$(node_archive_name "$os" "$arch")"
  if [[ -f "$STAGE_DIR/$archive" ]]; then
    verify_artifact "$archive"
    local extract_root="$TMP_ROOT/node-extract"
    mkdir -p "$extract_root"
    # Extract into a temporary root: a failed or partial extraction never
    # becomes the machine's Node installation.
    tar -xzf "$STAGE_DIR/$archive" -C "$extract_root" || die "could not extract $archive"
    local extracted
    extracted="$(find "$extract_root" -maxdepth 1 -mindepth 1 -type d | head -n 1)"
    [[ -n "$extracted" && -x "$extracted/bin/node" ]] || die "$archive does not contain bin/node; nothing has been changed"

    local major
    major="$(node_major "$extracted/bin/node")" \
      || die "the node runtime in $archive did not run on this machine; nothing has been changed"
    [[ "$major" -ge "$NODE_MIN_MAJOR" ]] \
      || die "the node runtime in $archive reports major version $major, need >= $NODE_MIN_MAJOR; nothing has been changed"

    NODE_ACTION="vendored"
    VALIDATED_NODE="$extracted"
    return
  fi

  if [[ "${HOMEPLANE_NODE_PACKAGE:-0}" == "1" ]]; then
    NODE_ACTION="package"
    return
  fi

  die "node >= $NODE_MIN_MAJOR is required and was not found.
Stage the checksummed tarball '$archive' in $STAGE_DIR (scripts/stage-release.sh does this), or re-run with HOMEPLANE_NODE_PACKAGE=1 to install it from this distribution's package manager.
Nothing has been installed."
}

provision_node_package() {
  local os="$1"
  [[ "$os" == "linux" ]] || die "package-manager Node provisioning is only supported on Linux; stage the checksummed node tarball instead"
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y nodejs
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y "nodejs$NODE_MIN_MAJOR" || sudo dnf install -y nodejs
  else
    die "no supported package manager (apt-get or dnf) found for Node provisioning"
  fi
}

# --- step 4b: validate the Bun prerequisite ----------------------------------
#
# Deliberately a SEPARATE prerequisite from Node rather than a replacement for
# it: vault sync runs on Node (obsidian-headless) and the retrieval engine runs
# on Bun (GNO). A machine needs both, and an installer that quietly accepted one
# would produce a machine that half works.

bun_version_string() {
  local bin="$1" version
  version="$("$bin" --version 2>/dev/null)" || return 1
  version="${version#v}"
  version="${version%%[!0-9.]*}"
  [[ -n "$version" ]] || return 1
  echo "$version"
}

# bun_at_least reports whether a version is >= BUN_MIN_MAJOR.BUN_MIN_MINOR. Bun
# is versioned 1.x, so unlike Node the minor is load-bearing and a major-only
# comparison would accept the 1.0 releases GNO does not run on.
bun_at_least() {
  local version="$1" major minor
  major="${version%%.*}"
  minor="${version#*.}"
  minor="${minor%%.*}"
  [[ -n "$major" && -n "$minor" ]] || return 1
  if (( major > BUN_MIN_MAJOR )); then return 0; fi
  if (( major < BUN_MIN_MAJOR )); then return 1; fi
  (( minor >= BUN_MIN_MINOR ))
}

have_bun() {
  local bin="${HOMEPLANE_BUN_BIN:-}"
  if [[ -z "$bin" ]]; then
    bin="$(command -v bun 2>/dev/null || true)"
  fi
  [[ -n "$bin" && -x "$bin" ]] || return 1
  local version
  version="$(bun_version_string "$bin")" || return 1
  bun_at_least "$version"
}

bun_archive_name() {
  local os="$1" arch="$2" bun_arch
  case "$arch" in
    arm64) bun_arch=aarch64 ;;
    amd64) bun_arch=x64 ;;
  esac
  echo "bun-v${BUN_VERSION}-${os}-${bun_arch}.zip"
}

# BUN_ACTION mirrors NODE_ACTION: none | vendored.
#
# There is no package-manager branch. Bun is not packaged consistently across
# distributions, and `curl | bash` from bun.sh is exactly the unverified install
# path R1 exists to refuse — so the staged, checksummed archive is the only
# provisioning route, and its absence is an honest failure rather than a
# silently half-working machine.
BUN_ACTION="none"
VALIDATED_BUN=""

prepare_bun() {
  local os="$1" arch="$2"
  if have_bun; then
    BUN_ACTION="none"
    info "bun ${BUN_MIN_MAJOR}.${BUN_MIN_MINOR}+ already present"
    return
  fi

  local archive
  archive="$(bun_archive_name "$os" "$arch")"
  [[ -f "$STAGE_DIR/$archive" ]] || die "bun >= ${BUN_MIN_MAJOR}.${BUN_MIN_MINOR} is required by the retrieval engine (GNO) and was not found.
Stage the checksummed archive '$archive' in $STAGE_DIR (scripts/stage-release.sh does this).
Nothing has been installed."

  verify_artifact "$archive"
  command -v unzip >/dev/null 2>&1 || die "unzip is required to install the staged bun archive; nothing has been changed"

  local extract_root="$TMP_ROOT/bun-extract"
  mkdir -p "$extract_root"
  # Extract into a temporary root: a failed or partial extraction never becomes
  # the machine's Bun installation.
  unzip -q "$STAGE_DIR/$archive" -d "$extract_root" || die "could not extract $archive"
  local extracted_bin
  extracted_bin="$(find "$extract_root" -type f -name bun | head -n 1)"
  [[ -n "$extracted_bin" ]] || die "$archive does not contain a bun executable; nothing has been changed"
  chmod 0755 "$extracted_bin"

  local version
  version="$(bun_version_string "$extracted_bin")" \
    || die "the bun runtime in $archive did not run on this machine. It is checksum-valid, so it is probably built for a different platform. Nothing has been changed."
  bun_at_least "$version" \
    || die "the bun runtime in $archive reports $version, need >= ${BUN_MIN_MAJOR}.${BUN_MIN_MINOR}; nothing has been changed"

  BUN_ACTION="vendored"
  VALIDATED_BUN="$extracted_bin"
}

commit_bun() {
  [[ "$BUN_ACTION" == "vendored" ]] || return 0

  mkdir -p "$PREFIX" "$BIN_DIR"
  rm -rf "$BUN_DIR.previous"
  if [[ -d "$BUN_DIR" ]]; then
    # Move the previous runtime aside rather than deleting it, exactly as the
    # Node path does: on_exit puts it back if anything after this point fails.
    mv "$BUN_DIR" "$BUN_DIR.previous"
    BUN_RESTORE_NEEDED=1
  else
    BUN_DIR_CREATED=1
  fi
  mkdir -p "$BUN_DIR"
  mv "$VALIDATED_BUN" "$BUN_DIR/bun"
  chmod 0755 "$BUN_DIR/bun"
  ln -sf "$BUN_DIR/bun" "$BIN_DIR/bun"
  info "provisioned bun v$BUN_VERSION from the staged archive into $BUN_DIR"
}

# --- step 5/6: commit --------------------------------------------------------

commit_node() {
  local os="$1"
  case "$NODE_ACTION" in
    none) return ;;
    package)
      provision_node_package "$os"
      have_node_22 || die "the distro package did not produce node >= $NODE_MIN_MAJOR"
      info "provisioned node from the distribution package manager"
      return ;;
  esac

  mkdir -p "$PREFIX" "$BIN_DIR"
  rm -rf "$NODE_DIR.previous"
  if [[ -d "$NODE_DIR" ]]; then
    # Move the previous runtime aside rather than deleting it. It is not removed
    # until the ENTIRE install has succeeded, and on_exit puts it back if
    # anything after this point fails.
    mv "$NODE_DIR" "$NODE_DIR.previous"
    NODE_RESTORE_NEEDED=1
  else
    NODE_DIR_CREATED=1
  fi
  mv "$VALIDATED_NODE" "$NODE_DIR"
  ln -sf "$NODE_DIR/bin/node" "$BIN_DIR/node"
  if [[ -x "$NODE_DIR/bin/npm" ]]; then
    ln -sf "$NODE_DIR/bin/npm" "$BIN_DIR/npm"
  fi
  info "provisioned node v$NODE_VERSION from the staged tarball into $NODE_DIR"
}

commit_agent() {
  mkdir -p "$BIN_DIR"
  local target="$BIN_DIR/homeplane-agent"
  local staging="$target.incoming.$$"
  cp "$VALIDATED_AGENT" "$staging"
  chmod 0755 "$staging"
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

  TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/homeplane-install.XXXXXX")"

  # Validate everything first...
  artifact="homeplane-agent-${os}-${arch}"
  prepare_agent "$artifact"
  prepare_node "$os" "$arch"
  prepare_bun "$os" "$arch"

  # ...then commit, newest-runtime-first, with the old one still recoverable.
  commit_node "$os"
  commit_bun
  commit_agent

  INSTALL_COMPLETE=1
  rm -rf "$NODE_DIR.previous" "$BUN_DIR.previous"

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
