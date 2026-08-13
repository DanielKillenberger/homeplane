#!/usr/bin/env bash
# install-server.sh — install (or upgrade) the Homeplane server and its composed
# gateway on a Linux host, under systemd --user supervision.
#
# It runs ON THE TARGET HOST, from a staging directory holding the artifacts and
# this script's siblings. deploy/server/deploy.sh is the thin driver that stages,
# uploads and runs it; nothing here needs that driver.
#
# Design rules this script is built around:
#
#   * Polite guest. Everything Homeplane owns lives under ONE prefix
#     (default ~/homeplane) plus two systemd --user units. No system paths, no
#     root, nothing shared with whatever else the host runs.
#   * Idempotent, state-preserving. A re-run with a newer binary is the upgrade
#     path: the state directory, the age key, the SQLite store and the tsnet node
#     identity are never re-created, never overwritten, never deleted.
#   * Fail closed on artifacts. Both the server binary and the ToolHive release
#     are verified against checksums BEFORE they are installed.
#   * No secret ever reaches argv or a log. The tailnet auth key is copied from a
#     0600 file into a 0600 EnvironmentFile; provider credentials only ever enter
#     through `homeplane-server admin secret import` on stdin or from a 0600 file.
#
# Usage:
#   install-server.sh [--stage-dir DIR] [--prefix DIR] [--config FILE]
#                     [--authkey-file FILE] [--no-start] [--dry-run]
set -euo pipefail

readonly PROGRAM="install-server.sh"
STAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PREFIX="${HOMEPLANE_PREFIX:-$HOME/homeplane}"
CONFIG=""
AUTHKEY_FILE=""
START=1
DRY_RUN=0

die() { echo "$PROGRAM: $*" >&2; exit 1; }
info() { echo "$PROGRAM: $*"; }
run() { if [[ $DRY_RUN -eq 1 ]]; then echo "would run: $*"; else "$@"; fi; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage-dir) STAGE_DIR="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --authkey-file) AUTHKEY_FILE="$2"; shift 2 ;;
    --no-start) START=0; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

readonly BIN_DIR="$PREFIX/bin"
readonly ETC_DIR="$PREFIX/etc"
readonly STATE_DIR="$PREFIX/var"
readonly UNIT_DIR="$HOME/.config/systemd/user"
readonly KEY_FILE="$STATE_DIR/secrets.age-key"
readonly AUTHKEY_ENV="$ETC_DIR/authkey.env"

# --- preconditions -----------------------------------------------------------
#
# Each of these has a specific failure mode it prevents, and each is checked
# before ANYTHING is written: a half-installed deployment is worse than a
# refused one.

[[ "$(uname -s)" == "Linux" ]] || die "the Homeplane server deploys on Linux only (this host: $(uname -s))"
command -v systemctl >/dev/null 2>&1 || die "systemctl not found: this deployment supervises with systemd --user"
systemctl --user show-environment >/dev/null 2>&1 \
  || die "no systemd --user session for $(id -un): run 'loginctl enable-linger $(id -un)' as an administrator first"

# Lingering is what keeps the units running when nobody is logged in. Without it
# the whole deployment dies at logout and comes back at the next SSH login,
# which looks exactly like a flapping service.
if command -v loginctl >/dev/null 2>&1; then
  if [[ "$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || echo no)" != "yes" ]]; then
    die "lingering is off for $(id -un): run 'sudo loginctl enable-linger $(id -un)' or the services stop at logout"
  fi
fi

command -v podman >/dev/null 2>&1 || command -v docker >/dev/null 2>&1 \
  || die "no container runtime: ToolHive needs Docker or Podman to run connector workloads"

# ToolHive discovers a rootless Podman socket at \$XDG_RUNTIME_DIR/podman/podman.sock.
# Two things go wrong here in practice, and both are silent:
#   1. the socket is not enabled, so ToolHive reports "no container runtime available"
#      even though `podman` is installed;
#   2. XDG_RUNTIME_DIR is unset in a non-interactive SSH session, so the same error
#      appears from the shell while the systemd units (which always have it) are fine.
if command -v podman >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
  if [[ -z "${XDG_RUNTIME_DIR:-}" ]]; then
    XDG_RUNTIME_DIR="/run/user/$(id -u)"
    export XDG_RUNTIME_DIR
    info "XDG_RUNTIME_DIR was unset (non-interactive shell); using $XDG_RUNTIME_DIR"
  fi
  if [[ ! -S "$XDG_RUNTIME_DIR/podman/podman.sock" ]]; then
    info "enabling the rootless podman socket (ToolHive's container runtime)"
    run systemctl --user enable --now podman.socket \
      || die "could not enable podman.socket; ToolHive cannot run workloads without it"
  fi
fi

# --- configuration -----------------------------------------------------------
#
# Precedence: an explicit --config, else the staged server.env, else the copy a
# previous run installed. The last case is what makes an upgrade a one-liner
# that cannot accidentally reshape the deployment.
if [[ -z "$CONFIG" ]]; then
  if [[ -f "$STAGE_DIR/server.env" ]]; then
    CONFIG="$STAGE_DIR/server.env"
  elif [[ -f "$ETC_DIR/server.env" ]]; then
    CONFIG="$ETC_DIR/server.env"
    info "reusing the installed configuration at $CONFIG"
  else
    die "no configuration: pass --config, or stage a server.env (see server.env.example)"
  fi
fi
[[ -f "$CONFIG" ]] || die "config $CONFIG not found"
# shellcheck disable=SC1090
source "$CONFIG"

: "${HOMEPLANE_HOSTNAME:?server.env must set HOMEPLANE_HOSTNAME}"
: "${HOMEPLANE_ADDR:?server.env must set HOMEPLANE_ADDR}"
: "${HOMEPLANE_TAILNET_FQDN:?server.env must set HOMEPLANE_TAILNET_FQDN}"
: "${HOMEPLANE_GATEWAY_PORT:?server.env must set HOMEPLANE_GATEWAY_PORT}"
: "${HOMEPLANE_GATEWAY_WORKLOAD:?server.env must set HOMEPLANE_GATEWAY_WORKLOAD}"
: "${HOMEPLANE_GATEWAY_NAME:=homeplane-gateway}"

# The endpoint URL handed to every harness has to name the port the control
# plane actually listens on, or grants point somewhere nothing answers. It is
# derived here rather than configured, so the two cannot drift.
port="${HOMEPLANE_ADDR#*:}"
if [[ "$port" == "80" ]]; then
  ENDPOINT_URL="http://${HOMEPLANE_TAILNET_FQDN}/mcp"
else
  ENDPOINT_URL="http://${HOMEPLANE_TAILNET_FQDN}:${port}/mcp"
fi

case "$(uname -m)" in
  x86_64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
readonly SERVER_ARTIFACT="homeplane-server-linux-${GOARCH}"

# --- artifact verification ---------------------------------------------------

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

expected_sha() {
  local name="$1" manifest="$2"
  awk -v want="$name" '$2 == want || $2 == "*" want { print $1; found=1 } END { if (!found) exit 1 }' "$manifest"
}

verify() {
  local file="$1" want="$2" got
  got="$(sha256_of "$file")"
  [[ "$got" == "$want" ]] || die "checksum mismatch for $file
  expected: $want
  actual:   $got
Nothing has been installed."
}

[[ -f "$STAGE_DIR/$SERVER_ARTIFACT" ]] \
  || die "no $SERVER_ARTIFACT in $STAGE_DIR (build it with scripts/stage-release.sh)"
[[ -f "$STAGE_DIR/SHA256SUMS" ]] \
  || die "no SHA256SUMS in $STAGE_DIR; refusing to install an unverified server binary"
SERVER_SHA="$(expected_sha "$SERVER_ARTIFACT" "$STAGE_DIR/SHA256SUMS")" \
  || die "$SERVER_ARTIFACT is not listed in SHA256SUMS; refusing to install it"
verify "$STAGE_DIR/$SERVER_ARTIFACT" "$SERVER_SHA"
info "verified $SERVER_ARTIFACT against SHA256SUMS"

# ToolHive is fetched (or reused from the stage dir) and verified against the
# repository's own pin file — not against whatever checksum the download itself
# advertises, which would verify nothing.
readonly THV_PINS="$STAGE_DIR/toolhive-pinned.sha256"
[[ -f "$THV_PINS" ]] || die "no toolhive-pinned.sha256 in $STAGE_DIR"
THV_ARCHIVE="$(awk '!/^#/ && NF == 2 {print $2}' "$THV_PINS" | grep -- "_linux_${GOARCH}\.tar\.gz$" | head -1)"
[[ -n "$THV_ARCHIVE" ]] || die "toolhive-pinned.sha256 pins no linux-$GOARCH archive"
THV_VERSION="$(sed -E 's/^toolhive_([0-9.]+)_.*/\1/' <<<"$THV_ARCHIVE")"

# --- install -----------------------------------------------------------------

info "prefix        $PREFIX"
info "state dir     $STATE_DIR (preserved across upgrades)"
info "tsnet node    $HOMEPLANE_HOSTNAME ($ENDPOINT_URL)"
info "gateway       thv $THV_VERSION, workload $HOMEPLANE_GATEWAY_WORKLOAD on 127.0.0.1:$HOMEPLANE_GATEWAY_PORT"

run mkdir -p "$BIN_DIR" "$ETC_DIR" "$PREFIX/releases" "$UNIT_DIR"
# 0700 on the state dir: it holds the age key, the credential store and the
# tsnet node identity.
run mkdir -p "$STATE_DIR"
run chmod 700 "$STATE_DIR"

# install(1) writes through a temporary and renames, so a running server is
# never reading a half-written binary; the unit restart below picks up the new
# one.
run install -m 0755 "$STAGE_DIR/$SERVER_ARTIFACT" "$BIN_DIR/homeplane-server"

if [[ ! -x "$BIN_DIR/thv" ]] || [[ "$("$BIN_DIR/thv" version 2>/dev/null | head -1)" != *"$THV_VERSION"* ]]; then
  archive="$PREFIX/releases/$THV_ARCHIVE"
  if [[ ! -f "$archive" ]]; then
    if [[ -f "$STAGE_DIR/$THV_ARCHIVE" ]]; then
      run cp "$STAGE_DIR/$THV_ARCHIVE" "$archive"
    else
      url="https://github.com/stacklok/toolhive/releases/download/v${THV_VERSION}/${THV_ARCHIVE}"
      info "downloading $url"
      run curl -fsSL --retry 2 -o "$archive.part" "$url" || die "could not download $url"
      run mv "$archive.part" "$archive"
    fi
  fi
  if [[ $DRY_RUN -eq 0 ]]; then
    verify "$archive" "$(expected_sha "$THV_ARCHIVE" "$THV_PINS")"
    info "verified $THV_ARCHIVE against the pin file"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    tar -xzf "$archive" -C "$tmp" thv
    install -m 0755 "$tmp/thv" "$BIN_DIR/thv"
  fi
else
  info "thv $THV_VERSION already installed"
fi

# Config and manifest are replaced on every run — they are declarative inputs,
# and an upgrade that left a stale manifest behind would authorize yesterday's
# tool surface.
run install -m 0600 "$CONFIG" "$ETC_DIR/server.env"
[[ -f "$STAGE_DIR/manifest.json" ]] || die "no manifest.json in $STAGE_DIR"
run install -m 0644 "$STAGE_DIR/manifest.json" "$ETC_DIR/manifest.json"
if [[ -f "$STAGE_DIR/README.md" ]]; then
  run install -m 0644 "$STAGE_DIR/README.md" "$PREFIX/README-deploy.md"
fi

# The tailnet auth key. Copied into a 0600 EnvironmentFile and never echoed. It
# is a BOOTSTRAP credential: once the node is registered, tsnet's state under
# the state dir keeps it authenticated, and this file can be deleted (see the
# runbook).
if [[ -n "$AUTHKEY_FILE" ]]; then
  [[ -f "$AUTHKEY_FILE" ]] || die "auth key file $AUTHKEY_FILE not found"
  perm="$(stat -c '%a' "$AUTHKEY_FILE")"
  [[ "$perm" == "600" || "$perm" == "400" ]] \
    || die "auth key file $AUTHKEY_FILE has mode $perm; want 600"
  if [[ $DRY_RUN -eq 0 ]]; then
    umask 077
    { printf 'TS_AUTHKEY='; cat "$AUTHKEY_FILE"; } > "$AUTHKEY_ENV.tmp"
    # A stray trailing newline inside the value would be sent to the control
    # server as part of the key; systemd needs exactly one line.
    tr -d '\r\n' < "$AUTHKEY_ENV.tmp" > "$AUTHKEY_ENV"
    printf '\n' >> "$AUTHKEY_ENV"
    rm -f "$AUTHKEY_ENV.tmp"
    chmod 600 "$AUTHKEY_ENV"
    info "installed the tailnet auth key at $AUTHKEY_ENV (0600, value not echoed)"
  fi
elif [[ -f "$AUTHKEY_ENV" ]]; then
  info "keeping the existing $AUTHKEY_ENV"
elif [[ ! -d "$STATE_DIR/tsnet" ]]; then
  info "no auth key and no tsnet state: the server will log a login URL to authenticate the node"
fi

# --- credential store bootstrap ----------------------------------------------
#
# init-key is run ONCE, on a state directory that has no key yet. Re-running it
# on an existing deployment would generate a new age key and orphan every stored
# provider secret, so the guard is the whole point.
if [[ -f "$KEY_FILE" ]]; then
  info "credential store already initialized ($KEY_FILE) — left untouched"
else
  info "initializing the credential store (age key, 0600)"
  run "$BIN_DIR/homeplane-server" admin secret init-key -state-dir "$STATE_DIR"
  info "BACK UP $KEY_FILE OFFLINE: without it every stored provider secret is unrecoverable"
fi

# --- units -------------------------------------------------------------------

render_unit() {
  local src="$1" dst="$2"
  sed -e "s#@PREFIX@#$PREFIX#g" \
      -e "s#@STATE_DIR@#$STATE_DIR#g" \
      -e "s#@HOSTNAME@#$HOMEPLANE_HOSTNAME#g" \
      -e "s#@ADDR@#$HOMEPLANE_ADDR#g" \
      -e "s#@ENDPOINT_URL@#$ENDPOINT_URL#g" \
      -e "s#@GATEWAY_PORT@#$HOMEPLANE_GATEWAY_PORT#g" \
      -e "s#@GATEWAY_WORKLOAD@#$HOMEPLANE_GATEWAY_WORKLOAD#g" \
      -e "s#@GATEWAY_NAME@#$HOMEPLANE_GATEWAY_NAME#g" \
      "$src" > "$dst"
}

for unit in homeplane-gateway homeplane-server; do
  src="$STAGE_DIR/units/$unit.service.tmpl"
  [[ -f "$src" ]] || die "missing unit template $src"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "would render $src -> $UNIT_DIR/$unit.service"
  else
    render_unit "$src" "$UNIT_DIR/$unit.service"
    chmod 644 "$UNIT_DIR/$unit.service"
  fi
done

run systemctl --user daemon-reload

if [[ $START -eq 0 ]]; then
  info "units installed but not started (--no-start)"
  exit 0
fi

# enable --now on the first run; restart on an upgrade. Both units are named
# explicitly so ordering is systemd's job, not this script's.
run systemctl --user enable homeplane-gateway.service homeplane-server.service
run systemctl --user restart homeplane-gateway.service
run systemctl --user restart homeplane-server.service

if [[ $DRY_RUN -eq 1 ]]; then
  exit 0
fi

# --- post-install report -----------------------------------------------------
#
# Reported, not asserted: this script says what the host now looks like, and
# deploy/server/verify.sh is what turns that into pass/fail evidence.
sleep 5
for unit in homeplane-gateway homeplane-server; do
  printf '%s: %-24s %s\n' "$PROGRAM" "$unit.service" "$(systemctl --user is-active "$unit.service" || true)"
done

# The auth key is a ONE-TIME bootstrap credential. Once tsnet has registered the
# node, its identity lives in the state directory and the key is never consulted
# again — so the copy under etc/ is removed rather than left lying around for
# the rest of the deployment's life. (The operator's own key file is not
# touched: it is theirs, not ours.) A wiped tsnet state needs a FRESH key, not
# this one; re-run with --authkey-file.
if [[ -f "$AUTHKEY_ENV" ]] && [[ -f "$STATE_DIR/tsnet/tailscaled.state" ]] \
   && [[ "$(systemctl --user is-active homeplane-server.service || true)" == "active" ]]; then
  rm -f "$AUTHKEY_ENV"
  info "tsnet node registered; removed the bootstrap auth key at $AUTHKEY_ENV"
fi

cat <<EOF

$PROGRAM: installed.

  binaries    $BIN_DIR/{homeplane-server,thv}
  config      $ETC_DIR/server.env, $ETC_DIR/manifest.json
  state       $STATE_DIR  (SQLite store, age key, tsnet identity — preserved on upgrade)
  units       $UNIT_DIR/homeplane-{gateway,server}.service

Next:
  systemctl --user status homeplane-server.service
  journalctl --user -u homeplane-server.service -n 50
  curl -sf http://$HOMEPLANE_TAILNET_FQDN/healthz     # from any tailnet node

If the node is not on the tailnet yet, the server logs a login URL:
  journalctl --user -u homeplane-server.service | grep -o 'https://login.tailscale.com/a/[a-z0-9]*'
EOF
