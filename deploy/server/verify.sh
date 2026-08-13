#!/usr/bin/env bash
# verify.sh — check a deployed Homeplane server against the deployment
# acceptance, FROM A SECOND TAILNET NODE.
#
# Where it runs is not an implementation detail: two of these checks — the
# gateway being unreachable and the edge being reachable — are only meaningful
# from a machine that is not the server. Run it from your laptop, pointing
# --host at the server's SSH name; the host-side checks go over SSH, the tailnet
# checks go over the tailnet from here.
#
# Usage:
#   deploy/server/verify.sh --host clawniel --fqdn homeplane.example.ts.net \
#                           [--host-ip 100.x.y.z] [--gateway-port 44022] [--json]
#                           [--pending <check> --pending-reason "<why>"]
#   deploy/server/verify.sh --host clawniel --snapshot   # state fingerprint only
#
# --snapshot prints the fingerprint of everything an upgrade must preserve (age
# key, credential store, tsnet node identity). Take one before a re-deploy and
# one after: identical fingerprints ARE the upgrade-path evidence.
set -euo pipefail

readonly PROGRAM="verify.sh"
HOST=""
FQDN=""
HOST_IP=""
GATEWAY_PORT=44022
PREFIX="\$HOME/homeplane"
AS_JSON=0
SNAPSHOT=0
PENDING_CHECKS=""
PENDING_REASON=""

die() { echo "$PROGRAM: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --fqdn) FQDN="$2"; shift 2 ;;
    --host-ip) HOST_IP="$2"; shift 2 ;;
    --gateway-port) GATEWAY_PORT="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --json) AS_JSON=1; shift ;;
    --pending) PENDING_CHECKS="$PENDING_CHECKS $2"; shift 2 ;;
    --pending-reason) PENDING_REASON="$2"; shift 2 ;;
    --snapshot) SNAPSHOT=1; shift ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ -n "$HOST" ]] || die "--host is required"

remote() { ssh -o BatchMode=yes "$HOST" "$@"; }

if [[ $SNAPSHOT -eq 1 ]]; then
  # Deliberately fingerprints rather than dumps: the age key's CONTENT must
  # never leave the host, but its hash is enough to prove it is the same key.
  #
  # What is fingerprinted is what an upgrade must PRESERVE, and nothing else.
  # The database's CONTENT is deliberately not hashed: reading the audit log
  # appends a row (every read is itself audited), so a content hash would differ
  # between two snapshots for reasons that have nothing to do with the upgrade.
  # Its inode is the honest identity claim — same file, not a re-created one —
  # and the secret-import row count is the claim that nothing was lost.
  remote "set -e
    S=$PREFIX/var
    printf '{'
    printf '\"age_key_sha256\": \"%s\", ' \"\$(sha256sum \$S/secrets.age-key | awk '{print \$1}')\"
    printf '\"age_key_mode\": \"%s\", ' \"\$(stat -c '%a' \$S/secrets.age-key)\"
    printf '\"db_inode\": %s, ' \"\$(stat -c '%i' \$S/homeplane.db)\"
    printf '\"tsnet_state_sha256\": \"%s\", ' \"\$(sha256sum \$S/tsnet/tailscaled.state | awk '{print \$1}')\"
    printf '\"secret_imported_rows\": %s, ' \"\$($PREFIX/bin/homeplane-server admin audit -state-dir \$S -limit 0 -json 2>/dev/null | grep -c secret_imported || true)\"
    printf '\"server_binary_sha256\": \"%s\", ' \"\$(sha256sum $PREFIX/bin/homeplane-server | awk '{print \$1}')\"
    printf '\"taken_at\": \"%s\"}' \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
    echo"
  exit 0
fi

[[ -n "$FQDN" ]] || die "--fqdn is required (the tsnet node's MagicDNS name)"
# The SERVER HOST's own tailnet address — the one a gateway that wrongly bound
# 0.0.0.0 would be reachable on. Not the tsnet node's address: that one belongs
# to the homeplane process and is checked separately below.
if [[ -z "$HOST_IP" ]]; then
  HOST_IP="$(remote "tailscale ip -4" | head -1)"
fi

RESULTS=()
FAILED=0
PENDING_COUNT=0

# check NAME COMMAND... — records the outcome, never aborts. A verification run
# that stops at the first failure tells you about one problem; this one tells
# you about all of them.
#
# A check named in --pending is recorded as "pending" with its declared reason
# instead of "fail". That exists for exactly one situation: a deployment step
# that is blocked on someone outside this machine (today: the Google OAuth app
# Daniel must create). The alternative — weakening the check until it passes —
# is how a verification suite quietly stops verifying. A pending check is
# printed loudly, is machine-readable in the JSON, and turns the overall result
# into "pass_with_pending", never "pass".
check() {
  local name="$1" expect="$2"; shift 2
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  local result="pass"
  if [[ "$expect" == "ok" && $rc -ne 0 ]] || [[ "$expect" == "fail" && $rc -eq 0 ]]; then
    if [[ " $PENDING_CHECKS " == *" $name "* ]]; then
      result="pending"; PENDING_COUNT=$((PENDING_COUNT + 1))
    else
      result="fail"; FAILED=1
    fi
  fi
  # Detail is truncated: this is evidence, not a log dump.
  local detail="${out//$'\n'/ }"
  detail="${detail:0:300}"
  local reason_json='null'
  if [[ "$result" == "pending" ]]; then
    reason_json="$(printf '%s' "$PENDING_REASON" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
  fi
  RESULTS+=("$(printf '{"check":"%s","expect":"%s","exit_code":%d,"result":"%s","detail":%s,"pending_reason":%s}' \
    "$name" "$expect" "$rc" "$result" "$(printf '%s' "$detail" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')" "$reason_json")")
  printf '%-34s %-8s %s\n' "$name" "$result" "$detail" >&2
}

# 1-2. Supervision. `is-active` is the whole assertion: systemd only reports
# active for a Type=exec unit whose process is still alive.
check units_gateway_active ok remote "systemctl --user is-active homeplane-gateway.service"
check units_server_active  ok remote "systemctl --user is-active homeplane-server.service"

# 3. The bypass boundary, stated by the kernel: the gateway's listening socket
# is bound to 127.0.0.1, not to 0.0.0.0 or the tailnet address.
check gateway_bound_loopback_only ok remote \
  "ss -ltnH 'sport = :$GATEWAY_PORT' | grep -q '127.0.0.1:$GATEWAY_PORT' && ! ss -ltnH 'sport = :$GATEWAY_PORT' | grep -qE '(0\\.0\\.0\\.0|\\*|$HOST_IP):$GATEWAY_PORT'"

# 4. The same boundary, exercised from THIS machine over the tailnet. Expected
# to FAIL: a success here would mean any tailnet node can talk to the gateway
# directly, skipping the grant token, the machine binding and the manifest.
check gateway_unreachable_from_peer fail \
  curl -sS --max-time 5 -o /dev/null "http://$HOST_IP:$GATEWAY_PORT/mcp"

# ...and not on the tsnet node's own address either. The server's tailnet
# identity serves exactly what it listens on; the gateway port is not part of
# that, and this check is what says so out loud.
check gateway_unreachable_via_node fail \
  curl -sS --max-time 5 -o /dev/null "http://$FQDN:$GATEWAY_PORT/mcp"

# 5. The edge IS reachable from this machine, and fails closed: no bearer token
# means 401 before anything reaches the gateway.
check edge_reachable_unauthenticated ok bash -c \
  "code=\$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}' 'http://$FQDN/mcp'); echo \"HTTP \$code\"; [ \"\$code\" = 401 ]"

# 6. /healthz green over the tailnet — 200 only when every server component
# (store, credential store, tsnet, gateway runtime) reports ok.
check healthz_green_over_tailnet ok bash -c \
  "body=\$(curl -sS --max-time 10 -f 'http://$FQDN/healthz'); echo \"\$body\"; echo \"\$body\" | grep -q '\"status\":\"ok\"'"

# 7. The admin CLI works against the real state directory. `audit` is the right
# probe: it opens the store, reads it, and writes its own audit row, so a
# success exercises read AND write.
check admin_cli_audit ok remote \
  "$PREFIX/bin/homeplane-server admin audit -state-dir $PREFIX/var -limit 3 >/dev/null && echo ok"

# 8. The credential store exists and is 0600. Checked as a fact on disk rather
# than inferred from a successful start, because a loosened key file is exactly
# the kind of thing that keeps working while being wrong.
check credential_key_0600 ok remote \
  "[ \"\$(stat -c '%a' $PREFIX/var/secrets.age-key)\" = 600 ] && echo 0600"

# 9. The provider app credentials the DEPLOYED MANIFEST requires are in the
# store NOW — asked of the store, not of the audit log.
#
# The distinction matters: an audit row proves an import happened once, which a
# restored-from-empty or replaced database would still show. `admin secret list`
# reports the store's current contents as metadata only (ref, generation,
# encrypted flag) and cannot return a value.
#
# The refs are read out of the manifest rather than hardcoded: they are exactly
# the driver's `*_ref` parameters, which is what the credential broker looks up
# when a machine starts an OAuth flow. A deployment missing one looks perfectly
# healthy and fails at the first `add-credentials`.
#
# This check FAILS while the Homeplane-owned Google OAuth app does not exist yet
# (Daniel's own Google Cloud Console action; feeds fn-1.12) — hence the
# --pending declaration in the runbook. An earlier version greped for any
# `secret_imported` row, which a throwaway self-test import satisfied: a
# verification that passes without the thing it verifies is worse than none.
check provider_secret_refs_present ok remote \
  "set -e
   stored=\$($PREFIX/bin/homeplane-server admin secret list -state-dir $PREFIX/var -json 2>/dev/null | jq -s '.')
   missing=''
   for ref in \$(jq -r '.connectors[].credential_acquisition.params | to_entries[] | select(.key | endswith(\"_ref\")) | .value' $PREFIX/etc/manifest.json); do
     if printf '%s' \"\$stored\" | jq -e --arg r \"\$ref\" 'any(.[]; .ref == \$r and .encrypted)' >/dev/null; then
       echo \"present: \$ref\"
     else
       missing=\"\$missing \$ref\"
     fi
   done
   if [ -n \"\$missing\" ]; then echo \"MISSING:\$missing\"; exit 1; fi"

# 10. Every secret the store currently holds is ciphertext. `encrypted` is the
# store's own structural check (the bytes are an age message), evaluated per row
# — so a single plaintext value cannot hide behind other rows that are fine.
check secrets_encrypted_at_rest ok remote \
  "set -e
   rows=\$($PREFIX/bin/homeplane-server admin secret list -state-dir $PREFIX/var -json | jq -s '.')
   total=\$(printf '%s' \"\$rows\" | jq 'length')
   plain=\$(printf '%s' \"\$rows\" | jq '[.[] | select(.encrypted | not)] | length')
   echo \"stored=\$total plaintext=\$plain\"
   [ \"\$total\" -gt 0 ] && [ \"\$plain\" -eq 0 ]"

if [[ $AS_JSON -eq 1 ]]; then
  printf '{"host":"%s","fqdn":"%s","host_ip":"%s","gateway_port":%s,"checked_at":"%s","pending_count":%d,"result":"%s","checks":[%s]}\n' \
    "$HOST" "$FQDN" "$HOST_IP" "$GATEWAY_PORT" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PENDING_COUNT" \
    "$(if [[ $FAILED -ne 0 ]]; then echo fail; elif [[ $PENDING_COUNT -gt 0 ]]; then echo pass_with_pending; else echo pass; fi)" \
    "$(IFS=,; echo "${RESULTS[*]}")"
fi

exit "$FAILED"
