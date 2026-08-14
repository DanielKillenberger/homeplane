#!/usr/bin/env bash
# capture-grok-contract.sh — capture the installed grok CLI's own surface AND
# its observed write behaviour.
#
# Homeplane writes into a config file it does not own, through a CLI it does not
# own. A stub can only prove our writer agrees with itself, so the surface is
# ALSO asserted against the REAL build's own parser output and its REAL
# behaviour, captured here verbatim and committed as testdata. This is the same
# discipline (and the same recorded lesson) as scripts/capture-gno-contract.sh:
# an invented flag cannot survive an assertion against upstream's own output.
#
# Beyond --help, this captures the four behaviours that decided fn-3's D2/D3 —
# each one a claim a future grok release could break silently:
#
#   1. `grok mcp add` DROPS COMMENTS from the whole config.toml (it round-trips
#      the document through a serializer, it does not splice).
#   2. `grok mcp add` RESETS the file mode to 0644, discarding a pre-set 0600.
#   3. A re-add with different arguments CLOBBERS the entry wholesale — an add
#      without `-H` silently deletes the entry's headers sub-table.
#   4. `${VAR}` in a header or url value is stored VERBATIM rather than
#      expanded at write time (which is why the placeholder, not the secret, is
#      what argv sees). Expansion at LOAD time is observed here for `url`;
#      header expansion is upstream-documented but NOT verified by this capture
#      — see docs/decisions/fn3-grok-surfaces.md section 3.
#
# Every probe runs in a SEALED HOME: $HOME and $GROK_HOME point into a throwaway
# directory (at two DIFFERENT roots, so GROK_HOME relocation is actually proven
# rather than assumed - see the decoy below), so the capture can never read the
# operator's real ~/.grok, ~/.claude.json or ~/.agents, and can never be
# polluted by them. Every probe also passes a leader socket path that does not
# exist, so no probe can attach to a resident leader process, and every
# invocation carries a timeout so none can hang.
#
# Usage: scripts/capture-grok-contract.sh [path-to-grok]
# Writes: internal/agent/harness/testdata/grok-<version>-contract.txt
set -euo pipefail

GROK_BIN="${1:-grok}"
command -v "$GROK_BIN" >/dev/null 2>&1 || { echo "capture-grok-contract.sh: $GROK_BIN not found" >&2; exit 1; }
GROK_BIN="$(command -v "$GROK_BIN")"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUT_DIR="$REPO_ROOT/internal/agent/harness/testdata"
mkdir -p "$OUT_DIR"

WORK="$(mktemp -d)"

# The EXIT trap owns cleanup of BOTH the scratch dir and any partial contract.
# It has to be the trap rather than code after the pipeline: `fail()` exits the
# pipeline subshell and `set -e` then aborts the script immediately, so
# anything written after the pipeline would never run and a truncated contract
# would survive to be committed as a real observation.
# The capture is written to a TEMPORARY file and only renamed over the
# committed contract once it has been validated. Writing straight to $OUT would
# truncate the last known-good artifact before the new one is known to be any
# good, so a transient failure — a grok that will not start, a network blip in
# `doctor` — would destroy the committed evidence and leave nothing.
CAPTURE_OK=""
OUT=""
OUT_TMP=""
cleanup() {
  if [ -n "$OUT_TMP" ] && [ -e "$OUT_TMP" ]; then
    command rm -f "$OUT_TMP"
  fi
  if [ -z "$CAPTURE_OK" ]; then
    echo "capture-grok-contract.sh: capture incomplete; the committed contract was left untouched" >&2
  fi
  command rm -rf "$WORK"
}
trap cleanup EXIT

# The sealed home, in two DELIBERATELY DIFFERENT roots.
#
# Overriding HOME as well as GROK_HOME is what makes the capture
# machine-independent: grok discovers ~/.claude.json, ~/.claude/skills,
# ~/.cursor/skills and ~/.agents/skills relative to HOME, and any of those would
# otherwise leak the capturing operator's own machine into committed testdata.
#
# But GROK_HOME must NOT be "$OS_HOME/.grok" — that is exactly the path grok
# would use if it ignored GROK_HOME entirely, so a capture rooted there proves
# nothing about relocation. GROK_HOME therefore points somewhere grok would
# never derive on its own, and a DECOY is seeded at "$OS_HOME/.grok" holding a
# uniquely named server. If grok ever reads the decoy, that name shows up in the
# captured output and the relocation claim fails loudly instead of silently.
OS_HOME="$WORK/os-home"
GROK_DIR="$WORK/grok-home-elsewhere"
mkdir -p "$OS_HOME/.grok/skills" "$GROK_DIR"
NO_LEADER="$WORK/definitely-absent.sock"

# Two more seals, each closing a route by which the CALLER's machine could
# contaminate a capture that claims to be machine-independent:
#
#   PROBE_CWD — grok reads PROJECT-level config from the working directory:
#   `./.grok/skills`, `./.mcp.json`, `.agents/skills`, and every directory up
#   to the git root. Running this script from a configured project would mix
#   that project's servers and skills into the observations, and could change
#   the compat and identity conclusions. Every probe therefore runs from an
#   empty directory that is not inside any repository.
#
#   The `env -u` list — the probe variables are the ones the capture sets
#   DELIBERATELY to demonstrate expansion. Inheriting them would mean the
#   probe labelled "HP_PROBE_HOST unset" was not unset at all, and — since
#   expansion reaches headers too — an exported REAL bearer token could be
#   loaded and sent during `doctor`, contradicting this script's claim that no
#   secret is ever used. They are unset for every probe, and set only for the
#   one invocation whose whole purpose is to observe expansion.
PROBE_CWD="$WORK/cwd"
mkdir -p "$PROBE_CWD"

# The decoy: a config and a skill that must NEVER appear in the capture.
cat > "$OS_HOME/.grok/config.toml" <<'DECOY'
[mcp_servers.decoy-must-never-appear]
command = "/usr/bin/false"
enabled = true
DECOY
mkdir -p "$OS_HOME/.grok/skills/decoy-skill-must-never-appear"
cat > "$OS_HOME/.grok/skills/decoy-skill-must-never-appear/SKILL.md" <<'DECOY'
---
name: decoy-skill-must-never-appear
description: Seeded at $HOME/.grok/skills to prove GROK_HOME relocates skills discovery.
---
Body.
DECOY

# grok_probe runs one probe in the sealed home, never attaching to a leader,
# and never hanging: every invocation carries its own alarm. The exit status is
# preserved in GROK_RC rather than propagated, because several probes below are
# captured precisely FOR their non-zero exit and `set -e` would abort on them.
# GROK_RC is ALSO written to a file. A probe captured with `$(...)` runs in a
# subshell, so a plain variable assignment there is lost to the caller and a
# later check would silently read a PREVIOUS probe's status — which is exactly
# how a failing probe can be written up as a passing observation. RC_FILE
# survives the subshell; expect_ok reads it, never the variable.
GROK_RC=0
RC_FILE="$WORK/last_rc"
echo 0 > "$RC_FILE"
grok_probe() {
  local secs="$1"; shift
  GROK_RC=0
  # --leader-socket is appended to EVERY probe, not just the ones that read MCP
  # state: a resident leader must be impossible by construction, including for
  # `inspect`, which is the skills-discovery oracle. Subcommands that do not
  # accept the flag are invoked through grok_probe_bare instead.
  ( cd "$PROBE_CWD" && env -u HP_PROBE_HOST -u HP_PROBE_TOKEN -u HOMEPLANE_GROK_TOKEN \
    HOME="$OS_HOME" \
    GROK_HOME="$GROK_DIR" \
    GROK_CLAUDE_MCPS_ENABLED=false GROK_CURSOR_MCPS_ENABLED=false \
    GROK_CLAUDE_SKILLS_ENABLED=false GROK_CURSOR_SKILLS_ENABLED=false \
      perl -e 'alarm shift; exec @ARGV' "$secs" "$GROK_BIN" "$@" \
        --leader-socket "$NO_LEADER" ) 2>&1 || GROK_RC=$?
  echo "$GROK_RC" > "$RC_FILE"
  return 0
}

# grok_probe_bare is for the few invocations whose subcommand does not accept
# --leader-socket (`--version`, `--help`, `help <...>`). They still get the
# sealed environment and the timeout - no grok invocation anywhere in this
# script runs unwrapped.
grok_probe_bare() {
  local secs="$1"; shift
  GROK_RC=0
  ( cd "$PROBE_CWD" && env -u HP_PROBE_HOST -u HP_PROBE_TOKEN -u HOMEPLANE_GROK_TOKEN \
    HOME="$OS_HOME" \
    GROK_HOME="$GROK_DIR" \
    GROK_CLAUDE_MCPS_ENABLED=false GROK_CURSOR_MCPS_ENABLED=false \
    GROK_CLAUDE_SKILLS_ENABLED=false GROK_CURSOR_SKILLS_ENABLED=false \
      perl -e 'alarm shift; exec @ARGV' "$secs" "$GROK_BIN" "$@" ) 2>&1 || GROK_RC=$?
  echo "$GROK_RC" > "$RC_FILE"
  return 0
}

CONFIG="$GROK_DIR/config.toml"

# `grok --version` prints e.g. `grok 1.0.3 (1a29d5bc12d4) [stable]`; the second
# field is the release the contract is pinned to. This runs through the SAME
# sealed, timed environment as every other probe — an earlier revision ran it
# before the sealed roots existed, which handed the real grok home to the
# executable and contradicted this script's own sealing claim.
VERSION="$(HOME="$OS_HOME" GROK_HOME="$GROK_DIR" \
  perl -e 'alarm shift; exec @ARGV' 30 "$GROK_BIN" --version | awk '{print $2}')"
[ -n "$VERSION" ] || { echo "capture-grok-contract.sh: could not parse a version" >&2; exit 1; }
OUT="$OUT_DIR/grok-$VERSION-contract.txt"
# Same directory as $OUT so the final rename is atomic (same filesystem).
OUT_TMP="$OUT_DIR/.grok-$VERSION-contract.txt.$$"

# fail() aborts the capture loudly. It exists because this script PRODUCES
# EVIDENCE: a probe that silently failed would otherwise be written up as a
# passing observation. The body below runs as the left side of a pipeline (a
# subshell), so `exit 1` there cannot kill the parent on its own — `pipefail`
# plus the sentinel file make the failure survive back to the top level, and
# the partial contract is deleted rather than left to be committed.
fail() {
  echo "CAPTURE ABORTED: $*" >&2
  : > "$WORK/CAPTURE_FAILED"
  exit 1
}

# TIMEOUT_RC is what `perl -e alarm` leaves behind when a probe runs long:
# SIGALRM kills the process and the shell reports 128+14. It gets its own
# rejection everywhere, including on probes we EXPECT to fail — a probe that
# hung for 30s and got killed is not evidence of a "fast, non-interactive
# failure", it is the exact opposite, and recording it as one would invert the
# finding the failure-shape section exists to establish.
TIMEOUT_RC=142

reject_timeout() {
  [ "$2" -ne "$TIMEOUT_RC" ] || fail "$1 TIMED OUT (exit $TIMEOUT_RC): it hung rather than failing fast"
}

# expect_ok asserts the LAST probe exited 0.
expect_ok() {
  local rc; rc="$(cat "$RC_FILE")"
  reject_timeout "$1" "$rc"
  [ "$rc" -eq 0 ] || fail "$1 exited $rc (expected 0)"
}

# expect_rc asserts an EXACT status, for the probes captured precisely for
# their non-zero exit. "non-zero" alone is too weak: it cannot tell grok's own
# refusal (1) from a clap parse error (2) from a timeout (142), and those are
# three different findings.
expect_rc() {
  local label="$1" want="$2" rc
  rc="$(cat "$RC_FILE")"
  reject_timeout "$label" "$rc"
  [ "$rc" -eq "$want" ] || fail "$label exited $rc (expected $want)"
}

{
  echo "# Captured from grok $VERSION by scripts/capture-grok-contract.sh."
  echo "# Verbatim upstream output and observed behaviour. Do not hand-edit."
  echo

  echo "=== grok --version ==="
  grok_probe_bare 30 --version; expect_ok "grok --version"
  echo

  # ---- Surface: the parser's own account of itself. -----------------------
  # Nested `--help` does NOT route past the first level (`grok mcp add --help`
  # prints the ROOT help), exactly as gno behaves. The child surfaces are
  # therefore captured through `grok help mcp <verb>`, which does route.
  echo "=== grok --help ==="
  grok_probe_bare 30 --help; expect_ok "grok --help"
  echo

  echo "=== grok mcp --help ==="
  grok_probe_bare 30 mcp --help; expect_ok "grok mcp --help"
  echo

  for verb in add list remove enable disable doctor; do
    echo "=== grok help mcp $verb ==="
    grok_probe_bare 30 help mcp "$verb"; expect_ok "grok help mcp $verb"
    echo
  done

  # ---- Behaviour 0: the never-launched state. -----------------------------
  # A machine with grok installed but never run has no config.toml at all.
  # Detection must survive that, so what the CLI does there is contract.
  # ---- GROK_HOME relocation, proven rather than assumed. ------------------
  # $HOME/.grok holds a decoy config + skill. If GROK_HOME were ignored, the
  # decoy names would appear in the two probes below. Their ABSENCE, next to
  # the presence of the entries we wrote to the relocated dir, is the proof.
  echo "=== decoy seeded at \$HOME/.grok (must NEVER appear below) ==="
  echo "  mcp server: decoy-must-never-appear"
  echo "  skill:      decoy-skill-must-never-appear"
  echo
  echo "=== GROK_HOME points somewhere \$HOME/.grok never would ==="
  echo "  HOME       = <os-home>        (so \$HOME/.grok = <os-home>/.grok)"
  echo "  GROK_HOME  = <grok-home>      (a different root entirely)"
  echo

  echo "=== never-launched sealed home: ls \$GROK_HOME ==="
  sealed_entries="$(find "$GROK_DIR" -mindepth 1 -maxdepth 1 -exec basename {} \; | sort)"
  echo "${sealed_entries:-(empty)}"
  echo
  echo "=== never-launched: grok mcp list --json ==="
  grok_probe 30 mcp list --json; expect_ok "never-launched mcp list --json"
  echo
  echo "=== never-launched: grok mcp list ==="
  grok_probe 30 mcp list; expect_ok "never-launched mcp list"
  echo

  # The single quotes below are load-bearing: `${HOMEPLANE_GROK_TOKEN}` and
  # `${HP_PROBE_HOST}` must reach grok as LITERAL placeholder text, because the
  # whole point is that grok stores them verbatim and expands them itself at
  # load time. Letting the shell expand them would write an empty value and
  # quietly destroy the very behaviour this capture pins.
  # shellcheck disable=SC2016

  # ---- Behaviour 1: preservation. ----------------------------------------
  # Seed a config that carries comments and an unrelated MCP entry, then let
  # `grok mcp add` rewrite it. The diff is the evidence that CLI verbs are NOT
  # a preserving write path.
  cat > "$CONFIG" <<'SEED'
# a hand-written preamble comment
[ui]
max_thoughts_width = 120

# an unrelated pre-existing MCP entry, with its own comment
[mcp_servers.preexisting-thing]
command = "/usr/bin/true"
args = ["--keep-me"]
enabled = true
SEED
  cp "$CONFIG" "$WORK/seed.toml"
  chmod 600 "$CONFIG"

  echo "=== seeded config.toml (mode 0600) ==="
  cat "$WORK/seed.toml"
  echo
  echo "=== grok mcp add --transport http <name> <url> --header 'Authorization: Bearer \${VAR}' ==="
  # shellcheck disable=SC2016
  grok_probe 30 mcp add --transport http homeplane-edge 'https://edge.example.invalid/mcp' \
    --header 'Authorization: Bearer ${HOMEPLANE_GROK_TOKEN}'
  expect_ok "mcp add homeplane-edge"
  echo
  echo "=== config.toml after the add ==="
  cat "$CONFIG"
  echo
  echo "=== diff: seeded -> after add (COMMENTS ARE DROPPED) ==="
  # Stable --label values: diff's default header carries mtimes, which would
  # make the committed testdata churn on every re-capture and bury a real
  # behavioural change in timestamp noise.
  diff -u --label "seeded config.toml" --label "config.toml after the add" \
    "$WORK/seed.toml" "$CONFIG" || true
  # ASSERTED, not merely displayed: the heading above states a conclusion, so
  # the conclusion is checked. If a future grok preserved comments, the diff
  # would simply look different and the heading would go on lying.
  grep -q '^# a hand-written preamble comment$' "$WORK/seed.toml" \
    || fail "the seed lost its comment before the probe even ran"
  if grep -q '^# a hand-written preamble comment$' "$CONFIG"; then
    fail "grok mcp add PRESERVED comments: the 'comments are dropped' conclusion is FALSIFIED"
  fi
  grep -q 'preexisting-thing' "$CONFIG" \
    || fail "the unrelated pre-existing entry was lost, not merely stripped of comments"
  echo
  echo "=== file mode: 0600 before the add, after the add ==="
  # Behaviour 2: the CLI rewrites via temp-file+rename and does not carry the
  # mode across, so a 0600 config comes back 0644 — world-readable.
  mode_after="$(stat -f '%Lp' "$CONFIG" 2>/dev/null || stat -c '%a' "$CONFIG")"
  echo "before: 0600 (set explicitly above)"
  echo "after:  $mode_after"
  [ "$mode_after" = "644" ] \
    || fail "the mode after the add is $mode_after, not 644: the 'mode is reset' conclusion is FALSIFIED"
  echo

  # ---- Behaviour 3: idempotency, then clobber. ---------------------------
  cp "$CONFIG" "$WORK/after-add.toml"
  echo "=== re-run the IDENTICAL add ==="
  # shellcheck disable=SC2016
  grok_probe 30 mcp add --transport http homeplane-edge 'https://edge.example.invalid/mcp' \
    --header 'Authorization: Bearer ${HOMEPLANE_GROK_TOKEN}'
  expect_ok "identical re-add"
  echo
  echo "=== diff after the identical re-run (expected: byte-identical) ==="
  if diff -u --label "before the re-add" --label "after the re-add" \
       "$WORK/after-add.toml" "$CONFIG"; then
    echo "(no diff: an identical re-add is idempotent)"
  fi
  cmp -s "$WORK/after-add.toml" "$CONFIG" \
    || fail "an identical re-add was NOT byte-identical: the idempotency conclusion is FALSIFIED"
  echo
  echo "=== re-add the SAME name with a different url and NO --header ==="
  grok_probe 30 mcp add --transport http homeplane-edge 'https://edge2.example.invalid/mcp'
  expect_ok "differing re-add"
  echo
  echo "=== config.toml after the differing re-add (the headers table is GONE) ==="
  cat "$CONFIG"
  grep -q 'edge2.example.invalid' "$CONFIG" \
    || fail "the differing re-add did not take effect at all"
  if grep -q 'mcp_servers.homeplane-edge.headers' "$CONFIG"; then
    fail "the headers sub-table SURVIVED a differing re-add: the wholesale-clobber conclusion is FALSIFIED"
  fi
  echo

  # ---- The read surfaces. -------------------------------------------------
  # shellcheck disable=SC2016
  grok_probe 30 mcp add --transport http homeplane-edge 'https://edge.example.invalid/mcp' \
    --header 'Authorization: Bearer ${HOMEPLANE_GROK_TOKEN}' >/dev/null
  expect_ok "restore homeplane-edge entry"
  echo "=== grok mcp list --json ==="
  # NOTE: header VALUES are echoed verbatim. A literal bearer token in the
  # config would be printed here in full — which is why fn-3 keeps this output
  # out of logs and model context.
  grok_probe 30 mcp list --json; expect_ok "mcp list --json"
  echo
  echo "=== grok mcp list ==="
  grok_probe 30 mcp list; expect_ok "mcp list"
  echo

  # ---- Behaviour 4: ${VAR} is verbatim on disk, expanded at load. ---------
  echo "=== \${VAR} in a url: stored verbatim ==="
  # shellcheck disable=SC2016
  grok_probe 30 mcp add --transport http expand-probe 'https://${HP_PROBE_HOST}/mcp' >/dev/null
  expect_ok "mcp add expand-probe"
  grep -A2 'expand-probe' "$CONFIG" \
    || fail "the expand-probe entry is not in the config at all"
  # The placeholder must be on disk LITERALLY. If grok expanded it at write
  # time, the whole "the secret never reaches argv or the file" reasoning in
  # docs/decisions/fn3-grok-surfaces.md section 3 would not hold.
  grep -q 'HP_PROBE_HOST' "$CONFIG" \
    || fail "the \${VAR} placeholder was NOT stored verbatim: it was expanded at write time"
  echo
  # doctor is captured with stdout and stderr SEPARATED, in full, with its exit
  # status. The separation is itself contract: doctor writes well-formed JSON to
  # stdout and an unstructured tracing line to stderr, so a caller that merges
  # the two cannot parse the result. Reducing this to one grepped field (as an
  # earlier revision did) would leave the decision record's claims about
  # `sources`, the per-server `checks`, and the handshake failure unevidenced.
  # $1 = label, $2 = "verbatim"|"classified" for the stderr treatment, rest =
  # doctor's own arguments.
  doctor_probe() {
    local label="$1"; local stderr_mode="$2"; shift 2
    # rc is function-LOCAL and reset per invocation. Reusing the global would
    # report a previous probe's failure against a later successful one.
    local rc=0 doctor_stdout=""
    # stdout is captured rather than streamed so it can be VALIDATED before it
    # is reported, and so stderr stays genuinely separate.
    doctor_stdout="$(cd "$PROBE_CWD" && env -u HP_PROBE_HOST -u HP_PROBE_TOKEN -u HOMEPLANE_GROK_TOKEN \
      HOME="$OS_HOME" GROK_HOME="$GROK_DIR" \
      GROK_CLAUDE_MCPS_ENABLED=false GROK_CURSOR_MCPS_ENABLED=false \
        perl -e 'alarm shift; exec @ARGV' 90 "$GROK_BIN" mcp doctor "$@" --json \
          --leader-socket "$NO_LEADER" 2>"$WORK/doctor.err")" || rc=$?
    echo "=== grok mcp doctor $label | STDOUT ==="
    printf '%s\n' "$doctor_stdout"
    echo "exit: $rc"
    echo
    # The claim "stdout is JSON, independently of stderr" is VERIFIED here, not
    # asserted: an earlier revision printed that line without ever parsing the
    # output. doctor exits non-zero for an unhealthy server, so a non-zero rc is
    # expected - but its stdout must still be well-formed JSON either way.
    reject_timeout "mcp doctor $label" "$rc"
    if ! printf '%s' "$doctor_stdout" | python3 -m json.tool >/dev/null 2>&1; then
      fail "mcp doctor $label did not emit parseable JSON on stdout"
    fi
    if [ "$stderr_mode" = verbatim ]; then
      echo "=== grok mcp doctor $label | STDERR ==="
      cat "$WORK/doctor.err"
    else
      # Upstream flushes this tracing line RACILY on exit — it appears on some
      # runs and not others for the same input. Recording it verbatim would
      # make the committed contract churn between runs and bury real
      # behavioural changes in that noise, so this probe records only the fact
      # the contract actually rests on: the streams are separate, and stdout
      # parsed as JSON regardless of whether stderr carried anything.
      echo "=== grok mcp doctor $label | STDERR (classified, see note) ==="
      echo "stdout parsed as JSON independently of stderr: yes"
      echo "note: upstream emits an unstructured tracing ERROR line here"
      echo "      non-deterministically; the verbatim form is captured above"
      echo "      for the unreachable-host probe."
    fi
  }

  # The broken HTTP entry: an unresolvable host, so the handshake genuinely
  # fails and the failure SHAPE is what gets pinned.
  doctor_probe "homeplane-edge (unreachable host)" verbatim homeplane-edge
  echo
  # The ${VAR} entry, unexpanded then expanded — the load-time expansion proof.
  doctor_probe "expand-probe (HP_PROBE_HOST unset)" classified expand-probe
  echo
  # The load-time expansion proof, and the LAST probe that used to fail open:
  # piping straight into `sed ... || true` meant a timeout, a CLI failure,
  # malformed JSON, or an unchanged target all still reached the end marker and
  # replaced the known-good contract. The expansion is now asserted, not
  # scraped — if grok stops expanding `${VAR}`, this capture fails rather than
  # quietly recording a placeholder as though it were the proof.
  echo "=== grok mcp doctor expand-probe | target WITH HP_PROBE_HOST set ==="
  expand_want="https://expanded.example.invalid/mcp"
  # Invoked directly rather than via grok_probe: grok_probe merges stderr into
  # stdout (2>&1) so its output can be captured verbatim into the contract, and
  # doctor's unstructured tracing line would make the JSON unparseable here.
  expand_rc=0
  expand_out="$(cd "$PROBE_CWD" && env -u HP_PROBE_TOKEN -u HOMEPLANE_GROK_TOKEN \
    HP_PROBE_HOST=expanded.example.invalid HOME="$OS_HOME" GROK_HOME="$GROK_DIR" \
    GROK_CLAUDE_MCPS_ENABLED=false GROK_CURSOR_MCPS_ENABLED=false \
      perl -e 'alarm shift; exec @ARGV' 90 "$GROK_BIN" mcp doctor expand-probe --json \
        --leader-socket "$NO_LEADER" 2>/dev/null)" || expand_rc=$?
  # doctor exits 1 for an unhealthy server, which this deliberately is (the
  # host does not resolve), so 1 is the expected status here — but a timeout is
  # still refused, and the JSON must still parse.
  reject_timeout "mcp doctor expand-probe (expanded)" "$expand_rc"
  [ "$expand_rc" -eq 1 ] \
    || fail "mcp doctor expand-probe (expanded) exited $expand_rc (expected 1)"
  expand_target="$(printf '%s' "$expand_out" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["servers"][0]["target"])' 2>/dev/null)" \
    || fail "mcp doctor expand-probe (expanded) did not emit parseable JSON with a server target"
  [ "$expand_target" = "$expand_want" ] \
    || fail "\${VAR} was NOT expanded at load time: target is '$expand_target', expected '$expand_want'"
  echo "target = \"$expand_target\""
  echo "(asserted equal to the expected expansion, not merely scraped)"
  echo

  # ---- Non-interactive failure shapes. -----------------------------------
  # Every one of these must fail FAST and LOUD rather than prompt: a writer
  # that hangs on a hidden prompt is the failure mode the timeout guards.
  echo "=== grok mcp remove <unknown> ==="
  grok_probe 30 mcp remove no-such-server; echo "exit: $(cat "$RC_FILE")"; expect_rc "mcp remove <unknown>" 1
  echo
  echo "=== grok mcp add <invalid name> ==="
  grok_probe 30 mcp add 'bad name!' 'https://x.invalid' -t http; echo "exit: $(cat "$RC_FILE")"; expect_rc "mcp add <invalid name>" 1
  echo
  echo "=== grok mcp add -t <invalid transport> ==="
  grok_probe 30 mcp add x 'https://x.invalid' -t carrier-pigeon; echo "exit: $(cat "$RC_FILE")"; expect_rc "mcp add <invalid transport>" 2
  echo
  echo "=== grok mcp enable <unknown> ==="
  grok_probe 30 mcp enable no-such; echo "exit: $(cat "$RC_FILE")"; expect_rc "mcp enable <unknown>" 1
  echo

  # ---- Skills discovery. --------------------------------------------------
  # Three linked skills, each proving one rule: symlinks are followed, the
  # frontmatter `name` beats the directory name, and a skill with no `name`
  # falls back to its directory name.
  mkdir -p "$WORK/vault/alpha" "$WORK/vault/beta" "$WORK/vault/gamma" "$GROK_DIR/skills"
  cat > "$WORK/vault/alpha/SKILL.md" <<'SK'
---
name: hp-probe-alpha
description: Probe skill whose frontmatter name matches its directory name.
---
Body.
SK
  cat > "$WORK/vault/beta/SKILL.md" <<'SK'
---
name: frontmatter-beta-name
description: Probe skill whose frontmatter name differs from its directory name.
---
Body.
SK
  cat > "$WORK/vault/gamma/SKILL.md" <<'SK'
---
description: Probe skill with NO name field, to prove directory-name fallback.
---
Body.
SK
  ln -sfn "$WORK/vault/alpha" "$GROK_DIR/skills/hp-probe-alpha"
  ln -sfn "$WORK/vault/beta"  "$GROK_DIR/skills/directory-beta-name"
  ln -sfn "$WORK/vault/gamma" "$GROK_DIR/skills/gamma-dir-name"

  echo "=== linked skills (all three are SYMLINKS into a vault outside ~/.grok) ==="
  echo "  hp-probe-alpha      -> frontmatter name: hp-probe-alpha      (agrees with dir)"
  echo "  directory-beta-name -> frontmatter name: frontmatter-beta-name (disagrees)"
  echo "  gamma-dir-name      -> frontmatter name: (absent)"
  echo
  echo "=== grok inspect | discovered probe skills ==="
  # Reported NAME is the contract: frontmatter wins, directory name is the
  # fallback, and the symlinked target is read through the link. inspect runs
  # ONCE and its output is reused by the relocation gate below, so the gate
  # judges the same observation that is reported here.
  inspect_out="$(grok_probe 90 inspect)"; expect_ok "grok inspect"
  printf '%s\n' "$inspect_out" \
    | grep -E 'hp-probe-alpha|frontmatter-beta-name|gamma-dir-name|directory-beta-name' \
    || fail "inspect returned no probe skills: skills discovery cannot be reported"
  # The D1 conclusion is that the frontmatter name WINS, which is only true if
  # the directory name is ABSENT. Reporting both would mean grok indexes a
  # skill under either name, and RuleNameMismatch would not apply as claimed.
  printf '%s\n' "$inspect_out" | grep -q 'frontmatter-beta-name' \
    || fail "the frontmatter name is missing: the 'frontmatter wins' conclusion is FALSIFIED"
  if printf '%s\n' "$inspect_out" | grep -q 'directory-beta-name'; then
    fail "grok reported the DIRECTORY name too: 'the frontmatter name wins' is FALSIFIED"
  fi
  printf '%s\n' "$inspect_out" | grep -q 'gamma-dir-name' \
    || fail "the name-less skill was not reported by its directory name: the fallback conclusion is FALSIFIED"
  echo

  # ---- Leader semantics. --------------------------------------------------
  echo "=== grok leader list (sealed home) ==="
  grok_probe 30 leader list; expect_ok "grok leader list"
  echo
  echo "=== a config change is visible to the very NEXT invocation ==="
  grok_probe 30 mcp add --transport http staleness-probe 'https://stale.example.invalid/mcp' >/dev/null
  expect_ok "mcp add staleness-probe"
  mcp_out="$(grok_probe 30 mcp list)"; expect_ok "mcp list (staleness)"
  printf '%s\n' "$mcp_out" | grep staleness \
    || fail "the entry just added is not visible to the next invocation"
  echo

  # ---- GROK_HOME relocation gate. -----------------------------------------
  # POSITIVE SENTINELS FIRST. Absence of the decoy proves nothing on its own:
  # a probe that failed, timed out, or returned empty also contains no decoy
  # names, and an earlier revision of this script would have reported that as
  # "relocation proven". So the relocated directory's OWN content must be
  # present in the same outputs before their silence about the decoy counts.
  echo "=== relocation gate: positive sentinels ==="
  for sentinel in homeplane-edge staleness-probe expand-probe; do
    printf '%s\n' "$mcp_out" | grep -q -- "$sentinel" \
      || fail "relocation gate: '$sentinel' (written to \$GROK_HOME) missing from mcp list"
    echo "  present in mcp list:  $sentinel"
  done
  for sentinel in hp-probe-alpha frontmatter-beta-name gamma-dir-name; do
    printf '%s\n' "$inspect_out" | grep -q -- "$sentinel" \
      || fail "relocation gate: skill '$sentinel' (linked into \$GROK_HOME) missing from inspect"
    echo "  present in inspect:   $sentinel"
  done
  echo

  echo "=== relocation gate: decoy absence ==="
  decoy_hits="$(printf '%s\n%s\n' "$mcp_out" "$inspect_out" \
    | grep -c 'decoy-must-never-appear\|decoy-skill-must-never-appear' || true)"
  [ "$decoy_hits" -eq 0 ] \
    || fail "$decoy_hits decoy reference(s) found: GROK_HOME did NOT relocate, and the relocation claim in docs/decisions/fn3-grok-surfaces.md is FALSIFIED"
  echo "0 decoy references, alongside the sentinels above:"
  echo "GROK_HOME relocated BOTH config and skills discovery"
  echo

  echo "=== END OF CAPTURE ==="
} | sed -E -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+Z/<timestamp>/g' \
          -e 's/"[a-z_]*elapsed[a-z_]*": [0-9.]+/"elapsed": <elapsed>/g' \
          -e 's/"detail": "[0-9]+\.[0-9]+s"/"detail": "<duration>"/g' \
    | sed -e "s|$WORK|<work>|g" -e "s|$OS_HOME|<os-home>|g" -e "s|$GROK_DIR|<grok-home>|g" -e "s|$HOME|<home>|g" -e "s|$GROK_BIN|<grok>|g" >"$OUT_TMP"

# Belt and braces on the fail-closed path. `set -e` + `pipefail` already abort
# on a fail() inside the pipeline, but this script writes committed evidence:
# if it ever exits successfully, the file it points at must be a COMPLETE
# capture. Only reaching here — with the end marker present — marks it keepable;
# every other exit path leaves CAPTURE_OK empty and the trap deletes the file.
if [ -e "$WORK/CAPTURE_FAILED" ] || ! grep -q '^=== END OF CAPTURE ===$' "$OUT_TMP"; then
  echo "capture-grok-contract.sh: capture incomplete" >&2
  exit 1
fi

# Only now is the new capture known-good, so only now does it replace the
# committed one. mv within the same directory is atomic: a reader either sees
# the whole old contract or the whole new one, never a half-written file.
mv -f "$OUT_TMP" "$OUT"
OUT_TMP=""
CAPTURE_OK=1

echo "wrote $OUT"
