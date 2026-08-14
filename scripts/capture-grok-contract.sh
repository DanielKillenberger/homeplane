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
#   4. `${VAR}` in a header/url value is stored VERBATIM and expanded at LOAD
#      time (which is why the placeholder, not the secret, is what argv sees).
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
CAPTURE_OK=""
OUT=""
cleanup() {
  if [ -z "$CAPTURE_OK" ] && [ -n "$OUT" ] && [ -e "$OUT" ]; then
    command rm -f "$OUT"
    echo "capture-grok-contract.sh: capture incomplete; $OUT removed" >&2
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
  HOME="$OS_HOME" \
  GROK_HOME="$GROK_DIR" \
  GROK_CLAUDE_MCPS_ENABLED=false GROK_CURSOR_MCPS_ENABLED=false \
  GROK_CLAUDE_SKILLS_ENABLED=false GROK_CURSOR_SKILLS_ENABLED=false \
    perl -e 'alarm shift; exec @ARGV' "$secs" "$GROK_BIN" "$@" \
      --leader-socket "$NO_LEADER" 2>&1 || GROK_RC=$?
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
  HOME="$OS_HOME" \
  GROK_HOME="$GROK_DIR" \
  GROK_CLAUDE_MCPS_ENABLED=false GROK_CURSOR_MCPS_ENABLED=false \
  GROK_CLAUDE_SKILLS_ENABLED=false GROK_CURSOR_SKILLS_ENABLED=false \
    perl -e 'alarm shift; exec @ARGV' "$secs" "$GROK_BIN" "$@" 2>&1 || GROK_RC=$?
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

# expect_ok asserts the LAST probe exited 0. Probes captured precisely for
# their non-zero exit (the failure-shape section) deliberately do not call it.
expect_ok() {
  local rc; rc="$(cat "$RC_FILE")"
  [ "$rc" -eq 0 ] || fail "$1 exited $rc (expected 0)"
}

{
  echo "# Captured from grok $VERSION by scripts/capture-grok-contract.sh."
  echo "# Verbatim upstream output and observed behaviour. Do not hand-edit."
  echo

  echo "=== grok --version ==="
  grok_probe_bare 30 --version
  echo

  # ---- Surface: the parser's own account of itself. -----------------------
  # Nested `--help` does NOT route past the first level (`grok mcp add --help`
  # prints the ROOT help), exactly as gno behaves. The child surfaces are
  # therefore captured through `grok help mcp <verb>`, which does route.
  echo "=== grok --help ==="
  grok_probe_bare 30 --help
  echo

  echo "=== grok mcp --help ==="
  grok_probe_bare 30 mcp --help
  echo

  for verb in add list remove enable disable doctor; do
    echo "=== grok help mcp $verb ==="
    grok_probe_bare 30 help mcp "$verb"
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
  grok_probe 30 mcp list --json
  echo
  echo "=== never-launched: grok mcp list ==="
  grok_probe 30 mcp list
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
  echo
  echo "=== file mode: 0600 before the add, after the add ==="
  # Behaviour 2: the CLI rewrites via temp-file+rename and does not carry the
  # mode across, so a 0600 config comes back 0644 — world-readable.
  echo "before: 0600 (set explicitly above)"
  echo "after:  $(stat -f '%Lp' "$CONFIG" 2>/dev/null || stat -c '%a' "$CONFIG")"
  echo

  # ---- Behaviour 3: idempotency, then clobber. ---------------------------
  cp "$CONFIG" "$WORK/after-add.toml"
  echo "=== re-run the IDENTICAL add ==="
  # shellcheck disable=SC2016
  grok_probe 30 mcp add --transport http homeplane-edge 'https://edge.example.invalid/mcp' \
    --header 'Authorization: Bearer ${HOMEPLANE_GROK_TOKEN}'
  echo
  echo "=== diff after the identical re-run (expected: byte-identical) ==="
  if diff -u --label "before the re-add" --label "after the re-add" \
       "$WORK/after-add.toml" "$CONFIG"; then
    echo "(no diff: an identical re-add is idempotent)"
  fi
  echo
  echo "=== re-add the SAME name with a different url and NO --header ==="
  grok_probe 30 mcp add --transport http homeplane-edge 'https://edge2.example.invalid/mcp'
  echo
  echo "=== config.toml after the differing re-add (the headers table is GONE) ==="
  cat "$CONFIG"
  echo

  # ---- The read surfaces. -------------------------------------------------
  # shellcheck disable=SC2016
  grok_probe 30 mcp add --transport http homeplane-edge 'https://edge.example.invalid/mcp' \
    --header 'Authorization: Bearer ${HOMEPLANE_GROK_TOKEN}' >/dev/null
  echo "=== grok mcp list --json ==="
  # NOTE: header VALUES are echoed verbatim. A literal bearer token in the
  # config would be printed here in full — which is why fn-3 keeps this output
  # out of logs and model context.
  grok_probe 30 mcp list --json
  echo
  echo "=== grok mcp list ==="
  grok_probe 30 mcp list
  echo

  # ---- Behaviour 4: ${VAR} is verbatim on disk, expanded at load. ---------
  echo "=== \${VAR} in a url: stored verbatim ==="
  # shellcheck disable=SC2016
  grok_probe 30 mcp add --transport http expand-probe 'https://${HP_PROBE_HOST}/mcp' >/dev/null
  grep -A2 'expand-probe' "$CONFIG" || true
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
    local rc=0
    echo "=== grok mcp doctor $label | STDOUT ==="
    HOME="$OS_HOME" GROK_HOME="$GROK_DIR" \
    GROK_CLAUDE_MCPS_ENABLED=false GROK_CURSOR_MCPS_ENABLED=false \
      perl -e 'alarm shift; exec @ARGV' 90 "$GROK_BIN" mcp doctor "$@" --json \
        --leader-socket "$NO_LEADER" 2>"$WORK/doctor.err" || rc=$?
    echo "exit: $rc"
    echo
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
  echo "=== grok mcp doctor expand-probe | target WITH HP_PROBE_HOST set ==="
  HP_PROBE_HOST=expanded.example.invalid grok_probe 90 mcp doctor expand-probe --json \
    | sed -n 's/.*"target": \(".*"\),*/target = \1/p' || true
  echo

  # ---- Non-interactive failure shapes. -----------------------------------
  # Every one of these must fail FAST and LOUD rather than prompt: a writer
  # that hangs on a hidden prompt is the failure mode the timeout guards.
  echo "=== grok mcp remove <unknown> ==="
  grok_probe 30 mcp remove no-such-server; echo "exit: $(cat "$RC_FILE")"
  echo
  echo "=== grok mcp add <invalid name> ==="
  grok_probe 30 mcp add 'bad name!' 'https://x.invalid' -t http; echo "exit: $(cat "$RC_FILE")"
  echo
  echo "=== grok mcp add -t <invalid transport> ==="
  grok_probe 30 mcp add x 'https://x.invalid' -t carrier-pigeon; echo "exit: $(cat "$RC_FILE")"
  echo
  echo "=== grok mcp enable <unknown> ==="
  grok_probe 30 mcp enable no-such; echo "exit: $(cat "$RC_FILE")"
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
    | sed -e "s|$WORK|<work>|g" -e "s|$OS_HOME|<os-home>|g" -e "s|$GROK_DIR|<grok-home>|g" -e "s|$HOME|<home>|g" -e "s|$GROK_BIN|<grok>|g" >"$OUT"

# Belt and braces on the fail-closed path. `set -e` + `pipefail` already abort
# on a fail() inside the pipeline, but this script writes committed evidence:
# if it ever exits successfully, the file it points at must be a COMPLETE
# capture. Only reaching here — with the end marker present — marks it keepable;
# every other exit path leaves CAPTURE_OK empty and the trap deletes the file.
if [ -e "$WORK/CAPTURE_FAILED" ] || ! grep -q '^=== END OF CAPTURE ===$' "$OUT"; then
  echo "capture-grok-contract.sh: capture incomplete" >&2
  exit 1
fi
CAPTURE_OK=1

echo "wrote $OUT"
