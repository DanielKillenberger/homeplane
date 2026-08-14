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
# Every probe runs in a SEALED HOME: both $HOME and $GROK_HOME point into a
# throwaway directory, so the capture can never read the operator's real
# ~/.grok, ~/.claude.json or ~/.agents, and can never be polluted by them. The
# leader socket is likewise pointed at a path that does not exist, so no probe
# can attach to a resident leader process.
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

# `grok --version` prints e.g. `grok 1.0.3 (1a29d5bc12d4) [stable]`; the second
# field is the release the contract is pinned to.
VERSION="$("$GROK_BIN" --version | awk '{print $2}')"
[ -n "$VERSION" ] || { echo "capture-grok-contract.sh: could not parse a version" >&2; exit 1; }
OUT="$OUT_DIR/grok-$VERSION-contract.txt"

WORK="$(mktemp -d)"
trap 'command rm -rf "$WORK"' EXIT

# The sealed home. Overriding HOME as well as GROK_HOME is what makes the
# capture machine-independent: grok discovers ~/.claude.json, ~/.claude/skills,
# ~/.cursor/skills and ~/.agents/skills relative to HOME, and any of those would
# otherwise leak the capturing operator's own machine into committed testdata.
SEALED="$WORK/home"
mkdir -p "$SEALED/.grok"
NO_LEADER="$WORK/definitely-absent.sock"

# grok_probe runs one probe in the sealed home, never attaching to a leader,
# and never hanging: every invocation carries its own alarm. The exit status is
# preserved in GROK_RC rather than propagated, because several probes below are
# captured precisely FOR their non-zero exit and `set -e` would abort on them.
GROK_RC=0
grok_probe() {
  local secs="$1"; shift
  GROK_RC=0
  HOME="$SEALED" \
  GROK_HOME="$SEALED/.grok" \
  GROK_CLAUDE_MCPS_ENABLED=false GROK_CURSOR_MCPS_ENABLED=false \
  GROK_CLAUDE_SKILLS_ENABLED=false GROK_CURSOR_SKILLS_ENABLED=false \
    perl -e 'alarm shift; exec @ARGV' "$secs" "$GROK_BIN" "$@" 2>&1 || GROK_RC=$?
  return 0
}

CONFIG="$SEALED/.grok/config.toml"

{
  echo "# Captured from grok $VERSION by scripts/capture-grok-contract.sh."
  echo "# Verbatim upstream output and observed behaviour. Do not hand-edit."
  echo

  echo "=== grok --version ==="
  "$GROK_BIN" --version 2>&1 || true
  echo

  # ---- Surface: the parser's own account of itself. -----------------------
  # Nested `--help` does NOT route past the first level (`grok mcp add --help`
  # prints the ROOT help), exactly as gno behaves. The child surfaces are
  # therefore captured through `grok help mcp <verb>`, which does route.
  echo "=== grok --help ==="
  grok_probe 30 --help
  echo

  echo "=== grok mcp --help ==="
  grok_probe 30 mcp --help
  echo

  for verb in add list remove enable disable doctor; do
    echo "=== grok help mcp $verb ==="
    grok_probe 30 help mcp "$verb"
    echo
  done

  # ---- Behaviour 0: the never-launched state. -----------------------------
  # A machine with grok installed but never run has no config.toml at all.
  # Detection must survive that, so what the CLI does there is contract.
  echo "=== never-launched sealed home: ls ~/.grok ==="
  sealed_entries="$(find "$SEALED/.grok" -mindepth 1 -maxdepth 1 -exec basename {} \; | sort)"
  echo "${sealed_entries:-(empty)}"
  echo
  echo "=== never-launched: grok mcp list --json ==="
  grok_probe 30 mcp list --json --leader-socket "$NO_LEADER"
  echo
  echo "=== never-launched: grok mcp list ==="
  grok_probe 30 mcp list --leader-socket "$NO_LEADER"
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
  grok_probe 30 mcp list --json --leader-socket "$NO_LEADER"
  echo
  echo "=== grok mcp list ==="
  grok_probe 30 mcp list --leader-socket "$NO_LEADER"
  echo

  # ---- Behaviour 4: ${VAR} is verbatim on disk, expanded at load. ---------
  echo "=== \${VAR} in a url: stored verbatim ==="
  # shellcheck disable=SC2016
  grok_probe 30 mcp add --transport http expand-probe 'https://${HP_PROBE_HOST}/mcp' >/dev/null
  grep -A2 'expand-probe' "$CONFIG" || true
  echo
  echo "=== grok mcp doctor expand-probe --json | target, WITHOUT the env var ==="
  grok_probe 60 mcp doctor expand-probe --json --leader-socket "$NO_LEADER" \
    | sed -n 's/.*"target": \(".*"\),*/target = \1/p' || true
  echo
  echo "=== grok mcp doctor expand-probe --json | target, WITH HP_PROBE_HOST set ==="
  HP_PROBE_HOST=expanded.example.invalid grok_probe 60 mcp doctor expand-probe --json --leader-socket "$NO_LEADER" \
    | sed -n 's/.*"target": \(".*"\),*/target = \1/p' || true
  echo

  # ---- Non-interactive failure shapes. -----------------------------------
  # Every one of these must fail FAST and LOUD rather than prompt: a writer
  # that hangs on a hidden prompt is the failure mode the timeout guards.
  echo "=== grok mcp remove <unknown> ==="
  grok_probe 30 mcp remove no-such-server; echo "exit: $GROK_RC"
  echo
  echo "=== grok mcp add <invalid name> ==="
  grok_probe 30 mcp add 'bad name!' 'https://x.invalid' -t http; echo "exit: $GROK_RC"
  echo
  echo "=== grok mcp add -t <invalid transport> ==="
  grok_probe 30 mcp add x 'https://x.invalid' -t carrier-pigeon; echo "exit: $GROK_RC"
  echo
  echo "=== grok mcp enable <unknown> ==="
  grok_probe 30 mcp enable no-such; echo "exit: $GROK_RC"
  echo

  # ---- Skills discovery. --------------------------------------------------
  # Three linked skills, each proving one rule: symlinks are followed, the
  # frontmatter `name` beats the directory name, and a skill with no `name`
  # falls back to its directory name.
  mkdir -p "$WORK/vault/alpha" "$WORK/vault/beta" "$WORK/vault/gamma" "$SEALED/.grok/skills"
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
  ln -sfn "$WORK/vault/alpha" "$SEALED/.grok/skills/hp-probe-alpha"
  ln -sfn "$WORK/vault/beta"  "$SEALED/.grok/skills/directory-beta-name"
  ln -sfn "$WORK/vault/gamma" "$SEALED/.grok/skills/gamma-dir-name"

  echo "=== linked skills (all three are SYMLINKS into a vault outside ~/.grok) ==="
  echo "  hp-probe-alpha      -> frontmatter name: hp-probe-alpha      (agrees with dir)"
  echo "  directory-beta-name -> frontmatter name: frontmatter-beta-name (disagrees)"
  echo "  gamma-dir-name      -> frontmatter name: (absent)"
  echo
  echo "=== grok inspect | discovered probe skills ==="
  # Reported NAME is the contract: frontmatter wins, directory name is the
  # fallback, and the symlinked target is read through the link.
  grok_probe 90 inspect | grep -E 'hp-probe-alpha|frontmatter-beta-name|gamma-dir-name|directory-beta-name' || true
  echo

  # ---- Leader semantics. --------------------------------------------------
  echo "=== grok leader list (sealed home) ==="
  grok_probe 30 leader list
  echo
  echo "=== a config change is visible to the very NEXT invocation ==="
  grok_probe 30 mcp add --transport http staleness-probe 'https://stale.example.invalid/mcp' >/dev/null
  grok_probe 30 mcp list --leader-socket "$NO_LEADER" | grep staleness || true
  echo
} | sed -e "s|$WORK|<work>|g" -e "s|$SEALED|<home>|g" -e "s|$HOME|<home>|g" -e "s|$GROK_BIN|<grok>|g" >"$OUT"

echo "wrote $OUT"
