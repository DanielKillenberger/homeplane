# D14/D15 — Skills linking mechanics per harness, and the profile format

**Status:** resolved and implemented (task fn-1.9, 2026-08-14).
**Scope:** how a vault-authored skill physically reaches Claude Code and Codex
(D14), and how "the appropriate skills" is expressed (D15).

Everything in the capability matrix below was established against the **real**
installed CLIs — `claude 2.1.227` and `codex-cli 0.146.0` — not inferred from
documentation. The assertions live in `internal/agent/skills/e2e_test.go`, which
links the real vault's skills into fixture harness directories and then makes a
FRESH process of each real CLI enumerate them.

## 1. Capability matrix (D14)

| Harness | Mechanism | Skills directory | Symlinks | Name comes from | Fresh-process proof |
|---|---|---|---|---|---|
| Claude Code | **native-link** | `$CLAUDE_CONFIG_DIR/skills`, else `~/.claude/skills` | followed, target reported unchanged | the **directory** name | first `system`/`init` event of `claude -p --output-format stream-json --verbose` carries a `skills` array |
| Codex | **native-link** | `$CODEX_HOME/skills`, else `~/.codex/skills` | followed, locator resolves to the real path | the SKILL.md frontmatter **`name`** | `codex debug prompt-input` renders a `<skills_instructions>` block listing every skill with its resolved `(file: …)` locator |

Both harnesses are **native-link**. No adapter was needed, and none was built:
an adapter that nobody needs is a second format to keep true.

Four consequences, each load-bearing:

- **No harness CONFIG file is touched.** Skills are discovered from a
  directory, so there is nothing to merge. The R5 merge machinery in
  `internal/agent/harness` is not invoked by the skills path at all — which is
  a stronger preservation guarantee than merging carefully would be, not a
  weaker one. Inside the skills directory the preservation rule is the same in
  spirit: Homeplane creates, repoints or withdraws only entries it created and
  recorded in its own manifest, and leaves everything else exactly as it was.

- **Symlinks are the mechanism, so the vault holds the only original.** Both
  CLIs follow a symlinked skill directory and read the file it points at.
  Codex proves this out loud: its locator for a linked skill is the **vault**
  path, not the path under `~/.codex/skills`. Claude Code's side is proven by
  inspection instead — `Inspect` requires the entry to be a symlink, to resolve
  inside the vault, and for `<entry>/SKILL.md` and the vault's SKILL.md to be
  the same device+inode.

- **The two harnesses name a skill differently.** Claude Code uses the
  directory it found the skill in; Codex uses the frontmatter `name`. Verified
  by linking one skill under a deliberately different directory name: Claude
  reported the directory, Codex reported the frontmatter. Homeplane therefore
  links under the vault's directory name AND refuses a skill whose frontmatter
  disagrees with it (`name-mismatch`), because a skill that answers to two
  names depending on the harness is an identity Homeplane cannot keep
  consistent. Daniel's vault currently has no such skill.

- **`$CLAUDE_CONFIG_DIR` relocates the skills directory too.** With it set,
  Claude Code enumerates `$CLAUDE_CONFIG_DIR/skills` and **ignores**
  `~/.claude/skills`. That is what lets the whole suite run against fixture
  harness directories with the real binaries, and it is why writing to
  `~/.claude/skills` unconditionally would be wrong on a machine that sets it.

**GNO's installer, checked and not used here.** `gno mcp install --target
claude-code|codex` covers GNO's own MCP server and its own bundled skills. It
does not provision arbitrary vault-authored skills, so it does not overlap this
path. It stays what D8 recorded it as: the MCP-side option for task .11.

### Why not a model turn, and what the probe DOES do

The obvious proof — ask the harness to run the skill — costs a model turn, needs
credentials, and is non-deterministic. Both probes above are structured and
offline. Claude Code emits the init event **before** it makes any request, so the
probe reads it and kills the process; the negative control is that an unknown
skill simply does not appear in the array (and an unknown slash command is
answered locally with `Unknown command`). The init event is not always the FIRST
line — a machine with hooks configured emits `system`/`hook_started` events
ahead of it, which is how the first version of this probe failed against
Daniel's real Claude Code and nowhere else.

What the probe is **not** is side-effect-free. It starts the real harness with
the operator's real configuration, so Claude Code runs the operator's configured
**hooks**, which can touch files, start processes, or use the network. That is
inherent to spawning a fresh harness process, which is the point of the proof:
the flags that suppress hooks (`--bare`, `--safe-mode`) also suppress the
personal skills directory, so a hook-free probe would enumerate nothing and
prove nothing. Verified, not assumed — `claude --bare` does not list personal
skills. A caller that needs isolation points the probe's environment at a
fixture configuration directory, which is what the test suite does.

## 2. Profile format (D15)

The profile is a **vault-resident TOML file** at
`<vault>/skills/homeplane.skills.toml`. It lives in the vault because it is
Daniel's assignment of his own skills, it belongs beside the skills it names,
and it syncs to every machine for free. The reference copy, fully commented, is
`configs/skills/homeplane.skills.toml`; the parser reads that same file in a
test, so the documented format cannot drift from the implemented one.

```toml
schema  = 1
profile = "daniel-skeleton"

[defaults]
skills = ["professional-writing", "casual-writing", "karpathy-guidelines"]

[harness.codex]
skills = ["professional-writing"]

[machine."studio"]
skills = ["professional-writing", "casual-writing"]

[machine."studio".harness.claude-code]
skills = []
```

Resolution is **most-specific-wins**, and a block **replaces** the less specific
set rather than adding to it:

```
[machine.<m>.harness.<h>]  →  [machine.<m>]  →  [harness.<h>]  →  [defaults]
```

Replacement, not union, is the honest semantic: a rule has to be able to say
"nothing on this harness", and an additive model cannot subtract.

An unknown key, an unknown harness, a schema this build does not read, or a
skill name that is not a plain directory name (`../…`, `/…`, `.ssh`) is a
refusal, not a warning. A profile whose meaning this build would get wrong is
worse than no profile.

**The skeleton profile** (Daniel, 2026-08-14) is `professional-writing`,
`casual-writing`, `karpathy-guidelines` on BOTH harnesses.

## 3. What is never linked, and why

Every candidate the vault holds gets a verdict, and a non-linkable verdict
always carries a reason and concrete evidence. Nothing is silently skipped
(R15).

| Rule | Status | What it catches |
|---|---|---|
| `credential-material` | rejected | a credential file (`.env`, `*.pem`, `credentials.json`, …) or credential-shaped text (provider key formats, a PEM block, a long opaque value assigned to a secret-sounding key) |
| `runtime-state` | rejected | databases, indexes, logs, sockets, binaries, unreadable or unscanned files |
| `escapes-vault` | rejected | a skill that resolves outside the vault, or that contains a link leaving its own directory |
| `invalid-skill-md` | rejected | missing, unclosed or incomplete frontmatter |
| `no-skill-md` | unsupported | a directory OF skills rather than a skill — Daniel's `hermes` |
| `name-mismatch` | unsupported | directory name and frontmatter `name` disagree (see above) |
| `initiative-signal` | unsupported | any file in the skill drives host scheduling or service control (cron, launchd, systemd) |
| `profile-unsupported` | unsupported | the profile's own `[unsupported.<skill>]` marking (see below) |

The containment rules run **first**, so a directory that is both malformed and
carrying a private key is reported as carrying a private key.

Two of these are worth spelling out because the obvious narrower version of
each is wrong:

- **The containment and initiative scans read every file, not just SKILL.md.**
  A benign-looking SKILL.md that points the harness at a bundled
  `scripts/setup.sh` which installs a cron job is precisely the case a
  SKILL.md-only scan waves through, and it is the case that matters most.
- **A file is scanned in full or the skill is rejected.** The size guard and the
  scanner used to share one number, so a single-line file of exactly that length
  passed the guard and then produced nothing to scan — a credential in it was
  accepted silently. The patterns now run over the whole (bounded) byte slice,
  and the boundary itself rejects.

### Per-harness incompatibility: `[unsupported]`

Discovery's rules are mechanical, and some incompatibility is not. Daniel's
`phone-home-coordinator` is a well-formed skill that names no scheduler and no
service manager — it is simply bound to the always-on Clawniel session and the
palantir bus, which an ordinary harness does not have. That is a judgement about
what the skill IS, and a classifier guessing at it would be wrong in both
directions.

So the profile states it and Homeplane enforces it:

```toml
[unsupported.phone-home-coordinator]
reason    = "Bound to the always-on Clawniel session: …"
harnesses = ["claude-code", "codex"]   # omit ⇒ every harness
```

A marking **beats every assignment**: a skill named in both `[defaults]` and
`[unsupported]` is refused, with the marking's own reason surfaced. A marking
without a `reason` is refused at load time, because R15's requirement is a
marking WITH a reason and an unexplained skip is what it exists to prevent.

`initiative-signal` deserves its own note. The spec's boundary is that Homeplane
distributes access and instructions and never initiative, so a skill whose text
reaches for the host's scheduler or service manager is held back rather than
handed to an ordinary harness. The classifier fires on a **mention**, not on
proven intent, which means it over-marks: in Daniel's vault it holds back
`ticktick`, whose matched line is the words "no cron". That is the safe
direction of error and it is not silent — the finding quotes the exact line, so
a false positive is one glance to see and the operator can move the skill or
reword it. A classifier that tried to infer intent would fail the other way.

The initiative rule is also why the skills path schedules nothing itself:
`skills refresh` is a command the operator runs. Nothing here registers a cron
job, a launchd agent or a systemd unit.

## 4. Commands

```
homeplane-agent skills list       [-json]            what the vault holds, and what the profile assigns
homeplane-agent skills provision  [-verify] [-json]  link the assigned skills into each harness
homeplane-agent skills refresh    [-verify] [-json]  re-scan, re-link, and withdraw links the profile dropped
```

`provision` is idempotent and never removes anything. `refresh` additionally
withdraws links Homeplane owns that the profile no longer assigns or whose vault
skill has gone — and only those. Broader dangling-link repair is deferred per
the spec's Boundaries.

`-verify` spawns each harness and requires it to enumerate what was linked. A
link the harness does not report is a failure, because the link is our claim and
the enumeration is the proof. `status` reports the skills component from the
ownership manifest (the machine's state, not the last run's) and reads
**degraded** when the last verification failed.

### Ownership

Ownership is recorded at `~/.homeplane/skills/skill-links.json` (0600). It lives
in Homeplane's state and not in the harness's skills directory, because that
directory is enumerated by the harness and a bookkeeping file there would be a
file the harness has to be trusted to ignore.

Being in the manifest is **not** ownership on its own. An entry is Homeplane's
only while it is still the symlink the manifest records — same path, same
target. If the operator repoints one of our links at their own copy, it is
theirs: `provision` will not take it back and `refresh` will not delete it, both
report the drift instead. A vault MOVE stays distinguishable, because there the
link still points at the recorded target and is repointed normally.

Two orderings protect that record:

- The whole run holds the **agent state lock** (the same one the harness
  configurator takes), because the manifest is a read-modify-write. Without it,
  two concurrent runs each save a manifest missing the other's links, and those
  links become entries nothing can withdraw.
- The manifest's writability is proven **before** the first link is created, and
  every mutation is recorded before the next is attempted. Saving once at the
  end meant any later failure left links on disk that nothing claimed.
