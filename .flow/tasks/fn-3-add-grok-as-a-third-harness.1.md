# fn-3-add-grok-as-a-third-harness.1 grok contract capture + surface probe (resolves D1/D2/D3)

## Description
Contract capture + probe of the real grok CLI on this machine — resolves D1 (skills discovery convention), D2 (config write mechanism), D3 (token custody shape), and the leader-process question BEFORE any writer code exists. Pattern: `scripts/capture-gno-contract.sh` + `internal/agent/gno/contract_test.go` (pin real behavior in testdata; never invent a CLI surface).

**Size:** M
**Files:** `scripts/capture-grok-contract.sh`, `internal/agent/harness/testdata/grok-<version>-contract.txt`, `docs/decisions/fn3-grok-surfaces.md`, (probe scratch only otherwise)

### Approach
- Capture `grok --version` and `--help` for `mcp` + every subcommand (`list/add/remove/enable/disable/doctor`) into redacted testdata (strip $HOME, tmp paths).
- Probe with disposable entries in an isolated-as-possible grok home (find the GROK_HOME-equivalent env var if one exists; otherwise snapshot+restore the real ~/.grok around probes): where MCP entries persist (config.toml vs separate store; `grok mcp list` authoritative), `add` idempotency (re-run: clobber/duplicate/error?), preservation of unrelated pre-seeded entries, enabled-vs-disabled default, non-interactive failure shape + need for timeouts, what `doctor` reports for a broken entry.
- Token custody: does any env-var indirection exist for headers? Confirm the argv exposure of `-H "Authorization: Bearer …"` and ratify the write path that keeps tokens out of argv (D3 hard constraint).
- Skills: link a disposable skill into ~/.grok/skills (directory-name and frontmatter-name variants, symlinked), verify discovery from a fresh process; probe whether a resident leader (leader.sock) serves stale config and how to force a fresh process.
- Never-launched state: what exists before first launch; does `grok mcp list` work pre-init?
- Record every ratified answer in `docs/decisions/fn3-grok-surfaces.md` (the D14-style decision doc for grok) — .2's writer implements exactly what this ratifies.

### Acceptance
- [ ] Capture script + committed redacted contract testdata for the installed grok version
- [ ] All five priority questions answered with observed evidence (mechanism, idempotency/preservation, skills convention, never-launched, leader/fresh-process), recorded in the decision doc
- [ ] D1/D2/D3 marked resolved in the spec's Decision context (values, not placeholders)
- [ ] Real ~/.grok left byte-identical to pre-probe state (snapshot-verified)

## Acceptance
- [ ] TBD

## Done summary
Probed the real installed grok 1.0.3 and pinned its CLI surface plus its actual
write behaviour in committed testdata (`scripts/capture-grok-contract.sh` →
`internal/agent/harness/testdata/grok-1.0.3-contract.txt`, byte-reproducible
across runs), resolving fn-3's D1/D2/D3, ratifying D4, and correcting the
spec's leader premise — so task .2 implements against observed behaviour rather
than an invented surface.

Ratified: **D1** native-link, symlinks followed, the frontmatter `name` winning
over the directory name (grok sits with Codex, so `RuleNameMismatch` applies
unchanged); **D2** direct byte-span TOML edit of `~/.grok/config.toml`, with the
`grok mcp *` CLI verbs disqualified on three observed grounds — they drop every
comment in the file, reset 0600 to 0644, and put the token in argv; **D3**
inline bearer in a 0600 config with no env indirection, matching the Codex
precedent fn-1 already tested in `codex_token_test.go`; **D4** (Daniel's call)
`[compat.claude] mcps = false`, accepting that grok stops inheriting `rize` and
other Claude-configured servers. The spec's leader premise was wrong — no
`leader.sock` exists and config is read fresh per invocation — so the
fresh-process contract is `--leader-socket <nonexistent>`, which defeats a
resident leader by construction rather than by coincidence.

Surfaced under the R12 gate: grok's default `[compat.claude] mcps = true`
already loads `~/.claude.json`, so before any fn-3 work grok could reach the
Homeplane edge under Claude Code's token and grant identity — which blocked R5
and corrupted R3's audit identity. D4 resolves it; **D4b (Cursor) is left open
for Daniel**, since disabling Claude promotes Cursor to the next inheriting
source and today's exclusivity holds only because `~/.cursor/mcp.json` is empty.

The capture script is an evidence producer, so it fails closed: every probe
asserts an exact exit status, timeouts are refused, each ratified conclusion is
asserted before its heading is emitted, and the environment, working directory
and grok home are all sealed. Thirteen tests drive it against stub groks —
including a positive run, because a script that refused everything would pass
every negative test while producing no evidence.

Ratified limitation: the task's "real `~/.grok` left byte-identical" criterion
is **not** satisfiable while Daniel's live sessions run, and stopping his work
to make a checkbox true was declined. Recorded honestly —
`whole_grok_home_byte_identical: false` — with what was proven instead:
non-interference (`config.toml`, `skills/`, `hooks/` byte-identical) and
attribution (the one changed file shown not ours by re-running the isolated
probes). His sessions were never disturbed and no probe artifact was left behind.

stage: impl-review - ran [23:07..01:27], SHIP on round 10 (0 introduced findings)
stage: delegation - skipped(config: delegation off)
## Evidence
- Commits: 9b47d09fb0eacbf0c611a9121be6a91855846d15, 58e1faf31281fbad24e45e90a8f1a700f94b4475, 1f5a1b62b119a7b6cd02813109cfd0206079e0fa, 743c09776eeafdf94729e10429c8390e952b443b, 6f5e7ff236c647a6c4828d348a2b4f70232c5fbe, 2c2378c79730cbe8ca35cbbca115e31605cadf6b, 27f436ce045814199dbe09a7a5722ca079512551, 64afca8e82750a3d5eeb8c4406dd572b13a898b9, b4ea97e3db919dd81c19e4c89b6f874d883d50f0, 801cddeda64731f9063bd2e78445df0d19a81423, 32b063422c1c4eab18d8bcaaa2391238aaaf3ece, 7f6570104a932815697c7d446120ebb34712c6ea, bd19d7d064acec67c5cdf77df3db06655449821f, dc4747290a4f9a116a634c4647ee16aaa218b1bf, f75767c7fac21b3b99ed74ceaa8dc99722f73d14, 6a7f43c4e1b42ed5b58d5d3a5a5acfa84f437f09, a434c5ccc59e8259c380c850352a81c404371321, 6642156d5e721169ca934d374d65a00687769d9e, 6b65b805be8027c2811c26e852e862f3bb701fe8, 9616e84adc9abecf247e72539f1d12e5c05c147f, 0a9f70e23376270ed1eff1952421e31903913de9, 10d784df50b61b9808b717249643b9ab6e1d5c70
- Tests: go build ./..., go vet ./..., go test ./..., shellcheck scripts/capture-grok-contract.sh, scripts/capture-grok-contract.sh (byte-reproducible across consecutive runs), go test ./internal/agent/harness/ -run Capture (13 capture-script tests: 12 negative + 1 positive), scripts/emit-evidence.sh fn-3-add-grok-as-a-third-harness.1 --extra <probe.json> (927/927 assertions, 3 gates)
- PRs: