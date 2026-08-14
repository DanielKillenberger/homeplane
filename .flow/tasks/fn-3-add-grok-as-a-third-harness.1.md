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
TBD

## Evidence
- Commits:
- Tests:
- PRs:
