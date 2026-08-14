---
satisfies: [R3, R5, R6]
---
# fn-3-add-grok-as-a-third-harness.3 Live e2e proof, evidence + gate, docs delta

## Description
Live end-to-end proof on this machine against clawniel, evidence + fn-3 acceptance gate, and the documentation delta. Extends fn-1's e2e stages (test/e2e/run.sh) — no parallel runner.

**Size:** M
**Files:** `test/e2e/` (grok stage extensions), `scripts/fn3-gate.py` (or extend pattern), `test/evidence/fn-3-*.json`, `README.md`, `docs/ARCHITECTURE.md`, `docs/RUNBOOK.md`, `docs/decisions/d14-skills-linking.md` (addendum)

### Approach
- Extend harnesses/skills/revocation/truth-table stages to cover grok; add grok halves of gno-retrieval and connector/calendar stages. Fresh-process discipline per .1's leader findings (the proof must defeat a stale resident process).
- R3: real Drive read + guarded manage_event (`send_updates:"none"`) from grok, audited under grok's grant with real artifact IDs; reversible, nothing left behind.
- R5: revoke grok → produce the actual denied call while claude-code and codex succeed; inverse direction; restore; audited. Produce failures, never assert on shape alone (memory: a-proof-must-produce-the-failure-mode).
- R4 vault edit: add the grok assignment to the ACTIVE vault profile (`~/Documents/daniel-os/skills/homeplane.skills.toml`) as an explicit evidenced step — existing assignments preserved byte-for-byte; the live skills stage must prove the grok key is READ (not passing via defaults). ROLLOUT GATE first: verify every machine consuming the synced profile runs a grok-aware agent, against the server's enrolled-machine list (today exactly this machine), and record that check in evidence; if it cannot be verified, defer the literal key (defaults apply) and record the deferral.
- R4 discovery proof runs the product path (`skills provision -verify`), not a bespoke probe.
- R6: fn-3 evidence file + gate per fn-1 pattern (commit-matched, ratified-limitations table, artifact identities non-"unknown", demonstrated tamper rejection — memory: an-acceptance-gate-that-accepts-partial).
- Docs delta per docs-gap-scout: README:79,135; ARCHITECTURE diagram + §Harness configuration (~308) + deferred-hardening "more than two harnesses" reframe (~358-368) + skills matrix grok row; RUNBOOK examples (48,50), §6 (421-434) + a "### grok CLI (<version>)" recipe + skills dirs (500-516); d14 addendum with grok's probed row. fn-1's gate/e2e "both harnesses" wording stays as historical record.

### Acceptance
- [ ] All six R-IDs closed by recorded live evidence at the shipped commit (incl. the active-vault grok assignment being read, not defaulted); fn-3 gate passes and demonstrably rejects tampered evidence
- [ ] Revocation asymmetry proven in BOTH directions with produced failures; grants restored
- [ ] Docs updated per the enumerated list; no stale "two harnesses" claim outside historical records
- [ ] `go build ./... && go vet ./... && go test ./...` green; machine left working (all three harnesses live)

## Acceptance
- [ ] TBD

## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
