---
satisfies: [R3, R4, R6]
---
# fn-4-complete-the-google-workspace-connector.3 Live proof, scope ratification, gate, docs

## Description
Live proof, scope ratification with Daniel, gate, docs.

**Size:** M
**Files:** `test/e2e/` (gmail/docs/sheets/contacts stages + skill-truth stages), `scripts/fn4-gate.py`, `test/evidence/fn-4-*.json`, `docs/ARCHITECTURE.md`, `docs/RUNBOOK.md`, `docs/decisions/fn4-google-surface.md` (ratification recorded)

### Approach
- Deploy order: manifest (+ --tools change) FIRST, then server binary (the new manifest-projection endpoint) and agent binary, all from this fn-3-based branch (grok's policy row must survive), version-verified, verify 11/11.
- Scope ratification + consent already happened in .1 (Phase B). Here: verify the replaced credential serves every live leg; distinguish scope-propagation 403s from policy denials (bounded retry, recorded).
- R4 write proof along the .1-ratified path (own-artifacts discipline; closest-reversible with recorded residue if the clean path doesn't exist) + both denial legs (send-class capability_missing produced live, unmapped-tool policy violation produced live); R2 one live read per family with provider-error distinction; R5 truthfulness legs (manifest-add changes content; revocation changes content; fresh-process discovery); R6 regression leg (fn-1 Drive read + guarded Calendar op unchanged).
- fn-4 gate per fn-3 pattern; docs delta; evidence at the shipped commit.
### Acceptance
- [ ] All six R-IDs closed by recorded live evidence; gate passes + tamper rejection demonstrated
- [ ] No mail sent; nothing pre-existing touched; mailbox/calendar clean per the .1-ratified path — FULL cleanup when the captured surface supports it, otherwise ONLY the specifically ratified residue recorded in RATIFIED_LIMITATIONS with its identity and cleanup owner (the gate enforces exactly this conditional); machine + server healthy
- [ ] Scope ratification + asymmetry recorded in the decision doc; docs updated
- [ ] go build/vet/test green


## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
