---
satisfies: [R5]
---
# fn-4-complete-the-google-workspace-connector.2 Generated capabilities skill

## Description
The generated capabilities skill: machine-local inventory rendered from server-fetched manifest + live grant state.

**Size:** M
**Files:** `internal/agent/skills/` (generator + provisioner integration), `internal/agent/` (regen hooks in configure/add-credentials/status-reconcile paths), `configs/skills/homeplane-capabilities/SKILL.md` (static prose keeps hand-authored content + pointer), the NEW authenticated manifest-projection endpoint (explicit ratified scope per revised R5 — server handler + route + tests; non-secret content only), tests

### Approach
- Per D3: generated inventory is a separate machine-local skill owned by Homeplane under the agent state dir, linked by the existing provisioner (ownership = record + live target); the vault SKILL.md is NEVER written through (it is a symlink into the synced vault).
- Canonicalized rendering (defined ordering, no map nondeterminism) — byte-stable when inputs unchanged, tested.
- Regen triggers: configure, add-credentials, revocation reconcile; serialized under the existing state lock; generation failure keeps last-good + marks staleness, never breaks provisioning (tested).
- Content derives ONLY from manifest data + grant state — no credentials, no runtime secrets, no payload.
### Acceptance
- [ ] Generated skill renders from real manifest+grant inputs; byte-stable idempotency test; staleness fallback test
- [ ] Regen fires on all three triggers (tested); concurrent regen serialized
- [ ] Vault file untouched by generation (test asserts no write through the symlink); provisioner links the generated skill in all harnesses' dirs
- [ ] go build/vet/test green; evidence JSON emitted


## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
