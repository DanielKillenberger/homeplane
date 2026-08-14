---
satisfies: [R15]
---
# fn-1-homeplane-walking-skeleton-install.9 Vault skills provisioning: discovery, profiles, linking into both harnesses

## Description
The skills layer: discover Daniel-authored skills in the vault (canonical source), assign via a profile, link into Claude Code and Codex, verify discovery in fresh harness processes, refresh on change.

**FIRST STEPS — resolve D14 + D15 (recorded open in the spec):**
1. D14: per-harness linking matrix — Claude Code external skill/plugin dirs (symlink support), Codex's equivalent surface (AGENTS.md-referenced dirs / generated adapters). Produce capability matrix: native-link | adapter | unsupported.
2. D15: profile format — vault-resident mapping (machine/harness → skill set); pin with Daniel; skeleton needs ONE working profile.

**Size:** M
**Files:** `internal/agent/skills/` (discover, profile, link, adapters, verify, refresh), `cmd/homeplane-agent/` (skills subcommand: provision/refresh/list), `docs/decisions/d14-skills-linking.md`

## Approach
- Discovery: scan the vault's skills area (per D15 convention); validate shape; reject skills containing credentials or runtime state.
- Linking: native dirs/symlinks where supported; thin generated adapters otherwise — adapters reference vault files, never editable copies.
- **Baseline success bar (review fix — no unsupported loophole):** the skeleton profile must include at least one skill that IS portably provisioned and fresh-process-discovered in BOTH Claude Code and Codex. "Unsupported" marking is allowed only for genuinely harness-specific skills beyond that baseline — it cannot be the path by which this task passes.
- Preservation: same merge discipline as R5 for any harness config touched.
- Refresh: a manual `skills refresh` re-scan command exists; full dangling-link repair machinery is deferred per spec Boundaries.
- Verification: fresh harness process per harness confirms discovery (scripted).
- Initiative boundary: nothing here registers cron/hooks/automation in any harness — skills are instructions only.

## Investigation targets
**Required:**
- `internal/agent/harness/` config writer + backup plumbing (from .6)
- Vault layout + skills area (with Daniel / D15)
- Claude Code skills/plugin external-directory docs; Codex instruction-surface docs (D14)
- GNO's own agent-skill installer (`gno mcp install --target claude-code|codex|…`; docs at https://gno.sh/docs/skills) — .11 delivered GNO with this native install path; check whether it covers part of D14's per-harness linking matrix before building a fully custom adapter for skills that pass through GNO <!-- Updated by plan-sync: fn-1.11 confirmed GNO ships native per-client skill/MCP installers relevant to D14 -->

## Acceptance
- [ ] D14 matrix + D15 profile format recorded; spec updated (D14/D15 → resolved)
- [ ] ≥1 real profile skill provisioned AND fresh-process-discovered in BOTH harnesses (hard requirement); canonical files remain only in the vault (inode/symlink or adapter inspection)
- [ ] Genuinely harness-specific skill correctly marked unsupported with reason (beyond the baseline, not instead of it)
- [ ] Skill containing a fake credential rejected with clear message
- [ ] Unrelated harness config semantically preserved
- [ ] `go test ./...` green
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)

## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
