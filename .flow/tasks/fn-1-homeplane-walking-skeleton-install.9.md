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
Built `internal/agent/skills`, the layer that publishes Daniel's vault-authored skills to his harnesses by LINKING rather than copying, plus `homeplane-agent skills list/provision/refresh` and the D14/D15 decision record.

**D14, established against the real CLIs rather than from docs (`claude 2.1.227`, `codex-cli 0.146.0`): both harnesses are native-link, and no adapter was needed or built.** Claude Code enumerates `$CLAUDE_CONFIG_DIR/skills` (else `~/.claude/skills`) and names a skill after the LINK DIRECTORY; Codex enumerates `$CODEX_HOME/skills` (else `~/.codex/skills`) and names it after the SKILL.md frontmatter — found by linking one skill under a deliberately different directory name and reading both answers back. So Homeplane links under the vault slug and refuses a skill whose two names disagree, because an identity it cannot keep consistent across harnesses is not one it should publish. Both follow symlinks into the vault: Codex says so out loud (its locator for a linked skill is the vault path), Claude Code's side is proven by device+inode identity. **No harness config file is touched at all** — skills are directory-discovered, so R5's merge machinery is not in this path.

**Fresh-process discovery, with no model turn.** Claude Code's `system`/`init` stream-json event carries the `skills` array it found; `codex debug prompt-input` renders a `<skills_instructions>` block with resolved file locators. The probe is honest about what it is not: it starts the harness as configured, so Claude Code runs the operator's hooks — which is how the `hook_started` prelude ahead of the init event was found, against Daniel's real machine and nowhere else. The flags that suppress hooks also suppress the personal skills directory (verified), so a hook-free probe would prove nothing.

**D15 profile:** vault-resident TOML (`<vault>/skills/homeplane.skills.toml`, schema 1), machine+harness → skill set, most-specific-wins with REPLACE so a rule can subtract. The reference copy in `configs/skills/` is parsed by a test, so the documented format cannot drift from the implemented one.

**What is never linked.** A skill carrying credential material or runtime state is rejected; one whose text drives host scheduling or service control is marked unsupported with the matched line quoted. Every non-linkable verdict carries a reason and evidence — nothing is silently skipped. The classifier reads every file in the skill, not just SKILL.md, so a benign-looking skill whose bundled script installs a cron job is caught.

**The real run:** all three profile skills (`professional-writing`, `casual-writing`, `karpathy-guidelines`) linked from the real vault into Daniel's real `~/.claude/skills` and `~/.codex/skills`, enumerated by a fresh process of each real CLI, with every pre-existing entry byte-identical afterwards and the vault never written. Recorded in `test/evidence/…9.live.json` (8 assertions).

**Two review rounds (codex, gpt-5.6-sol @ xhigh): 7 findings, then SHIP.** The one worth remembering: ownership was keyed on the manifest record alone, so a link the OPERATOR had repointed was still treated as ours — provision took it back and refresh deleted it. Ownership is now the record AND the link still pointing where the record says; the "vault moved" case stays distinguishable for free, because there the link still points at the recorded old target. The manifest is also now proven writable before the first link, saved after every mutation, and written under the agent state lock, so no run can leave a link that nothing claims.
## Evidence
- Commits: 52d4ed0844ec9fe222ce5ac3dba524445607d897, 665c151e38371c34fbfc9e578fd48b4d4c02364a, 40a797ced1afcbd0f47ae1a3f1b92a28337ad097, a7399522783212b5d265a10af1323cbabe56ce1d, 93d5703934ddeb3648d5606f67dc2e2bf8fa6e5f
- Tests: go build ./... && go test ./... (847/847 assertions, 21 packages green), go vet ./..., scripts/emit-evidence.sh fn-1-homeplane-walking-skeleton-install.9, homeplane-agent skills provision -verify against the REAL ~/.claude/skills and ~/.codex/skills (recorded in test/evidence/fn-1-homeplane-walking-skeleton-install.9.live.json, 8 live assertions), flowctl codex impl-review (gpt-5.6-sol @ xhigh): round 1 NEEDS_WORK 7 findings, round 2 SHIP, 0 open
- PRs: