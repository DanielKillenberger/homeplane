<!-- scope: business -->

## Goal & context

Complete the Google Workspace connector surface so every enrolled harness reaches Daniel's mail, documents, spreadsheets, and contacts through the same guarded plane that already serves Drive and Calendar — and make the capabilities skill machine-generated so it stays truthful as the tool surface grows.

The pinned workspace-mcp workload (1.24.0, uvx via ToolHive, tool families gated by its `--tools` flag) already implements Gmail/Docs/Sheets/Contacts tools; Homeplane's manifest doesn't map them, so the fail-closed engine denies them. fn-4 is manifest authoring + scope ratification + generated skill + live proof. The connector-agnostic architecture (fn-1 R12, re-falsification-tested in fn-3) means enrolment, grants, custody, audit, and revocation change not at all; no new workload, credential driver, or edge change (fn-5's gaps).

**Base + deploy-order constraint (spec-scout):** fn-4 branches off `fn-3-add-grok-as-a-third-harness` (NOT master) — clawniel's deployed binary carries grok's compiled-in policy row; a master-based redeploy would strip it and break parked fn-3's resume with `403 unknown harness`. fn-4 rebases/merges after fn-3 lands. The manifest is deployed DATA (`deploy/server/manifest.json`, replaced at deploy); the policy table is BINARY — task .1 verifies whether anything fn-4 adds needs a binary redeploy and what an unrecognized manifest construct does at load (expect fail-closed refuse-to-load; prove it).

Capability model (Daniel-ratified, 2026-08-15 — REVISED after plan-review round 1): **platform capability and grant policy are separate questions.** The manifest maps Gmail's write surface with honest action classes so writes are technically expressible and enforceable; WHO may exercise them is per-harness grant policy — the Calendar precedent exactly (write-granted harnesses may update any event; send maps to `connector.send`, which no current grant holds, so it is refused live: platform supports, policy withholds).
- **Gmail reads**: read-class, granted to current harnesses like Drive reads.
- **Gmail writes MAPPED with honest classes**: draft creation and label mutations as write-class; trash as delete-class; untrash/unmark as write-class — all requiring the corresponding `connector.*` capability a grant may or may not hold. No provenance guard is needed or promised: write authority means write authority, exactly as Calendar's update works today; per-harness withholding is a policy-table decision (parked as a follow-up — today's uniform capability sets stay).
- **Send-class withheld by POLICY, mapped by PLATFORM**: send/reply/forward (and any tool the capture shows dispatches mail) map to `connector.send` — which no current grant holds — so live calls are refused `capability_missing`, the same proven mechanism as Calendar's notification guard. Scope-exceeds-policy asymmetry recorded D18-style.
- **Spam/sensitive-label tools**: mapped or excluded per what the capture shows they do; anything unclassifiable is excluded with a cited reason (fail-closed), never guessed.
- **Docs, Sheets, Contacts: read-only in fn-4.** Workspace writes collide with D18 (creating a doc IS a Drive write) — deferred with a named revisit trigger; revisiting D18 is its own decision, not smuggled here.
- **Capabilities skill becomes generated** (see R5/D3).

Guardrails verbatim from fn-1/fn-3: complete-registration rule (every advertised tool mapped or excluded with a reason, else the connector refuses to load); fail-closed extractors (identifier-shape validated, args-digest fallback, never fabricated); audit metadata never payload — message/thread/draft/label IDs only, never subjects, bodies, or ATTACHMENT content; audit committed with its mutation; proofs produce their failure modes; mint-authority-last (all local validation before the irreversible credential replacement); verification queries current state.

## Acceptance criteria

- **R1:** The Google manifest (both copies, plus a new automated equality test between them) maps the COMPLETE advertised Gmail tool inventory with honest action classes: reads as read-class; draft creation and label/untrash ops as write-class; trash as delete-class; send-capable tools (send, and reply/forward per captured semantics) mapped to `connector.send` — refused live for every current grant (`capability_missing`), the platform-supports/policy-withholds pattern Calendar's notification guard proved; tools the capture shows to be unclassifiable excluded with cited reasons. Response-side artifact-id extractors from CAPTURED shapes only (id-format vs the identifier-shape rule; empty-result/multi-id per captured contract; args-digest fallback, never fabricated). Error cases: an unmapped-tool live call refused as policy violation; a send-class live call refused as capability_missing; connector load with a deliberately-incomplete manifest refused (complete-registration).
- **R2:** Docs, Sheets, Contacts read tools mapped read-only with extractors; their write tools excluded; one live read per family returns real content, audited with a real artifact ID; a provider-side failure (API not enabled, quota) is reported distinctly from a policy refusal.
- **R3:** The OAuth scope set is ratified by Daniel in task .1 Phase B — after schema capture forms the candidate, BEFORE any empirical mutation capture or live leg (minimal set serving R1/R2; scope-exceeds-policy recorded in the decision doc) — then applied via `add-credentials google -replace` — the existing CAS/atomic-replacement semantics asserted in the proof: the prior credential stays live until commit, consent abandonment leaves it intact, concurrent replacement detected; transient scope-propagation 403s after re-consent distinguished from policy denials (bounded retry with the distinction recorded).
- **R4:** A reversible Gmail WRITE proof from at least one live harness, its exact op-path RESOLVED BY .1's capture against what the pinned workload can actually do (upstream lacks draft get/update/delete — known; candidate path: create draft → locate it via search/read tools → label op on the created message → trash it for cleanup, since drafts are messages; if no fully-clean path exists, the closest reversible path is ratified with the residue recorded as a limitation, never papered over). Proof discipline — not an engine guarantee — restricts ops to the proof's own artifacts, exactly like the Calendar six-op. Every step audited with correct class and real artifact IDs; no mail sent; plus both denial legs (send-class capability_missing, unmapped-tool policy violation) actually produced.
- **R5:** A new authenticated, non-secret capability-manifest projection endpoint on the server (explicit binary scope — this is deliberate new server surface for the skill, NOT an R12 violation, and it means .3 deploys server AND agent binaries with version verification, manifest-first order preserved) feeds the generated skill: a machine-local generated skill (OUTSIDE the Obsidian-synced vault; the vault skill keeps the hand-authored prose and points to it) rendered from the server-fetched manifest + this machine's live grant state; regenerated on configure, add-credentials, and revocation reconcile; canonicalized rendering (byte-stable when inputs unchanged — defined ordering, no map-iteration nondeterminism); generation failure never breaks provisioning (last-good kept, staleness marked); concurrent regen serialized under the existing state lock; provisioned/linked into harnesses by the existing provisioner (ownership = record + live target); truthfulness proven live: content changes when a manifest entry is added AND when a grant is revoked, and a fresh harness process discovers it.
- **R6:** Versioned evidence + an fn-4 gate per the fn-3 pattern (commit-ancestor checks, artifact-identity rejection of "unknown", RATIFIED_LIMITATIONS table, demonstrated tamper rejection); a regression leg re-runs the fn-1 Drive read + guarded Calendar op unchanged; machine and server healthy; docs updated (ARCHITECTURE/RUNBOOK connector surface, a d-fn4 scope decision doc modeled on d18).

## Boundaries

- No new workload, credential driver, or edge routing change; no version bump of workspace-mcp (1.24.0 stays pinned — the write-proof path adapts to its real surface per R4). Engine delta expected: NONE for connector mapping (no new classes/capabilities; no provenance guard — deliberately not built); ONE new server endpoint (manifest projection, R5) as explicit scope. Anything beyond these is a surfaced R12 finding.
- No mail sending in any form (send-class refused by policy for every current grant); no Docs/Sheets/Contacts writes; Drive stays read-only. Proof legs touch only their own artifacts (discipline, as always). Per-harness DIFFERENTIATION of google write capability (which harness holds connector.write) is parked as its own policy follow-up — today's uniform sets stay.
- Oura, Rize, TickTick → fn-5/fn-6. grok's parked fn-3 legs untouched; fn-4 proofs run from claude-code and/or codex.
- The generated skill covers the capability inventory only; not a template engine. Pagination beyond first-page reads: deferred (proof legs are single-artifact/single-page; recorded).
- Contacts "other contacts" (auto-collected) inclusion: whatever the captured contract's read tool returns; no special-casing.

## Strategy Alignment

Active tracks served by this plan:
- **Server capability plane** — this is the track's core roadmap item: Google Workspace beyond Drive/Calendar reaching every harness with credentials in exactly one place.
- **Operations & trust** — send-class authority stays separately granted; audit metadata boundary extended to mail (the most payload-sensitive connector yet).
- **Local capability bootstrap** — the generated capabilities skill keeps every harness's instructions truthful as capability grows.

## Decision context

- **D1 (fn-4) — Gmail scope set: OPEN, resolved with Daniel before live legs.** Planning candidate from capture: the minimal set that makes the mapped read+draft+label tools function (workspace-mcp's own scope requirements per tool are part of the .1 capture); scope-exceeds-policy asymmetry recorded. Interactive consent moment via -replace is a live-leg step like fn-1's.
- **D2 (fn-4) — workspace-mcp contract: resolved by task .1.** tools/list against the live gateway with the expanded `--tools` set (that flag change is deploy data, part of .1's deliverable), captured response shapes for every mapped tool (prose-vs-JSON is tool-specific — Calendar answers in prose, Drive doesn't; never assume), reply/forward draft-vs-send semantics, id formats, empty-result shapes. Pinned version stays 1.24.0; a version bump is out of scope.
- **D3 (fn-4) — generated skill residency: resolved direction.** The vault SKILL.md is a symlinked vault file — generation must NOT write through it into the synced vault. The generated inventory is a separate machine-local skill owned by Homeplane (it is machine-generated, not vault-authored, so the "vault skills never copied" rule doesn't apply to it), living under the agent's state dir and linked by the provisioner; the vault skill's static prose references it. Exact naming/link mechanics per D14's rules resolved in .2.
- **D4 (fn-4) — manifest-vs-binary deploy:** .1 verifies that fn-4's additions are manifest-data-only (no new action class/capability) and proves the load behavior for an unrecognized construct (expect refuse-to-load). Deploy order: server manifest first, then proofs — from the fn-3-based branch so grok's policy row survives.
- Model routing per project pins. Live legs on this machine against clawniel; Daniel present for the consent moment.

## Requirement coverage

| Req | Description | Task(s) |
|-----|-------------|---------|
| R1  | complete Gmail mapping + extractors + exclusions + denial/load proofs | .1 (capture+manifest), .3 (live legs) |
| R2  | Docs/Sheets/Contacts read-only mapping + live reads | .1, .3 |
| R3  | scope ratification + -replace semantics asserted | .1 Phase B (D1 with Daniel), .3 (served legs) |
| R4  | reversible draft proof + both denial legs | .3 |
| R5  | generated capabilities skill + truthfulness proof | .2 (build), .3 (live truth legs) |
| R6  | gate + regression + docs | .3 |

Execution: .1 → .2 → .3 (sequential; .2 consumes .1's manifest shape; .3 needs both).
