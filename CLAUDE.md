<!-- BEGIN FLOW-NEXT -->
<!-- flow-next:snippet:v1 -->
## Flow-Next

This project uses Flow-Next for ALL task tracking. `flowctl` comes from the flow-next plugin install — every flow-next skill resolves it itself, and on Claude Code it is also on PATH. Do NOT create markdown TODOs or use TodoWrite. Cold session: `flowctl brief` first — one bounded call (specs, ready tasks, memory); go deeper with `show`/`cat`/`anchor <task-id>`.

- Lifecycle: `flowctl list` / `show fn-N.M` / `start fn-N.M` / `done fn-N.M --summary-file s.md --evidence-json e.json` (e.json: `{"commits": ["<sha>"], "tests": ["<cmd>"], "prs": []}`)
- BEFORE any other flowctl operation, or when unsure of a flag: run `flowctl usage` (CLI cheatsheet + orchestration recipes) or `flowctl --help`.
- BEFORE bridging work to another model/CLI (`codex exec`, `cursor-agent`, `claude -p`, `grok`) or picking an implementation/review model: run `flowctl usage` and follow "Orchestration & model steering" exactly.
- Creating a spec: write it directly — `/flow-next:plan` is task breakdown only. `flowctl spec create --title "Short title" --plan-file plan.md --json`, then `/flow-next:plan <spec-id>`. Scaffold cascade (first match wins): `SPEC.md` -> `spec.md` -> bundled template.
- If `flowctl` is not found: your shell lacks the plugin's `scripts/` dir on PATH (only Claude Code injects it). Resolve it the way the skills do - the plugin install's `scripts/flowctl` (Claude/Droid: plugin-root env var; Codex: `${CODEX_HOME:-$HOME/.codex}/scripts/flowctl`; Cursor/Grok: two levels above any flow-next SKILL.md) - or update/reinstall the flow-next plugin. A repo with no `.flow/` yet: run `/flow-next:setup`.
<!-- END FLOW-NEXT -->

<!-- flow-next:model-routing:start -->
## Picking models for flow-next workflows and subagents

_Scaffolded by `/flow-next:setup` — edit freely; re-run setup to regenerate. These scores are starting opinions (as of Jul 2026): re-rank them to what you actually pay for and prefer. This section is yours now._

**Project routing (explicit user pins for Homeplane):** fable-5 (session model) plans and authors specs; composer-2.5 implements via the grok CLI bridge; gpt-5.6-sol reviews plans AND implementations via the codex bridge (`review.backend codex:gpt-5.6-sol:xhigh`). These pins override the generic defaults below.

Rankings, higher = better. **cost** = how lightly it rides your subscription quota (higher = run it freely; lower = it burns the plan's budget fast, so spend it sparingly), NOT list $/token, and each provider is a separate budget; **speed** = output speed at *default* reasoning effort (raising effort trades speed for intelligence); **intelligence** = how hard a problem you can hand it unsupervised; **taste** = UI/UX, code quality, API design, copy.

| model         | cost | speed | intelligence | taste |
|---------------|------|-------|--------------|-------|
| opus-5 @ med  | 5    | 4     | 9            | 9     |
| fable-5       | 2    | 2     | 10           | 9     |
| opus-4.8      | 4    | 3     | 7            | 8     |
| gpt-5.6-sol   | 8    | 5     | 9            | 6     |
| gpt-5.6-terra | 9    | 7     | 7            | 5     |
| grok-4.5      | 9    | 9     | 7            | 5     |
| composer-2.5  | 9    | 10    | 6            | 6     |
| sonnet-5      | 5    | 6     | 7            | 7     |
| haiku-4.5     | 8    | 9     | 4            | 4     |

How to apply — defaults, not limits. Unless prompted otherwise, route work across these models as you judge best — no permission needed; an explicit user instruction always overrides this table. Standing permission to escalate: if a cheaper model misses the bar, rerun on a smarter one without asking. Judge the output, not the price tag.
- For anything that ships, intelligence > taste > cost; cost is a tie-breaker only.
- Orchestration, planning, review verdicts, anything ambiguous → the session model (whichever row you are running as the conductor). Never delegate judgment.
- Anything user-facing (UI, copy, API design) needs taste ≥ 7 → keep on the session model even if it looks mechanical.
- Reviews prefer a different family than the writer — uncorrelated blind spots.
- Graceful degrade: a routed CLI that is missing, unauthenticated, or errors → report it unavailable and fall back to the session model. Never block.

This project's pipeline: fable-5 (session) authors specs — capture, interview, plan — then composer-2.5 implements via the grok CLI bridge, then gpt-5.6-sol reviews plans and implementations via `review.backend codex:gpt-5.6-sol:xhigh` (cross-family vs both the planner and the implementer).

flow-next wiring — roles with a MENU, not fixed pairings: pick per task. Claude tiers run natively (spawn subagents with the model parameter); other families ride the headless bridges — recipes: run `flowctl usage` § Orchestration & model steering (copy-mode repos also have it on disk at `flowctl usage`). Probe-marked lines are live only if their CLI is installed:
- Implementation, native: a worker/subagent on opus-5 (quality) or sonnet-5 (speed) via the model parameter.
Implementation via gpt-5.6-terra @ medium (the packaged delegate default): `/flow-next:work <id> delegate:codex` (consent-gated, host keeps git/review) or a direct `codex exec` bridge. Eval-matched gpt-5.6-sol correctness at ~2/3 wall-clock on strong specs; escalate work.delegateModel to gpt-5.6-sol for gnarly tasks.
<!-- not detected on this machine — install cursor-agent, then uncomment: Implementation via composer-2.5: the `cursor-agent` bridge (`--force` to apply); host reviews + commits. -->
Implementation via the grok CLI (THIS PROJECT'S IMPLEMENTATION LANE, pinned to composer-2.5): flags BEFORE -p: `grok --always-approve -m composer-2.5 --reasoning-effort high -p "<task>"` - blanket approval, trusted repos only; acceptEdits skips Bash and silently truncates shell-using tasks; recipe in `flowctl usage`; host reviews + commits on a taste-heavier tier. Route it to bulk/implementation, NOT UI or final taste-critical work.
Review, cross-family (THIS PROJECT'S REVIEW LANE): `review.backend codex:gpt-5.6-sol:xhigh`; per-task `review:` pins exceptions; escalate reviewer↔worker disagreements to the session model.
<!-- not detected on this machine — install cursor-agent, then uncomment: Review, cross-family via cursor (multi-family reach): `review.backend cursor:claude-opus-5-thinking-high` (Claude-family default; `cursor:claude-fable-5-thinking-high` only when you explicitly want the Fable gate — NO ZDR) or `cursor:gpt-5.6-sol-high` (GPT-family) — pick the family that did NOT write the diff. Ids are volatile → `cursor-agent --list-models`. Composer/grok tiers are quick extra voices, never the gate. -->
- Review, same-family heavy: a fresh-context reviewer subagent on opus-5 (or the session model) with the review criteria — no registry rung needed; describe the arrangement.
<!-- not detected on this machine — install cursor-agent, then uncomment: Bulk, low-judgment reads (codebase sweeps): scouts may shell out to `cursor-agent`; only the digest returns. -->
- Bulk reads, native: haiku-4.5 / sonnet-5 subagents for scans and digests.
- Autonomous loops: never call a bridge CLI raw - wrap it in a thin fast-tier subagent that runs the bridge in the FOREGROUND and self-heals environment failures only (bridges fail silently outside trusted git dirs), never judgment; recipes via `flowctl usage` § Orchestration & model steering.
Reach gpt-5.6-terra inside a subagent (thin-wrapper) for cheap bulk reads/digests only — not implementation: a cheap wrapper writes a self-contained prompt, runs `codex exec` over Bash, returns the digest.
<!-- flow-next:model-routing:end -->
