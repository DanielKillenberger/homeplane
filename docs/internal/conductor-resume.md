# Conductor resume note — written 2026-08-14 before session restart

Cold-start: `.flow/bin/flowctl brief`, then read this.

## State
- Spec fn-1-homeplane-walking-skeleton-install: 12/14 done (.1 .2 .3 .4 .5 .6 .8 .9 .11 .12 .15 .16). Plan review: SHIP. All decisions D1–D18 resolved (see spec Decision Context).
- **.7 (e2e proof): in_progress** — a worker was running the live proof when the session restarted; it was asked to park (commit WIP + write `.flow/tmp/t7-resume.md`). If that file exists, resume a fresh opus worker from it. If NOT, diagnose from ground truth: `git log`/`git status` on branch fn-1-homeplane-walking-skeleton-install, `/tmp/hp-t7-*` handovers, `homeplane-agent status`, `ssh clawniel systemctl --user status homeplane-server`, `thv list` (local + clawniel).
- .14 (docs + evidence gate): todo, deps .7.

## Working agreements (carry forward)
- Workers: opus-5 subagents (flow-next:worker), single-worker in main checkout for .7/.14; reviews = `flowctl codex impl-review <task> --base <task base> --receipt /tmp/impl-review-receipt-tN.json` (gpt-5.6-sol @ xhigh via config).
- Flat-trajectory ESCALATE from review-rounds = known false positive; `flowctl review-rounds reset <spec> --kind impl --task <id>` has standing Daniel authorization (run it in the same directory the review runs).
- Parallel waves used worktrees under ~/Projects/.homeplane-worktrees (all cleaned up); .7/.14 run in main checkout.
- Merge trap: `git add -A` after a conflicted merge silently commits conflict markers — always check `git status | grep ^UU` after every merge.
- Review runs write flowctl state in the CWD's .flow — run conductor reviews from the main checkout for .7/.14.

## .7 interactive legs (Daniel present required)
1. `add-credentials google` against clawniel — browser consent (3 ratified scopes: drive.readonly, calendar.events, calendar.readonly).
2. Obsidian sync activation on real vault: DECISION PENDING — Daniel quits Obsidian.app (headless takes over, full R14 leg) vs detect-only + disposable-vault headless proof. Snapshot + destructive-diff guard mandatory before any real-vault sync write.
3. Skills profile vault-residency: `cp configs/skills/homeplane.skills.toml ~/Documents/daniel-os/skills/` (may already be done).
4. Inherited acceptance items in .7's task file: guarded-Calendar live proof incl. DENIAL leg (from .12); Codex authenticated-call half (from .6).

## Infrastructure facts
- Server LIVE on clawniel: tsnet node `homeplane` (100.68.162.126 / homeplane.tailab4e9b.ts.net), state /home/claw/homeplane/var, systemd --user, rootless podman; google/client-id + google/client-secret imported; deploy/server/README.md = runbook. Tailscale auth key at clawniel:~/.homeplane/authkey (90-day; consumed on first join). Daniel should disable key expiry for the node in the TS admin console (may not be done yet).
- Google OAuth desktop client JSON: ~/.homeplane-spike/google-oauth-client.json (0600) on this Mac.
- Local live-t12 store/workload: torn down (Daniel may still need `rm -rf ~/.homeplane-live-t12` if not done).
- caffeinate -ims running (system awake, display allowed to sleep).

## After .7 ships
- .14: docs (README/ARCHITECTURE/RUNBOOK) + evidence gate (sources enumerated in its task file; REJECT missing/commit-mismatched artifacts).
- Then: 3g completion review (`/flow-next:spec-completion-review` via codex), Phase 4 gates, Phase 5 ship summary (Tracker sync: n/a — bridge inactive). Do NOT close the spec unless Daniel asks; offer PR (`/flow-next:make-pr`).
- HTML plan artifact: https://claude.ai/code/artifact/b49e68f6-35bc-45a5-b3dd-6dd61b866aca (update after ship; scratchpad copy may be stale after restart — regenerate from repo state if needed).
