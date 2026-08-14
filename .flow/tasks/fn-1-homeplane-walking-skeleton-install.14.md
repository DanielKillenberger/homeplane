# fn-1-homeplane-walking-skeleton-install.14 Operator docs + final acceptance gate

## Description
Operator documentation written against observed behavior, plus the final small acceptance gate. Evidence sources are enumerated per R-ID: R6–R10 come from .7's machine-readable evidence file; R1–R5 and R12–R15 come from their owning tasks' versioned evidence artifacts at `test/evidence/<task-id>.json` (commit SHA, platform, commands, assertions, timestamps — every owning task's acceptance requires emitting one), re-validated green at the final commit; .14 REJECTS missing or commit-mismatched artifacts; R12's design-review row points at a recorded passing review artifact.

**Size:** S
**Files:** `README.md` (install → enrol → verify), `docs/ARCHITECTURE.md` (two-plane model, grant model + threat-model honesty, composed-gateway boundary, skills layer, D16 seam, deferred-hardening list), `docs/RUNBOOK.md` (status/healthz reading, degraded states + retries, revocation, add-credentials re-run incl. Testing-mode token expiry, log + backup locations)

### Approach
- Docs from observed behavior (the .7 evidence file + live runs), never aspirational.
- Final gate: every current R-ID (R1–R10, R12–R15) closed by PASSING recorded evidence from its enumerated source above, current against the shipped commit. Deferred-hardening items live in the spec's Boundaries and are NOT gate obligations. Missing/failed evidence → gate fails, spec stays open. Emit the completion summary into the spec directory.

### Investigation targets
**Required:**
- Evidence file from .7 + owning tasks' test suites; spec Requirement coverage table
- `docs/decisions/d6-gateway.md` "Consequences / follow-ups" + gate 1 client-compat notes (from .1) — known runbook nuances: under `codex exec`'s default read-only sandbox, MCP tool calls are auto-cancelled (interactive sessions or a permissive approval policy are required); Codex static bearer config via `bearer_token_env_var` (0.146.0); Claude Code HTTP MCP via `claude mcp add --transport http --header "Authorization: Bearer …"` (2.1.227) <!-- Updated by plan-sync: fn-1.1 spike recorded these client-compat nuances for the runbook -->
- Evidence-chain caveats to reconcile before closing the gate: (1) .12's guarded-Calendar-mutation live leg was deferred (Daniel-authorized 2026-08-14) and is inherited as an acceptance item on .7 — R7's final-gate evidence for that sub-item comes from .7's evidence file, not .12's `test/evidence/...12.live.json`; (2) .12's evidence recorded a KNOWN FLAKE (`internal/server/credflow TestARelayedFlowIsNotExpiredByTheConsentWindow`, a race under full test parallelism) that .12 did not fix — .15 fixed the exact race in commit `49f36b91877fccd68b056af9889184806d17107f`, so re-validating `go test ./...` at the final commit should no longer reproduce it; treat a recurrence as a regression, not a known issue; (3) .15's Google client-id/secret import was itself deferred to .12 (Daniel-authorized) — verify `deploy/server/verify.sh` reports `provider_secret_refs_present` passing (not `pending`) at the final commit before treating .15's deploy criterion as fully closed <!-- Updated by plan-sync: fn-1.12/.15 evidence-chain caveats (deferred sub-items across .15→.12→.7, and a flake fixed downstream of the task that recorded it) -->

## Acceptance
- [ ] README + ARCHITECTURE + RUNBOOK accurate to observed behavior (spot-checked against live system)
- [ ] Final gate report: every executable R-ID (R1–R15, minus deferred items in Boundaries) mapped to passing evidence; design-review rows point at recorded passing artifacts; any failure blocks the gate
- [ ] `go build ./... && go test ./...` green


## Done summary
Wrote the operator documentation from observed behaviour — README as an
install → enrol → verify entry point, `docs/ARCHITECTURE.md` (two-plane model,
grant model with its same-OS-user threat-model honesty, composed-gateway bypass
boundary, connector manifest, skills layer, D16 seam, deferred-hardening list),
and `docs/RUNBOOK.md` (status vs /healthz, every degraded state and its retry,
revocation, add-credentials re-run incl. Google Testing-mode token expiry,
log/state/backup locations, hand-wiring recipes, and the `codex exec`
read-only-sandbox MCP cancellation) — then built and ran the spec's final
acceptance gate.

**Gate: PASS, 14/14 executable requirements** (R1–R10, R12–R15) at
`6251edb`, with `go build`/`go vet`/`go test ./... -count=1` all green and
`deploy/server/verify.sh` passing 11/11 with zero pending. Completion summary at
`.flow/specs/fn-1-homeplane-walking-skeleton-install.completion.md`;
machine-readable result in `test/evidence/fn-1-homeplane-walking-skeleton-install.14.json`
under `extra`.

`scripts/final-gate.py` verifies rather than restates: each artifact must exist,
name a commit that is an ancestor of the gate head, record a clean worktree,
pass with zero failed assertions, and contain the named stages and tests. A
`partial` live stage is not waved through — every false assertion must match a
`RATIFIED_LIMITATIONS` entry by exact claim text, so a new limitation in a
re-recorded artifact fails. R12's design-review row is resolved against tracker
state (task, kind, verdict, head SHA, artifact hash, ancestry) and the decision
document's existence. The negative suite (eleven tamper cases) was run and every
one fails as required.

The three evidence-chain caveats were reconciled against the live system:
`.12`'s deferred guarded-Calendar leg is closed by `.7`'s calendar stage for both
harnesses; the credflow race `.15` fixed did not recur under `-race -count=20`;
`provider_secret_refs_present` passes, so `.15`'s deploy criterion is fully
closed. The two non-`ok` components on Daniel's Mac (`sync: not_configured`,
`gno: degraded`) are ratified arrangements, recorded in the spec's Boundaries.

Open for Daniel, documented not resolved: the D8 gno 1.29.6 daemon-vs-stdio
index-lock exclusivity (`docs/decisions/d8-gno.md` §8, `docs/RUNBOOK.md` §7),
with both candidate resolutions and their costs.

Review: codex (gpt-5.6-sol @ xhigh), 2 rounds — round 1 NEEDS_WORK with 6
findings (3 P1 gate-strength, 2 P1 doc-correctness, 1 P2 each), all fixed with
the negative suite as the regression proof; round 2 SHIP with zero findings.

stage: impl-review - ran [round 1 NEEDS_WORK (6 findings) .. round 2 SHIP (0 findings)], backend codex/gpt-5.6-sol @ xhigh, receipt /tmp/impl-review-receipt-t14.json
stage: delegation - skipped(config: delegation off)
## Evidence
- Commits: 00912b3315923ccf69d3f34cd2d0bcf54271b8c6, 4f10b1272ed1420c5a194fc3cd9bf3710767c2ab, 0b315b943c186d20d49eef33f2dad168d403d306, e431d06dff109690073ee491019dd80188c6d0c0, 6251edb2c1468bd5a2fb92d0803a5a54b6b145a4, 6854b15eadad5beff9c9a0d123d8dc298fada07a
- Tests: go build ./..., go vet ./..., go test ./... -count=1 (21 packages ok, 0 failures), go test ./internal/server/credflow/ -run TestARelayedFlowIsNotExpiredByTheConsentWindow -count=20 -race (the .12 flake did not recur), python3 scripts/final-gate.py --gate build=0 --gate vet=0 --gate test=0 --deploy-verify <json> -> pass, 14/14 requirements, deploy/server/verify.sh --host clawniel --fqdn homeplane.tailab4e9b.ts.net -> pass, 11/11 checks, 0 pending, scripts/emit-evidence.sh fn-1-homeplane-walking-skeleton-install.14 -> 876/876 assertions, clean worktree at 6251edb, negative suite against the gate: missing artifact, non-ancestor commit, dirty worktree, failed assertion, absent named test, absent named stage, unratified false assertion, tampered review receipt, missing decision doc, pending deployment check, empty gate list -> all fail as required
- PRs: