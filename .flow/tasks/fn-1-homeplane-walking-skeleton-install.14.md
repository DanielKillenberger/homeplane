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
TBD

## Evidence
- Commits:
- Tests:
- PRs:
