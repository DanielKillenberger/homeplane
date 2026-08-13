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
