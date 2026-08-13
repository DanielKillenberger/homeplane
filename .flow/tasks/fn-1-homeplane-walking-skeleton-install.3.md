---
satisfies: [R12]
---
# fn-1-homeplane-walking-skeleton-install.3 Manifest + policy/audit engine (in-process, stub-tested)

## Description
The declarative core of the connector plane, tested entirely in-process against a stub tool runtime — no network, no gateway (split per plan review; the streamable-HTTP edge + gateway integration is .16). This makes the policy/audit logic independently acceptable before any integration risk.

**Size:** M
**Files:** `internal/server/connectors/` (manifest schema + loader, policy engine, audit extraction), stub tool runtime in tests

## Approach
- **Manifest schema:** {provider, credential ref, credential-acquisition metadata (driver ref `oauth2-authcode` + declarative endpoints/scopes/client refs), MCP server/tools source, per-tool mapping → action class (read|write|send|delete) + required capability + optional artifact-id extractor (JSONPath-style)}.
- **Policy engine (pure functions over the manifest):** capability check per tool; **unmapped tools fail closed** — denied + policy-violation audit event, never forwarded; incomplete registration refused where the tool list is known.
- **Audit extraction:** action class from mapping; artifact id via extractor when declared, else args-digest (hash, never the args) + `unknown`; metadata only, never payload bodies; actor model per spec (machine|operator|system).
- Everything exercised against an in-process stub runtime with fake tools spanning read and write classes; a second fake connector — including a fake OAuth provider with its own driver parameters — registers via manifest entry only (R12 schema-level proof).

## Investigation targets
**Required:**
- `docs/decisions/d6-gateway.md` — adopted shape (from .1)
- `internal/server/` grant/audit interfaces (from .2)
- `.flow/specs/fn-1-homeplane-walking-skeleton-install.md` — R7/R12 + Architecture manifest section

## Acceptance
- [ ] Stub connector registered via manifest entry only; second fake connector (incl. fake OAuth provider params) needs zero code changes outside the manifest (R12)
- [ ] Capability enforcement: read-only grant invoking a write-class tool → authorization error; matching grant → allowed
- [ ] Unmapped-tool invocation denied + audited as policy violation; incomplete registration refused
- [ ] Audit rows: manifest-derived action class, extractor artifact id vs args-digest+`unknown`, metadata-only, actor model correct (all unit-tested in-process)
- [ ] `go test ./...` green
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)

## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
