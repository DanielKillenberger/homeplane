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
- `.flow/memory` SQLite-trap entries from .2 (pooled-PRAGMA, RFC3339Nano ordering, WAL sidecar perms) — this task extends the same store with audit rows and should not rediscover them <!-- Updated by plan-sync: fn-1.2 recorded SQLite pitfalls downstream store-touching tasks should read first -->

## Acceptance
- [ ] Stub connector registered via manifest entry only; second fake connector (incl. fake OAuth provider params) needs zero code changes outside the manifest (R12)
- [ ] Capability enforcement: read-only grant invoking a write-class tool → authorization error; matching grant → allowed
- [ ] Unmapped-tool invocation denied + audited as policy violation; incomplete registration refused
- [ ] Audit rows: manifest-derived action class, extractor artifact id vs args-digest+`unknown`, metadata-only, actor model correct (all unit-tested in-process)
- [ ] `go test ./...` green
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)

## Done summary
Built the declarative connector core in `internal/server/connectors`: a strict connector-manifest schema and loader (unknown JSON fields refused, https-only driver endpoints, secret references never literals, bounded identifiers, complete registration enforced where the gateway tool inventory is declared), a pure policy engine that decides every tool call from the manifest plus the grant's issued capabilities — with a tool's required capability derived from its action class so a manifest edit cannot weaken authority — declarative JSONPath-style artifact-id extraction (full 64-bit numeric precision) with a one-way args-digest fallback used only while the artifact is unknown, and an in-process broker that records the decision before forwarding, refuses any call it cannot audit, and writes the post-call result row on a cancellation-detached, time-bounded context. Unmapped and explicitly excluded tools fail closed as audited policy violations, and caller-supplied provider/tool names are sanitized so a denial is always recordable. Proven against an in-process stub tool runtime and the real SQLite audit log, including the D18 scope policy (Drive read-only, Calendar read/write/delete), audit-failure injection on both denial and admission paths, and R12 — a second fake connector with its own fake OAuth provider registering from a manifest entry alone. Five impl-review findings (2 P1, 3 P2) were fixed with regression tests.
## Evidence
- Commits: d0e9db54a67533df1002de64dd157a91921334be, 5b77df11060091d78a142807135289103f81ef6d, 0bde55b158b9deaa105dcc0497bd9ea05acb6d0f, 167222358494d526060a157c8bbb3e2beac535a3
- Tests: go build ./..., go vet ./..., gofmt -l . (clean), go test ./... -count=1 (all packages ok; 174 assertions, 40 tests in internal/server/connectors), go test ./internal/server/connectors/ -count=1 -race (ok), scripts/emit-evidence.sh fn-1-homeplane-walking-skeleton-install.3 -> test/evidence/fn-1-homeplane-walking-skeleton-install.3.json (pass, 174/174 assertions, 3 gates, clean worktree at 0bde55b1)
- PRs: