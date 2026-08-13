---
satisfies: [R7]
---
# fn-1-homeplane-walking-skeleton-install.16 Streamable-HTTP connector edge: gateway integration, machine binding, isolation

## Description
The network half of the connector plane (split from .3 per plan review): the streamable-HTTP MCP edge that fronts the composed gateway with the .3 policy/audit engine, over the tailnet.

**Size:** M
**Files:** `internal/server/edge/` (streamable-HTTP MCP proxy, auth middleware), `cmd/homeplane-server/` wiring

### Approach
- Edge terminates harness MCP connections (streamable HTTP + `Authorization: Bearer <grant_token>`), applies the .3 policy engine per tool call, forwards allowed calls to the composed gateway (per D6 adopted shape), writes audit rows via the .3 extraction.
- **Machine binding:** verifies the WhoIs-resolved source tailnet node matches the grant's machine — a valid token replayed from a different tailnet machine → rejected + audited as a violation with observed-identity attribution.
- **Bypass boundary:** the composed gateway's upstream listener binds loopback/isolated-namespace only; direct access from a second node must fail while edge access succeeds (tested).
- Revocation latency: revoked grant → auth error within seconds (no hang).
- MCP revision compatibility per the .1 spike evidence (Claude Code + Codex clients).

### Investigation targets
**Required:**
- `docs/decisions/d6-gateway.md` — adopted shape + client-compat evidence (from .1)
- `internal/server/connectors/` policy/audit engine (from .3); grant interfaces (from .2)
- `.flow/memory` SQLite-trap entries from .2 (pooled-PRAGMA, RFC3339Nano ordering, WAL sidecar perms) — the edge appends audit rows to the same store via the .3 extraction <!-- Updated by plan-sync: fn-1.2 recorded SQLite pitfalls downstream store-touching tasks should read first -->

## Acceptance
- [ ] MCP call with valid grant traverses client → edge → gateway → stub tool over streamable HTTP from another machine
- [ ] Revoked token → auth error within seconds; replayed token from second tailnet node → rejected + audited as violation
- [ ] Gateway upstream unreachable from a second node; edge reachable
- [ ] Every forwarded and rejected call produces the correct audit row (via .3 engine)
- [ ] `go test ./...` green
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)


## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
