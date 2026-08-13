---
satisfies: [R4, R6]
---
# fn-1-homeplane-walking-skeleton-install.11 GNO install, supervision, disposable index + local MCP endpoint descriptor

## Description
Install/configure/launch/supervise GNO against the synced vault with a disposable per-machine index, exposed as a local MCP server, producing the endpoint descriptor .6 consumes. Split from vault/sync (.5) per plan review.

**FIRST STEP — resolve D8 with Daniel:** GNO's install source (repo/release), config surface for pointing at a vault, index location + rebuild command, and MCP exposure mode (stdio process vs long-running daemon with local socket/port). Record in spec (D8 → resolved) and emit the **endpoint descriptor** (transport, address/command) into agent state for .6. If GNO is stdio-per-client, supervision means health-checking an on-demand launch template instead of a daemon — decide per D8 and design supervision to match (review fix: the two lifecycles are materially different).

**Size:** M
**Files:** `internal/agent/gno/` (install, config, index location, supervise or launch-template), supervision templates (shared framework from .5)

### Approach
- D16 seam: the agent supervises "the retrieval engine" as a named component with its own config/health slot; harnesses reach it via the endpoint descriptor, not GNO-specific wiring. GNO is the only implementation — no plugin interface.
- Index: OUTSIDE the vault and outside any synced path (R14 contract from .5); disposable + rebuildable (`gno reindex` or equivalent); deleting the index and restarting must self-heal.
- Supervision (daemon mode): launchd LaunchAgent (KeepAlive; agent tracks restart counts — crash-loop >5 restarts/5min → degraded), systemd user unit (Restart=on-failure) + linger (framework from .5). Vault missing → GNO not started, degraded named (R4).

### Investigation targets
**Required:**
- D8 resolution (ask Daniel — see FIRST STEP)
- `internal/agent/vault/` + supervision framework (from .5)

## Acceptance
- [ ] D8 recorded resolved in spec; endpoint descriptor written to agent state (consumed by .6)
- [ ] GNO lifecycle per D8 mode (spec R4): daemon → survives kill, pid + restart count in status, crash-loop surfaced; stdio → launch-template probe results + per-launch failures in status (no persistent-pid claim)
- [ ] Index verifiably outside synced paths; delete-index → self-heals via rebuild
- [ ] Local MCP call returns real vault content (R6 groundwork)
- [ ] `go test ./...` green; supervision validated on both OSes
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)


## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
