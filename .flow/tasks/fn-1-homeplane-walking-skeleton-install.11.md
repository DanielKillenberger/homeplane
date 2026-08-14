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
Supervised the GNO retrieval engine with a disposable index and a published endpoint descriptor, then closed the review findings: the descriptor is published last, and installation is now transactional across re-activation — each destination is snapshotted (bytes + permissions) before being overwritten and restored on failure, so a failed upgrade can no longer destroy a working installation. Supervision units are written atomically. Regression test forces a re-activation failure and asserts every original artifact is byte-for-byte intact with the descriptor still valid.
## Evidence
- Commits: 6abc0868b73237bad3d7aa78ce2f16815464b703, 1822b90fe069cc4a4c1bd9bc5d9b5df0915e1f66, 2a2bcce7a50886ec40dd52eadc3f9a8ee68b4d26, 6c8a103feb5fbe34df40ca5ef6126f04dfedcc93, 2532da10ddcf7925a7863704a0e7e7d7fb3901f2
- Tests: go build ./..., go vet ./..., go test ./... (all packages ok), go test -race ./internal/agent/gno/ ./internal/agent/supervise/, baseline: red (gofmt -l flags internal/store/model.go, pre-existing from ab21a29, untouched by this task)
- PRs: