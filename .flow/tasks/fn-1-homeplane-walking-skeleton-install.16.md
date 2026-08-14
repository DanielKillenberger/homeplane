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
Built the network half of the connector plane in `internal/server/edge`: a streamable-HTTP MCP edge that terminates harness connections over the tailnet, authenticates the `Authorization: Bearer <grant token>` against the store on EVERY request (no cache, so a revoked grant stops working on the next call), binds each call to the WhoIs-observed tailnet node — a token replayed from another node is refused 403 and audited against the OBSERVED node with the bound machine as metadata and a token fingerprint, never attributed to the machine that owns it — and routes every `tools/call` through the task .3 manifest engine, which decides and records it before the admitted call is forwarded to the composed gateway over streamable HTTP with the Homeplane token stripped. Every other MCP frame (initialize, `tools/list`, the SSE stream, session teardown) is forwarded verbatim: MCP semantics stay with the gateway (D6's adopted shape), and the edge only does auth, binding, policy and audit. `cmd/homeplane-server serve` composes both planes behind the one tsnet listener, wiring the edge only when both `-connector-manifest` and a LOOPBACK `-gateway-mcp-url` are given.

Refusals are structural rather than conventional: a non-loopback gateway URL is refused at construction (the isolation guarantee is that the only route to the gateway from another node runs through the edge); a connector claiming a reserved provider marker is refused; a JSON-RPC batch is refused rather than forwarded, because its `tools/call` would slip past the single-frame parse unauthorized; and a call or refusal that cannot be recorded is refused (503) rather than answered quietly. A tool name that belongs to no declared connector is denied as `unknown_provider` with provider `unrouted`, a bare name claimed by two connectors is denied as `ambiguous` while its `provider__tool` form still routes, and an excluded tool routes to its own connector so the row reads `excluded_tool`.

Deployment mistakes are caught at startup, not on the machines: the edge's mount path is normalized and refused if it is non-literal, root, or would shadow `/enrol`, `/grants` or `/healthz`; `-connector-endpoint-url` is required whenever the edge is wired and its path must match the mount path (a path-less URL is completed from it), so no grant can be issued carrying an `endpoint_url` the edge does not answer.

Two bugs were found by asserting behaviour rather than by review: `httputil` path joining sent forwarded frames to the gateway's `/mcp/mcp` (the outbound URL is now the gateway endpoint exactly), and the batch bypass above.

Five codex impl-review findings (2 P1, 3 P2) were fixed with tests that fail against the old behaviour: the listener's 30s ReadTimeout is kept when the edge is wired (only the write deadline is lifted for SSE — a slow-drip body no longer pins a goroutine, proven against a real listener), the endpoint-URL/mount-path agreement above, a bounded gateway transport (dial, TLS handshake, response headers; the body stays unbounded so established SSE streams survive a silent gateway being cut off at 502), the mount-path validation above, and the router no longer refuses a manifest whose connectors share a bare tool name — refusing it would have made ordinary multi-connector compositions unrunnable (R12).

Test boundary (stated, as task .4 did): the edge is exercised against the REAL store, the REAL policy/audit engine and a real loopback streamable-HTTP gateway stub, with a stand-in WhoIs resolver naming the two tailnet nodes — so every rule built on observed identity is proven here, but the live tailnet leg (tsnet dialling, real WhoIs, a genuinely remote node) is not, and remains the residual obligation recorded by the .1 spike for .16/.15. The bypass boundary is covered in the always-runnable half: the gateway's port is unreachable on this host's routable IPv4 while the edge, bound to that same routable address, serves the identical call; the cross-node half is the spike's live evidence (`docs/decisions/d6-gateway.md`, gate 1). Client compatibility (Claude Code, Codex CLI) against protocol 2025-06-18 is likewise spike evidence, not re-proven here.
## Evidence
- Commits: dc862d84cd1d8d079b34cb44e2c5bb57f2bc3dc1, 5050e7bccdd52cfdbaff20ab352c465c30dd3b4c, 7b4fc8e3a4e8f93b22ed8ae69eb69c84e1e6681d, 8443b775f61f1123f6e91fb5c0ffcb25cef64a6c
- Tests: go build ./... (exit 0), go vet ./... (exit 0), go test ./... -count=1 (exit 0; 254 assertions, 0 failures), go test ./internal/server/edge/ ./cmd/homeplane-server/ -count=1 -race (exit 0), scripts/emit-evidence.sh fn-1-homeplane-walking-skeleton-install.16 -> test/evidence/fn-1-homeplane-walking-skeleton-install.16.json (pass, 254/254, 3 gates, commit 7b4fc8e3)
- PRs: