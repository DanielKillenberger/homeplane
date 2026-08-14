---
satisfies: [R5, R6, R7]
---
# fn-1-homeplane-walking-skeleton-install.6 Harness configuration writer (Claude Code + Codex, merge-only)

## Description
Detect installed harnesses (Claude Code, Codex per D1) and configure each with (a) local GNO MCP using the **endpoint descriptor produced by .11** (stdio vs daemon transport per D8 — never assumed) and (b) the server connector MCP endpoint using that harness's own grant token via the **single-phase superseding grant lifecycle** — structure-aware, merge-only writes.

**Size:** M
**Files:** `internal/agent/harness/` (detect, claude.go, codex.go, backup), `cmd/homeplane-agent/` (configure-harnesses subcommand wired into enrol flow)

## Approach
- **Grant flow:** request grant (capabilities come from server policy; supersedes any prior grant for the pair) → write harness config. The flow is idempotent: any failure → re-run requests a fresh grant and rewrites the config, converging to a consistent state. (Two-phase activation is deferred hardening per spec Boundaries.)
- Claude Code: USER scope (`~/.claude.json`) or local scope — NEVER project scope (git-shared `.mcp.json` would leak tokens, R5/R17). Server entry: HTTP + `Authorization: Bearer <token>` header; GNO entry per the .11 endpoint descriptor.
- Codex: `~/.codex/config.toml` `[mcp_servers.X]`. **Token propagation (review fix):** primary = inline bearer value in the user-only 0600 config.toml IF Codex's config reference supports it; verified fallback = a launcher shim that reads the 0600 token file and exports the env var named by `bearer_token_env_var` before exec'ing codex. Must pass a fresh-process-tree test (no inherited env). Static bearer only (Codex OAuth buggy).
- **Merge discipline (semantic preservation per amended R5):** parse (JSON/TOML), touch only Homeplane-managed entries, write back; verification = parse(after) minus managed entries deep-equals parse(before) minus managed entries; TOML span-scoped to the managed table where the library allows. Timestamped backup before every write. Malformed existing config → skip harness + message + backup intact.

## Investigation targets
**Required:**
- Endpoint descriptor from .11 (GNO transport) — .11 shipped it: descriptor published LAST after transactional install (artifactSnapshot rollback across re-activation), so .6 must read a fully-installed descriptor, never a partial one
- `internal/server/` grant API from .2 (superseding lifecycle); connector endpoint shape from .3, but the actual wire endpoint is served by .16's streamable-HTTP edge — `-connector-endpoint-url` must match the edge's mount path (`-connector-edge-path`) or grant issuance is refused, and calls must be qualified `provider__tool` through .16's router when a bare tool name is ambiguous across connectors; read .16's done summary before wiring the server MCP entry <!-- Updated by plan-sync: fn-1.16 built the actual edge (endpoint-URL/mount-path agreement, provider__tool qualification) that .3's original design only sketched -->
- Claude Code MCP config docs (scopes); Codex config reference (verify inline bearer support: https://developers.openai.com/codex/config-reference/)
**Optional:**
- Go TOML libraries with comment/format round-trip

## Acceptance
- [ ] Both harnesses configured with pre-existing unrelated MCP servers + settings; semantic-preservation check passes; backups created; repeated runs idempotent
- [ ] Config-write failure path: re-run converges to a working config + valid grant (induced write failure test)
- [ ] Each harness holds a DISTINCT grant token; tokens absent from git-shared files; token files 0600
- [ ] Codex token propagation passes fresh-process-tree test
- [ ] Malformed-config path: harness skipped, message clear, original untouched
- [ ] From each harness: local GNO call (per descriptor) and server stub-connector call succeed
- [ ] `go test ./...` green
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)

## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
