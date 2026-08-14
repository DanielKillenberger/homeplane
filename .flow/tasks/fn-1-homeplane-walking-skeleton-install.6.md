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
  <!-- Amended during .6 implementation (impl-review round 2, 2026-08-14), scoped to what a
  harness CLI can actually be made to do without a model turn — NOT a weakening of R6/R7,
  which the spec's coverage table already assigns jointly to .11 · .6 · .7 and .16 · .12 · .6 · .7.
  Claude Code: FULLY proven in-suite — `claude mcp list` opens a real MCP session against both
  written entries, launching the stdio engine and authenticating to the connector stub with that
  harness's own grant token; a wrong token fails the test (negative control run).
  Codex: proven in-suite — config resolution, inline-bearer resolution under an EMPTY environment,
  the descriptor's exact command/argv, and a real outbound connection to the endpoint URL we wrote
  (`codex doctor` reachability). NOT provable in-suite — an AUTHENTICATED Codex tool call: codex-cli
  0.146 exposes no non-model MCP invocation (`mcp` only lists/gets/adds/removes; `doctor`'s probe
  deliberately carries no Authorization header, verified by the stub recording it arriving with
  none), so the only path is a `codex exec` model turn needing live credentials.
  INHERITED BY .7, whose live end-to-end proof drives real harnesses against the deployed server.
  Needs product-owner confirmation at .7 time; recorded here rather than left implied. -->
- [ ] `go test ./...` green
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)

## Done summary
Built `internal/agent/harness`, the merge-only MCP configuration writer that wires Claude Code and Codex (D1) to Homeplane's two capability surfaces: the locally supervised retrieval engine, copied verbatim from the endpoint descriptor task .11 publishes (the D16 seam — nothing branches on which engine is behind it), and task .16's connector edge, reached with a grant token minted per harness. Plus `homeplane-agent configure-harnesses`, wired into `main` and named by `enrol` as the next step.

**Merge discipline.** Codex is edited by BYTE SPAN: a scanner locates each `[mcp_servers.X]` table (tracking multi-line strings, comments, and array/inline-table depth so a nested `[1, 2]` is not mistaken for a header) and rewrites only those spans, leaving every comment, blank line, key order and inline-vs-sub-table choice literally unchanged. Claude Code is edited as an ordered JSON object, so untouched top-level values are written back byte-for-byte in their original positions and a compact file stays compact. Every write is then checked as the amended R5 equation states it — `parse(after) − managed == parse(before) − managed`, computed with a REAL parser for the format rather than the editing code being checked — BEFORE the file is touched, and again from disk afterwards, with a restore from the timestamped backup if the landed bytes disagree. A config that cannot be parsed causes that harness to be skipped with its original intact; a backup that cannot be taken makes it a failure, because the skip contract promises one.

**Ordering and containment** (both hardened by the review). Everything that can fail locally now happens before the grant request, which is an irreversible server-side supersession: the descriptor is validated and converted once before the loop, and `Preflight` parses the existing config, so a local problem never revokes a working harness. The whole run is held under the agent state lock, closing the "A issues, B issues, B writes, A writes" window. Writes are optimistic and re-merge against fresh bytes, because Claude Code and Codex rewrite their own configs while we work. A config path is judged by where it LANDS — symlinks resolved, and any git worktree above it refused unless `git check-ignore` says the file is ignored and untracked — so `CODEX_HOME` or a symlinked `~/.codex` cannot put a bearer token in a checkout; git absent or erroring means refuse.

**Codex token propagation needs no launcher shim.** The Codex config reference documents `mcp_servers.<id>.http_headers`, so the bearer lives inline in the 0600 `config.toml` with no environment anywhere — proven by running the real `codex` binary with an EMPTY environment and reading back `auth_status: bearer_token`.

**What the harness tests actually drive.** Real CLIs against stub endpoints. `claude mcp list` opens a genuine MCP session against both written entries — launching the stdio engine and authenticating to the connector stub with that harness's own token — and a wrong token fails it (verified by negative control). Codex is proven for config resolution, empty-environment bearer resolution, the descriptor's exact command/argv, and a real outbound connection to the URL we wrote (`codex doctor`); an AUTHENTICATED Codex tool call is not reachable without a model turn (codex-cli 0.146 has no non-model MCP invocation, and `doctor`'s probe carries no auth header — the stub records it arriving with none), so that half is recorded as inherited by task .7 in this task's acceptance criterion, matching the spec's own R6/R7 coverage rows. Daniel's real `~/.claude.json` and `~/.codex/config.toml` were never written to: every test runs against fixture copies with `HOME`, `CODEX_HOME` and `CLAUDE_CONFIG_DIR` pinned to temp dirs (`CLAUDE_CONFIG_DIR` is now honored — verified against the installed CLI, which reads the relocated file and ignores `~/.claude.json` when they differ).

Three codex impl-review rounds (gpt-5.6-sol @ xhigh): 9 findings, then 4, then SHIP. Two of the fixes were found by my own regression tests rather than by the reviewer — the `--no-index` flag that would have let a force-added tracked config through, and the comment-above-the-next-table that the first span scanner swallowed.
## Evidence
- Commits: 80ea8cd2fa43e05a3c815203ee18b3f4a51adc06, 2bf84ca752b5a6abfe1f707b623d1b2b52bcc37f, 6dc653792c730cf8a3ba3010bde424978d267bbd, df162293e8d7e9a0cf8cad2b83ae42fa6c331006, 6befac6aa8d9aea7cd430f30c5915394d7a09fa3, 93f392018fb0dbb0dc297d373c304445dd917c5d
- Tests: go build ./... && go test ./... (752/752 assertions, 20 packages green), go vet ./..., scripts/emit-evidence.sh fn-1-homeplane-walking-skeleton-install.6 -> test/evidence/fn-1-homeplane-walking-skeleton-install.6.json at df16229, flowctl codex impl-review --base da5f338 (gpt-5.6-sol xhigh): NEEDS_WORK(9) -> NEEDS_WORK(4) -> SHIP
- PRs: