---
satisfies: []
---
# fn-1-homeplane-walking-skeleton-install.1 D6 spike: validate ToolHive as bare-server Tailnet MCP gateway (go/no-go)

## Description
Time-boxed spike resolving D6/D3/D10 before anything depends on them. Deploy ToolHive in CLI (non-k8s) mode on a Linux host (server or local sim) and validate it against Homeplane's requirements. Produce a written decision record, not production code.

**Size:** M
**Files:** `docs/decisions/d6-gateway.md` (decision record), scratch code under `spike/` (disposable)

## Go/no-go criteria (each PASS/FAIL with evidence)
1. Remote exposure — FULL PATH: client → Homeplane edge (thin prototype is enough) → gateway → tool, over streamable HTTP from another machine, speaking an MCP revision current Claude Code and Codex CLI clients accept (verify actual client compatibility, not spec text — note the 2026-07-28 RC transport/auth changes). Whatever shape is adopted must demonstrably admit the Homeplane edge invariants in front of it (WhoIs machine binding, manifest authorization, unmapped-tool denial, authoritative audit) — a runtime that cannot be fronted this way FAILS regardless of its other merits.
2. Per-client auth: two distinct bearer tokens/clients for the same underlying MCP server; revoking one takes effect within seconds while the other keeps working (R9). Check Cedar authz + JWT middleware, RFC 7591 dynamic client registration, RFC 8693 token exchange.
3. Audit: per-request logs attributable to the calling client identity? If not natively, confirm the D13 thin-proxy-in-front shape is viable.
4. Secrets: secret store usable headless on a Linux server (OS keyring without desktop session — document workaround or fallback for D3).
5. Google connectors — EXACT OPERATIONS **(re-adjudicated by Daniel, 2026-08-13, spec D18: Drive is READ-ONLY by scope policy; Calendar carries read+write; the six-op reversible proof targets an isolated Calendar test event)**: evidence that the adopted runtime's tool surface supports (a) Drive READ under `drive.readonly`, (b) the Calendar six-op — create, read back, update, verification read, delete, cleanup verification — under `calendar.events`, with artifact IDs present in results (needed for artifact-id extraction), and (c) a Drive write attempt being refused (fail-closed, doubling as the D18 policy proof). Live proof of the six operations against real Google is required for the spike leg (direct API calls on the credential-holding server are acceptable evidence, with the through-the-adopted-stack rerun owned by .12 as part of R8); the provider credential must remain server-resident throughout (custody rule). Plus the OAuth token provisioning path (informs D10; the Homeplane-owned client + add-credentials consent remain .8/.12's obligation).

## Fallback ladder — SAME GATES APPLY (review fix)
If ToolHive-direct fails: (b) ToolHive as connector runtime + Homeplane thin auth/audit proxy (D13), then (c) MCPJungle. **Whichever shape is adopted — including a fallback — must itself PASS criteria 1–5 with recorded evidence before adoption.** Adoption with rationale alone is insufficient; an unvalidated fallback is a FAIL, and the terminal outcome is NEEDS_HUMAN with findings. Building a bespoke MCP gateway remains forbidden (STRATEGY.md).

## Investigation targets
**Required:**
- `.flow/specs/fn-1-homeplane-walking-skeleton-install.md` — R7/R8/R9/R12/R13 + D3/D6/D10/D13
- https://docs.stacklok.com/toolhive/ — CLI mode, run-mcp-servers, auth framework, token exchange, authz policy reference
**Optional:**
- https://github.com/mcpjungle/MCPJungle
- https://modelcontextprotocol.io/specification/draft/basic/authorization

## Key context
- Research flags ToolHive's remote multi-client gateway (vMCP) as Kubernetes-Operator-first; the CLI path is described as testing/evaluation. Do not assume, demonstrate.
- Codex MCP client: `~/.codex/config.toml` `[mcp_servers.X]` with `url` + bearer token config; OAuth path buggy — static bearer preferred. Claude Code: `claude mcp add --transport http --header "Authorization: Bearer …"`.

## Acceptance
- [ ] Decision record `docs/decisions/d6-gateway.md` with PASS/FAIL per criterion + evidence (commands, outputs) for the ADOPTED shape (fallbacks re-run all five gates)
- [ ] Explicit adopted shape: ToolHive-direct, ToolHive+thin-proxy (D13), or MCPJungle — with gate evidence, not rationale alone
- [ ] D3 (credential store) and D10 (OAuth broker mechanics incl. redirect shape) resolved to one concrete design in the record
- [ ] Spec Decision Context updated (D3/D6/D10 marked resolved with outcome)

## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
