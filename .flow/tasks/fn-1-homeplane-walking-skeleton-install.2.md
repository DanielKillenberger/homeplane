---
satisfies: [R2, R9, R10]
---
# fn-1-homeplane-walking-skeleton-install.2 Repo scaffold + homeplane-server control plane (enrol, grants, audit, health, admin CLI)

## Description
Greenfield Go scaffold and the control-plane core: tsnet-embedded server with enrolment, single-phase superseding grant lifecycle, append-only metadata audit, server-side health, and the server-local operator admin CLI. Connector traffic lands in .3 — this builds the substrate it plugs into.

**Size:** M
**Files:** `go.mod`, `cmd/homeplane-server/` (incl. `admin` subcommands), `internal/server/` (enrol, grants, audit, health handlers), `internal/store/` (SQLite via modernc.org/sqlite), `.gitignore`, `go test ./...` wiring

## Approach
- Single Go module, two binaries eventually (`cmd/homeplane-server`, `cmd/homeplane-agent` — agent lands in .4).
- tsnet listener; every request resolves caller via `LocalClient().WhoIs()` (D2/D12: auto-approve tailnet nodes; NO pending state).
- `POST /enrol`: auto-approve; **re-enrol = explicit rotation** (same machine record, new credential returned, old atomically invalidated) — never a duplicate identity, never a silent no-op (review fix: server stores only hashes so it cannot re-return the original secret).
- **Grant lifecycle:** `POST /grants` issues an active grant; capabilities are clamped/validated against a **server-side per-harness capability policy** (clients never self-select authority). A new grant for the same (machine, harness) supersedes and revokes the prior one — exactly one active grant per pair; the agent's configure flow is idempotent and converges on re-run. `DELETE /grants/{id}` idempotent, 404 unknown. `GET /grants`: non-secret metadata for the calling machine (id, harness, capabilities, state, revoked_at). (Two-phase activation and revocation tombstones are deferred hardening per spec Boundaries.)
- **Authorization invariants:** WhoIs node must match enrolled machine; machine credential must hash-match; grants creatable/activatable/revocable only by their own machine over HTTP (cross-machine → 403). Tailnet reachability alone is never authorization.
- **Operator surface:** server-local admin CLI — `homeplane-server admin audit [--since]`, `homeplane-server admin revoke-grant <id>`, `homeplane-server admin secret import <ref>` (bootstrap of provider app credentials from protected stdin or a validated 0600 file into the D3 store — never over the network API). Operator identity = local shell access on the server host. (Machine-level revocation and block/unblock are deferred hardening per spec Boundaries.) Operator identity = local shell access on the server host; no operator HTTP credential in the skeleton. Machines never read global audit.
- `GET /healthz`: **server components only** (store, gateway runtime, tsnet, credential store); machine state is the agent's job (review fix).
- AuditEvent: append-only; metadata only, never payload bodies (audit metadata discipline — former R16, folded per D17). Records enrolment + credential rotation + grant lifecycle now.
- Grant + machine credentials: random 256-bit, stored hashed.

## Investigation targets
**Required:**
- `docs/decisions/d6-gateway.md` — adopted gateway shape (from .1)
- `.flow/specs/fn-1-homeplane-walking-skeleton-install.md` — API Contracts + Edge Cases
- https://pkg.go.dev/tailscale.com/tsnet — tsnet server + WhoIs

## Acceptance
- [ ] `go build ./...` + `go test ./...` green; tests cover: enrol, re-enrol rotation (old credential rejected, no duplicate record), grant supersede rule, over-policy capability request clamped/rejected, revocation idempotence, 401/403/404 paths
- [ ] Cross-machine grant issuance/activation/revocation rejected with 403 (two simulated machine identities)
- [ ] `GET /grants` returns calling machine's grants only, non-secret fields
- [ ] Admin CLI: audit query + revoke work locally on the server host; not exposed over HTTP
- [ ] Audit schema splits observed (WhoIs machine) vs authenticated (harness, grant) identity; rejected-call rows carry token fingerprint + violation reason; rows are metadata-only, never payload bodies (schema tests)
- [ ] Audit rows carry attribution and no payload bodies (schema-level assertion)
- [ ] `/healthz` covers server components only; degraded → BOTH non-2xx AND named component-level degraded payload (`curl -sf` fails); tested for store-down, gateway-down, credential-store-down
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)

## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
