# fn-1-homeplane-walking-skeleton-install.15 Server deployment: homeplane-server + gateway on the real Tailnet server

## Description
Productionize the server side on Daniel's real Tailnet server (round-4 review fix — the D6 spike deployment is disposable; nothing else installs/supervises the real server that .7 assumes). Infrastructure task; enables R7-R13 verification but owns no R-ID directly.

**Size:** M
**Files:** `deploy/server/` (install script or systemd units + config templates), `docs/decisions/` note if deployment shape deviates from the spike

### Approach
- Linux server artifact built by the same staged release-form process as the agent artifacts (.4).
- Persistent configuration + state location (`/var/lib/homeplane/` or similar): SQLite store, connector manifest, credential store per D3, tsnet state (auth key bootstrap documented). **Secret-store bootstrap (actual implementation, .2):** the D3 age-encrypted secret store requires `homeplane-server admin secret init-key` to be run once on a fresh state directory BEFORE `admin secret import` will succeed — `init-key` creates and 0600-protects the age key file that `import` encrypts against; back it up offline (without it, imported secrets are unrecoverable). <!-- Updated by plan-sync: fn-1.2 added `admin secret init-key` as a required deploy-time prerequisite to `admin secret import`, not present in the original spec text -->
- **Container runtime requirement (from .1 spike, docs/decisions/d6-gateway.md):** ToolHive CLI requires Docker or Podman to run connector workloads; the real production server (clawniel) has **Podman, not Docker** — the CLI+Docker runtime path was only validated headless in DinD during the spike, so confirm/adapt the ToolHive↔Podman integration on the actual host. <!-- Updated by plan-sync: fn-1.1 spike found production server runs podman not docker --> `thv run --enable-audit` on every workload for supplementary diagnostics.
- Supervision: systemd service units for homeplane-server AND the composed gateway (per D6 adopted shape), restart-on-failure, ordered startup (gateway before edge or health-gated).
- Gateway upstream bound loopback/isolated namespace only (bypass boundary — verified here on the real host and in .3's test).
- Upgrade path: re-run deploy with a newer artifact → config/state preserved, services restarted cleanly.
- Clean-server health check: fresh deploy → `/healthz` green over tailnet, admin CLI functional.

### Investigation targets
**Required:**
- `docs/decisions/d6-gateway.md` — adopted shape + its deployment requirements (from .1)
- `internal/server/` config surface (from .2/.3); staged artifacts (.4)

## Acceptance
- [ ] Fresh deploy on a clean Linux host: services supervised, `/healthz` green over tailnet, admin CLI works
- [ ] Gateway upstream unreachable from a second tailnet node; edge reachable
- [ ] Upgrade re-run preserves state + config; services restart cleanly
- [ ] tsnet bootstrap documented (auth key handling never in logs/argv)
- [ ] `admin secret init-key` run once on the fresh state dir before first import (age key created, 0600, backed up offline); Provider app credentials (Google OAuth client id/secret) imported via `admin secret import` from a 0600 file/stdin; verified present in the D3 store and absent from logs/argv/network API <!-- Updated by plan-sync: fn-1.2 used a separate `admin secret init-key` step not in the original spec text -->
  - **Google client id/secret import DEFERRED to fn-1.12 — authorized by Daniel, 2026-08-13 (asked during .15, answer: "defer").** The Homeplane-owned Google OAuth client must be created in Daniel's own Google Cloud Console session; nothing in this task can or should mint credentials inside his Google account, and reusing the co-resident Hermes OAuth client was explicitly rejected (ownership, revocation scope, blast radius). Everything else in this criterion IS met on clawniel: `init-key` run once and guarded against re-running, age key 0600 and backed up off-server with a verified sha256, and the import path exercised end to end against a throwaway ref (value from a 0600 file, never argv; ciphertext at rest; audit records ref + generation only). `deploy/server/verify.sh` reports the missing refs as `pending` with that reason and downgrades the run to `pass_with_pending` — it never passes. Completion command is in `deploy/server/README.md`.
- [ ] `go test ./...` green
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)


## Done summary
Deployed the Homeplane server and its composed ToolHive gateway onto the real Tailnet host (clawniel, rootless Podman) under systemd --user in a single polite-guest prefix, with `deploy/server/` carrying the whole path: a checksum-verified installer that acquires and validates every input before touching the running deployment, rendered unit templates, the connector manifest, a pinned ToolHive release, a runbook, and a verification script that runs from a second tailnet node. The server joins the tailnet as its own `homeplane` node; the gateway stays loopback-only and is unreachable from another node while the edge answers and fails closed without a grant token; re-deploys preserve the age key, database and node identity. The one acceptance item not met — importing the Google OAuth client id/secret — was deferred with Daniel's explicit authorization (creating that OAuth app is an action inside his own Google account); it is recorded on this task, inherited by fn-1.12, and reported by the verifier as `pending`, never as a pass.
## Evidence
- Commits: 871bd357c8f90a0849745c80a9f39287c15f2083, df1cd0adacb80a891d2428cf799b86dd439093b0, 724ad2a0e535079093232c73ab422bc5e6051059, 6ba1e43dbf3c0638d59ccb94f3496c93c13ce156, 85f54bfb746d0ed9ee6c43127cd7eebaf0373be6, 243955cd6fd4421c7d66f6ba20cfc78fbe46157a, 49f36b91877fccd68b056af9889184806d17107f, eec69e6b7bec4edf78681bfafc0e8e58a4c3fb61, 4d1c720b32f975e91039e97ea4f36cee2d24b63c
- Tests: go build ./... && go vet ./... && go test ./... -count=1 (538/538 assertions green), go test ./internal/server/credflow/ -count=40 -run TestARelayedFlowIsNotExpiredByTheConsentWindow, go test -race ./internal/server/credflow/ -count=5, scripts/emit-evidence.sh fn-1-homeplane-walking-skeleton-install.15 --extra <live-deployment run> (538/538, 3 gates, pass, clean tree), deploy/server/verify.sh --host clawniel --fqdn homeplane.tailab4e9b.ts.net (10 checks: 9 pass, 1 declared pending) run from this Mac as a second tailnet node, deploy/server/verify.sh --host clawniel --snapshot (before/after each re-deploy: age key, db inode, tsnet identity, stored secrets all preserved), deploy/server/deploy.sh --host clawniel (first install + 4 upgrade re-runs), ssh clawniel install-server.sh --stage-dir . with no staged server.env (installed-config fallback path)
- PRs: