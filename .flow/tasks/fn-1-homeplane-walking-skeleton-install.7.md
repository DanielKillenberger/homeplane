---
satisfies: [R8, R9, R10]
---
# fn-1-homeplane-walking-skeleton-install.7 End-to-end proof automation: six-step Drive write, revocation, status/healthz truth

## Description
Deterministic, scripted e2e proof of the walking skeleton on a real machine + real server. Operator docs + final acceptance gate are .14. (Network-capture and token-sweep verification are deferred hardening per spec Boundaries.)

**Size:** M
**Files:** `test/e2e/` (scripted proof runs, rerunnable)

## Approach
- Full flow from the staged release-form artifacts (.4): install → enrol → vault → sync → GNO (.11) → skills (.9) → harnesses (.6) → GNO + Drive access (.12).
- R8 proof, per harness: server-created test folder — (1) create uniquely named file (machine+harness+timestamp), (2) read back, (3) update, (4) verify, (5) trash via files.update(trashed=true), (6) verify cleanup. Step failure → stop, surface, point at remaining artifact. Pre-existing files untouched (folder listing before/after). Both harnesses run to demonstrate collision safety.
- Audit review via `homeplane-server admin audit`: ALL six steps per harness incl. reads, manifest-derived action class, artifact id (Drive extractor), (machine, harness, grant) attribution, metadata only (R16 spot-check).
- R9 proof: revoke harness A (machine-side DELETE and server-side `admin revoke-grant` both exercised) → A fails with auth error within seconds; B keeps working; A's `status` shows revoked via live reconcile; repeat-revoke idempotent; unknown grant → 404.
- R10 sweep (demo-path modes only per amended spec): revoked grant, server down, GNO killed, vault missing → `status` truthful + correct exit codes; gateway down → `/healthz` truthful. No machine state in /healthz.
- Output: a machine-readable evidence file (JSON log of steps + assertions) consumed by .14's acceptance gate.

## Investigation targets
**Required:**
- All prior task outputs; spec R8–R10 + Edge Cases; audit/API shapes from .2/.3/.8/.12

## Acceptance
- [ ] Scripted e2e passes from BOTH harnesses on one machine; rerunnable; evidence file emitted
- [ ] Audit shows all six steps per harness incl. reads, correct action classes + artifact ids, metadata-only verified
- [ ] Revocation asymmetry demonstrated and audited (both paths); revoked state visible in agent status; repeat-revoke idempotent
- [ ] Status/healthz truth-table (demo-path modes) passes with the machine/server split honored
- [ ] `go build ./... && go test ./...` green

## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
