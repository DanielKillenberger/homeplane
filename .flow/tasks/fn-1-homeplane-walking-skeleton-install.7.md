---
satisfies: [R8, R9, R10]
---
# fn-1-homeplane-walking-skeleton-install.7 End-to-end proof automation: six-step Calendar proof, Drive read, revocation, status/healthz truth

## Description
Deterministic, scripted e2e proof of the walking skeleton on a real machine + real server. Operator docs + final acceptance gate are .14. (Network-capture and token-sweep verification are deferred hardening per spec Boundaries.)

**Size:** M
**Files:** `test/e2e/` (scripted proof runs, rerunnable)

## Approach
- Full flow from the staged release-form artifacts (.4): install → enrol → vault → sync → GNO (.11) → skills (.9) → harnesses (.6) → GNO + Google connector access (.12: Drive read-only + Calendar read/write, per D18).
- R8 proof, per harness (Calendar, per D18): isolated uniquely named test event (summary embeds machine+harness+timestamp; dedicated Homeplane test calendar when the granted scope allows calendar creation, else namespaced in primary) — (1) create the event, (2) read back, (3) update, (4) verify, (5) delete, (6) verify cleanup (direct get shows cancelled/gone AND a summary-filtered list shows no non-cancelled match). Step failure → stop, surface, point at the remaining event (it MUST be deleted even on failure paths — loud pointer if cleanup itself fails). Pre-existing events untouched (summary-filtered listing before/after). Both harnesses run to demonstrate collision safety.
- D18 connector checks, per harness: a Drive READ succeeds under `drive.readonly`; a Drive write-class call is denied fail-closed (unmapped in the manifest) and audited as a policy violation — the live proof of the D18 policy.
- Audit review via `homeplane-server admin audit`: ALL six Calendar steps per harness incl. reads, plus the Drive read and the Drive write denial — manifest-derived action class, artifact id (Calendar event-id extractor; Drive file-id extractor for the read), (machine, harness, grant) attribution, metadata only (R16 spot-check).
- R9 proof: revoke harness A (machine-side DELETE and server-side `admin revoke-grant` both exercised) → A fails with auth error within seconds; B keeps working; A's `status` shows revoked via live reconcile; repeat-revoke idempotent; unknown grant → 404.
- R10 sweep (demo-path modes only per amended spec): revoked grant, server down, GNO killed, vault missing → `status` truthful + correct exit codes; gateway down → `/healthz` truthful. No machine state in /healthz.
- Output: a machine-readable evidence file (JSON log of steps + assertions) consumed by .14's acceptance gate.

## Investigation targets
**Required:**
- All prior task outputs; spec R8–R10 + Edge Cases; audit/API shapes from .2/.3/.8/.12

## Acceptance
- [ ] Scripted e2e passes from BOTH harnesses on one machine; rerunnable; evidence file emitted
- [ ] Audit shows all six Calendar steps per harness incl. reads, the Drive read, and the Drive write denial — correct action classes + artifact ids, metadata-only verified
- [ ] Revocation asymmetry demonstrated and audited (both paths); revoked state visible in agent status; repeat-revoke idempotent
- [ ] Status/healthz truth-table (demo-path modes) passes with the machine/server split honored
- [ ] `go build ./... && go test ./...` green
- [ ] Inherited from .12 (Daniel-authorized deferral 2026-08-14): the guarded Calendar mutation path (send_updates:"none" + connector.send gating) is proven LIVE against real Google as part of this task's six-op run — including one denied manage_event call WITHOUT send_updates:"none" (or RSVP) audited as capability_missing <!-- Updated by plan-sync: fn-1.12 used a "(or RSVP)" denial path (rsvp is unclassified and denied per .12's done summary) not present in the acceptance item as inherited here -->

## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
