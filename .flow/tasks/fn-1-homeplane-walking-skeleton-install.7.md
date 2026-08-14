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
The walking skeleton, proven end to end on Daniel's Mac against the live server
on clawniel: install → enrol → vault → retrieval engine → skills → both
harnesses → brokered credential → Drive read → the reversible Calendar write →
revocation → status/healthz → the operator's audit review. `test/e2e/` is the
scripted, stage-selectable proof; `test/evidence/…7.live.json` is its record —
14 stages, 113 assertions, 0 failed — and `docs/runbooks/e2e-proof.md` says how
to run it and how to read it.

**What settles a claim is the server's audit log**, read through the operator
CLI on the server host. Both harnesses invoke MCP tools only inside a model turn,
so the proof runs one (`claude -p`, `codex exec`) — and a model's account of what
it did is recorded beside every connector assertion and never believed on its
own. That distinction is not decorative: a model that declined to call a tool
left an error string containing neither the event id nor the summary, which the
first version of step 6 read as proof of deletion.

**R8 from BOTH harnesses**, including the item inherited from .12: six operations
on an isolated event (create, read back, update, verify, delete, verify cleanup)
with every mutation carrying `send_updates:"none"`, and the same call WITHOUT it
refused as `capability_missing` (required `connector.send`) — the guard watched
refusing, not only permitting. Absence is established positively: the filtered
listing (which excludes cancelled events) shows nothing, and a second delete has
the provider answer Gone. **R7/D18**: a real Drive read, and `create_drive_file`
refused as an `excluded_tool` policy violation, per harness. **R9**: revocation
through both paths R9 names — the operator's server-local CLI and the machine's
own authenticated `DELETE /grants/{id}`, with an unknown grant answering 404 —
the other harness unaffected, the revoked grant admitting nothing after, and
status showing it via live reconcile. **R10**: every mode actually produced,
including the gateway stopped on the server so `curl -sf` fails and the payload
names the degraded component.

**Two decisions of Daniel's are recorded rather than worked around.** Obsidian.app
stays the operating sync client for the real vault, so Homeplane detects it and
never writes to it; the headless client's leg is a limitation with an owner until
he supplies a login and a throwaway remote (`vault sync activate -smoke-remote`,
added here). And the engine runs in stdio mode, because gno 1.29.6 allows one
resident runtime per index: with the daemon loaded a harness session fails with
`database is locked`, and the same exclusivity bites two consecutive clients.
That is a D8 follow-up, not a defect this task hides.

**The live run found nine real faults, all fixed here.** The deployment could not
run the Google connector at all: the manifest that shipped was the pre-guard one,
the gateway had no way to carry a connector's own `thv` flags, and a brokered
credential had nowhere to land. Then, on a rootless-Podman host, the workload
could not READ a credential the server owns — and, an hour later, could not
REWRITE the token it refreshes, which is why every call worked for exactly one
token lifetime and then demanded re-authentication. The engine died under launchd
with `env: bun: No such file or directory` (a supervised process inherits almost
no PATH); activation was not idempotent; re-activation ran `gno setup` against an
index the running daemon held; ordinary MCP sessions were recorded as failed
launches until "25 consecutive failures" were all successes; and a lock holder
stranded by a killed engine turned a machine into a crash loop no restart fixed.

**Three review rounds (codex, gpt-5.6-sol @ xhigh): 7 findings, then 1, then
SHIP.** The one worth remembering is the first: the truth-table stage reported
green while three of its four modes were never produced — an invalid flag whose
usage error satisfied "non-zero exit", a `deactivate` without `-execute` that
changed nothing, a missing-vault check that only rejected a path which never
existed. Every assertion was true; none was about what it claimed. The last
finding was the same shape one layer up: a delivery failure was observable on
`/healthz` while `add-credentials` still reported clean success, so storage and
readiness are now separate claims — the credential stays stored, the flow carries
a non-retryable `delivery_failed` diagnostic, and the agent says "stored, NOT
usable, do not authorize again" and exits non-zero.

stage: impl-review - ran [3 rounds: 7 findings → 1 finding → SHIP]
stage: delegation - skipped(config: delegation off)
## Evidence
- Commits: cbf93526563972f02aee240525a3b58bb6e139be, 0b518c49a52a7b0cda9305a6055cfe2c75b7dfc5, a5e69efb7e71eecf4b08c104ce2fdd07a3bdd255, f1989bb1e765e934e4badeff6db8215ea635a2f0, 5de7172b11879a637ef7b6436db6eab24e596488, ca067cb97af07ef65b6ac0077e4ff4c9b92dac99, e5babd249c92a2bfa92aca7e9bf7514d813b7f94, daff160fac4977d9d0471a10a1179901ffacb6a2, e630d32c695730614077e51330e6e5e011137ef5, 2529653ae7b0e177d20a3af8a0ce1d7e0a259608, 97cad3d81f7c54141ef6716be08e71e6692dfab1, c38f214a577070a468a1904e3eecddd51ab74df3, b4830df35850193c338d6feb8751c75f83595e86, 65dea61363cbf21f477db69b005aa86480cf58b2, 2b54af347353181eda1d71bb13860ba59ee596ba, d3a22e1518a97c37eb11b5b53a2245571d55cfb1, 8a6df685e71524d8ce3479404b2f887c1bd98cfc, f72f7fe9a35b1402cf3f121f533f356a18f0c9ee, 1a5fa04247255e3217bc6dd28ffb384a48dfb663, d2c1e7d1c598b90824e3f1c00d28433fea2250a3, 4e58bf31a4b23f86171d622765bec4f0d3fb1951, ebffe8fe48072b09826c8a05cde787760bab7111, 2af67c702c29fa2a77bd8ff0b289918a2b592944, 423d678f13e7fe17f7ec0a64c2195c3900c03320, 9e7946153a6100397f3278d0c308db2507b86865
- Tests: go build ./... && go test ./..., test/e2e/run.sh (live_e2e, 14 stages, 113 assertions — test/evidence/fn-1-homeplane-walking-skeleton-install.7.live.json), deploy/server/verify.sh --host clawniel --fqdn homeplane.tailab4e9b.ts.net
- PRs: