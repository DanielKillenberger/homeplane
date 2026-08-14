---
satisfies: [R7]
---
# fn-1-homeplane-walking-skeleton-install.12 Live Google connectors: Drive (read-only) + Calendar (read/write), real-credential proof

## Description
Make the Google connectors live through the .3 manifest/edge using a credential added via the .8 broker against real Google: Drive READ-ONLY and Calendar read+write per the D18 scope policy. Split from the broker per plan review.

**Size:** S/M
**Files:** Drive manifest entry (with per-tool action-class/capability mapping), `internal/server/connectors/drive_test.go` (or e2e-tagged tests), test-folder bookkeeping

### Approach
- Both land as manifest entries only (R12 discipline) — provider, credential ref, MCP source: pinned connector **`workspace-mcp` v1.24.0** (taylorwilsdon/google_workspace_mcp), run via ToolHive's `uvx://workspace-mcp` scheme (pin the version in the uvx spec) <!-- Updated by plan-sync: fn-1.1 pinned the connector name/version, was generic "MCP source (per D6 spike outcome)" -->, per-tool mapping with artifact-id extractors (file id / event id). Tool mapping: Calendar `manage_event` (create/update/delete) + `get_events` (read); Drive read via `get_drive_file_content`/`search_drive_files`. **D18 scope policy:** Drive maps READ tools only (`drive.readonly` scope); Drive write tools (`create_drive_file`/`update_drive_file`) stay unmapped → fail-closed denial (this is a live policy-engine proof, test it). Calendar maps read + write tools (`calendar.events` scope); event delete (`manage_event`'s delete path) maps to the `delete` action class (Calendar has a real delete tool — no polymorphic-update collapse needed here).
- Scopes: `drive.readonly` + `calendar.events` ONLY (both non-restricted; app stays in Testing mode — note limited refresh-token lifetime in runbook material). Real credential via `add-credentials google` (.8) — this is the first real-Google exercise of the broker.
- Six-op proof target: an isolated, uniquely named Calendar test event (namespaced summary; dedicated test calendar if scope allows creation, else primary calendar with unique namespacing); created/updated/deleted by the proof itself, no pre-existing event touched.

### Investigation targets
**Required:**
- `internal/server/connectors/` manifest + edge (from .3); credflow (from .8)
- https://developers.google.com/workspace/drive/api/guides/api-specific-auth — drive.file semantics

## Acceptance
- [ ] **Inherited from fn-1.15 (deferred there with Daniel's authorization, 2026-08-13):** the Homeplane-owned Google OAuth client exists (Daniel creates it in his own Google Cloud Console — Desktop/loopback app, scopes `drive.readonly` + `calendar.events`, Testing mode is fine) and its credentials are imported on the server as `google/client-id` + `google/client-secret` via `admin secret import` from 0600 files (never argv, never a chat channel). Verify with `deploy/server/verify.sh --host clawniel --fqdn <fqdn>` run WITHOUT `--pending`: `provider_secret_refs_present` must pass. Do NOT reuse the co-resident Hermes OAuth client — separate systems, separate app identities. <!-- Added by fn-1.15: this is the one .15 acceptance item that could not be completed there -->
- [ ] `add-credentials google` end-to-end against real Google; credential server-side only; agent filesystem free of provider tokens
- [ ] Drive READ call with valid grant reaches real Drive through the edge; a Drive write-class invocation is denied fail-closed + audited; Calendar six-op sequence succeeds; revoked grant → auth error in seconds
- [ ] Calendar test event fully cleaned up after the proof; no pre-existing event or file touched (verified by before/after listing)
- [ ] Drive + Calendar calls audited with correct action classes (incl. Calendar delete as delete-class), metadata only
- [ ] `go test ./...` green (live-Google e2e behind a build tag/env guard)
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)


## Done summary
Live Google connector (Drive read-only + Calendar read/write per D18) through the .3 manifest and .16 edge, plus the six review fixes: notifications are now treated as send authority via a declarative manifest capability guard on `manage_event`'s `send_updates`, `rsvp` is unclassified and denied, the live six-op's cleanup stays armed until absence is observed, test-event summaries are collision-proof, the tag-gated live run is recorded as an embedded evidence artifact, and the runbook's client-JSON import no longer globs through `open()`.

Round-2's single finding — the guarded Calendar mutation path lacks a matching live run — is closed by Daniel's explicit deferral of that live leg into task .7 (2026-08-14, same precedent as .15's deferred credential import). The deferral is recorded in `docs/decisions/d18-google-scopes.md`, the runbook's Evidence section, and the live evidence JSON's `deferral` object (`deferred_to`, `authorized_by`, `authorized_on`, `inherited_acceptance_item`). This task does NOT claim the guarded path is live-proven.

### FOR THE CONDUCTOR — acceptance item to append to task .7 in main's `.flow`

```
- [ ] Inherited from .12 (Daniel-authorized deferral 2026-08-14): the guarded Calendar mutation path (send_updates:"none" + connector.send gating) is proven LIVE against real Google as part of this task's six-op run — including one denied manage_event call WITHOUT send_updates:"none" (or RSVP) audited as capability_missing.
```

The denial half is load-bearing: a guard only ever observed permitting is not a guard anyone has watched refuse.
## Evidence
- Commits: 606b5a01557cfad0903165308b2a186a9447eeac, 11360881db6c92282a791940d75bcf548db3d133, c81f4af5ab69a2b2f19743928e86a283a09036be, 69a680fb6d87a9e3d02c577b18b7615a8aeeb1e2, 65343af76e0ca1dea7ac91ca88dc8b1a6e3b3c62, 11d2307d2561ac205dfd35e496b6e022aea8891e, 8e82152d35fe81c6b4bc32d90ce940e54074b826
- Tests: go build ./... (rc=0), go vet ./... (rc=0), go vet -tags live_google ./cmd/homeplane-agent/ ./internal/server/edge/ (rc=0), gofmt -l . -> internal/store/model.go only (INHERITED, untouched by this task), go test ./... -count=1 -p 2 (18 packages, rc=0), go test ./internal/server/connectors/ ./internal/server/workloadcred/ ./internal/server/edge/ -count=1 -race (rc=0), scripts/emit-evidence.sh fn-1-homeplane-walking-skeleton-install.12 -> pass, 548/548 assertions, 3 gates, 11 embedded live assertions at 11d2307, KNOWN FLAKE (not this task): internal/server/credflow TestARelayedFlowIsNotExpiredByTheConsentWindow failed under emit-evidence total parallelism, passes 8/8 in isolation; it is the exact race fixed by task .15 commit 49f36b9, which is not in this worktrees base (621f1c5), LIVE (real Google, build tag live_google) NOT re-run this session — teardown removed the workload and store, so a re-run needs fresh browser consent. The original runs commands/timestamps/redacted env/commit/per-assertion results are recorded in test/evidence/fn-1-homeplane-walking-skeleton-install.12.live.json and embedded in the artifact., DEFERRED (Daniel-authorized 2026-08-14, same precedent as .15s credential import): the live proof of the GUARDED Calendar mutation path (send_updates:"none" under connector.send gating, plus one denied manage_event call WITHOUT it audited capability_missing) is inherited by fn-1-homeplane-walking-skeleton-install.7. Recorded in docs/decisions/d18-google-scopes.md, docs/runbooks/live-google-proof.md, and the live evidence JSONs deferral object. This task does not claim the guarded path is live-proven.
- PRs: