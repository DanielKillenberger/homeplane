---
satisfies: [R7]
---
# fn-1-homeplane-walking-skeleton-install.12 Live Google connectors: Drive (read-only) + Calendar (read/write), real-credential proof

## Description
Make the Google connectors live through the .3 manifest/edge using a credential added via the .8 broker against real Google: Drive READ-ONLY and Calendar read+write per the D18 scope policy. Split from the broker per plan review.

**Size:** S/M
**Files:** Drive manifest entry (with per-tool action-class/capability mapping), `internal/server/connectors/drive_test.go` (or e2e-tagged tests), test-folder bookkeeping

### Approach
- Both land as manifest entries only (R12 discipline) — provider, credential ref, MCP source (per D6 spike outcome), per-tool mapping with artifact-id extractors (file id / event id). **D18 scope policy:** Drive maps READ tools only (`drive.readonly` scope); any Drive write-class tool the runtime exposes stays unmapped → fail-closed denial (this is a live policy-engine proof, test it). Calendar maps read + write tools (`calendar.events` scope); event delete maps to the `delete` action class (Calendar has a real delete tool — no polymorphic-update collapse needed here).
- Scopes: `drive.readonly` + `calendar.events` ONLY (both non-restricted; app stays in Testing mode — note limited refresh-token lifetime in runbook material). Real credential via `add-credentials google` (.8) — this is the first real-Google exercise of the broker.
- Six-op proof target: an isolated, uniquely named Calendar test event (namespaced summary; dedicated test calendar if scope allows creation, else primary calendar with unique namespacing); created/updated/deleted by the proof itself, no pre-existing event touched.

### Investigation targets
**Required:**
- `internal/server/connectors/` manifest + edge (from .3); credflow (from .8)
- https://developers.google.com/workspace/drive/api/guides/api-specific-auth — drive.file semantics

## Acceptance
- [ ] `add-credentials google` end-to-end against real Google; credential server-side only; agent filesystem free of provider tokens
- [ ] Drive READ call with valid grant reaches real Drive through the edge; a Drive write-class invocation is denied fail-closed + audited; Calendar six-op sequence succeeds; revoked grant → auth error in seconds
- [ ] Calendar test event fully cleaned up after the proof; no pre-existing event or file touched (verified by before/after listing)
- [ ] Drive + Calendar calls audited with correct action classes (incl. Calendar delete as delete-class), metadata only
- [ ] `go test ./...` green (live-Google e2e behind a build tag/env guard)
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)


## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
