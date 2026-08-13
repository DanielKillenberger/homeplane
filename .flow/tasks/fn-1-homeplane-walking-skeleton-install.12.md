---
satisfies: [R7]
---
# fn-1-homeplane-walking-skeleton-install.12 Live Google Drive connector: manifest entry, test folder, real-credential proof

## Description
Make Google Drive live through the .3 manifest/edge using a credential added via the .8 broker against real Google. Split from the broker per plan review.

**Size:** S/M
**Files:** Drive manifest entry (with per-tool action-class/capability mapping), `internal/server/connectors/drive_test.go` (or e2e-tagged tests), test-folder bookkeeping

### Approach
- Drive lands as a manifest entry only (R12 discipline) — provider, credential ref, MCP source (per D6 spike outcome), per-tool mapping with artifact-id extractors (file id). **Action-class honesty (review fix):** Google's `files.update` is polymorphic (metadata/content update AND trash), so a static tool-level rule cannot separate trash from update. **Decision: the Drive skeleton explicitly collapses write and delete** — the Drive manifest entry declares no delete-class tools, trash rides the write capability, and the collapse is recorded in the manifest entry and docs (a grant authorized to write Drive test files is authorized to trash them; fine for the isolated test folder). If the composed MCP server exposes a distinct trash tool, map it to `delete` instead. Never claim delete-class granularity the tool surface cannot deliver.
- `drive.file` scope ONLY (non-sensitive, no Google verification; app stays in Testing mode — note limited refresh-token lifetime in runbook material). Real credential via `add-credentials google` (.8) — this is the first real-Google exercise of the broker.
- Test folder CREATED by the app (drive.file cannot see pre-existing folders); folder id persisted server-side; reused idempotently across runs. Trash via files.update(trashed=true), never files.delete.

### Investigation targets
**Required:**
- `internal/server/connectors/` manifest + edge (from .3); credflow (from .8)
- https://developers.google.com/workspace/drive/api/guides/api-specific-auth — drive.file semantics

## Acceptance
- [ ] `add-credentials google` end-to-end against real Google; credential server-side only; agent filesystem free of provider tokens
- [ ] Drive MCP call with valid grant reaches real Drive through the edge; revoked grant → auth error in seconds; capability mapping enforced (read-only grant cannot create)
- [ ] Test folder created + persisted + reused; verified invisible interference with pre-existing files (drive.file scope)
- [ ] Drive calls audited with correct action classes, metadata only
- [ ] `go test ./...` green (Drive e2e behind a build tag/env guard)
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)


## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
