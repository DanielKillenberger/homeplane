---
satisfies: [R3, R14]
---
# fn-1-homeplane-walking-skeleton-install.5 Vault detect/retrieve + continuous sync (obsidian-headless)

## Description
Find or retrieve the Daniel-OS vault and keep it continuously synchronized under supervision. GNO moves to .11 (split per plan review — vault/sync and GNO/supervision are independently risky integrations).

**Size:** M
**Files:** `internal/agent/vault/` (detect, retrieve, sync), sync supervision templates under `internal/agent/supervise/templates/` (shared framework also used by .11)

## Approach
- Detect: standard Obsidian vault locations + explicit `--vault-path` override; multiple candidates → explicit selection, never guess (R3).
- Retrieve when absent: official `obsidianmd/obsidian-headless` CLI (Node 22+ provisioned by the installer, .4). Verify non-interactive login viability. Obsidian Sync credential = NAMED custody exception (spec D4 adjudication): 0600 in agent/Obsidian state area, never in logs/argv/git-tracked files; never in logs/argv/git-tracked files. Fallback: launch Obsidian app once and wait for the vault. Auth-failure distinguished from no-vault in status. Retrieval failure → enrolment unaffected, degraded + retryable (R3).
- **Sync safety (upstream data-loss report against obsidian-headless 0.0.12):** pin + checksum the exact tested CLI version; snapshot the real vault (local copy) before first sync activation; abort + surface on unexpected destructive diff (mass deletions/overwrites) rather than syncing through it. (A full disposable-vault conflict-rehearsal matrix is deferred per spec Boundaries — a basic smoke on a test vault before real-vault activation is still required.)
- **Continuous sync (R14):** `ob sync --continuous` (or equivalent) under supervision (launchd LaunchAgent / systemd user unit + `loginctl enable-linger`); sync state in `status`; sync death → supervisor restarts; sync failure → degraded, retryable, vault stays locally readable. Nothing machine-local (indexes etc.) may be written into synced paths — reserve the index location contract for .11.
- Supervision framework built here (templates + restart tracking) is shared with .11.

## Investigation targets
**Required:**
- `internal/agent/` state + status plumbing from .4
- https://github.com/obsidianmd/obsidian-headless — CLI modes, login, continuous sync
**Optional:**
- Apple launchd KeepAlive docs; systemd user-unit + linger docs

## Acceptance
- [ ] Existing-vault machine: detected + recorded, no retrieval; multi-candidate → explicit selection
- [ ] Absent-vault machine: headless retrieval works (or documented fallback exercised); auth-failure vs no-vault distinguished in status
- [ ] Basic smoke on a disposable test vault passes on the pinned CLI version before real-vault activation; real vault snapshotted; destructive-diff guard tested
- [ ] Continuous sync supervised on both OSes; kill → restart; failure → degraded while vault stays readable
- [ ] Sync credential 0600, absent from logs/argv
- [ ] `go test ./...` green
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)

## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
