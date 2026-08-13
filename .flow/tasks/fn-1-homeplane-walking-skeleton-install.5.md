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
Vault detect/retrieve + supervised continuous sync, built against the REAL obsidian-headless 0.0.13 contract (captured from the pinned build's own parser and asserted on every run; the pin carries verified tarball and cli.js checksums). Activation is a three-stage sequence (prepare → install → apply) where every step refuses independently. The pre-activation rehearsal has two explicit modes: a default unauthenticated CONTRACT check that requires the build to refuse an unconfigured directory the way upstream does, and a LIFECYCLE rehearsal (sync-setup against a disposable remote, then a real pass) reserved for .7; the fake CLI is stateful so an invalid lifecycle fails a test rather than passing. Retrieval runs login → sync-list-remote (explicit selection) → sync-setup → a pull-only first pass → restored bidirectional, failing loudly if the restore fails. Two distinct credentials never touch argv. Sync liveness is an external probe (pid signal-0 by default, launchctl/systemctl optionally), so a SIGKILLed process that recorded no exit reports degraded instead of a permanent false ok.
## Evidence
- Commits: bc33814b46c68256a7297d1d0246c896418be844, d369ba6a84173e32a25addc51809fa5f6ba0c0f9, 8e0a4e36c72e87117bcb9d574ece4860a496979d, a512b447e4d8b12cb2120a0a9f9a188eaf7d6f3e, 2411b9c64c07c0605aac2441ffcb13ae6cece97c, 270a7c164126144a21d4592d3d454df773fa8f91
- Tests: go build ./..., go vet ./..., go test ./... -count=1, HOMEPLANE_OB_BIN=<real 0.0.13> go test ./internal/agent/vault/ -run 'PinnedBuild|PinnedContract|Attested|SecretsAreNever' (PASS against the real artifact), scripts/emit-evidence.sh fn-1-homeplane-walking-skeleton-install.5 (401/401 assertions, 3 gates, pass)
- PRs: