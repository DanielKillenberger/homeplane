---
satisfies: [R1, R2, R10]
---
# fn-1-homeplane-walking-skeleton-install.4 Installer + homeplane-agent CLI (install, enrol, status)

## Description
The installer script and the agent's core CLI: `enrol`, `status`. Install verification runs against locally staged, checksummed release-form artifacts (a published CI pipeline and `uninstall` are deferred hardening per spec Boundaries). Vault/sync (.5), GNO (.11), harness config (.6), credentials (.8), skills (.9) plug into this skeleton.

**Size:** M
**Files:** `cmd/homeplane-agent/` (enrol, status subcommands), `internal/agent/` (state, server client), `install.sh`

## Approach
- `install.sh`: detect OS/arch (darwin arm64/amd64, linux amd64/arm64) AND init system — supported = macOS launchd, systemd-based Linux with `systemctl --user` + linger; non-systemd Linux is REJECTED before install with a clear message. Fetch the staged release-form artifact, verify SHA-256 (mismatch/corrupt → abort loudly, no partial install), place binary, idempotent re-run = refresh (R1). **Prerequisite provisioning:** the installer ensures Node 22+ deterministically (distro package where available, else a checksummed vendored tarball) rather than leaving a supported fresh machine unable to sync its vault (review fix — degraded-only is not acceptable for a supported platform).
- Agent state dir: `~/.homeplane/` (0700; XDG on Linux) — machine identity + credential, server address, vault path, grant metadata, harness-config backups. All tokens 0600 (token-hygiene discipline — former R17, folded per D17).
- `enrol`: reach server over tailnet; **re-enrol = rotation** — persist the new machine credential atomically before acknowledging (review fix); unreachable → actionable error, no partial local state (R2).
- `status`: enrolment, vault path, sync state, GNO state, harnesses, skills summary, grants **reconciled live via `GET /grants`** — revoked shows revoked; unreachable server shows `unknown (server unreachable)`, never stale `active`. Degraded → named component + non-zero exit (R10).

## Investigation targets
**Required:**
- `internal/server/` API shapes from .2 (incl. `GET /grants`, rotation semantics)
- `.flow/specs/fn-1-homeplane-walking-skeleton-install.md` — R1/R2/R10 + Edge Cases

## Acceptance
- [ ] Fresh Linux + macOS install via one command (staged release-form artifacts); re-run idempotent; tampered-checksum aborts; Node 22 provisioned when missing
- [ ] `enrol`: success, re-enrol rotation (old credential invalid after, agent state consistent), unreachable-server path
- [ ] `status` truth-table: not-enrolled / enrolled-no-vault / revoked-grant (live reconcile) / server-unreachable (unknown, not active); exit codes correct
- [ ] `go test ./...` green
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)

## Done summary
Added the machine side of the walking skeleton: `install.sh` (platform/init gating before any filesystem write; validate-then-commit ordering — artifact checksums, the agent binary actually running here, and the extracted Node runtime reporting 22+ are all proven before the install prefix is touched, with the previous Node runtime retained and restored by an exit trap if any step fails), `scripts/stage-release.sh` (cross-compiled agents AND the pinned Node 22 runtime verified against upstream checksums in `scripts/node-pinned.sha256`, so a fresh Mac with no Node can install), `internal/agent` (0700 state dir with 0600 credential/state, atomic writes, control-plane client) and `cmd/homeplane-agent` with `enrol` (identity-preserving rotation; nothing written when the server is unreachable; concurrent enrolments serialized by a state-dir lock and guarded by a credential-version check that refuses to persist a superseded response) and `status` (grants reconciled live via `GET /grants`; revoked reads revoked, unreachable reads unknown, degraded names the component and exits non-zero).

All three codex impl-review findings (P1 Node staging, P2 install atomicity, P2 concurrent-enrolment credential loss) are fixed, each with tests that fail against the old behaviour.

Test boundary: the agent is exercised against the REAL server from .2 (same handlers, store, policy, auth) over httptest loopback with a stand-in WhoIs resolver; the actual tailnet leg (tsnet dialling, real WhoIs) is not covered here and belongs to the integration tasks. The installer tests run the real scripts and substitute only the Node distribution (a file:// dist tree with a stand-in runtime); the production download-and-verify path was additionally smoke-tested against nodejs.org by hand.
## Evidence
- Commits: c596861ee0ad4aff8c13f778399faf2906d30402, 2d28d31c5053cf338f5eca0ff5a7fff8306018fc, 1bedc33168610064c724912a6c28fb6c548ae1b0, 50edec26324fad4acf80c92f0936842e5de3cbe5
- Tests: go build ./... (exit 0), go vet ./... (exit 0), go test ./... -count=1 (exit 0; 131 assertions, 0 failures), go test ./internal/agent/ -count=1 -race (exit 0; covers the 8-way concurrent rotation test), shellcheck install.sh scripts/stage-release.sh scripts/emit-evidence.sh (exit 0, no findings), scripts/emit-evidence.sh fn-1-homeplane-walking-skeleton-install.4 -> test/evidence/fn-1-homeplane-walking-skeleton-install.4.json (pass, 131/131, 3 gates, commit 1bedc331), manual smoke (real network, real artifacts): HOMEPLANE_STAGE_PLATFORMS='darwin arm64' scripts/stage-release.sh -> downloaded node-v22.11.0-darwin-arm64.tar.gz from nodejs.org and verified it against the pinned upstream checksum; ./install.sh with HOMEPLANE_NODE_BIN pointing at a nonexistent node installed onto a Node-less prefix; installed node reported v22.11.0 and the installed agent reported its build version, manual smoke (earlier): installed agent 'status' on a fresh state dir exited 2 (not_enrolled) with every component named
- PRs: