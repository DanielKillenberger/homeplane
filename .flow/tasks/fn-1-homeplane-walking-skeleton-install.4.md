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
TBD

## Evidence
- Commits:
- Tests:
- PRs:
