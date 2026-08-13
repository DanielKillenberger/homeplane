# Vault detection and continuous sync (R3, R14)

Operator runbook for `homeplane-agent vault`. Implemented in task
`fn-1-homeplane-walking-skeleton-install.5`.

## Why this is written defensively

Obsidian Sync reconciles a local vault against a remote one, in place. If the
remote side is empty, stale, or the wrong vault, "reconcile" means "delete
Daniel's notes" — and there is an upstream data-loss report against
obsidian-headless 0.0.12. Every refusal below exists because of that.

## The safety sequence

`homeplane-agent vault sync activate` runs a fixed order and stops at the first
failure:

| # | Step | Refusal |
|---|------|---------|
| 1 | the recorded path is a real vault | `vault: path is not an Obsidian vault` |
| 2 | a sync credential is stored | `vault: no Obsidian Sync credential stored` |
| 3 | the CLI matches the version + SHA-256 pin | `ErrPinUnset` / `ErrPinMismatch` |
| 4 | a **disposable** vault syncs cleanly on that build | smoke failure; the real vault is never touched |
| 5 | the real vault is snapshotted (files + content manifest) | abort before any sync |
| 6 | one real sync pass, then a content diff | auth / network failure, retryable |
| 7 | the diff is inside the guard policy | `DestructiveDiffError`, naming the snapshot |
| 8 | only now: install + activate supervision | — |

Steps 4 and 5 are the point of the ordering: by the time the real vault is
synced, the same build has already been proven against a throwaway vault and the
real vault has already been copied aside.

## The pin

`internal/agent/vault/obsidian-headless-pinned.sha256` is compiled into the
agent. It ships with `checksum = PENDING`, which is a **hard refusal**, not a
warning — the agent will not run an unverified sync binary. Task .7's live proof
is what fills it in.

To bump the pin:

1. Download the release and verify it against upstream's published checksum.
2. Smoke it on a disposable vault (activation does this automatically, but do it
   deliberately once, by hand, on a new version).
3. Record the new `version` and `shasum -a 256` of the executable in that file.
4. Update `TestLoadPinIsPendingUntilAReleaseIsStaged` — the test fails on
   purpose when the pin changes, so a human confirms where the bytes came from.

## The destructive-diff guard

`DefaultGuardPolicy` allows unlimited **additions** (receiving notes from another
machine is the point) and bounds destruction two ways, because they fail
differently:

- absolute: more than 5 deletions, or more than 50 in-place rewrites
- fractional: more than 5% of the vault deleted, or 25% rewritten

An absolute floor alone would wave through a large vault losing thousands of
files; a fraction alone would wave through a six-note vault being wiped.

On a refusal the error names the snapshot directory, which holds the pre-sync
tree under `tree/` and a content manifest in `manifest.json`.

## Credential custody

The Obsidian Sync credential is the spec's **named custody exception** (D4). It
is the one remote-service secret that lives on the machine, because the sync
process runs there.

- stored 0600 at `<state-dir>/obsidian-sync.cred`, written atomically
- read from **stdin** (`homeplane-agent vault set-credential`), never a flag
- passed to the CLI through `OBSIDIAN_SYNC_PASSWORD` in the environment, never
  argv (`ps` is world-readable); every exec asserts this
- never in `state.json`, never in a supervision unit, and redacted out of every
  error and log line
- a credential file whose permissions have loosened is refused, not used

## Supervision

The supervised unit runs `homeplane-agent vault sync run`, **not** the sync CLI
directly. That keeps the unit file free of secrets and lets the agent record its
own starts in a restart ledger, so `status` can report a restart count — and a
crash loop — identically on both platforms without parsing launchd or journald.

- macOS: `~/Library/LaunchAgents/com.homeplane.vault-sync.plist`, `KeepAlive`,
  `ThrottleInterval` ≥ 10s
- Linux: `~/.config/systemd/user/homeplane-vault-sync.service`,
  `Restart=always`, plus `loginctl enable-linger` — without linger the unit dies
  at logout, which is exactly the "sync quietly stopped" failure R14 forbids

Installing the unit file and **activating** it are separate. Without `-apply`,
activation writes the file and prints the commands that would load it; nothing
in a test ever mutates a live launchd or systemd session.

## Index location (reserved for .11)

`vault.EnsureOutsideVault` refuses any machine-local path that resolves inside
the vault. Vault files sync; machine-local indexes must not. Task .11 owns the
GNO index itself, but the contract lives next to the sync that would otherwise
propagate it.

## Status

| Situation | `status` vault/sync component |
|---|---|
| vault detected and present | `vault: ok` with the path |
| no vault on this machine | `vault: degraded`, "no vault found … retryable" |
| multiple candidates | `vault: degraded`, both paths listed — never a guess |
| sync auth rejected | `sync: degraded`, "authentication failed (retryable)" |
| sync network failure | `sync: degraded`, "network failure (retryable)" |
| destructive diff refused | `sync: degraded`, naming the snapshot |

In every sync failure the vault stays readable locally — a broken sync must
never look like a lost vault.
