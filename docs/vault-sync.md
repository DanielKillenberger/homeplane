# Vault detection, retrieval, and continuous sync (R3, R14)

Operator runbook for `homeplane-agent vault`. Implemented in task
`fn-1-homeplane-walking-skeleton-install.5`.

## Why this is written defensively

Obsidian Sync reconciles a local vault against a remote one, in place. If the
remote side is empty, stale, or the wrong vault, "reconcile" means "delete
Daniel's notes" — and there is an upstream data-loss report against
obsidian-headless 0.0.12. Every refusal below exists because of that.

## The upstream contract

The agent drives the real `obsidian-headless` CLI. Its lifecycle is upstream's,
not one this repository invented:

```
ob login [--email E]                          # → account auth token
ob sync-list-remote                           # → what the account has
ob sync-setup --vault NAME --path DIR         # bind a local dir to a remote vault
ob sync-config --path DIR --mode pull-only    # force a safe first pass
ob sync --path DIR [--continuous]             # sync; --continuous watches
```

The pinned build's own `--help` output is captured verbatim in
`internal/agent/vault/testdata/ob-0.0.13-contract.txt` (regenerate with
`scripts/capture-ob-contract.sh`). `TestArgvMatchesThePinnedContract` asserts
every argument the agent emits appears in that parser, and
`TestAgainstTheRealPinnedBuild` re-checks it against a live binary when
`HOMEPLANE_OB_BIN` is set. A wrapper that invented flags cannot pass either.

## The pin

`internal/agent/vault/obsidian-headless-pinned.sha256` is compiled into the
agent and holds **two** checksums, verified at two different times:

| Field | Covers | Verified |
|---|---|---|
| `tarball` | the `npm pack` artifact | at staging, by `scripts/fetch-obsidian-headless.sh`, before anything is installed |
| `checksum` | the package's `cli.js` (what node executes) | on **every run**, by `vault.CLI.Verify` |

npm installs `ob` as a symlink to `cli.js`; `Verify` resolves the link before
checksumming, because a shim's bytes vary per install while `cli.js` does not.

`checksum = PENDING` is a hard refusal (`vault.ErrPinUnset`), not a warning.

To bump the pin:

1. `scripts/fetch-obsidian-headless.sh --version <new> --record` — download and
   print both checksums. Verify the tarball against upstream's own published
   integrity value before recording it.
2. `scripts/capture-ob-contract.sh <path-to-ob>` — re-capture the parser
   contract and **review the diff**: a removed flag is a breaking change.
3. Update the pin file and the assertions in `cli_test.go`. The test fails on
   purpose when the pin changes, so a human confirms where the bytes came from.
4. Re-run the authenticated smoke (below) before pointing it at the real vault.

## The safety sequence

`homeplane-agent vault sync activate` runs three stages, and every step refuses
independently:

**Prepare**

| # | Step | Refusal |
|---|------|---------|
| 1 | the vault path is canonicalized and is a real vault | `vault: path is not an Obsidian vault` |
| 2 | an account token is stored | `ErrNoAuthToken` |
| 3 | the CLI matches the version + SHA-256 pin | `ErrPinUnset` / `ErrPinMismatch` |
| 4 | a **disposable** vault survives a pass on that build | smoke failure; the real vault is never touched |
| 5 | the real vault is snapshotted (files + content manifest) | abort before any sync |
| 6 | one real sync pass, then a content diff | auth / network failure, retryable |
| 7 | the diff is inside the guard policy | `DestructiveDiffError`, naming the snapshot |

**Install** — write the supervision unit, persist the resolved CLI path.
**Apply** — load the unit into launchd/systemd. Explicit, never implicit.

Steps 4 and 5 are the point of the ordering: by the time the real vault is
synced, the same build has been exercised against a throwaway vault and the real
vault has already been copied aside.

### What the smoke does and does not prove

The pre-activation smoke is **unauthenticated-safe**: it proves the pinned build
runs, accepts the argv the agent emits, and leaves a vault it was pointed at
intact. An auth refusal during the smoke is tolerated (the build ran and
declined); a destroyed smoke vault is fatal.

It does **not** prove a full authenticated round-trip against Obsidian's
servers. That needs Daniel's account and is **deferred to task .7**, with him
present — along with the first activation against the real vault.

## Retrieval (absent vault)

`homeplane-agent vault retrieve -path DIR [-remote NAME]`:

- refuses to run over an existing vault — `sync-setup` against a populated
  directory reconciles, and reconciling an unrelated vault has no undo
- refuses to guess when the account has more than one matching remote vault
- forces the first pass to `--mode pull-only`: a bidirectional first pass
  against a freshly created empty directory is exactly how an empty local side
  gets propagated to the remote
- reports an auth failure as an auth failure, never as "no vault" — they need
  different fixes, and R3 requires status to say which happened
- `-app-fallback` launches Obsidian once and waits (bounded) for the vault to
  appear. It is **not** attempted for auth failures: an app that will also fail
  to authenticate only hides the reason.

A failed retrieval never blocks enrolment; the vault component reports degraded
and retryable.

## Credential custody

Two **distinct** credentials, and conflating them is a real hazard:

| Secret | What it does | How it travels |
|---|---|---|
| account auth token | authenticates to Obsidian; revocable server-side | `OBSIDIAN_AUTH_TOKEN` env var |
| E2E password | decrypts vault content; **not** recoverable from the account | stdin, at upstream's own prompt |

Upstream accepts both as `--password` flags. The agent never uses them: argv is
world-readable in `ps`. Every exec asserts no secret reached argv, and output is
streamed through a redacting writer that survives a secret split across two
writes.

Both live 0600 in the agent state directory (`obsidian-auth.token`,
`obsidian-e2e.pass`), written atomically, absent from `state.json` and from
supervision units, and refused outright if their permissions loosen. The agent
also confines obsidian-headless's own config directory under the state dir, so
it can neither read nor clobber a human's interactive `ob login` — and an
ambient `OBSIDIAN_AUTH_TOKEN` in the operator's shell is never inherited.

## The destructive-diff guard

`DefaultGuardPolicy` allows unlimited **additions** (receiving notes from another
machine is the point) and bounds destruction two ways:

- absolute: more than 5 deletions, or more than 50 in-place rewrites
- fractional: more than 5% of the vault deleted, or 25% rewritten

An absolute floor alone would wave through a large vault losing thousands of
files; a fraction alone would wave through a six-note vault being wiped.

The vault path is **canonicalized** before any of this. `filepath.WalkDir` does
not follow a symlink root, so a symlinked vault would otherwise snapshot nothing
and produce an empty manifest — and the guard would then compare nothing against
nothing while the real CLI resolved the link and synced the target.

## Supervision and liveness

The supervised unit runs `homeplane-agent vault sync run -state-dir DIR -ob PATH`
— **not** the sync CLI directly. That keeps the unit free of secrets, carries the
verified CLI path so the supervised process never has to guess it, and lets the
agent record its own starts in a restart ledger.

- macOS: `~/Library/LaunchAgents/com.homeplane.vault-sync.plist`, `KeepAlive`,
  `ThrottleInterval` ≥ 10s
- Linux: `~/.config/systemd/user/homeplane-vault-sync.service`,
  `Restart=always`, plus `loginctl enable-linger` — without linger the unit dies
  at logout, exactly the "sync quietly stopped" failure R14 forbids

Continuous sync runs **unbounded**: it ends only when its context is cancelled.
One-shot calls (`--version`, `sync-list-remote`, `sync-setup`, a single pass)
are bounded by a timeout. Captured output is a bounded tail, so a process that
runs for months cannot grow a buffer without limit.

**Status is derived from the ledger, not from a claim.** Activation records what
it did; the ledger records what the process has done since. A machine can be
SIGKILLed, crash-loop, or never load the unit at all — and a status that only
echoed the recorded claim would report a healthy sync through all three.

| Situation | `status` sync component |
|---|---|
| unit installed, not loaded | `degraded` — "installed but not loaded — vault is NOT syncing" |
| loaded, never started | `degraded` — "supervised but never started" |
| running | `ok` — with restart count and pid |
| exited / SIGKILLed | `degraded` — "not running", retryable, vault still readable |
| >5 starts in 5 minutes | `degraded` — "crash-looping" |
| restarted and healthy again | `ok` — the earlier degraded record does not stick |
| activation refused | `degraded` — the refusal reason, unchanged |

Vault component:

| Situation | `status` vault component |
|---|---|
| vault detected and present | `ok` with the path |
| no vault on this machine | `degraded`, "no vault found … retryable" |
| multiple candidates | `degraded`, both paths listed — never a guess |
| auth failure during retrieval | `degraded`, "authentication failed … re-run vault login" |
| no remote vault on the account | `degraded`, explicitly "NOT an auth failure" |

In every sync failure the vault stays readable locally — a broken sync must
never look like a lost vault.

## Index location (reserved for .11)

`vault.EnsureOutsideVault` refuses any machine-local path that resolves inside
the vault. Vault files sync; machine-local indexes must not. Task .11 owns the
GNO index itself, but the contract lives next to the sync that would otherwise
propagate it.

## Deferred to task .7 (needs Daniel present)

- the **authenticated** disposable-vault smoke against a real Obsidian account
- the first activation against the **real** Daniel-OS vault
- the full conflict-rehearsal matrix (deferred per the spec's Boundaries)

Everything unauthenticated — contract validation against the real pinned build,
checksum verification, the guard, the snapshot, supervision rendering, and
status projection — is exercised now.
