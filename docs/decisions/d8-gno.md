# D8 — GNO: install source, config surface, and lifecycle mode

**Status:** resolved and implemented (task fn-1.11, 2026-08-14).
**Scope:** how Homeplane installs, configures, supervises, and exposes the local
retrieval engine, and which of R4's two lifecycle modes applies to which half.

Everything below was validated against the **real** `gno 1.29.6` binary, not
inferred from documentation. The captured evidence lives in
`internal/agent/gno/testdata/gno-1.29.6-contract.txt`, produced by
`scripts/capture-gno-contract.sh` and asserted by
`TestArgvMatchesThePinnedContract`.

## 1. Install source and prerequisites

- GNO is `@gmickel/gno` (gmickel/gno, <https://gno.sh>), distributed on npm and
  executed by **Bun**.
- Bun ≥ 1.3 is therefore a **new prerequisite**, provisioned exactly the way
  task .4 provisions Node: upstream checksums pinned in
  `scripts/bun-pinned.sha256`, staged by `scripts/stage-release.sh`, verified
  again by `install.sh` against the staging manifest, and installed into
  `$PREFIX/bun` with the previous runtime kept recoverable until the whole
  install succeeds.
- Node and Bun are **both** prerequisites, not alternatives: vault sync runs on
  Node (`obsidian-headless`), the retrieval engine runs on Bun (GNO). An
  installer that accepted one would produce a half-working machine.
- The GNO package itself is pinned by tarball SHA-256 in
  `internal/agent/gno/gno-pinned.sha256` and installed by
  `scripts/fetch-gno.sh`, which verifies the tarball **before** extraction.

**Why no per-file runtime checksum** (unlike obsidian-headless): `ob` executes a
single `cli.js`, so hashing it at every run is a real integrity check. GNO's
entrypoint is a TypeScript module that imports several hundred files from its
package tree; hashing the entrypoint alone would prove nothing about the code
that actually runs. The runtime check is therefore the **version probe**
(`gno --version` must equal the pin) and the integrity check is the
**install-time tarball checksum**. This is stated in the pin file so nobody
later mistakes the difference for an oversight.

## 2. Vault binding and configuration

- Binding is `gno setup <vault> --name <collection> --no-semantic --json`.
- `setup` is a **verified** operation upstream: it only reports success after a
  real lexical retrieval returns a hit. That is why activation uses it rather
  than `collection add` — the activation step and the proof are the same step.
- `--no-semantic` is deliberate. Semantic indexing pulls a ~639 MB model; a
  first install must not do that silently. Embeddings are an explicit later
  step (`gno models pull` / `gno embed`).
- Configuration and data locations are pinned per machine through
  `GNO_CONFIG_DIR`, `GNO_DATA_DIR`, and `GNO_CACHE_DIR`, all under the agent
  state directory. Any ambient `GNO_*` in the environment is **dropped** before
  exec, so a developer's own exported value cannot redirect the agent's index.

## 3. The index: machine-local and disposable (R14)

- Index: SQLite at `<GNO_DATA_DIR>/index-<name>.sqlite` (upstream's own layout).
- Homeplane puts it at `<state-dir>/gno/data/`, i.e. outside the vault by
  construction — and then **asserts** it, because "by default" is not "always":
  `EnsureDisposable` refuses any index directory inside the vault (R14's
  contract, inherited from task .5's `vault.EnsureOutsideVault`) or inside a
  known synchronized tree (iCloud, Dropbox, Google Drive, OneDrive, Nextcloud,
  Syncthing, plus operator-declared roots). Symlinks are resolved first.
- Deleting the index is a **supported operation**: `homeplane-agent gno rebuild`
  discards it and re-runs the verified `setup` from the vault alone. The vault
  is never modified. `TestLiveDeletedIndexSelfHeals` exercises this against the
  real engine.
- A rebuild **stops the daemon first**. The supervised daemon holds the SQLite
  index open continuously, and on Unix removing the file underneath it leaves the
  daemon writing to an unlinked database while every client reads the
  replacement — continuous indexing silently attached to state nobody can see. So
  the rebuild takes an exclusive lock, quiesces the daemon through the platform
  supervisor, rebuilds, verifies, and resumes it (including after a failed
  rebuild — a recoverable problem must not become an outage). With no way to stop
  the daemon it REFUSES rather than racing, and an unobservable daemon counts as
  running. `TestLiveRebuildWhileTheDaemonIsRunning` proves a document written
  after the rebuild reaches the NEW index.

## 4. Lifecycle mode — the decision

R4 offers two mutually exclusive lifecycles and forbids blurring them. GNO
supports **both**, so the honest answer is that the two halves have different
lifecycles, and Homeplane reports each one as what it is:

| Half | Mode | What `status` may claim |
|---|---|---|
| The engine (indexing + health) | **supervised daemon** (`gno --offline daemon --host 127.0.0.1 --port N --mcp-token-file …`) | pid, restart count, crash-loop |
| The harness endpoint | **stdio, per client**, launched through the agent | the per-launch history — never a pid |

**Why the daemon is supervised.** GNO's `daemon` gives live continuous indexing
and watch, so the index stays current without anyone remembering to re-index.
It is a long-lived process, which is exactly what the task .5 supervision
framework was built for: launchd/systemd unit templates, the shared restart
ledger, crash-loop detection, and external liveness probes. The unit runs
`homeplane-agent gno run`, **not** `gno` directly, because the agent recording
its own start and exit in the ledger is the only thing that makes a crash loop
visible to `status` — both supervisors restart a dying process forever without
telling anyone.

`--offline` is part of the decision: without it the daemon downloads model
weights on first start, so a freshly installed machine would spend its first ten
minutes pulling 639 MB from a unit that looks like it is hanging. Verified
empirically — see the probe log in this task's evidence.

`--json` is deliberately NOT passed: upstream accepts it on `daemon` only
together with `--status`, and refuses the long-running form with a VALIDATION
error. Passing it made the daemon fail on every start, and only running the real
binary caught it — the captured contract now records the constraint and a test
enforces it.

**The gateway is loopback-only, and that is checked rather than documented.**
`ValidateGateway` refuses anything that is not a literal loopback IP —
`0.0.0.0`, a LAN address, and even `localhost` (a hostname can be re-pointed in
`/etc/hosts`) — and validates the port range. It runs at activation, at unit
write, and again in the supervised process, because the unit is written once and
then runs for months. The gateway additionally requires a bearer token from a
0600 file (`--mcp-token-file`); harnesses never use this HTTP path, so nothing
legitimate needs it open, and an unauthenticated retrieval endpoint over the
whole vault is the worst thing this component could leave running. The unit
carries the token's PATH, never its bytes.

**Harnesses launch the agent, not the engine.** The descriptor's command is
`homeplane-agent gno mcp`, a transparent stdio pass-through that runs the derived
upstream template with the harness's own pipes attached and records the outcome
of every launch. The reason is R4: a probe taken once at activation cannot report
that launches have been failing since, because a harness starts its own server
whenever it likes and nothing else observes it. The engine's own template is
published alongside as `underlying`, so the indirection stays debuggable and an
operator can run it by hand. `status` reads that launch history and reports a
healthy daemon with failing harness launches as degraded — the two halves fail
independently.

**Why harness access is stdio, not the daemon's HTTP gateway.** The daemon does
expose an MCP gateway on loopback, and Homeplane deliberately does not wire
harnesses to it:

1. It would need a shared bearer token across every harness on the machine, and
   the skeleton has no way to revoke that **per harness** — which is the entire
   point of R9's per-grant revocation.
2. GNO's own installers (`gno mcp install --target claude-code|codex`) emit a
   stdio entry, so stdio is the path upstream supports and tests.
3. A stdio server is started and stopped by the client, so there is no shared
   long-lived process whose failure takes down every harness at once.

The daemon's host and port are still recorded in the descriptor — as
**diagnostics**, explicitly not as the harness path.

## 5. The endpoint descriptor (the D16 seam)

`<state-dir>/endpoints/retrieval-engine.json`, named for the **role**, not the
product. It carries transport, command, argv, environment, server name,
collection, vault path, and a `supervision` block describing the daemon. Task .6
wires harnesses from this file and never learns the word GNO.

The launch template is **derived, not invented**: Homeplane runs
`gno mcp install --target claude-code --scope user --dry-run --json` and records
the server entry upstream itself would have written. Two consequences worth
stating:

- The task .5 review lesson ("never invent a third-party CLI's surface") is
  enforced structurally here rather than by discipline.
- The derivation is only legitimate because upstream emits the **same** entry
  for `claude-code` and `codex` — asserted against the captured contract and
  re-asserted against the live binary, rather than assumed.

A dry run that reports a real write is refused: that would mean upstream changed
a harness config behind task .6's back.

**The endpoint probe is held to ground truth.** Activation asks the index
directly what a correct answer looks like — a document URI from a real lexical
hit — and then requires the stdio endpoint's `gno_search` response to contain
that same URI. Without it a probe passes on an empty result, on an in-band MCP
error (`isError` is reported inside a perfectly successful JSON-RPC response), or
on a server answering from somebody else's index. All three are now refusals, and
an index that returns nothing for any candidate query fails activation rather
than yielding an endpoint nobody verified.

**Installation publishes the descriptor last.** It writes the unit, then the
config, then the removal plan, and only then the descriptor — because the
descriptor is the file other components consume, so it must not exist until
everything it describes does. Any failure along the way rolls back what was
already written; a failed activation leaves no endpoint for task .6 to wire a
harness to.

Descriptors are also refused if they carry anything credential-shaped, because
the descriptor is copied verbatim into harness config files that are not 0600.

## 6. Uninstall-hook registration

`homeplane-agent uninstall` is deferred hardening (spec Boundaries, D17), and
this task does not build it. What activation **does** do is register a
machine-readable removal plan at `<state-dir>/removal/retrieval-engine.json`:
deactivation commands, the unit path, both harnesses' `gno mcp uninstall`
commands, the machine-local paths to delete, and an explicit `keep` list naming
the vault. `homeplane-agent gno deactivate` executes the component's half; the
deferred global uninstall reads the same file. Deleting anything inside a `keep`
path is refused at execution time — an uninstall that deleted synchronized
content would propagate the deletion to every other machine.

## 7. What was proven against the real engine

With `HOMEPLANE_GNO_BIN` set (`internal/agent/gno/live_test.go`):

- a real temporary corpus is indexed, and the index lands **only** under the
  machine-local path — nothing is written into the corpus;
- a real stdio MCP launch completes the handshake, lists tools, and returns the
  corpus's marker phrase from `gno_search` (R6 groundwork);
- deleting the index and rebuilding recovers retrieval from the corpus alone;
- the real daemon starts under `RunDaemon`, **binds its loopback port**, is
  still running when checked (its goroutine has not completed), and returns
  `context.Canceled` when stopped — recorded as a CLEAN exit, because a
  deliberate stop must not inflate the crash-loop signal;
- a rebuild performed while that daemon is running stops it, replaces the index,
  resumes it, and a document written afterwards reaches the new index.

That daemon test is what caught the `--json` argv bug: the earlier version
recorded a start before invoking GNO and never checked whether the process
survived, so a daemon that failed immediately on every start passed.

**The boundary, recorded honestly:** these tests are skipped when
`HOMEPLANE_GNO_BIN` is unset, because a CI machine need not carry Bun and a
10 MB package. Without the binary, this package's guarantees rest on the stub
**plus** the captured upstream contract; with it, they rest on the engine
itself. The evidence artifact records which of the two ran.

## 8. Open follow-up — daemon and stdio cannot share the index (UNRESOLVED)

Found on the live machine during the end-to-end proof (task .7, 2026-08-14) and
recorded in that task's evidence file under the `gno` stage. **This is an open
decision for Daniel, not a defect and not something a later task should quietly
pick a side on.**

**The observation.** gno 1.29.6 allows **one resident runtime per index**. With
the supervised daemon loaded, a harness stdio launch fails with `database is
locked`; with the daemon stopped, the same launch connects. The two lifecycles
§4 deliberately separated turn out to be mutually exclusive on this build for a
single index.

**What the machine does today, and what it costs.** §4 chose supervised-daemon
mode for the indexing half. Since the halves cannot coexist, the stdio half —
the one harnesses actually use — wins, and the daemon is not loaded. The index
is therefore refreshed **at activation, not continuously**. `status` reports
that as `degraded` with the reason spelled out ("supervision unit installed but
not loaded — the index is NOT being kept current") rather than rounding a
partial arrangement up to `ok`. That reporting is the correct behaviour of the
existing design and is not what needs deciding.

**The two candidate resolutions, neither taken:**

1. **Point harnesses at the daemon's own loopback MCP gateway instead of stdio.**
   Restores continuous indexing. The cost is precisely the one §4 rejected the
   gateway for: a single bearer token shared by every harness on the machine,
   which the skeleton cannot revoke **per harness** — the guarantee R9 exists
   for. It would also leave the harness path on a route upstream's own
   installers do not emit, and make one long-lived process a single point of
   failure for every harness at once.
2. **Schedule index refreshes without a resident daemon.** Keeps stdio,
   per-harness revocation, and the upstream-supported path; pays for freshness
   with periodic reindexing instead of watch-driven indexing, and needs a
   refresh cadence chosen against how often the vault actually changes.

A third possibility exists and is not ours to schedule: an upstream gno release
that lets a daemon and a stdio client share one index. Worth re-checking before
committing to either option above.

**Blast radius if this is left as it is:** retrieval keeps working; results go
stale between activations. Nothing about identity, custody, authorization,
audit or revocation is affected — the seam in §5 means whichever way this is
resolved, the change is an endpoint descriptor and a supervision decision, not
a change to any other component.
