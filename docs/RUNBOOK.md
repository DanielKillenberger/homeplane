# Homeplane runbook

Day-two operation of a live Homeplane: reading the two health surfaces, working
through each degraded state, revoking, re-authorizing a provider, and wiring a
harness by hand when the automatic path is not what you want.

For deploying or upgrading the **server**, see `deploy/server/README.md`. For
why any of this is shaped the way it is, see `docs/ARCHITECTURE.md`.

Everything below was run against the live deployment: server `homeplane` on
clawniel (`homeplane.tailab4e9b.ts.net`, systemd `--user`, rootless podman,
state in `~/homeplane/var`), machine agent at `~/.homeplane/bin/homeplane-agent`.

---

## 1. Reading the two health surfaces

They answer different questions and neither can substitute for the other.

```bash
# machine side — what THIS box can actually do
homeplane-agent status
homeplane-agent status -json

# server side — what the control plane's own components are doing
curl -sf http://homeplane.tailab4e9b.ts.net/healthz | jq .
```

`status` exit codes: **0** ok · **1** a named component is degraded · **2** this
machine is not enrolled. `/healthz` returns **200** green and **503** with a
component-level payload when degraded — so a plain `curl -sf` fails, which is
the point: a script that only checks the exit code still notices.

A healthy machine looks like this (the grant table below the summary lists every
grant this machine has ever held, live-reconciled):

```
homeplane: ok
state dir: /Users/daniel/.homeplane
machine:   m-1bc11c520f7c59e2 (Daniels-MacBook-Pro.local, darwin)
server:    http://homeplane.tailab4e9b.ts.net

COMPONENT  STATE  DETAIL
enrolment  ok     machine m-… enrolled at …, credential version 14
vault      ok     /Users/daniel/Documents/daniel-os
sync       ok     …
gno        ok     …
harnesses  ok     claude-code, codex
skills     ok     casual-writing, karpathy-guidelines, professional-writing
grants     ok     active: claude-code, codex (revoked: …)
server     ok     http://homeplane.tailab4e9b.ts.net
```

**Grants are reconciled live on every run.** A revoked grant reads `revoked`,
and a server that cannot be reached makes grant state `unknown (server
unreachable)` — never a stale `active`. `-offline` skips the reconcile
deliberately and reads every server-dependent field as `unknown`.

**Machine failures never appear in `/healthz`.** This is verified rather than
promised: during the end-to-end proof the retrieval engine was deactivated, the
machine went degraded and exited 1, and `/healthz` stayed green with all five
components ok. If you are debugging "is Homeplane up", ask both.

### Known-truthful states on Daniel's Mac today

These two are **chosen arrangements**, not faults, and `status` names them
rather than rounding them up to fine:

| Component | Reads | Why |
|---|---|---|
| `sync` | `not_configured` | Daniel keeps Obsidian.app as the vault's operating sync client. Homeplane detects the vault and never writes to it. Detect-only is the decision, so nothing here needs "fixing". |
| `gno` | `degraded` — "supervision unit installed but not loaded — the index is NOT being kept current" | gno 1.29.6 allows one resident runtime per index (§7). The stdio half — which is what harnesses actually use — works; the indexing daemon is stopped, so the index refreshes at activation rather than continuously. |

Both make `status` exit 1. That is correct: the machine is not in its fully
configured shape, and the exit code says so.

---

## 2. Degraded states, and what to do about each

Work the component the detail names. Every one of these was reached on purpose
during the end-to-end proof, so the message you get is the message it was tested
against.

### `enrolment` — not enrolled, or credential refused

```bash
homeplane-agent enrol -server http://homeplane.tailab4e9b.ts.net
```

Re-running `enrol` on an already-enrolled machine is **identity-preserving
rotation**: same `machine_id`, a new credential, the old one invalid
immediately. It is never a duplicate identity and never a silent no-op. If the
server cannot be reached, **nothing is written** to `~/.homeplane` — retry when
it is back. Concurrent enrolments are safe: the state directory is locked, and a
response older than the stored credential version is discarded rather than
written over the live credential.

### `vault` — degraded (path missing) or ambiguous

```bash
homeplane-agent vault detect                     # never guesses
homeplane-agent vault detect -vault-path DIR -record
homeplane-agent vault retrieve -path DIR         # when the vault is absent
```

Multiple candidate vaults require an explicit `-vault-path`; the agent will not
pick one for you. A vault whose recorded path no longer exists reads
`degraded (vault path … does not exist)` and the machine exits 1. Enrolment and
the server connectors are unaffected — the stages fail independently.

### `sync` — `not_configured`, or a sync failure

Only relevant if you want Homeplane supervising Obsidian Sync (on this machine,
Daniel does not — see §1). Activation is a fixed safety sequence and every step
can refuse:

```bash
homeplane-agent vault login -email <address>     # password on stdin, never argv
homeplane-agent vault set-e2e-password           # stdin
homeplane-agent vault sync activate
homeplane-agent vault sync apply                 # load the installed unit
```

1. the CLI must be the pinned, checksummed `obsidian-headless` build;
2. a **disposable** vault must survive a pass on that build first;
3. the real vault is snapshotted before it is ever synced;
4. a pass that deletes or rewrites too much aborts activation.

A sync auth failure is reported distinctly from a network failure, and either
way the vault stays readable locally. Retry is just re-running `activate`.

### `gno` — retrieval engine degraded

```bash
homeplane-agent gno doctor          # the engine's own health report
homeplane-agent gno endpoint        # what harnesses are wired from
homeplane-agent gno apply           # load the supervision unit
homeplane-agent gno activate -apply # re-bind the vault and re-publish
homeplane-agent gno rebuild         # discard the index, rebuild from the vault
```

Read the detail rather than the word: it carries the vault path, the collection,
the engine version, the index location, the `gno doctor` check count, and **the
result of the last stdio launch**. `status` never claims a pid for the stdio
half — a harness starts its own server whenever it likes, so the launch history
is the only honest signal.

A healthy daemon with failing harness launches is reported degraded: the two
halves fail independently and are reported independently.

`gno rebuild` stops the daemon before replacing the index and resumes it
afterwards, and refuses rather than racing if it cannot. The index is disposable
by design — deleting it is supported, and rebuild recovers it from the vault
alone.

Model-weight warnings in `doctor` (`embed-model warn`, `rerank-model warn`,
`gen-model warn`, `embedding-fingerprint warn`) are GNO's own report about
optional model assets; lexical retrieval works without them, which is what the
proof exercised.

### `harnesses` — a harness was skipped

A **malformed existing config** aborts that harness with a clear message and the
backup intact. Homeplane never clobbers a config it cannot parse. Fix the file
(or restore the backup, §5) and re-run:

```bash
homeplane-agent configure-harnesses
```

It is idempotent, and re-running it is also the recovery path after a revocation
(§3): it requests a fresh grant and rewrites the entry.

### `skills` — unsupported or refused

```bash
homeplane-agent skills list
homeplane-agent skills provision -verify
homeplane-agent skills refresh
```

`-verify` spawns each harness and requires it to enumerate what was linked —
that, not Homeplane's own record, is what proves provisioning. Neither probe
makes a model request.

Two refusals are intentional and will not be argued out of: a skill carrying
credential material or runtime state is never linked, and a skill that drives
host scheduling or service control is marked unsupported with the line that
matched it. A skill whose vault slug and SKILL.md `name` disagree is refused
rather than provisioned under two names.

### `grants` — revoked, or unknown

`revoked` is usually intentional (§3); recover with `configure-harnesses`.
`unknown (server unreachable)` means exactly that — check `/healthz` and the
tailnet before assuming anything about authority.

### `server` — `/healthz` degraded

```bash
curl -s http://homeplane.tailab4e9b.ts.net/healthz | jq .
ssh clawniel 'systemctl --user status homeplane-server.service homeplane-gateway.service'
ssh clawniel 'journalctl --user -u homeplane-server.service -n 100 --no-pager'
```

| Component degraded | Where to look |
|---|---|
| `gateway_runtime` | the gateway unit is down, or its port differs from `HOMEPLANE_GATEWAY_PORT`. `gateway unreachable: … connection refused` is the message the proof produced by stopping it deliberately. |
| `store` | the SQLite state directory — disk, permissions, `~/homeplane/var` |
| `credential_store` | the age key is missing (`var/secrets.age-key`); `admin secret init-key` was never run, or `var/` was wiped |
| `tsnet` | the node's own key expired, or `var/tsnet/` was wiped (see `deploy/server/README.md`) |
| `workload_credential` | a credential is stored but was not delivered to the connector workload. Re-run `add-credentials -replace`, or check the credential dir's group/setgid under rootless podman. |

Full deployment re-verification, run from a **second** tailnet node (the
isolation checks are meaningless from the server itself):

```bash
deploy/server/verify.sh --host clawniel --fqdn homeplane.tailab4e9b.ts.net
deploy/server/verify.sh --host clawniel --fqdn homeplane.tailab4e9b.ts.net --json
```

Eleven checks, all of which must pass; `--pending <check>` is the only honest
way to record a step blocked outside the machine, and it downgrades the run's
result to `pass_with_pending` rather than `pass`.

---

## 3. Revoking

Revocation is **server-side**. It does not require touching the machine, and it
takes effect on the next call — the edge resolves the grant from the store on
every request, so there is no cache to wait out. Measured during the proof: the
revoked harness was refused and the refusal audited, with zero calls admitted on
that grant afterwards, while the other harness's next call succeeded.

```bash
# operator, on the server host (authority is shell access — there is no
# operator HTTP credential to leak)
ssh clawniel 'cd homeplane && bin/homeplane-server admin revoke-grant -state-dir var <grant-id>'
```

```bash
# the machine revoking its own grant, over the API
DELETE /grants/{grant_id}     # machine-credential auth
```

Semantics, all of them exercised:

- **Repeat revocation is idempotent** — exit 0, "was already revoked at …"
  (HTTP 200 over the API).
- **An unknown grant is an error, not a silent success** — exit 1 from the CLI,
  HTTP 404 over the API.
- **Cross-machine revocation** happens only through the server-local admin CLI;
  over the API a grant must belong to the calling machine.
- **The revocation is audited**, as are the refusals that follow it.

Find the grant id from either side:

```bash
homeplane-agent status                       # the grant table
ssh clawniel 'cd homeplane && bin/homeplane-server admin audit -state-dir var -limit 20'
```

**Recovery** is one command on the machine — it requests a fresh grant and
rewrites the harness entry:

```bash
homeplane-agent configure-harnesses
```

Machine-level revocation and revocation tombstones (`--block`/unblock) are
deferred hardening (see `docs/ARCHITECTURE.md`). A lost machine is handled by
revoking its grants and rotating.

---

## 4. Re-authorizing a provider (`add-credentials`)

```bash
homeplane-agent add-credentials google              # first time
homeplane-agent add-credentials google -replace     # re-authorize
homeplane-agent add-credentials google -no-browser  # print the URL instead
```

The consent screen opens on the machine where you run it. The credential is
stored **only on the server** and is usable by every enrolled machine's grants
the moment it lands — this machine never receives, writes or logs a provider
token.

**A configured provider is refused rather than overwritten.** Observed exactly:

```
homeplane-agent add-credentials: start credential flow: server refused the
request (409 conflict): provider "google" already has a credential; re-run with
replace to authorize a new one (the existing credential stays active until the
replacement is stored)
```

**`-replace` is an atomic swap.** The existing credential stays active until the
new one is durably stored, so a declined, expired, failed or abandoned flow
leaves it exactly as it was. Two flows racing for the same provider produce one
commit and one clear "nothing was overwritten, re-run to retry" — never a silent
overwrite.

### When to expect to run this: Testing-mode token expiry

The Homeplane-owned Google OAuth app runs in OAuth **"Testing"** mode (no
verification required, which is why it exists at all). Google gives
testing-mode refresh tokens a **limited lifetime** — they stop working after
roughly a week, without anything on our side changing.

The symptom is Google-side, so it does **not** show up as a Homeplane component
failure: `status` and `/healthz` stay green, and connector calls start failing
with the connector reporting that the user must authenticate again. The fix is
always the same:

```bash
homeplane-agent add-credentials google -replace
```

This is an accepted skeleton limitation, not a bug to hunt. Publishing the app
(or moving it to an internal Workspace app) is what removes the expiry, and that
is a decision beyond the skeleton.

Two related failure shapes worth recognizing, both found the hard way and both
fixed in the deployment:

- the connector resolves its OAuth **client** separately from the user
  credential (`GOOGLE_CLIENT_SECRET_PATH`) and refuses to refresh without it;
- it **persists** the refreshed token, so a credential it can read but not
  rewrite dies at the first expiry — reporting "authenticate again" moments
  after a refresh actually succeeded.

If `add-credentials` reports the credential is stored but **not usable yet**,
storage succeeded and delivery to the connector workload did not: `/healthz`
shows `workload_credential` degraded until a later delivery succeeds. Storage
and readiness are separate claims and the deployment reports them separately.

The provider list comes from the connector manifest; an unknown provider is a
404 listing the known ones.

---

## 5. Where the logs, state and backups are

### On a machine (`~/.homeplane`, override with `HOMEPLANE_AGENT_STATE_DIR`)

| Path | What |
|---|---|
| `bin/homeplane-agent` | the installed agent |
| `state.json`, `machine.cred` | enrolment record and machine credential (0600) |
| `logs/gno.log`, `logs/gno.err.log` | the supervised retrieval-engine daemon's stdout/stderr |
| `endpoints/retrieval-engine.json` | the endpoint descriptor harness config is generated from |
| `endpoints/retrieval-engine.launches.json` | the stdio launch history `status` reports |
| `harnesses/claude-code.json`, `harnesses/codex.json` | what Homeplane wrote into each harness, and where |
| `skills/skill-links.json` | the skill links Homeplane created — and the only ones it will ever touch |
| `gno/data/index-*.sqlite` | the machine-local, disposable index (never in the vault) |
| `gno/config`, `gno/cache` | engine config and cache |
| `supervise/`, `removal/` | supervision ledger; per-component removal plans |
| `backups/` | operator backups (e.g. the copied server age key) |

Supervision units themselves are platform-native:
`~/Library/LaunchAgents/com.homeplane.*.plist` (macOS) or
`~/.config/systemd/user/homeplane-*.service` (Linux).

**Harness config backups sit next to the config they protect**, timestamped, one
per write:

```
~/.claude.json.homeplane-backup-20260814T161203Z
~/.codex/config.toml.homeplane-backup-20260814T161203Z
```

To roll a harness back, copy the backup over the config and re-run
`configure-harnesses` (which will issue a fresh grant — the token in an old
backup is revoked by supersession).

### On the server (`~/homeplane`)

| Path | What |
|---|---|
| `bin/homeplane-server`, `bin/thv` | binaries (replaced on upgrade) |
| `etc/server.env`, `etc/manifest.json` | deployment config (0600) and the manifest the edge authorizes against |
| `var/` (0700) | SQLite store, age key, tsnet node identity — **never touched by an upgrade** |
| `var/secrets.age-key` | the key every stored provider secret is encrypted against |
| `releases/`, `stage/` | verified archives and the last uploaded artifacts |

Logs are journald, not files:

```bash
ssh clawniel 'journalctl --user -u homeplane-server.service -n 100 --no-pager'
ssh clawniel 'journalctl --user -u homeplane-gateway.service -n 100 --no-pager'
```

The audit log is in SQLite and is read through the admin CLI, never over HTTP:

```bash
ssh clawniel 'cd homeplane && bin/homeplane-server admin audit -state-dir var --since 24h'
ssh clawniel 'cd homeplane && bin/homeplane-server admin audit -state-dir var --json'
```

**Back up `var/secrets.age-key` off the server.** Without it every stored
provider secret is unrecoverable — a lost key is not a degraded deployment, it
is a destroyed one. The current copy is at
`~/.homeplane/backups/clawniel-secrets.age-key` (0600, sha256-verified equal to
the on-host key). A laptop is off the *server*, which protects against losing
the box; it is not a cold backup.

Two operational gotchas that cost real time:

- **`XDG_RUNTIME_DIR` is unset in a non-interactive SSH command**, so
  `ssh clawniel thv list` fails with "no container runtime available" while the
  systemd units work fine. Prefix manual invocations with
  `XDG_RUNTIME_DIR=/run/user/$(id -u)`.
- **Without `loginctl enable-linger`** the user units stop at logout, which
  looks exactly like a flapping service.

---

## 6. Wiring a harness by hand

`homeplane-agent configure-harnesses` is the supported path — it merges
semantically, backs up first, and records what it wrote. These recipes are for
**debugging the endpoint itself**, or reconfiguring one of the two supported
harnesses by hand.

Two constraints, both enforced server-side rather than by convention:

- **Only `claude-code` and `codex` exist.** Server policy names exactly those
  two harnesses (`internal/policy`), so a grant request for anything else is
  refused. Wiring an unsupported harness is not a documentation gap you can
  work around here — it needs the policy to name it first.
- **Use a freshly issued grant for the harness you are wiring — never another
  harness's token.** Reusing one makes every call appear under the *original*
  harness: the audit attributes it there, and revoking the harness you think
  you configured leaves the calls working. Per-harness attribution and
  revocation are the two things the grant model actually guarantees, and
  sharing a token discards both.

Issue one over `POST /grants` (machine-credential auth, `{harness,
capabilities}`), or simply re-run `configure-harnesses`, which issues a fresh
grant per harness and supersedes the previous one. The response's
`endpoint_url` is the URL to use below.

### Claude Code (2.1.227)

```bash
claude mcp add --transport http homeplane \
  http://homeplane.tailab4e9b.ts.net/mcp \
  --header "Authorization: Bearer <claude-code grant token>"
```

Verified against the live edge: the health check reports `✔ Connected` (a real
initialize handshake) and calls forward through the edge. Use **user or local
scope only** — never project scope, which lands the token in a git-shared
`.mcp.json`.

### Codex CLI (0.146.0)

In `~/.codex/config.toml` (the file must be 0600):

```toml
[mcp_servers.homeplane]
type = "http"
url = "http://homeplane.tailab4e9b.ts.net/mcp"

[mcp_servers.homeplane.http_headers]
Authorization = "Bearer <codex grant token>"
```

`bearer_token_env_var` also works on this version (that is how the D6 spike
supplied a static bearer via `-c` overrides), but Homeplane deliberately writes
the header **inline** instead. Any environment indirection —
`bearer_token_env_var`, `env_http_headers`, `env` — makes the token depend on
the launching process's environment: it works in the shell that exported the
variable and fails from a launchd-started editor, a desktop app, or anything
else that did not inherit that shell. `http_headers` carries the bearer with no
environment involved at any point, verified against the real `codex` binary
launched with an **empty** environment. The config file is 0600 either way.

### The nuance that will waste an afternoon: `codex exec` cancels MCP tool calls

Under `codex exec` with the **default read-only sandbox**, MCP tool calls are
auto-cancelled — the transcript says *"user cancelled MCP tool call"* and
nothing reaches the edge. The MCP server is connected and the config is correct;
the sandbox is refusing the call.

An interactive Codex session, or a permissive approval policy, is required for
MCP tools to actually run. If you are testing the connector from `codex exec`
and seeing cancellations with an empty server-side audit, this is why — check
the audit log before suspecting auth:

```bash
ssh clawniel 'cd homeplane && bin/homeplane-server admin audit -state-dir var -limit 20'
```

No audit row at all means the call never left the client.

### The local retrieval engine (both harnesses)

Generate from the descriptor rather than hand-writing it:

```bash
homeplane-agent gno endpoint -json
```

It is a stdio entry whose command is `homeplane-agent gno mcp` — the agent's
transparent pass-through, which is what makes every launch (including the failing
ones) visible to `status`. The engine's own template is published alongside as
`underlying` for debugging by hand.

### Skills need no config at all

Both harnesses discover skills from a directory
(`~/.claude/skills`, `~/.codex/skills`), so nothing in this section applies to
them. Use `homeplane-agent skills provision -verify`.

---

## 7. Open: the GNO daemon/stdio index lock (D8 follow-up)

**Unresolved — a decision for Daniel, recorded here so it is not mistaken for a
fault.**

gno 1.29.6 allows **one resident runtime per index**. With the supervised daemon
loaded, a harness stdio launch fails with `database is locked`; with the daemon
stopped, the same launch connects. D8 chose supervised-daemon mode, so on this
machine the two modes cannot coexist and the stdio half — the one harnesses
actually use — wins.

The cost, stated plainly and reported by `status` rather than hidden: **the
index is not being kept current.** It refreshes when activation runs, not
continuously.

The two candidate resolutions, neither taken:

1. point harnesses at the daemon's own loopback MCP gateway instead of stdio —
   which reintroduces a bearer token shared by every harness on the machine,
   with no per-harness revocation (the thing R9 exists to guarantee); or
2. schedule index refreshes without a resident daemon — keeping stdio and
   per-harness revocation, and paying for freshness with periodic reindexing.

See `docs/decisions/d8-gno.md` §8. Do not "fix" the degraded `gno` state by
loading the daemon: that trades a reported staleness for silently broken harness
retrieval.
