# Homeplane server deployment (runbook)

The Homeplane server and its composed gateway, installed on a Linux host under
`systemd --user`, joined to the tailnet as their own node.

Everything Homeplane owns lives under **one prefix** (`~/homeplane` by default)
plus two user units. Nothing is installed system-wide, nothing runs as root, and
nothing shares a directory with whatever else the host is already running. That
is a deliberate constraint: this deploys onto a machine with other people's
services on it.

```
harness  ──tailnet, Bearer <grant token>──►  homeplane-server (tsnet node "homeplane")
                                                 │  control plane: /enrol /grants /healthz
                                                 │  connector edge: /mcp
                                                 ▼  loopback only
                                             thv (ToolHive) workload proxy 127.0.0.1:44022
                                                 ▼
                                             containerized MCP server (rootless podman)
```

The loopback binding is the **bypass boundary**: from any other tailnet node the
only route to the gateway runs through the edge, where the grant token, the
WhoIs machine binding and the connector manifest apply. See D6
(`docs/decisions/d6-gateway.md`) for why the gateway is composed rather than
built.

## Layout on the host

| Path | What | Upgrade behavior |
|---|---|---|
| `<prefix>/bin/homeplane-server`, `<prefix>/bin/thv` | binaries | replaced |
| `<prefix>/etc/server.env` | deployment config (0600) | replaced |
| `<prefix>/etc/manifest.json` | connector manifest the edge authorizes against | replaced |
| `<prefix>/etc/authkey.env` | tailnet bootstrap key (0600) | removed after a successful join |
| `<prefix>/var/` (0700) | SQLite store, age key, tsnet node identity | **never touched** |
| `<prefix>/releases/`, `<prefix>/stage/` | verified archives + last uploaded artifacts | replaced |
| `~/.config/systemd/user/homeplane-{gateway,server}.service` | units | re-rendered |

## Prerequisites

* **Linux + systemd**, and `loginctl enable-linger <user>` — without lingering
  the units stop at logout, which looks exactly like a flapping service.
* **Podman or Docker.** On the production host (clawniel) it is **rootless
  Podman**, not Docker. ToolHive talks to it through the user socket:
  `systemctl --user enable --now podman.socket`. The installer enables it if it
  is missing.
  * Gotcha worth knowing: ToolHive finds that socket via `XDG_RUNTIME_DIR`,
    which is **unset in a non-interactive SSH command**. `ssh host thv run …`
    then fails with *"no container runtime available"* while the systemd units —
    which always have `XDG_RUNTIME_DIR` — work fine. Prefix manual invocations
    with `XDG_RUNTIME_DIR=/run/user/$(id -u)`.
* A **tailnet auth key** for the first join (below).

## Install / upgrade

From the repository, one command:

```bash
deploy/server/deploy.sh --host clawniel --authkey-file '$HOME/.homeplane/authkey'
```

It stages the release (`scripts/stage-release.sh`, which now builds
`homeplane-server-linux-*` alongside the agent), uploads the artifacts and this
directory, and runs `install-server.sh` on the host. `--skip-build` reuses an
existing `dist/`. Drop `--authkey-file` once the node has joined.

To do it by hand (no SSH access from your machine): copy `dist/` plus this
directory to the host and run
`./install-server.sh --stage-dir <dir> [--authkey-file <path>]`.

**Upgrade = the same command with a newer binary.** The state directory, the age
key, the credential store and the tsnet node identity are never re-created; the
units are re-rendered and restarted. Proof, not promise:

```bash
deploy/server/verify.sh --host clawniel --snapshot   # before
deploy/server/deploy.sh --host clawniel
deploy/server/verify.sh --host clawniel --snapshot   # after — same fingerprints
```

Both binaries are verified against checksums before installation: the server
against `dist/SHA256SUMS` from the staging script, ToolHive against
`toolhive-pinned.sha256` in this directory. An unpinned or mismatched artifact
aborts the install with nothing written.

## Tailnet identity (tsnet) — bootstrap and lifecycle

The server joins the tailnet as **its own node** (`homeplane`), not as the
host's tailscaled identity. That is what makes `homeplane.<tailnet>.ts.net` a
name harnesses can be pointed at, independent of the machine it runs on.

* **The auth key is consumed once, at the first join.** After that, tsnet's node
  identity lives in `<prefix>/var/tsnet/` and the key is never consulted again.
  The provided key expiring (90 days) is therefore harmless once the node is up.
* **Key handling.** The key is read from a 0600 file on the host, copied into
  `<prefix>/etc/authkey.env` (0600) and passed to the process as `TS_AUTHKEY`.
  It is never a command-line argument (argv is world-readable via `ps`) and
  never logged. `install-server.sh` **deletes** `etc/authkey.env` once the node
  is registered and the service is running.
* **The recurring concern is the NODE's own key expiry** (Tailscale default
  ~180 days), not the auth key. When it expires the node drops off the tailnet
  and every harness loses the server at once. Turn it off: Tailscale admin
  console → **Machines → `homeplane` → Disable key expiry**.
* **If `<prefix>/var/tsnet/` is ever wiped**, the node must re-join and needs a
  **fresh** auth key at `~/.homeplane/authkey`, then a re-run with
  `--authkey-file`. The old key cannot be reused.
* **No key at all?** The server logs a login URL instead of failing, and waits:

  ```bash
  journalctl --user -u homeplane-server.service | grep -o 'https://login.tailscale.com/a/[a-z0-9]*'
  ```

  Open it, approve the node, and the server continues. (`tsnet`'s user-facing
  log line is routed into the structured log at INFO level for exactly this
  reason — the backend firehose it used to share a logger with runs at DEBUG.)

## Credential store (D3)

`install-server.sh` runs **`admin secret init-key` once**, on a state directory
that has no key yet, and never again — re-running it would generate a new age
key and orphan every stored secret. It is a hard prerequisite for
`admin secret import`, which encrypts against that key.

```bash
# BACK THIS UP OFF THE SERVER. Without it, every stored provider secret is
# unrecoverable — a lost key is not a degraded deployment, it is a destroyed one.
mkdir -p ~/.homeplane/backups && chmod 700 ~/.homeplane ~/.homeplane/backups
scp clawniel:homeplane/var/secrets.age-key ~/.homeplane/backups/clawniel-secrets.age-key
chmod 600 ~/.homeplane/backups/clawniel-secrets.age-key
# Verify the copy rather than assuming scp succeeded:
shasum -a 256 ~/.homeplane/backups/clawniel-secrets.age-key
ssh clawniel 'sha256sum homeplane/var/secrets.age-key'
```

Done for this deployment on 2026-08-14 (copy at
`~/.homeplane/backups/clawniel-secrets.age-key`, 0600, sha256 verified equal to
the on-host key). Move it somewhere genuinely offline when convenient — a
laptop is off the *server*, which is what protects against losing the box, but
it is not a cold backup.

Importing a provider app credential (never as an argument, never echoed):

```bash
# from a 0600 file on the host. NOTE the flag order: Go's flag parser stops at
# the first positional, so the ref goes LAST.
homeplane/bin/homeplane-server admin secret import \
  -state-dir homeplane/var -file ~/secret.txt google/client-secret
# or on stdin
pass show google/client-secret | homeplane/bin/homeplane-server admin secret import \
  -state-dir homeplane/var google/client-secret
```

The refs `google/client-id` / `google/client-secret` named in `manifest.json`
are the **Homeplane-owned Google OAuth app's** credentials. Creating that app is
Daniel's own step (it needs a Google account, not code) and its output feeds
fn-1.12; until it exists there is nothing real to import here. The import path
itself is verified on every deployment against a throwaway ref
(`deploy/bootstrap-selftest`): imported from a 0600 file, encrypted at rest —
the plaintext does not appear in the database — and recorded in the audit log by
ref and generation only.

### Pending: the Google OAuth app credentials

`provider_secret_refs_present` in `verify.sh` **fails today**, on purpose. The
refs the deployed manifest requires — `google/client-id`, `google/client-secret`
— are not in the store, because the Homeplane-owned Google OAuth client does not
exist yet. Creating it is Daniel's own action (an authenticated Google Cloud
Console session on his account; nothing here can or should mint credentials
inside it), and its output feeds fn-1.12.

Deliberately NOT done: reusing the existing Hermes OAuth client on the same
host. Two systems sharing one app identity blurs ownership, makes revocation
ambiguous, and widens the blast radius of a single compromised client.

The completion step, once the client exists (values into 0600 files on the host,
never through a chat channel, never as an argument):

```bash
# on clawniel, after placing ~/.homeplane/google-client-{id,secret} (0600)
cd ~/homeplane
bin/homeplane-server admin secret import -state-dir var -file ~/.homeplane/google-client-id     google/client-id
bin/homeplane-server admin secret import -state-dir var -file ~/.homeplane/google-client-secret google/client-secret
rm -f ~/.homeplane/google-client-id ~/.homeplane/google-client-secret
```

Then re-run `verify.sh` WITHOUT `--pending`; all ten checks must pass.

## Connector manifest

`manifest.json` is what the **edge authorizes against**; it does not start
anything. Only the read surface is mapped — Drive read and Calendar read — with
the Calendar write tool and both Drive write tools declared and *excluded*, so
the edge fails closed on them (D18: Drive is read-only; the Calendar write
mapping and the through-the-stack six-op proof are **fn-1.12**'s).

The workload the gateway actually supervises is `HOMEPLANE_GATEWAY_WORKLOAD` in
`server.env`. Until fn-1.12 lands the real `workspace-mcp` workload it is the
pinned `fetch` server from the D6 spike: a genuine containerized MCP workload,
so the runtime, the supervision and the isolation boundary are all really
exercised, and every tool call through the edge is refused as unmapped — which
is the correct behavior for a server with no connector wired yet.

## Verifying a deployment

Run from a **second tailnet node** (your laptop) — the isolation checks are
meaningless from the server itself:

```bash
deploy/server/verify.sh --host clawniel --fqdn homeplane.tailab4e9b.ts.net
deploy/server/verify.sh --host clawniel --fqdn homeplane.tailab4e9b.ts.net --json
```

| Check | Asserts |
|---|---|
| `units_gateway_active`, `units_server_active` | both units supervised and alive |
| `gateway_bound_loopback_only` | the gateway socket is bound to 127.0.0.1 only |
| `gateway_unreachable_from_peer` | the gateway is **not** reachable over the tailnet |
| `edge_reachable_unauthenticated` | the edge answers over the tailnet, and 401s without a grant token |
| `healthz_green_over_tailnet` | every server component reports ok |
| `admin_cli_audit` | the admin CLI reads and writes the real state directory |
| `credential_key_0600` | the age key exists with 0600 |
| `provider_secret_refs_present` | every `*_ref` the deployed manifest names is in the store **now**, encrypted (currently **pending**, above) |
| `secrets_encrypted_at_rest` | every stored secret is an age message, checked per row |

The last two ask the store, not the audit log: an audit row proves an import
happened once, which a database restored from an empty state would still show.
`admin secret list` answers from current contents and reports metadata only
(ref, generation, encrypted, size) — it has no code path that can return a
value:

```bash
homeplane/bin/homeplane-server admin secret list -state-dir homeplane/var
REF                        GENERATION  ENCRYPTED  BYTES  UPDATED
deploy/bootstrap-selftest  1           true       232    2026-08-13T22:36:55Z
```

A check listed in `--pending` is reported as `pending` with its reason instead of
`fail`, and the run's result becomes `pass_with_pending` — never `pass`. It is
the one honest way to record a step blocked outside this machine; weakening a
check until it goes green is how a verification suite stops verifying:

```bash
deploy/server/verify.sh --host clawniel --fqdn homeplane.tailab4e9b.ts.net \
  --pending provider_secret_refs_present \
  --pending-reason "Homeplane-owned Google OAuth app not created yet (Daniel; feeds fn-1.12)"
```

## Troubleshooting

```bash
systemctl --user status homeplane-server.service homeplane-gateway.service
journalctl --user -u homeplane-server.service -n 100 --no-pager
journalctl --user -u homeplane-gateway.service -n 100 --no-pager
XDG_RUNTIME_DIR=/run/user/$(id -u) homeplane/bin/thv list
homeplane/bin/homeplane-server admin audit -state-dir homeplane/var -limit 20
```

| Symptom | Cause |
|---|---|
| gateway unit restarts in a loop, "no container runtime available" | `podman.socket` not enabled, or `XDG_RUNTIME_DIR` unset |
| `/healthz` 503 with `gateway_runtime` degraded | the gateway unit is down, or its port differs from `HOMEPLANE_GATEWAY_PORT` |
| server exits with "credential store unusable" | the age key is missing — `admin secret init-key` was never run (or `var/` was wiped) |
| everything stops when you log out | lingering is off: `sudo loginctl enable-linger <user>` |
| harnesses get 404 from their endpoint URL | `HOMEPLANE_TAILNET_FQDN` / `HOMEPLANE_ADDR` disagree with where the edge is mounted |

## Uninstall

```bash
systemctl --user disable --now homeplane-server.service homeplane-gateway.service
rm ~/.config/systemd/user/homeplane-{server,gateway}.service
systemctl --user daemon-reload
XDG_RUNTIME_DIR=/run/user/$(id -u) homeplane/bin/thv rm homeplane-gateway
# Back up homeplane/var/secrets.age-key first — deleting it destroys every stored secret.
rm -rf ~/homeplane
```
