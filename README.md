# homeplane

Self-hosted capability plane for personal AI agents.

Homeplane enrols a machine over Tailnet, issues per-(machine, harness) grants
with their own revocable tokens, keeps provider credentials on the server, and
records every lifecycle event in an append-only, metadata-only audit log. Your
harnesses get the vault, the retrieval engine, your skills, and the Google
connectors — and you get one place to see and revoke all of it.

```
machine: vault · retrieval engine · skills · harness config
   │  tailnet, Bearer <grant token>
server: enrolment · grants · audit · provider credentials · composed gateway
```

**Where to go next**

| Document | What it answers |
|---|---|
| this page | how do I install a machine and check that it worked |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | it is running — how do I read status, fix a degraded component, revoke, re-authorize, find the logs |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | how is it built, what does it actually guarantee, and what is deliberately missing |
| [`deploy/server/README.md`](deploy/server/README.md) | deploying and upgrading the server itself |
| [`docs/decisions/`](docs/decisions/) | why each contested choice went the way it did |

---

## Install

The server must already be deployed (`deploy/server/README.md`) and reachable on
the tailnet. Then, on the machine:

```bash
scripts/stage-release.sh dist        # agent binaries + pinned Node 22 + Bun 1.3 + SHA256SUMS
./install.sh --stage-dir dist        # verify checksums, provision both runtimes, install
```

Supported: **macOS 13+ (launchd)** and **systemd-based Linux** with
`systemctl --user` and linger. Anything else is rejected *before* anything is
written. The installer validates artifact checksums, that the agent binary runs
here, and that the extracted Node runtime runs and reports 22+, all before it
touches the install prefix — and it keeps the previous Node runtime until the
whole install has landed, restoring it if any step fails. A checksum mismatch
aborts with nothing installed. A re-run is an idempotent refresh that leaves
enrolment state alone.

Node and Bun are both prerequisites, not alternatives: vault sync runs on Node
(`obsidian-headless`), the retrieval engine runs on Bun (GNO, D8). A machine
that cannot get either fails the install rather than ending up quietly unable to
sync its vault. `stage-release.sh` verifies each runtime against its upstream
checksums (`scripts/node-pinned.sha256`, `scripts/bun-pinned.sha256`) before
allowing it into the staging directory — which is what makes a fresh-machine
install work, since macOS has no package-manager fallback.

## Enrol

```bash
~/.homeplane/bin/homeplane-agent enrol -server http://homeplane.<tailnet>.ts.net
```

Enrolment is identity-preserving: re-running it rotates this machine's
credential on the same server-side record, and the previous credential stops
working immediately. If the server cannot be reached, nothing is written to
`~/.homeplane`. Concurrent enrolments are safe — the state directory is locked
for the write, and a response older than the stored credential version is
discarded rather than written over the live one.

Then bring up the rest of the machine:

```bash
homeplane-agent vault detect -record                  # or: vault retrieve -path DIR

# fetch-gno.sh prints the pinned executable's path; activation needs it, because
# a package installed under --prefix is on no PATH.
GNO_BIN=$(scripts/fetch-gno.sh --prefix ~/.homeplane/gno-pkg)
homeplane-agent gno activate -apply -bin "$GNO_BIN"   # bind the vault, supervise, publish

homeplane-agent configure-harnesses                   # Claude Code + Codex + grok, one grant each
homeplane-agent skills provision -verify              # link vault skills, prove in a fresh process
homeplane-agent add-credentials google                # consent here, credential stays on the server
```

Each step is independent: enrolment succeeding while GNO fails still leaves the
server connectors usable, and `status` names which stage is where.

**The scheme is `http://`, deliberately.** The server listens on plain HTTP
inside the tailnet (`HOMEPLANE_ADDR=:80`) — Tailscale is the transport boundary,
and there is no public listener to protect with TLS. Tailnet reachability is
never treated as authorization: every capability call still requires a valid
grant. Pointing an `https://` URL at it fails the TLS handshake.

## Verify

```bash
homeplane-agent status                                        # machine side
curl -sf http://homeplane.<tailnet>.ts.net/healthz | jq .     # server side
```

`status` exits **0** ok, **1** a named component is degraded, **2** not enrolled;
grants are reconciled live against the server on every run, so a revoked grant
reads `revoked` and an unreachable server makes grant state `unknown` rather
than a stale `active`. `/healthz` reports **server** components only and returns
503 with a component-level payload when degraded, so `curl -sf` fails.

Machine-local failures are `status`'s job and never appear in `/healthz`. That
separation is checked, not promised. Reading either surface, and what to do
about each degraded component, is [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

To re-verify the **server** deployment — run from a second tailnet node, because
the isolation checks are meaningless from the server itself:

```bash
deploy/server/verify.sh --host <server> --fqdn homeplane.<tailnet>.ts.net
```

End-to-end, from the harnesses themselves: the recorded proof of a real machine
installed, enrolled, configured, and exercised against the live server is
`test/evidence/fn-1-homeplane-walking-skeleton-install.7.live.json` — fourteen
stages, each assertion carrying the observation that settles it, with connector
claims settled by the server's own audit log rather than by what a harness said
it did.

---

## Layout

| Path | What it is |
|---|---|
| `cmd/homeplane-server` | Control plane: tsnet-embedded HTTP server + server-local admin CLI |
| `cmd/homeplane-agent` | Machine agent: `enrol`, `status`, `vault`, `gno`, `configure-harnesses`, `skills`, `add-credentials` |
| `internal/agent` | Agent state directory, control-plane client, enrolment, status |
| `internal/agent/vault` | Vault detection, retrieval, supervised continuous sync |
| `internal/agent/gno` | Retrieval engine: install, disposable machine-local index, supervision, endpoint descriptor |
| `internal/agent/harness` | Merge-only harness configuration writer (Claude Code, Codex, grok) |
| `internal/agent/skills` | Vault skill discovery, profiles, linking, fresh-process verification |
| `internal/agent/credflow` | Machine half of the credential flow: loopback listener, browser, relay |
| `internal/server` | Enrolment, grant lifecycle, audit, health handlers |
| `internal/server/credflow` | Credential broker: the OAuth flow state machine and credential swap |
| `internal/server/connectors` | Connector manifest, policy engine, audit derivation, in-process broker |
| `internal/server/edge` | Streamable-HTTP MCP edge: grant auth, WhoIs machine binding, gateway forwarding |
| `internal/policy` | Server-side per-harness capability policy |
| `internal/cred` | Credential minting, hashing, audit fingerprints |
| `internal/secrets` | age encryption for provider secrets at rest |
| `internal/store` | SQLite persistence (machines, grants, audit, encrypted secrets) |
| `internal/health` | Server-component health probes |
| `internal/tsnetid` | tsnet WhoIs identity resolution |
| `install.sh` | Installer: platform gating, checksummed artifacts, Node 22 + Bun 1.3 provisioning |
| `deploy/server` | Server deployment: units, manifest, installer, `verify.sh` |
| `test/evidence` | Versioned evidence artifacts, one per implementation task |
| `spike/` | Disposable D6-spike prototypes — not production code |

## Build and test

```bash
go build ./...
go test ./...

# Record a versioned evidence artifact for a flow task
scripts/emit-evidence.sh <task-id>   # -> test/evidence/<task-id>.json
```

## Running the control plane

```bash
export HOMEPLANE_STATE_DIR=/var/lib/homeplane

# One-time: create the age key protecting provider secrets (back it up offline)
homeplane-server admin secret init-key

homeplane-server serve \
  --hostname homeplane \
  --addr :80 \
  --connector-endpoint-url http://homeplane.<tailnet>.ts.net/mcp \
  --gateway-health-url http://127.0.0.1:8080/health \
  --connector-manifest /etc/homeplane/connectors.json \
  --gateway-mcp-url http://127.0.0.1:44022/mcp
```

The edge is served on `--connector-edge-path` (default `/mcp`) once **both**
`--connector-manifest` and `--gateway-mcp-url` are given; supplying one without
the other is refused rather than quietly serving no connectors.
`--connector-endpoint-url` is then required and its path must match the mount
path — that URL is handed to every harness with its grant, so a mismatch would
issue working grants pointing at an endpoint that answers 404. A mount path that
would shadow a control-plane route (`/enrol`, `/grants`, `/healthz`) is refused
at startup, and `--gateway-mcp-url` must be a **loopback** address: that binding
is the bypass boundary.

## Operator surface

The admin CLI is server-local by design — operator authority is shell access to
the server host, so there is no operator HTTP credential to leak.

```bash
homeplane-server admin audit --since 24h            # or --json
homeplane-server admin revoke-grant <grant-id>      # any machine's grant
pass show google/oauth-client | \
  homeplane-server admin secret import google/oauth-client
```

Secret values are never accepted as command-line arguments (argv is
world-readable via `ps`): pipe them on stdin, or pass `-file` pointing at a 0600
file.

---

Scope, requirements and the decisions behind them live in `STRATEGY.md`,
`.flow/specs/`, and `docs/decisions/`.
