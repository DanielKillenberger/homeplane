# homeplane

Self-hosted capability plane for personal AI agents.

Homeplane enrols a machine over Tailnet, issues per-(machine, harness) grants
with their own revocable tokens, keeps provider credentials on the server, and
records every lifecycle event in an append-only, metadata-only audit log.

Architecture, decisions, and scope live in `STRATEGY.md`,
`.flow/specs/`, and `docs/decisions/`.

## Layout

| Path | What it is |
|---|---|
| `cmd/homeplane-server` | Control plane: tsnet-embedded HTTP server + server-local admin CLI |
| `cmd/homeplane-agent` | Machine agent: `enrol`, `status`, `add-credentials` |
| `internal/agent` | Agent state directory, control-plane client, enrolment, status |
| `internal/agent/credflow` | Machine half of the credential flow: loopback listener, browser, relay |
| `internal/server/credflow` | Credential broker: the OAuth flow state machine and credential swap |
| `install.sh` | Installer: platform gating, checksummed artifacts, Node 22 provisioning |
| `internal/store` | SQLite persistence (machines, grants, audit, encrypted secrets) |
| `internal/server` | Enrolment, grant lifecycle, audit, health handlers |
| `internal/server/connectors` | Connector manifest, policy engine, audit derivation, in-process broker |
| `internal/server/edge` | Streamable-HTTP MCP edge: grant auth, WhoIs machine binding, gateway forwarding |
| `internal/policy` | Server-side per-harness capability policy |
| `internal/cred` | Credential minting, hashing, audit fingerprints |
| `internal/secrets` | age encryption for provider secrets at rest |
| `internal/health` | Server-component health probes |
| `internal/tsnetid` | tsnet WhoIs identity resolution |
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
  --addr :443 \
  --connector-endpoint-url https://homeplane.<tailnet>.ts.net/mcp \
  --gateway-health-url http://127.0.0.1:8080/health \
  --connector-manifest /etc/homeplane/connectors.json \
  --gateway-mcp-url http://127.0.0.1:44022/mcp
```

`GET /healthz` reports **server** components only (store, gateway runtime,
tsnet, credential store) and returns 503 with a component-level payload when
any is degraded, so `curl -sf .../healthz` fails. Machine-side state
(enrolment, vault, sync, GNO, harness config) belongs to `homeplane-agent
status`.

## The connector edge

The control plane and the connector edge share one tsnet listener. The edge is
served on `--connector-edge-path` (default `/mcp`) once **both**
`--connector-manifest` and `--gateway-mcp-url` are given; supplying one without
the other is refused rather than quietly serving no connectors.

A harness points at the edge with the grant token it was issued:

```
harness  --(streamable HTTP + Authorization: Bearer <grant token>, tailnet)-->  edge
edge     --(loopback HTTP, grant token stripped)-->  composed gateway (ToolHive)
```

What the edge adds, and nothing else (D6's adopted shape — see
`docs/decisions/d6-gateway.md`):

- **Grant authentication**, resolved from the store on every request. There is
  no token cache, so a revoked grant stops working on the next call.
- **Machine binding**: the WhoIs-observed tailnet node must be the node the
  grant's machine enrolled from. A token replayed from another node is refused
  and audited against the node that sent it, never against the token's owner.
- **Manifest authorization and the authoritative audit row** for every
  `tools/call`, via `internal/server/connectors` — unmapped and excluded tools
  fail closed, and a call that cannot be recorded is not forwarded.

`--gateway-mcp-url` must be a **loopback** address and is refused otherwise:
the isolation guarantee is that the only route to the gateway from another
tailnet node runs through the edge. Every other MCP frame (initialize,
`tools/list`, the SSE stream, session teardown) is forwarded verbatim with the
Homeplane grant token stripped — MCP semantics stay with the gateway.

## Installing a machine

```bash
scripts/stage-release.sh dist        # agent binaries + pinned Node 22 + SHA256SUMS
./install.sh --stage-dir dist        # verify checksums, provision Node 22, install

~/.homeplane/bin/homeplane-agent enrol -server https://homeplane.<tailnet>.ts.net
~/.homeplane/bin/homeplane-agent status
```

`stage-release.sh` stages both halves of a release: the cross-compiled agent for
every supported platform, and the pinned Node 22 runtime, verified against the
upstream checksums in `scripts/node-pinned.sha256` before it is allowed into the
staging directory. That is what makes a fresh-machine install work — macOS has
no package-manager fallback.

The installer supports macOS (launchd) and systemd-based Linux with
`systemctl --user`; anything else is rejected **before** anything is written. It
validates everything — artifact checksums, that the agent binary runs here, that
the extracted Node runtime runs and reports 22+ — before it touches the install
prefix, and it keeps the previous Node runtime until the whole install has
landed, restoring it if any step fails. A checksum mismatch aborts with nothing
installed, and a re-run is an idempotent refresh that leaves enrolment state
alone. A machine that cannot get Node 22 (staged tarball, or the distribution's
package manager with `HOMEPLANE_NODE_PACKAGE=1`) fails the install rather than
ending up quietly unable to sync its vault.

Enrolment is identity-preserving: re-running `enrol` rotates this machine's
credential on the same server-side record and the previous credential stops
working immediately. If the server cannot be reached, nothing is written to
`~/.homeplane`. Concurrent enrolments are safe: the state directory is locked
for the write, and a response older than the stored credential version is
discarded rather than written over the live credential.

`homeplane-agent status` reconciles grants **live** against the server on every
run: a revoked grant reads `revoked`, and a server that cannot be reached makes
grant state `unknown` rather than a stale `active`. Exit codes are `0` ok, `1`
a named component is degraded, `2` this machine is not enrolled.

## Authorizing a provider

```bash
homeplane-agent add-credentials google-drive            # first time
homeplane-agent add-credentials google-drive -replace   # re-authorize
```

The provider's consent screen opens on the machine where you run it, and the
credential is stored **only on the server** — this machine never receives,
writes, or logs a provider token, and every enrolled machine's grants can use
the credential the moment it lands.

The flow is an asynchronous state machine (`pending` → `completed` | `denied` |
`expired` | `failed`), driven from the machine but decided by the server:

- The agent binds a loopback listener **first** and passes that exact address as
  the redirect URI; the server validates it is genuinely `http://127.0.0.1:<port>`
  or `http://[::1]:<port>` and uses the identical URI when building the
  authorization URL and again at token exchange.
- The authorization outcome is relayed **once** (a replay is refused with 409),
  with PKCE and the state parameter verified server-side.
- Replacement is an atomic swap: the existing credential stays active until the
  new one is durably stored, so a declined, expired, failed, or abandoned flow
  leaves it exactly as it was. Two flows racing for the same provider produce
  one commit and one clear "nothing was overwritten, re-run to retry".
- A terminal failure returns a safe diagnostic — `{error_code, message,
  retryable}` from a closed vocabulary — that can never carry a provider
  response body or token.

Providers come from the connector manifest (`homeplane-server serve
-connector-manifest …`): onboarding another OAuth provider is a manifest entry
plus its client credentials, with no code change.

## Audit guarantees

The audit log is authoritative (D13), so it is fail-closed in both directions:

- A lifecycle mutation (enrolment, credential rotation, grant issuance or
  supersession, revocation, secret import) and its audit rows commit in one
  SQLite transaction — if the record cannot be written, the change does not
  happen.
- A rejected call that cannot be recorded returns 503 rather than a plain
  401/403. The request is refused either way; the different status says the
  server could not uphold its own audit guarantee.

Rows are metadata only — enforced by the schema and an allow-listed detail
vocabulary, not by convention — and attribution splits observed identity
(WhoIs) from authenticated identity (credential), with rejected calls carrying
a non-reversible token fingerprint instead of an owner.

## Operator surface

The admin CLI is server-local by design: operator authority is shell access to
the server host, so there is no operator HTTP credential to leak.

```bash
homeplane-server admin audit --since 24h            # or --json
homeplane-server admin revoke-grant <grant-id>      # any machine's grant
pass show google/oauth-client | \
  homeplane-server admin secret import google/oauth-client
```

Secret values are never accepted as command-line arguments (argv is
world-readable via `ps`): pipe them on stdin, or pass `-file` pointing at a
0600 file.
