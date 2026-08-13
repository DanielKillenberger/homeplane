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
| `cmd/homeplane-agent` | Machine agent: `enrol`, `status` |
| `internal/agent` | Agent state directory, control-plane client, enrolment, status |
| `install.sh` | Installer: platform gating, checksummed artifacts, Node 22 provisioning |
| `internal/store` | SQLite persistence (machines, grants, audit, encrypted secrets) |
| `internal/server` | Enrolment, grant lifecycle, audit, health handlers |
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
  --gateway-health-url http://127.0.0.1:8080/health
```

`GET /healthz` reports **server** components only (store, gateway runtime,
tsnet, credential store) and returns 503 with a component-level payload when
any is degraded, so `curl -sf .../healthz` fails. Machine-side state
(enrolment, vault, sync, GNO, harness config) belongs to `homeplane-agent
status`.

## Installing a machine

```bash
scripts/stage-release.sh dist        # build release-form artifacts + SHA256SUMS
./install.sh --stage-dir dist        # verify checksums, provision Node 22, install

~/.homeplane/bin/homeplane-agent enrol -server https://homeplane.<tailnet>.ts.net
~/.homeplane/bin/homeplane-agent status
```

The installer supports macOS (launchd) and systemd-based Linux with
`systemctl --user`; anything else is rejected **before** anything is written. A
checksum mismatch aborts with nothing installed, and a re-run is an idempotent
refresh that leaves enrolment state alone. Node 22 is provisioned
deterministically — from a checksummed vendored tarball staged alongside the
agent, or from the distribution's package manager with
`HOMEPLANE_NODE_PACKAGE=1` — and a machine that cannot get it fails the install
rather than ending up quietly unable to sync its vault.

Enrolment is identity-preserving: re-running `enrol` rotates this machine's
credential on the same server-side record and the previous credential stops
working immediately. If the server cannot be reached, nothing is written to
`~/.homeplane`.

`homeplane-agent status` reconciles grants **live** against the server on every
run: a revoked grant reads `revoked`, and a server that cannot be reached makes
grant state `unknown` rather than a stale `active`. Exit codes are `0` ok, `1`
a named component is degraded, `2` this machine is not enrolled.

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
