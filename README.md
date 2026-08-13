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
