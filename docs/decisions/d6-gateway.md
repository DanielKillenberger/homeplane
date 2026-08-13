# D6 — Gateway composition: ToolHive as bare-server Tailnet MCP gateway

**Status:** Resolved — GO, adopted shape (b): **ToolHive CLI as connector runtime + Homeplane thin auth/audit edge proxy in front (the D13 shape)**. Gates 1–4 PASS; gate 5 is **CONDITIONAL** — the Drive tool surface is proven in source at a pinned version, but the strict `drive.file`-only six-operation run cannot complete in this spike environment (no Google OAuth app credentials exist yet) and is a named blocking obligation on task .12 (the spec's designated real-Google proof task) before any Drive-dependent work ships.
**Date:** 2026-08-13
**Task:** fn-1-homeplane-walking-skeleton-install.1 (time-boxed spike)
**Also resolves:** D3 (credential store), D10 (OAuth broker mechanics)

## Environment and honesty notes

- Spike ran on macOS 26.5 (arm64), ToolHive **v0.42.1** (`thv`, Homebrew), Docker 28.0.1, real Tailscale
  tailnet present (node IP `100.107.192.94`).
- **No second physical machine was available.** "Remote client" was simulated by binding the Homeplane
  edge prototype to the machine's *tailnet* interface (`100.107.192.94:9100`) and calling it via that
  non-loopback address, while the ToolHive workload proxy stayed bound to `127.0.0.1` only. Every
  network property claimed below (edge reachable on tailnet iface, gateway loopback-only) is verified
  from listener bindings (`netstat`) and real traffic, but a genuine cross-node call and tsnet WhoIs
  binding remain to be exercised on the real server (task .16/.15).
- Linux-headless behavior for secrets (gate 4) was verified from ToolHive source AND empirically in
  a headless Debian bookworm (arm64) container running the official `toolhive_0.42.1_linux_arm64`
  release — no D-Bus, no desktop (evidence in gate 4). The Linux *workload* runtime was ALSO
  exercised empirically: inside a headless Linux Docker-in-Docker environment (docker:27-dind,
  arm64), the same official release ran `thv run fetch` end-to-end — image pulled, container
  supervised, streamable-HTTP proxy up on `http://127.0.0.1:52295/mcp` (loopback-bound), and the
  MCP initialize handshake (protocol 2025-06-18) answered:

  ```
  fetch  ghcr.io/stackloklabs/gofetch/server:1.0.5  running  http://127.0.0.1:52295/mcp  52295
  data: {"jsonrpc":"2.0","id":1,"result":{...,"protocolVersion":"2025-06-18","serverInfo":{"name":"fetch-server",...}}}
  ```

  The real Linux server deployment (systemd, real Docker daemon, tailnet) is still task .15's job.
- Scratch code: `spike/edge-proxy/` (disposable prototype, ~160 lines Go). Not production code.

## Adopted shape

```
harness (Claude Code / Codex CLI)
  │  streamable HTTP + Authorization: Bearer <homeplane grant token>   [tailnet-only]
  ▼
Homeplane edge (thin reverse proxy; real version adds tsnet WhoIs machine-binding,
  manifest authorization incl. unmapped-tool denial, authoritative AuditEvent log)
  │  loopback HTTP (grant token stripped)
  ▼
ToolHive workload proxy (thv run …, binds 127.0.0.1 only)
  ▼
containerized MCP server (Docker), egress-controlled by ToolHive permission profile
```

ToolHive supplies: container supervision, image/registry management, streamable-HTTP proxying,
session management, egress permission profiles, secrets injection, supplementary audit.
Homeplane supplies (in the edge): per-(machine, harness) grant tokens, revocation, WhoIs machine
binding, manifest authorization, authoritative audit. This is composition, not a gateway build:
the edge does auth + audit + policy only; all MCP semantics stay in ToolHive.

**Why not ToolHive-direct (shape a):** ToolHive CLI's inbound auth validates externally-issued
OIDC JWTs only — it cannot issue or revoke its own per-client bearer tokens, and without OIDC its
audit attributes every request to the local OS user (evidence in gates 2–3). Running a full OIDC
IdP just to mint per-harness tokens, plus Cedar policies keyed on JWT claims, is far heavier than
the ~100-line edge the D13 shape needs, and revocation latency would depend on token TTL /
introspection rather than being immediate. The fallback ladder's shape (b) was therefore adopted
and itself validated against all five gates below.

---

## Gate 1 — Remote exposure, full path, real clients: **PASS**

Workload: `thv run fetch` (registry server `ghcr.io/stackloklabs/gofetch/server:1.0.5`,
streamable-http). ToolHive proxied it at `http://127.0.0.1:<port>/mcp`, **loopback-bound by
default** (`--host` defaults to 127.0.0.1):

```
$ netstat -an | grep 43815
tcp4  0  0  127.0.0.1.43815    *.*    LISTEN          # gateway: loopback only
$ netstat -an | grep 9100
tcp4  0  0  100.107.192.94.9100  *.*  LISTEN          # edge: tailnet iface only
```

Full path (simulated-remote client → edge on tailnet IP, bearer token → loopback ToolHive →
container → real fetch of example.com), speaking MCP protocol **2025-06-18**:

```
$ curl -si -X POST http://100.107.192.94:9100/mcp -H "Authorization: Bearer $TOK" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",...}}'
HTTP/1.1 200 OK
Mcp-Session-Id: USIGC4FG3772XFFM5YQ46VE7PX
data: {"jsonrpc":"2.0","id":1,"result":{...,"protocolVersion":"2025-06-18","serverInfo":{"name":"fetch-server",...}}}

tools/list  → fetch tool schema returned
tools/call  → "This domain is for use in documentation examples..." (real fetch through container)
```

**Actual client compatibility (not spec text):**

- **Codex CLI 0.146.0** — full end-to-end model-driven tool call through the edge with a static
  bearer token (`mcp_servers.homeplane_fetch.url` + `bearer_token_env_var`, config supplied via
  `-c` overrides):
  ```
  mcp: homeplane_fetch/fetch (completed)
  codex: DONE This domain is for use in documentation examples without needing permission.
  ```
  Session teardown observed at the edge (`DELETE /mcp`). Nuance for the runbook: under
  `codex exec` with the default read-only sandbox, MCP tool calls are auto-cancelled
  ("user cancelled MCP tool call") — interactive sessions or a permissive approval policy are
  required for MCP tools to actually run.
- **Claude Code 2.1.227** — `claude mcp add --transport http --header "Authorization: Bearer …"`
  against the edge: health check reports `✔ Connected` (real initialize handshake), and a later
  invocation forwarded initialize + SSE GET through the edge (audit lines at 17:50:21). The full
  model-driven call in the *nested* CLI session failed on Claude Code's own model login
  ("OAuth session expired"), unrelated to MCP transport/auth — the MCP client layer connected and
  initialized twice.
- ToolHive's proxy accepts any `MCP-Protocol-Version` by default; `--strict-protocol-validation`
  exists (streamable-HTTP proxy) to reject unknown revisions with HTTP 400 — relevant to the
  2026-07-28 RC transport/auth changes: nothing in the path pins an old revision, and both current
  clients negotiated 2025-06-18 through it.

**Edge invariants — demonstrated, not asserted:** the edge terminates every request before the
gateway (401 without/with-unknown token, below), strips the grant token before forwarding upstream,
and writes the authoritative per-request audit. **Manifest authorization incl. unmapped-tool
denial was demonstrated live**, not just argued: the prototype takes a declarative
`manifest.json` (tool → action class), parses `tools/call` from the JSON-RPC body at the edge, and
fails closed —

```
mapped tool   (fetch, read):        HTTP 200, forwarded
unmapped tool (delete_everything):  HTTP 403 "tool not authorized by manifest"
audit: {"action_class":"read","client":"claude-code","event":"forwarded","tool":"fetch",...}
audit: {"client":"claude-code","event":"denied","reason":"unmapped_tool","tool":"delete_everything",...}
```

so per-call audit rows carry (client, tool, action_class) and denials are attributed to the
authenticated client — the full attribution tuple the real edge extends with (machine, grant).
**Residual (named, not waved off):** WhoIs machine-binding requires tsnet on the real server (its
listener yields the caller's tailnet node identity) and a genuine second node — neither exists in
this spike environment; the network shape is identical to the spike's tailnet-iface listener, and
the binding is exercised by tasks .16/.15 with a direct-access-fails test from a second node.
Gateway bypass boundary holds here: the workload proxy is loopback-only, so only the edge is
network-reachable.

## Gate 2 — Per-client auth, revocation within seconds: **PASS**

Two distinct bearer tokens for the same underlying workload (`claude-code`, `codex`), issued by
Homeplane (a JSON token→client map in the spike; SQLite grant table in the real server). Edge
re-checks the token store on every request, so revocation is next-request:

```
codex  pre-revoke tools/list: 200
claude pre-revoke tools/list: 200
# revoke = remove codex entry from token store
codex  post-revoke: 401   (0.049 s after revocation)
claude post-revoke: 200   (unaffected)
```

ToolHive-native check (why the edge owns this instead): `thv run` inbound auth flags are
OIDC-validation only (`--oidc-issuer/--oidc-audience/--oidc-jwks-url` + `--authz-config` Cedar
policies). Docs: "clients must include a valid JWT … issued by your configured identity provider" —
ToolHive **does not issue per-client tokens**. RFC 7591 dynamic client registration and RFC 8693
token exchange are present but serve outbound/backend legs (ToolHive as OAuth *client* to remote
MCP servers; exchanging inbound tokens for backend-audience tokens) — neither gives Homeplane
per-harness issuance/revocation. Cedar could express per-tool policy keyed on JWT claims if we ever
front ToolHive with a real IdP; not needed for the skeleton.

## Gate 3 — Audit attributable to calling client: **PASS** (edge authoritative; ToolHive supplementary — D13 confirmed viable)

Edge audit (JSON lines, per request): identity, method, path, remote, timestamp; unknown/revoked
tokens recorded with a SHA-256 token fingerprint and **never misattributed**:

```
{"client":"codex","event":"forwarded","method":"POST","path":"/mcp","remote":"100.107.192.94:53047","ts":"2026-08-13T17:41:55.150592Z"}
{"event":"denied","reason":"unknown_or_revoked_token","token_fingerprint":"2a45cb275872","remote":"100.107.192.94:53051","ts":"2026-08-13T17:41:55.244868Z"}
```

48 forwarded + 2 denied events captured over the spike session, including Claude Code's and Codex's
real sessions (initialize/POST, SSE GET, session DELETE all attributed).

ToolHive native audit (`thv run fetch --enable-audit`) is structured and per-tool-call —
`mcp_initialize`, `mcp_request`, `mcp_tool_call` with tool name, outcome, duration_ms, source IP,
and **no payload bodies** — but without OIDC its subject is the local OS user:

```
{"type":"mcp_tool_call","outcome":"success","subjects":{"user":"Local User: daniel","user_id":"daniel"},
 "target":{"method":"tools/call","name":"fetch","type":"tool"},"metadata":{"extra":{"duration_ms":83}}}
```

Exactly the D13 split the spec assumed: Homeplane's `AuditEvent` log at the edge is authoritative
for (machine, harness, grant) attribution; ToolHive's audit is supplementary diagnostics (useful:
tool-level outcome + latency).

## Gate 4 — Secrets usable headless on a Linux server: **PASS** (empirical, with documented workaround)

Providers (ToolHive v0.42.1): `encrypted` (AES-256-GCM file, key in OS keyring), `1password`
(read-only), `environment` (`TOOLHIVE_SECRET_*`, read-only). Source-verified headless behavior
(`pkg/secrets/keyring/composite.go`): the keyring is a composite — zalando/go-keyring (macOS
Keychain / Windows / **Linux D-Bus Secret Service**) with a **Linux-only fallback to kernel keyctl**
(`pkg/secrets/keyring/keyctl_linux.go`, `KEY_SPEC_USER_KEYRING`) — so `encrypted` works on a
headless Linux server **without any desktop session or D-Bus**.

**Empirically validated on headless Linux** (Debian bookworm arm64 container, official
`toolhive_0.42.1_linux_arm64` release, `dbus-daemon` absent):

```
=== D-Bus present? NO
=== secret setup non-interactive attempt (encrypted provider, no TTY):
Error: … failed to get secrets password: … inappropriate ioctl for device
=== secret setup with pseudo-TTY (one-time):
Please enter your keyring password:            # accepted
=== keyring after setup (kernel keyctl, user keyring):
 175615276 --alswrv  0  0   \_ user: toolhive:toolhive
=== set + get secret from FRESH processes, no prompt:
$ echo -n "s3cret-value" | thv secret set spike-test   # ok
$ thv secret get spike-test                            # → s3cret-value
$ thv secret list                                      # → spike-test
```

Caveats, verified empirically + in source:

- Setup (first password entry) needs a TTY once: with no keyring entry and no TTY it fails
  (`inappropriate ioctl for device` on Linux, `operation not supported by device` on macOS).
  After that one-time seed, all secret operations run headless from fresh processes.
- The kernel user keyring does not survive reboot: after reboot the keyring password must be
  re-seeded once (interactive `thv secret setup` on a TTY, e.g. over SSH).
- `TOOLHIVE_SECRETS_PASSWORD` is **not** a user-facing fallback: it is only used internally to pass
  the password to detached child processes (`pkg/workloads/manager.go`); `GetSecretsPassword` never
  reads it at startup (`pkg/secrets/factory.go`).
- `environment` provider (`TOOLHIVE_SECRET_*` env vars) is the fully non-interactive fallback,
  read-only by design — viable under systemd `EnvironmentFile=` with 0600 perms.

**D3 resolution** (see below) keeps Homeplane's own credentials out of this problem entirely.

## Gate 5 — Google Drive exact operations under `drive.file`: **CONDITIONAL — not yet PASS; blocking obligation on task .12**

What this spike CAN and CANNOT evidence, stated plainly: the six-operation tool surface and
file-ID availability are proven in source at a pinned version (below). A **live** six-operation run
under `drive.file`-only was NOT performed and cannot be performed in this environment — no Google
OAuth app credentials exist yet (creating them and completing the browser consent is Daniel-side
work that the spec assigns to the credential tasks), and the server's read tools as shipped declare
`drive.readonly` (details below), which conflicts with the strict `drive.file`-only criterion.
**Adoption of the D13 shape does NOT rest on this gate** (gates 1–4 carry it); Drive-dependent
work does. Gate 5 completes in task .12 (the spec's designated real-Google proof task) under the
pinned conditions at the end of this section, and .12 MUST NOT be marked done without them.

The ToolHive registry has **no Google Drive server** (`thv search drive/google/workspace` → none),
and the reference `@modelcontextprotocol/server-gdrive` is read-only (fails this gate outright).
The selected Drive connector is **`workspace-mcp`** (taylorwilsdon/google_workspace_mcp, PyPI
`workspace-mcp`), **pinned: release v1.24.0, main @ `99fa5e9add78` at inspection time**, runnable
in ToolHive via the `uvx://workspace-mcp` protocol scheme (ToolHive builds the container; pin the
version in the uvx spec). Tool-surface evidence, verified in source (`gdrive/drive_tools.py`):

| Proof step | Tool | Evidence |
|---|---|---|
| 1. create | `create_drive_file` | `@require_google_service("drive", "drive_file")`; result text: `Successfully created file '<name>' (ID: <file-id>) … Link: <webViewLink>` — **file ID present in tool result** |
| 2. content read | `get_drive_file_content` | dedicated read tool |
| 3. update | `update_drive_file(content=…)` | in-place `files().update`, "preserving the existing file ID" |
| 4. verification read | `get_drive_file_content` | same as 2 |
| 5. trash | `update_drive_file(trashed=true)` | param `trashed: Optional[bool]`; `update_body["trashed"] = trashed` → **exactly `files.update(trashed=true)`**; result reports "moved to trash" |
| 6. cleanup verification | `search_drive_files` / metadata | search appends `and trashed=false` by default; file metadata renders `Trashed: True` |

Scopes: the server defines `drive_file` → `https://www.googleapis.com/auth/drive.file` and the
write tools (create/update/trash) require exactly it. **The blocker:** its *read* tools
(`get_drive_file_content`, `search_drive_files`) declare `drive_read` → `drive.readonly`
(SCOPE_GROUPS, `auth/service_decorator.py:565`), and the decorator passes those `required_scopes`
into credential retrieval — a `drive.file`-only credential triggers reauth for reads rather than
being used. The Drive API itself permits reading app-created files under `drive.file` alone
(documented `drive.file` semantics: per-file access, including read, to files created or opened by
the app), so this is a conservative scope *declaration* in the connector, not an API limitation.

**Pinned resolution (one, not a menu):** Homeplane carries a pinned patch of workspace-mcp
v1.24.0 remapping the two read tools used by the six-step proof to the `drive_file` scope group
(a two-line SCOPE_GROUPS/decorator change), consumed by ToolHive as a pinned uvx/container ref —
still composition (the patch changes a scope constant, no MCP or connector logic). Granting
`drive.file + drive.readonly` instead was considered and rejected: it violates the gate's
`drive.file`-only criterion and widens read access to the whole Drive. **Task .12 must: build the
pinned patched ref, run all six operations live with a `drive.file`-only credential, capture file
IDs from tool results and the trash/cleanup verification, and record that evidence — gate 5 flips
to PASS only on that recorded run.**

Either way the six operations exist concretely with IDs in results — the surface is not partial
and not read-only. Artifact-id extraction note for the manifest: results are text, so the
declarative extractor for this connector is a regex over `(ID: <id>)` rather than a JSONPath
(manifest already allows "JSONPath-style pointer into the tool's request or response"; request-side
`file_id` is a clean JSONPath for steps 2–6).

OAuth provisioning path: workspace-mcp uses your own Google OAuth client
(`GOOGLE_OAUTH_CLIENT_ID/SECRET`), supports loopback-redirect flows, and persists per-user
credentials in a configurable credential-store directory (`.credentials/`, or GCS backend). It also
supports an external-auth mode (validate bearer tokens only). This feeds D10 below.

---

## D3 resolution — credential store

**Resolved: Homeplane owns its own credential store; ToolHive secrets are not used for Homeplane
state.**

- Provider OAuth credentials (Google refresh tokens, API keys), grant-token hashes, machine
  records: **server-local SQLite (D11) with 0600 file perms**, provider secrets encrypted at rest
  with an age key file read at service start (systemd `LoadCredential=`/0600 file). No OS keyring,
  no desktop session, no reboot re-seeding problem, atomic swap semantics implementable in SQL
  (R13's compare-and-swap).
- Injection into connector workloads happens at `thv run` time via env/volume (e.g. workspace-mcp's
  credential dir mounted from a Homeplane-materialized tmpdir) — ToolHive's `--secret` flag remains
  available but optional.
- Rationale: gate 4 shows ToolHive's encrypted provider is *usable* headless but couples secret
  availability to a kernel-keyring seeding step per boot and to ToolHive's provider model
  (read-only for env/1password). Homeplane's custody, atomic-replacement, and audit requirements
  (R13) sit naturally next to the grant registry in SQLite. Bootstrap import
  (`homeplane-server admin secret import`) writes into this store per the spec.

## D10 resolution — add-credentials OAuth broker mechanics

**Resolved: client loopback redirect + server-brokered exchange, as pinned in the spec's API
Contracts; the composed gateway is NOT in the OAuth-dance loop.**

- Redirect shape: **short-lived loopback listener on the client machine**
  (`http://127.0.0.1:<port>` / `http://[::1]:<port>` only — Google's supported desktop pattern).
  The agent binds the port, sends `redirect_uri` in `POST /credentials/flows`, the server builds
  the authorization URL (PKCE + state) with Homeplane's own Google OAuth app client-id/secret from
  the D3 store, the browser lands on the loopback listener, the agent one-shot relays
  `{code, state}` to the server, and the **server** performs the token exchange and stores the
  refresh token in the D3 store. Tokens never touch the machine; the client sees only the
  authorization URL and flow status. This matches the spec's flow state machine verbatim — the
  spike found nothing forcing a change.
- ToolHive's RFC 7591/8693 machinery and `--remote-auth` are for ToolHive acting as OAuth client
  to *remote MCP servers* — not reusable as Homeplane's broker; not needed.
- Connector consumption: Homeplane materializes the stored credential into the connector workload
  (for workspace-mcp: credential-store dir/env at container start). Re-auth = re-run
  `add-credentials` (replace=true), atomic swap in the D3 store, workload restart or its native
  credential reload.

## Consequences / follow-ups for dependent tasks

1. **.16 (edge):** real edge = spike shape + tsnet WhoIs binding + manifest authorization
   (unmapped-tool denial by parsing `tools/call` at the edge) + SQLite-backed grant lookup +
   AuditEvent writes. Keep the token-strip behavior. Keep ToolHive workloads loopback-bound
   (default) — verify with the direct-access-fails test from a second node (spike limitation).
2. **.15 (deployment):** ToolHive CLI on the Linux server requires Docker/Podman (the CLI + Docker
   runtime path is validated headless in DinD above; the real server adds systemd + tailnet).
   `thv run --enable-audit` on every workload for supplementary diagnostics. If ToolHive secrets
   end up used at all, document the per-boot keyring seeding or use the `environment` provider.
   Owns the direct-access-fails test from a second tailnet node.
3. **.12 (Drive) — carries gate 5's blocking obligation:** build the pinned patched
   workspace-mcp ref (v1.24.0 + read-tools→`drive_file` scope remap), run the live six-operation
   proof with a `drive.file`-only credential, record file IDs + trash/cleanup evidence; use
   `--tools` filtering to the six-step surface; manifest extractors: request-side JSONPath
   `$.file_id` for steps 2–6, response-text regex for create. Gate 5 flips to PASS only on that
   recorded run.
4. **Runbook:** Codex MCP tool calls are auto-cancelled under `codex exec` read-only sandbox;
   static bearer config via `bearer_token_env_var` works on 0.146.0. Claude Code HTTP MCP with
   `--header "Authorization: Bearer …"` works on 2.1.227.
5. **Protocol hygiene:** consider `--strict-protocol-validation` on workloads once the supported
   client matrix is pinned.

## Review disposition (codex impl-review, 2026-08-13)

Two review rounds (gpt-5.6-sol @ xhigh) returned **NEEDS_HUMAN** — the task's own designed
terminal for an adoption whose gates cannot all complete in the spike environment. Findings the
spike RESOLVED in-round: manifest authorization / unmapped-tool denial now demonstrated live
(gate 1), headless-Linux secrets validated empirically (gate 4), Linux workload runtime validated
in DinD (environment note), gate 5 honestly downgraded to CONDITIONAL with a pinned single
resolution and version pin. Findings that REMAIN and are Daniel-gated / environment-gated:

1. **Cross-node + tsnet WhoIs proof (gate 1):** requires a second tailnet node and the real tsnet
   edge — neither exists in this environment (conductor-acknowledged limitation). Owner: .16/.15.
2. **Live `drive.file`-only six-operation Drive run (gate 5):** requires a Google OAuth app +
   Daniel's browser consent — credentials do not exist yet by design (server-side custody lands in
   .8/.12). Owner: .12, blocking obligation recorded above.

Human decision requested: accept D6 = GO with these two named residuals (proceed to Wave 2, the
residuals blocking .16/.15/.12 respectively), or hold D6 open until a second node and Google OAuth
app are provisioned and re-run the spike's missing legs first.

## Fallback ladder disposition

- (a) ToolHive-direct: rejected (gate 2/3 native limitations above), not needed.
- (b) ToolHive + thin Homeplane edge (D13): **adopted — gates 1–4 PASS with the evidence above;
  gate 5 CONDITIONAL with its completion pinned as a blocking obligation on task .12 (no
  Drive-dependent work ships before its recorded live run).**
- (c) MCPJungle: not reached — (b) carries the adoption. No bespoke gateway (forbidden by
  STRATEGY.md); the edge is auth/audit/policy only.
- Residuals that intentionally survive this spike, each with a named owner: real cross-node call +
  tsnet WhoIs binding + direct-access-fails test (.16/.15), Linux workload runtime on the real
  server (.15), live `drive.file`-only six-op run (.12).
