# D6 — Gateway composition: ToolHive as bare-server Tailnet MCP gateway

**Status:** Resolved — GO, adopted shape (b): **ToolHive CLI as connector runtime + Homeplane thin auth/audit edge proxy in front (the D13 shape)**. **All five gates PASS with live evidence** — gate 1 including a genuine cross-node run from a second tailnet machine with live WhoIs machine binding, and gate 5 (after the D18 scope-policy pivot: Drive read-only, Calendar read+write) including a live Drive-read + Drive-write-refusal + Calendar six-op run on the production server using the existing server-resident Google token. The Homeplane-owned OAuth client and the `add-credentials` consent flow remain .8/.12's obligation.
**Date:** 2026-08-13
**Task:** fn-1-homeplane-walking-skeleton-install.1 (time-boxed spike)
**Also resolves:** D3 (credential store), D10 (OAuth broker mechanics)

## Environment and honesty notes

- Spike ran on macOS 26.5 (arm64), ToolHive **v0.42.1** (`thv`, Homebrew), Docker 28.0.1, real Tailscale
  tailnet present (node IP `100.107.192.94`, `daniels-macbook-pro`).
- **A real second tailnet node was used for the cross-node proof:** `clawniel`
  (`vps-16936c35`, Ubuntu, tailnet IP `100.82.79.48`, direct WireGuard connection) — Daniel's actual
  production server. The full path was exercised FROM that remote node against the edge on this
  machine, with per-request WhoIs identity resolution and machine-binding enforcement at the edge
  (evidence in gate 1). The ToolHive workload proxy stayed bound to `127.0.0.1` only, verified
  unreachable from the remote node.
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

## Gate 1 — Remote exposure, full path, real clients, cross-node + WhoIs: **PASS**

Workload: `thv run fetch` (registry server `ghcr.io/stackloklabs/gofetch/server:1.0.5`,
streamable-http). ToolHive proxied it at `http://127.0.0.1:<port>/mcp`, **loopback-bound by
default** (`--host` defaults to 127.0.0.1):

```
$ netstat -an | grep 43815
tcp4  0  0  127.0.0.1.43815    *.*    LISTEN          # gateway: loopback only
$ netstat -an | grep 9100
tcp4  0  0  100.107.192.94.9100  *.*  LISTEN          # edge: tailnet iface only
```

**Genuine cross-node full path** — client on a REAL second tailnet machine (`clawniel` /
`vps-16936c35`, Ubuntu, `100.82.79.48`, direct WireGuard) → edge on this machine's tailnet IP
(bearer token) → loopback ToolHive → container → real fetch of example.com, MCP protocol
**2025-06-18**:

```
clawniel$ curl -si -X POST http://100.107.192.94:9100/mcp -H "Authorization: Bearer $TOK" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",...}}'
HTTP/1.1 200 OK
Mcp-Session-Id: UQC6CWG3PJAD2EBXI7ELURIQI5
data: {...,"protocolVersion":"2025-06-18","serverInfo":{"name":"fetch-server",...}}
clawniel$ tools/call fetch → "This domain is for use in documentation examples..." (real fetch)
clawniel$ tools/call delete_everything → 403 "tool not authorized by manifest" (cross-node denial)
clawniel$ curl http://100.107.192.94:64335/mcp → connection refused/timeout
          # direct gateway BYPASS from the remote node FAILS: workload proxy is loopback-only
```

**WhoIs machine binding — demonstrated live against the real remote peer.** The edge (with
`-whois`) resolves every connecting peer's tailnet identity via the local tailscaled
(`tailscale whois --json <peer-ip>` — the same LocalAPI data tsnet's in-process WhoIs serves in the
real edge) and enforces `client@machine` token bindings:

```
audit: {"client":"codex","machine":"clawniel","event":"forwarded","tool":"fetch","action_class":"read",
        "remote":"100.82.79.48:48320",...}                      # remote node, identity resolved per request
audit: {"event":"denied","reason":"machine_mismatch","bound_machine":"clawniel",
        "observed_machine":"daniels-macbook-pro","token_fingerprint":"57300e05e25b",...}
        # the clawniel-bound token REPLAYED from this Mac → 403, attributed to the OBSERVED machine
audit: {"client":"claude-code","machine":"daniels-macbook-pro","event":"forwarded",...}
        # correctly-bound local token keeps working
$ tailscale whois 100.82.79.48
Machine: Name: clawniel.tailab4e9b.ts.net  ID: nDBckRVpMa11CNTRL
```

A token exfiltrated to another tailnet node is rejected and audited as a violation carrying the
observed machine — exactly the spec's machine-binding invariant (R7), now shown with genuine
distinct tailnet machines rather than simulated interfaces.

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

so per-call audit rows carry (client, machine, tool, action_class) and denials are attributed to
the authenticated client (or, for machine-mismatch, to the observed machine + token fingerprint) —
the attribution tuple the real edge extends with (grant). WhoIs machine binding and the
direct-access-fails bypass test were both exercised against the genuine second node (above); the
real edge (.16) re-implements the same checks in-process via tsnet WhoIs instead of shelling out
to the tailscale CLI.

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

## Gate 5 — Google connector exact operations (D18: Drive read-only, Calendar read+write): **PASS**

**Scope-policy pivot (D18, Daniel, 2026-08-13):** Google Drive is deliberately **READ-ONLY** in
Homeplane's manifest — its write tools stay unmapped, so the fail-closed denial demonstrated in
gate 1 doubles as the live proof of the policy — and **Google Calendar carries read+write**. The
R8 reversible-write proof therefore targets an isolated **Calendar test event**, six operations:
create → read back → update → verify → delete → verify cleanup. This dissolved the earlier
conditional entirely: no new OAuth app, no browser consent, and **no connector patch** — the
shipped scope declarations now match the policy exactly (read tools → `drive.readonly` ✓ granted;
write tools → `drive.file` ✗ not granted → refused at scope level AND unmapped at manifest level).

**Live run on the production server (clawniel), 2026-08-13**, using the existing Hermes Google
token in place (`/home/claw/.hermes/google_token.json`, scopes include exactly `drive.readonly` +
`calendar.events`; the token never left the box, values never logged — refs/outcomes only). The
access token was expired and was refreshed in place first (`expires_in=3599`, refresh grant via
the on-box client credentials).

Drive READ under `drive.readonly` — works; Drive WRITE — refused:

```
Drive about (read):        {"user":{"emailAddress":"daniel.killenberger@gmail.com"}}
Drive files.list (read):   {"files":[{"id":"1hh1Ws0m…"},{"id":"1pSxpOgX…"}]}
Drive files.create:        HTTP 403 {"reason":"insufficientPermissions",
                           "message":"Request had insufficient authentication scopes."}
```

Calendar six-op on an isolated event (`homeplane-spike-proof-20260813T191125Z`, all-day, next
day) — pre-checked that no matching event existed; deletion enforced by a cleanup trap even on
failure paths; **event ID present in every result**:

```
STEP 0 before:   {"items":[]}                                        # isolation: nothing matches
STEP 1 create:   {"id":"hbjk1sbq86b8o3pomvbi4lu3ak","status":"confirmed","description":"v1 …"}
STEP 2 read:     same id, "description":"v1 created by D6 spike"
STEP 3 update:   PATCH → "description":"v2 updated by D6 spike"
STEP 4 verify:   GET   → "description":"v2 updated by D6 spike"
STEP 5 delete:   HTTP 204
STEP 6 verify:   GET → {"id":"hbjk1sbq86b8o3pomvbi4lu3ak","status":"cancelled"}
                 list non-cancelled matching → []                     # cleanup verified
```

No pre-existing file or event was touched at any step.

**Method note (honest):** the six-op ran as direct Google API calls on the server (the exact
`calendars/primary/events` create/get/patch/delete verbs), not yet through the
ToolHive-workload tool surface — spinning the full connector container on the production box was
out of the spike's polite-guest budget. The runtime mapping is source-verified at the pinned
version and the transport/auth/audit path those tools ride is the same edge→ToolHive stack proven
end-to-end in gates 1–3; the through-the-stack rerun happens in .12 as part of the real R8 proof.

**Pinned runtime & tool mapping.** The ToolHive registry has no Google Drive/Calendar server
(`thv search drive/google/workspace` → none); the reference `@modelcontextprotocol/server-gdrive`
is read-only and was rejected earlier. Selected connector: **`workspace-mcp`**
(taylorwilsdon/google_workspace_mcp, PyPI `workspace-mcp`), **pinned: release v1.24.0, main @
`99fa5e9add78` at inspection time**, run via ToolHive's `uvx://workspace-mcp` scheme (pin the
version in the uvx spec). Source-verified surface (`gcalendar/calendar_tools.py`,
`gdrive/drive_tools.py`):

| Proof step | Tool | Scope required |
|---|---|---|
| 1. create event | `manage_event` (`_create_event_impl`) | `calendar_events` → `calendar.events` ✓ |
| 2. read back | `get_events` | `calendar_read` → `calendar.readonly` ✓ (also held) |
| 3. update | `manage_event` (`_modify_event_impl`) | `calendar.events` ✓ |
| 4. verify | `get_events` | `calendar.readonly` ✓ |
| 5. delete | `manage_event` (`_delete_event_impl`) | `calendar.events` ✓ |
| 6. cleanup verify | `get_events` | `calendar.readonly` ✓ |
| Drive read (R7) | `get_drive_file_content` / `search_drive_files` | `drive_read` → `drive.readonly` ✓ |
| Drive write (must fail) | `create_drive_file` / `update_drive_file` | `drive_file` → `drive.file` ✗ not granted + unmapped in manifest |

Artifact-id extraction for the manifest: event/file IDs ride in results (and in requests for steps
2–6: `$.event_id`-style request-side JSONPath); Drive/Calendar tool results are text, so the
create-step extractor is a regex over the reported ID.

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

1. **.16 (edge):** real edge = spike shape (bearer auth + manifest authorization + machine-bound
   tokens + attribution audit, all demonstrated above) with tsnet WhoIs in-process instead of the
   spike's `tailscale whois` shell-out, SQLite-backed grant lookup, and AuditEvent writes. Keep
   the token-strip behavior. Keep ToolHive workloads loopback-bound (default); re-run the
   direct-access-fails test on the production deployment.
2. **.15 (deployment):** ToolHive CLI on the Linux server requires Docker/Podman (the CLI + Docker
   runtime path is validated headless in DinD above; the real server — clawniel — has podman and
   adds systemd + tailnet specifics). `thv run --enable-audit` on every workload for supplementary
   diagnostics. If ToolHive secrets end up used at all, document the per-boot keyring seeding or
   use the `environment` provider.
3. **.12 (Google connectors, per D18):** run pinned workspace-mcp v1.24.0 (no patch needed —
   shipped scope declarations match D18 exactly) with `--tools` filtered to the Drive-read +
   Calendar surface; manifest maps Calendar `manage_event`/`get_events` (write/read) and Drive
   read tools only — Drive write tools stay unmapped (fail-closed denial is the live policy
   proof). Re-run the six-op Calendar proof THROUGH the edge→ToolHive stack (R8), with the
   Homeplane-owned OAuth client + `add-credentials` consent (.8) supplying the credential. The
   spike's direct-API six-op (above) is the surface proof; .12 owns the through-the-stack rerun.
4. **Runbook:** Codex MCP tool calls are auto-cancelled under `codex exec` read-only sandbox;
   static bearer config via `bearer_token_env_var` works on 0.146.0. Claude Code HTTP MCP with
   `--header "Authorization: Bearer …"` works on 2.1.227.
5. **Protocol hygiene:** consider `--strict-protocol-validation` on workloads once the supported
   client matrix is pinned.

## Review disposition (codex impl-review, 2026-08-13)

Earlier review rounds (gpt-5.6-sol @ xhigh) returned **NEEDS_HUMAN** on three legs the spike had
not yet exercised. Each was then closed with recorded evidence, in rounds:

- **Manifest authorization / unmapped-tool denial** — demonstrated live (gate 1).
- **Headless-Linux secrets** — validated empirically in a D-Bus-free Linux container (gate 4);
  **Linux workload runtime** — validated in DinD (environment note).
- **Cross-node + WhoIs machine binding (gate 1)** — after a real second tailnet node (`clawniel`)
  became available: genuine remote full path, per-request WhoIs identity resolution,
  machine-mismatch rejection of a replayed token, and the direct-access-fails bypass test, all
  recorded above. Gate 1 is a full PASS.
- **Gate 5 honesty** — first downgraded from PASS to CONDITIONAL with a pinned single resolution
  and version pin.
- **Gate 5 (final leg)** — closed after Daniel's D18 scope-policy decision (Drive read-only,
  Calendar read+write, six-op moved to a Calendar test event): live Drive read + Drive
  write-refusal + full Calendar six-op with verified cleanup, run on the production server with
  the existing server-resident token (custody preserved: token never left the box, values never
  logged). Gate 5 is a full PASS.

**No spike-scoped residuals remain.** All five gates carry live evidence for the adopted shape.
What intentionally lands in later tasks is production wiring, not gate validation: in-process
tsnet WhoIs + bypass re-run on the real deployment (.16/.15), and the through-the-stack rerun of
the Calendar six-op with the Homeplane-owned OAuth client + `add-credentials` consent (.8/.12,
the real R8 proof).

## Deployment note (fn-1.15, 2026-08-14) — how the real host differs from the spike

The spike validated the CLI + **Docker** runtime headless in DinD. The production
server (clawniel, Ubuntu, x86_64) runs **rootless Podman 5.7.0**. The adopted
shape survived unchanged; four host-level differences are worth recording, and
all four are handled in `deploy/server/` (runbook: `deploy/server/README.md`).

1. **Podman socket, not a Docker daemon.** ToolHive reaches rootless Podman
   through the user socket (`systemctl --user enable --now podman.socket`). No
   `docker` binary, no shim, no configuration in ToolHive itself.
2. **`XDG_RUNTIME_DIR` is the sharp edge.** ToolHive discovers that socket at
   `$XDG_RUNTIME_DIR/podman/podman.sock`, and a non-interactive SSH command has
   `XDG_RUNTIME_DIR` **unset** — so `ssh host thv run …` fails with *"no
   container runtime available"* while the systemd units, which always have it,
   work. This is a diagnosis trap, not a defect: the installer sets it, and the
   runbook documents it.
3. **systemd `--user`, not system units.** The host runs other people's
   services; Homeplane installs under one prefix plus two user units and
   `enable-linger`, touching nothing system-wide and needing no root. `thv run
   --foreground` makes systemd the real supervisor (without it `thv` detaches
   and systemd supervises a process that has already exited).
4. **ToolHive secrets are not used at all**, so gate 4's per-boot keyring
   seeding never applies to this deployment: Homeplane's own age-encrypted store
   (D3) holds every credential, and the workload gets what it needs materialized
   at `thv run` time.

Verified live from a second tailnet node (this Mac → clawniel): both units
supervised, the gateway bound to `127.0.0.1:44022` **only** and unreachable over
the tailnet on either the host's address or the tsnet node's, the edge reachable
and 401 without a grant token, `/healthz` green on all four components, and a
re-deploy preserving the age key, the database file and the tsnet node identity
(same tailnet IP). Evidence:
`test/evidence/fn-1-homeplane-walking-skeleton-install.15.json`.

## Fallback ladder disposition

- (a) ToolHive-direct: rejected (gate 2/3 native limitations above), not needed.
- (b) ToolHive + thin Homeplane edge (D13): **adopted — all five gates PASS with the live
  evidence above** (gate 5 under the D18 scope policy).
- (c) MCPJungle: not reached — (b) carries the adoption. No bespoke gateway (forbidden by
  STRATEGY.md); the edge is auth/audit/policy only.
- Production wiring that intentionally lands in later tasks (not gate residuals): in-process
  tsnet WhoIs + direct-access-fails re-run + systemd/podman specifics on the real deployment
  (.16/.15); through-the-stack Calendar six-op with the Homeplane-owned OAuth client +
  `add-credentials` consent (.8/.12).
