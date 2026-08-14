# Homeplane architecture

What the walking skeleton actually is, and — just as deliberately — what it is
not. Every claim here is one the end-to-end proof
(`test/evidence/fn-1-homeplane-walking-skeleton-install.7.live.json`) or a test
in this repository settles. Where a guarantee is weaker than it sounds, this
document says so rather than letting the name carry it.

Decisions are recorded in `docs/decisions/`; the spec they serve is
`.flow/specs/fn-1-homeplane-walking-skeleton-install.md`.

## Two planes

Homeplane is two halves that never trade places. The **server** owns identity,
authority and provider credentials. The **machine** owns the vault, the local
retrieval engine, and the harness configuration. Nothing that grants authority
lives on a machine, and nothing machine-local is reported by the server.

```
┌─ machine (Mac / Linux, one per box) ──────────────────────────────────────┐
│                                                                            │
│  homeplane-agent   enrol · vault · gno · configure-harnesses · skills      │
│        │                        · add-credentials · status                 │
│        │                                                                   │
│        ├── vault  (Obsidian, Daniel-OS)      ── files sync between machines│
│        ├── retrieval engine (GNO)            ── index is machine-local     │
│        │      └─ stdio MCP ──────────────┐      and disposable             │
│        └── harness configs (0600)        │                                 │
│               Claude Code · Codex ───────┤                                 │
└───────────────────────────────────────────┼───────────────────────────────┘
                                            │
                        tailnet, Authorization: Bearer <grant token>
                                            │
┌─ server (its own tsnet node, "homeplane") ▼───────────────────────────────┐
│                                                                            │
│  homeplane-server                                                          │
│    control plane   /enrol  /grants  /healthz  /credentials/flows           │
│    connector edge  /mcp    ── grant auth · machine binding · manifest      │
│                                authorization · authoritative audit         │
│                            │                                               │
│                            ▼ loopback only                                 │
│    composed gateway  ToolHive (thv) workload proxy 127.0.0.1:44022         │
│                            ▼                                               │
│    containerized MCP server (rootless podman) ──► Google Drive / Calendar   │
│                                                                            │
│    SQLite: machines · grants · audit · age-encrypted provider secrets      │
└───────────────────────────────────────────────────────────────────────────┘
```

The split is visible in the two health surfaces and is checked, not asserted:
`GET /healthz` reports **server** components only (store, gateway runtime,
tsnet, credential store, workload credential); `homeplane-agent status` reports
**machine** state (enrolment, vault, sync, retrieval engine, harnesses, skills,
grants). During the proof the machine's retrieval engine was deactivated: the
machine went degraded and exited 1, and `/healthz` stayed green — a
machine-local failure has no route into the server's health surface.

## Identity and the grant model

Three records, and no fourth:

| Record | What it is | Where it lives |
|---|---|---|
| `Machine` | an enrolled device, identified by its tailnet node | server (SQLite) |
| `Grant` | (machine, harness) → capability set, with its own revocable token | server; the token also in that harness's 0600 config |
| `AuditEvent` | append-only record of every connector call and every lifecycle event | server (SQLite) |

Granularity stops at machine + harness deliberately (Daniel, 2026-08-13). Two
harnesses on one machine hold two distinct grants, and revoking one leaves the
other working — the proof revoked Claude Code's grant and watched Codex's next
Drive read succeed while Claude Code's was refused within seconds and audited.

**Enrolment is identity-preserving.** Re-running `enrol` rotates this machine's
credential on the same server-side record: same `machine_id`, new credential,
old one dead immediately, no second identity created. The server stores only a
hash, so the rotation is explicit rather than a silent no-op.

**Capabilities are server-policy-bound.** A machine asks for a grant; the server
decides what that harness may hold. The client never self-selects its authority,
and a grant is only ever created for the calling machine — no caller-supplied
`machine_id`.

**Grants supersede.** Issuing a new grant for the same (machine, harness)
revokes the previous one, which is what makes `configure-harnesses` safe to
re-run: a harness whose grant was revoked recovers by re-running it and gets a
fresh grant plus a rewritten config.

### Threat-model honesty

Both harnesses on one machine run as the same OS user. A process running as
Daniel can read the other harness's 0600 token file. **Per-harness token
separation on a single machine is an operational revocation boundary, not a
security boundary against a malicious local process.** Nothing in this design
claims otherwise.

What the grant model does guarantee, each of it demonstrated:

- **Server-side kill switches per harness.** Revocation is resolved from the
  store on every request — there is no token cache — so a revoked grant stops
  working on the next call, without touching the machine.
- **Machine binding at the edge.** Every connector call checks that the
  WhoIs-observed tailnet node is the node the grant's machine enrolled from. A
  token exfiltrated to another node is refused and audited against the node that
  sent it, never against the token's owner.
- **Per-harness attribution.** Every connector row in the audit log carries
  (machine, harness, grant): the proof's run recorded 194 connector rows with
  zero unattributed.
- **Provider credentials never reach a machine at all.** That is a custody
  boundary, not a permission boundary, and it holds regardless of who is running
  on the box.

Cross-user or sandboxed isolation is out of scope for the skeleton.

**One named exception to server-only custody:** Obsidian Sync credentials. A
machine that holds a synchronized vault inherently holds its sync credential —
that is what having the vault locally means. The credential lives 0600 in the
agent/Obsidian state area and never reaches logs, argv or git-tracked files. The
server-only rule, and the R7 machine-inspection procedure, are scoped to
**remote-service connector credentials** (Google, and whatever follows).

## The composed-gateway boundary

Homeplane does not implement MCP proxying, container supervision or provider
connectors. It composes ToolHive for those and puts a thin edge in front (D6,
`docs/decisions/d6-gateway.md`). ToolHive-direct was rejected on evidence: its
inbound auth validates externally-issued OIDC JWTs only — no per-client token
issuance or revocation — and its native audit attributes to the local OS user.

```
harness  ──(streamable HTTP + Bearer <grant token>, tailnet)──►  edge
edge     ──(loopback HTTP, grant token stripped)─────────────►  gateway
```

The edge adds exactly three things and nothing else:

1. **Grant authentication**, resolved from the store per request.
2. **Machine binding** via in-process tsnet WhoIs.
3. **Manifest authorization and the authoritative audit row** for every
   `tools/call`. A call that cannot be audited is not forwarded.

Every other MCP frame — initialize, `tools/list`, the SSE stream, session
teardown — is forwarded verbatim with the Homeplane token stripped. MCP
semantics stay with the gateway.

**The bypass boundary is the loopback binding.** `--gateway-mcp-url` must be a
literal loopback address and is refused otherwise, so the only route to the
gateway from another tailnet node runs through the edge, where grants,
revocation, capability checks and audit apply. `deploy/server/verify.sh` proves
it from a second node on every deployment: `gateway_bound_loopback_only`,
`gateway_unreachable_from_peer`, `gateway_unreachable_via_node`.

### The connector manifest

Connectors are declarative. A manifest entry carries the provider, its
credential references, the MCP source, and a per-tool mapping to an action class
(read | write | delete | send) plus the capability that class requires. The edge
derives authorization and the audit row from that mapping — there is no
connector-specific authorization code anywhere.

Three properties matter more than the schema:

- **Unmapped tools fail closed.** A tool the gateway exposes with no mapping is
  denied at invocation and audited as a policy violation. A connector upgrade
  cannot introduce an unclassified write with implicit access. Live: a Drive
  write from both harnesses was refused `excluded_tool` with the reason "D18:
  Drive is read-only in Homeplane".
- **Argument-level guards are declarative too.** Calendar's `manage_event`
  defaults `send_updates` to `all`, which emails every attendee — sending. The
  manifest guards it: a call without `send_updates:"none"` requires
  `connector.send`, which neither skeleton harness holds. Live: refused
  `capability_missing` from both harnesses.
- **Audit is metadata, never payload.** A mapping may declare a JSONPath-style
  artifact-id extractor (event id, file id); without one the row records the tool
  name plus a digest of the arguments — never the arguments. Enforced by the
  schema and an allow-listed detail vocabulary, not by convention. Live: 840
  rows checked, zero carrying the test event's summary, zero oversized values.

**Connector-agnosticism is tested, not asserted** (R12):
`internal/server/connectors/r12_test.go` registers a second connector from a
manifest entry alone, and `internal/server/credflow/onboarding_test.go` onboards
a second OAuth provider the same way — no code outside the manifest.

### Credential custody

Provider credentials exist only on the server, encrypted at rest with an age key
(`var/secrets.age-key`, 0600, systemd-provisioned). `homeplane-agent
add-credentials <provider>` runs the consent on the machine and lands the
credential server-side:

- The agent binds a loopback listener **first** and passes that exact address as
  the redirect URI. The server validates it is genuinely `http://127.0.0.1:<port>`
  or `http://[::1]:<port>` and uses the identical URI when building the
  authorization URL and again at token exchange.
- The outcome is relayed **once** (replay → 409), PKCE and state verified
  server-side. Redeeming the code is a **server-owned job** no request can
  cancel; the machine learns the result by polling, so a lost relay response
  costs one poll rather than a false failure.
- The flow's window bounds how long the human has to consent, not how long the
  exchange may take.
- **Replacement is an atomic swap.** The existing credential stays active until
  the new one is durably stored, so denied, expired, failed and abandoned flows
  all leave it untouched. Two racing flows produce one commit and one clear
  "nothing was overwritten".
- Terminal failures return `{error_code, message, retryable}` from a closed
  vocabulary that cannot carry a provider body or token.

Live on this deployment: an already-configured provider was refused with a 409
rather than silently overwritten; the credential is in the encrypted store; a
search of the agent state and both harness configs found zero provider tokens on
the machine; the commit was audited by ref and generation, never by value.

**Storage and readiness are separate claims.** The connector reads its
credential from a directory, so the server materializes it there. `completed`
is the READY state: a client that polls its way there may make a connector call
next, and it never carries a diagnostic. If delivery fails the credential is
still stored — re-authorizing would change nothing — and the flow ends in its
own terminal state, **`undelivered`**, carrying the non-retryable
`delivery_failed` diagnostic. `add-credentials` then says the credential is
stored and NOT usable yet and exits non-zero, and `/healthz` reports
`workload_credential` degraded until a later delivery succeeds. The state exists
because neither neighbour is true: `completed` would promise a usable connector,
and `failed` would promise that nothing was stored.

## The retrieval engine, and the D16 seam

The machine plane's "index and search the vault" responsibility is a **named
role**, not a hard-wired dependency on GNO (D16). There is no plugin interface —
building one now would be speculation — but the seam is kept where it is cheap:

- The agent supervises *the retrieval engine* as a named component with its own
  config and health slot.
- Activation publishes an **endpoint descriptor** at
  `~/.homeplane/endpoints/retrieval-engine.json` (transport, command, argv, env).
- The harness writer consumes only that descriptor.
  `EntryFromDescriptor` branches on nothing engine-specific: swapping the engine
  means publishing a different descriptor, not editing the harness package.

Two lifecycles, deliberately not conflated (D8, `docs/decisions/d8-gno.md`):

| Half | Mode | What `status` may claim |
|---|---|---|
| indexing + health | supervised **daemon** | pid, restart count, crash-loop |
| the harness endpoint | **stdio**, per client | the last launch's result — never a pid |

Harnesses launch `homeplane-agent gno mcp`, not the engine directly, so every
launch — including the ones that fail instantly — is recorded and reported. The
daemon's own loopback MCP gateway is deliberately *not* the harness path: it
would need one bearer token shared across every harness on the machine, which
the skeleton cannot revoke per harness, and that is the whole point of R9.

**The index is machine-local and disposable.** It lives under the agent state
directory, never inside the vault or any synchronized tree — activation refuses
otherwise — and `gno rebuild` recovers it from the vault alone. Vault files sync
between machines; indexes never do.

**Open, on this machine, right now:** gno 1.29.6 allows one resident runtime per
index. With the daemon loaded a harness stdio launch fails with `database is
locked`; with it stopped the same launch connects. D8 chose daemon mode, so this
machine runs the stdio half only and refreshes the index by activation rather
than continuously — `status` says so instead of rounding it up to fine. The
follow-up is recorded, unresolved, in `docs/decisions/d8-gno.md` §8.

## The skills layer

Vault-authored skills reach each harness by **linking**, never by copying. The
vault is the only original, so editing a skill in Obsidian changes what every
harness reads.

Established against the real `claude 2.1.227` and `codex-cli 0.146.0` (D14/D15,
`docs/decisions/d14-skills-linking.md`) — both harnesses turned out to be
native-link, so no adapter was needed or built:

- Claude Code enumerates `$CLAUDE_CONFIG_DIR/skills` (else `~/.claude/skills`)
  and names a skill after the **link directory**.
- Codex enumerates `$CODEX_HOME/skills` (else `~/.codex/skills`) and names it
  after the SKILL.md frontmatter **`name`**.
- Homeplane links under the vault slug and refuses a skill whose two names
  disagree rather than provisioning something that would be called two things.

**No harness config file is touched at all** — skills are directory-discovered,
so R5's merge machinery is not in this path. Inside the skills directory
Homeplane only creates, repoints or withdraws entries it created and recorded in
`~/.homeplane/skills/skill-links.json`; an entry it did not create is left
exactly as it was.

Two refusals are part of the design, not politeness: a skill carrying credential
material or runtime state is never linked, and a skill that drives host
scheduling or service control is marked unsupported with the line that matched —
Homeplane distributes access and instructions, not initiative.

Provisioning is proved by a **fresh harness process**, not by our own record:
Claude Code's `system`/`init` stream-json event carries a `skills` array, and
`codex debug prompt-input` renders `<skills_instructions>` with resolved
locators. Neither probe makes a model request.

## Harness configuration

Two harnesses (D1: Claude Code, Codex), each configured with the local retrieval
engine (stdio) and the server connector endpoint (HTTP + its own bearer):

- **Merge-only, semantically.** The parse of the file after the write, minus the
  Homeplane-managed entries, is deep-equal to the parse before. TOML writes are
  span-scoped so only the managed table is touched. A malformed existing config
  aborts that harness with a clear message and an intact backup — never a
  clobber.
- **A timestamped backup precedes every write**
  (`<config>.homeplane-backup-<UTC timestamp>`).
- **Token hygiene.** Grant tokens live only in user-scoped 0600 files, never in
  a git-shared file — Claude Code user/local scope only, never project-scope
  `.mcp.json`. Codex's bearer lives inline in the 0600 `config.toml`: the
  environment-variable indirections (`bearer_token_env_var`, `env_http_headers`)
  were tested against the real binary and do not reach the HTTP request.

## Audit

The audit log is authoritative (D13); the gateway's own logs are supplementary
diagnostics. It is fail-closed in both directions:

- A lifecycle mutation and its audit rows commit in **one SQLite transaction**.
  If the record cannot be written, the change does not happen.
- A rejected call that cannot be recorded returns **503**, not a plain 401/403.
  The request is refused either way; the different status says the server could
  not uphold its own audit guarantee.

Attribution splits **observed** identity (WhoIs) from **authenticated** identity
(credential), with an explicit actor model — `machine`, `operator` (server-local
admin CLI, no observed machine), `system` (expiry, supersession). Rejected calls
carry a non-reversible token fingerprint and a violation reason instead of an
owner, so a replayed token is never misattributed to the machine it was stolen
from, and never dropped.

## What is deliberately not here

Out of scope permanently: technical-services clients (GitHub, git, Vercel,
shell, filesystem, web search) — those authenticate locally and never pass
through Homeplane; a general-purpose agent tool platform; multi-user support;
building an MCP gateway; web UI; production-hardening GNO itself.

**Deferred hardening** — descoped by Daniel on 2026-08-13 to keep the skeleton
honest and small. Each revisits when the plane grows past single-operator /
few-machines; none is a gate obligation for the skeleton:

| Deferred | Why the skeleton is still honest without it |
|---|---|
| Revocation tombstones (`--block`/unblock) and machine-level revocation | plain per-grant revocation proves the claim; a lost machine is handled by rotating manually |
| Two-phase grant activation | supersede + idempotent `configure-harnesses` converges; the transient stranded-config window is accepted at this scale |
| Published CI release pipeline and tag ceremony | locally staged, checksummed release-form artifacts satisfy R1 |
| Network-capture proof of the no-connector-cloud constraint | the constraint is architectural (self-hosted by design) and verified by design review |
| Standalone token-sweep verification | token-handling rules live in R5/R7 and their tests |
| `homeplane-agent uninstall` and credential cleanup on removal | — |
| Full Obsidian-Sync conflict-rehearsal matrix | the pinned CLI version and the pre-activation vault snapshot remain |
| Skills refresh / dangling-link repair beyond the R15 baseline | — |
| Local (GNO) revocation | skeleton revocation is server-side only; D7 covers extending it |

Also deferred by shape rather than by hardening: workload-granularity grants were
dropped entirely, more than two harnesses, and every connector beyond Drive and
Calendar — each of which is a manifest entry plus credentials, which is exactly
what R12 exists to keep true.
