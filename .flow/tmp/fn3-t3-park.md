# fn-3 task .3 — park brief (2026-08-15)

**Task:** `fn-3-add-grok-as-a-third-harness.3` — live e2e proof, evidence + gate,
docs delta. **Status: `in_progress`, parked by Daniel's decision.**

**Parked at:** `bc2b600` on branch `fn-3-add-grok-as-a-third-harness`. Tree clean.
**Base for review:** `77dd536` (four commits: `c3a17b6`, `7ba2fe6`, `bc2b600`, plus
the receipt commit that follows this file).

---

## Why it is parked

Every remaining requirement needs grok to make a **model turn**, and grok's
account has no credit:

```
API error (status 402 Payment Required): Grok Build usage balance exhausted
```

Daniel has decided **not** to top up the balance. Rerouting grok to another
provider was explored and then stopped on his instruction — findings are in
"Rerouting: what was learned" below so the next worker does not redo it.

---

## Leg status

| R-ID | State | Where the evidence is |
|---|---|---|
| **R1** detect grok, version + support verdict | **CLOSED live** | `grok-harness` stage, 19/19 |
| **R2** configure with its own grant, preserving | **CLOSED live** | `grok-harness` stage |
| **R3** fresh grok → gno + edge, audited | **BLOCKED (402)** | `grok-gno`, `grok-connector` recorded **fail**, with the 402 captured verbatim |
| **R4** skills linked + discovered, profile key read | **CLOSED live** | `grok-rollout-gate` 6/6, `grok-skills` 11/11 |
| **R5** revocation asymmetry both directions | **BLOCKED (402)** | `grok-revocation` never ran |
| **R6** five status states render distinctly | **CLOSED live** | `grok-status-truth` 8/8 — all five PRODUCED |
| **R12** falsification gate | **PASS** | computed by the gate from `b261dbc` |

Gate today: `scripts/fn3-gate.py` → **R1, R2, R4, R6, R12 pass; R3, R5 fail**;
tamper rejection demonstrated 3/4 (the fourth mutation targets a calendar audit
row that does not exist yet, and correctly declines to claim it).

### What was proven live, in one line each

- grok configured through the ordinary `configure-harnesses` entrypoint with its
  **own** grant (`g-bc17b426a960c6e9`), both surfaces, 0600 re-asserted, a
  timestamped backup, **zero** lines of Daniel's config or comments lost, and
  `[compat.claude] mcps = false` + `[compat.cursor] mcps = false` set and
  re-asserted on the idempotent re-run.
- Rollout gate: the server's `machines` table holds **exactly** this machine
  (`m-1bc11c520f7c59e2`), so the vault profile may name grok.
- Four vault skills linked (symlinks into the vault, never copies) and
  enumerated by a **fresh** `grok inspect`, including `homeplane-capabilities`.
- The `[harness.grok]` key is proven **read, not defaulted**, by falsification:
  changing only that block moves grok's assignment and leaves claude-code's and
  codex's untouched.
- All five status states produced on this machine, none narrated.

---

## Resume procedure

1. **Probe the balance with ONE minimal turn** and nothing else:
   ```bash
   grok --leader-socket /nonexistent --always-approve -p "Say OK."
   ```
   Still 402 → re-park, consume nothing further.
2. If it answers, run the two legs in order (each writes into the same evidence
   file and REPLACES its own stage record):
   ```bash
   export HOMEPLANE_E2E_TASK=fn-3-add-grok-as-a-third-harness.3
   export HOMEPLANE_E2E_EVIDENCE=test/evidence/fn-3-add-grok-as-a-third-harness.3.live.json
   test/e2e/run.sh grok-gno,grok-connector      # R3, first half
   test/e2e/run.sh grok-calendar                # R3, the guarded six-op (~9 turns)
   test/e2e/run.sh grok-revocation              # R5, both directions + restores
   test/e2e/run.sh grok-status-truth            # re-run: it re-reads grants
   test/e2e/run.sh grok-audit                   # settles R3/R5 from the audit log
   ```
3. Re-run the gate, expecting 6/6 + R12:
   ```bash
   python3 scripts/fn3-gate.py --out test/evidence/fn-3-add-grok-as-a-third-harness.3.gate.json \
     --gate build=0 --gate vet=0 --gate test=0
   ```
4. `scripts/emit-evidence.sh fn-3-add-grok-as-a-third-harness.3` for the unit
   artifact (it embeds the `.live.json` under a `live` key).
5. Review loop, then `flowctl done`:
   ```bash
   .flow/bin/flowctl codex impl-review fn-3-add-grok-as-a-third-harness.3 \
     --base 77dd536 --receipt /tmp/impl-review-receipt-fn3-t3.json
   ```
   Foreground waits only. Flat-trajectory reset authorised. Report rather than
   grind past ~6 flattening rounds.

---

## Files, backups, and how to undo anything

| What | Where |
|---|---|
| Live proof artifact | `test/evidence/fn-3-add-grok-as-a-third-harness.3.live.json` |
| fn-3 gate | `scripts/fn3-gate.py` (fn-1's `final-gate.py` untouched) |
| New e2e stages | `test/e2e/grok_test.go` (+ registrations in `proof_test.go`) |
| grok config **before** fn-3 | `~/.homeplane/fn3-grok-backup/config.toml.20260815T004003Z` (sha256 `9b8cdca9…19cd51`) |
| grok config, product backups | `~/.grok/config.toml.homeplane-backup-2026081509142{0,1}Z` |
| Vault profile **before** fn-3 | `~/.homeplane/fn3-vault-profile-backup/homeplane.skills.toml.pre-fn3` (sha256 `627a8c0d…e088`) |

**To undo the vault edit** (only needed if a second machine enrols before the
work resumes — see gotcha 2): `cp` the `.pre-fn3` backup back over
`~/Documents/daniel-os/skills/homeplane.skills.toml`. grok still receives all
four skills through `[defaults]`, so nothing breaks.

---

## Machine end state — healthy, all three harnesses live

```
claude-code  configured  g-633b1d8872079fb2
codex        configured  g-9eabff2ce164f5ce
grok         configured  g-bc17b426a960c6e9   compat=[project(.mcp.json)]
```
`~/.grok/skills/` holds the four linked skills. `status` reads **degraded** only
because of `gno` (fn-1's ratified stdio-mode limitation) and `sync`
(deliberately not configured) — neither is fn-3's doing. Nothing is left on the
calendar; no test event was ever created, because the six-op stage never ran.

**Server:** clawniel was redeployed during this task (it predated grok's policy
row). `verify.sh` 11/11; the upgrade preserved the age key, db inode, tsnet
identity and secret rows — only `server_binary_sha256` moved
(`e190ecc3…` → `193f15de…`).

---

## Gotchas for the resuming worker

1. **`grok mcp list` echoes bearer tokens verbatim.** Never run it where output
   is captured. Use `grok mcp doctor <name> --json` or read the entry.
2. **The vault edit is gated on the fleet.** It is safe today because exactly
   one machine is enrolled. If another machine enrols before this resumes, it
   must run a grok-aware agent, or an older agent will REFUSE the whole profile
   (fail-closed on the unknown `[harness.grok]` key) and skills provisioning
   breaks there. Re-check the `machines` table before assuming.
3. **`HOMEPLANE_E2E_EVIDENCE` must be repo-relative or absolute** — a relative
   path used to resolve against `test/e2e/`, silently writing an artifact nobody
   read. Fixed in `loadEnv`, but do not undo it.
4. **`configure-harnesses` re-mints on every run**, so `~/.grok/config.toml` is
   not byte-stable across runs and the previous grant becomes `revoked`. That
   supersede is what `grok-status-truth` harvests for its `revoked` state — do
   not "clean up" revoked grants before running it.
5. **Deploy order matters**: the policy table is compiled into the server, so a
   harness the deployed server does not know is refused `403 policy: unknown
   harness` at grant issuance. Server first, then machine. This is now written
   into `ARCHITECTURE.md` and `RUNBOOK.md`.
6. **`RATIFIED_LIMITATIONS` in `scripts/fn3-gate.py` is deliberately empty.**
   With nothing ratified, every false assertion fails its requirement. If R3/R5
   are ever accepted as blocked-on-billing rather than proven, that is the table
   to edit — and it needs Daniel's decision named in it, not a placeholder.

---

## Rerouting: what was learned before the stop

Recorded so it is not re-investigated from scratch. **No configuration was
changed and no key material was touched.**

- **grok 1.0.3 does support provider rerouting.** `~/.grok/docs/user-guide/11-custom-models.md`
  documents `[model.<name>]` with `base_url`, `api_backend`
  (`chat_completions` / `responses` / `messages`), `api_key`, and `env_key` — the
  last of which names an environment variable, so a key need never be written to
  disk. `[endpoints] models_base_url` + `XAI_API_KEY` is the global equivalent.
- **A local endpoint would need no credential**, and Ollama is installed and
  serving on this machine — but **none of its three models supports tool
  calling** (`deepseek-r1:8b/14b/32b` each answer
  `does not support tools`, HTTP 400). grok's MCP proof needs tool calls, so the
  local route requires pulling a tool-capable model (a multi-GB download onto
  Daniel's machine — his call, not a worker's).
- **No grok verb makes an MCP tool call without a model turn.** `grok mcp` has
  only `list/add/remove/enable/disable/doctor` (captured contract, not guessed).
- **`grok mcp doctor homeplane` does succeed with no credit**, and it is worth
  knowing what that proves: `server started`, `handshake OK (protocol
  2025-11-25)`, `24 tools discovered`, `healthy: true`. So grok's MCP client
  reaches the Homeplane edge over the tailnet and completes an authenticated
  initialize handshake **using the bearer token Homeplane wrote for grok**. That
  is a real fragment of the wiring — but it is **not** R3: no tool is invoked, so
  there is no action class, no artifact id, and no `connector_tool_call` row.
  Whether the edge audits the handshake was being checked when work stopped; the
  answer is unknown and should not be assumed either way.
