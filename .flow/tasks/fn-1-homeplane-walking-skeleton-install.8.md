---
satisfies: [R13]
---
# fn-1-homeplane-walking-skeleton-install.8 Credential broker: async OAuth flow state machine + add-credentials client

## Description
The server-brokered OAuth credential flow end to end against the spec's state machine — server side and agent side. The live Google Drive connector wiring is .12 (split per plan review). Provable against a fake/test OAuth provider; real-Google proof lands in .12.

**Size:** M
**Files:** `internal/server/credflow/` (state machine, code relay, poll endpoint, credential store write), `internal/agent/credflow/` (loopback listener, browser open, poll loop), `cmd/homeplane-agent/` (add-credentials subcommand)

## Approach
- Server per spec API Contracts (review-fixed): `POST /credentials/flows` `{provider, replace, redirect_uri}` → `{flow_id, authorization_url, expires_at}`; authorization URL and token exchange both use the client's exact loopback redirect_uri (Google requirement); one-shot `POST /credentials/flows/{id}/code` `{code,state}` | `{error,state}` (replay → 409; PKCE + state verified); `GET /credentials/flows/{id}` → `{state: pending|completed|denied|expired|failed, provider, created_at, expires_at}` plus, on terminal failure, the epic's safe diagnostic `{error_code, message, retryable}` distinguishing provider denial, expiry, exchange failure, store failure, and lost-concurrent-commit — never containing provider bodies or tokens. `failed` = exchange/store failure after valid code, retryable via new flow, nothing partial.
- Agent: binds the loopback listener FIRST (choosing the port), passes redirect_uri at flow start, opens browser where Daniel sits, relays outcome once, polls to terminal state. Provider tokens never touch agent disk/argv/logs (R17).
- Already-configured provider → refused without `replace=true`. **Replacement = atomic swap (round-4 fix):** old credential stays active until the replacement is durably stored; every unsuccessful terminal state preserves the old credential untouched (tested per state). **Concurrency (round-5 fix):** flows serialized per provider or CAS on credential generation — two racing flows: one commits, the loser terminates `failed` with a must-retry message; two-machine concurrency test required. Unknown provider → 404 + known list.
- Credential drivers: implement the `oauth2-authcode` driver consuming the manifest's credential-acquisition metadata; prove a SECOND fake OAuth provider onboards via manifest entry only (R12).
- Credential store write per D3 outcome from the spike.

## Investigation targets
**Required:**
- `docs/decisions/d6-gateway.md` — D3/D10 outcomes (from .1)
- `internal/agent/` CLI plumbing (from .4); `internal/server/` from .2
- https://developers.google.com/identity/protocols/oauth2/native-app — loopback flow requirements

## Acceptance
- [ ] Full flow against a test OAuth provider: completed credential lands server-side only; agent filesystem free of provider tokens
- [ ] State machine tests: denial relay, expiry, abandoned (no partial), one-shot replay → 409, exchange failure → `failed` + clean retry, unknown provider 404, replace confirmation required
- [ ] Replacement atomicity: old credential survives every unsuccessful terminal state; swap only on durable store (tests per state)
- [ ] Two-machine concurrent flow race: exactly one commits, loser fails cleanly with clear message (test)
- [ ] Second fake OAuth provider onboarded via manifest entry only — no code changes (R12 proof)
- [ ] redirect_uri consistency: authorization URL and token exchange use the client-bound loopback URI
- [ ] redirect_uri validation: non-loopback forms (any other host, https, path tricks) rejected with 400; `http://127.0.0.1:<port>` and `http://[::1]:<port>` accepted
- [ ] Credential immediately visible to grant-holding callers (stub connector resolves the new credential ref)
- [ ] `go test ./...` green
- [ ] Terminal-diagnostic tests: each failure class returns its distinct `error_code` + correct `retryable`; responses verifiably free of provider bodies/tokens
- [ ] Emits versioned evidence artifact `test/evidence/<task-id>.json` (commit SHA, platform, commands run, assertions, timestamps)

## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
