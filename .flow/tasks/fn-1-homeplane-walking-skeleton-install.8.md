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
- `.flow/memory` SQLite-trap entries from .2 (pooled-PRAGMA, RFC3339Nano ordering, WAL sidecar perms) — the credential-flow state machine writes to the same store <!-- Updated by plan-sync: fn-1.2 recorded SQLite pitfalls downstream store-touching tasks should read first -->

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
Implemented R13's credential broker end to end, closing all eight impl-review findings across three rounds. `internal/server/credflow` runs the OAuth flow as a genuinely asynchronous state machine: the relay consumes the one-shot outcome and returns 202 pending, while a server-owned exchange job — uncancellable by any request, awaited at shutdown — redeems the code and commits the credential via `store.PutSecretCAS`. The flow's window bounds the human's consent, not the exchange, and that exclusion is now claimed atomically: eligibility and the terminal decision happen in one locked step, so expiry and a concurrent relay compete for the same lock and exactly one of them wins. Terminal states are fail-closed on audit (decided, recorded, only then exposed) and neither transition can overwrite an existing ending; open flows are bounded per machine and swept; both driver secrets are validated before consent is spent.

`internal/agent/credflow` plus `homeplane-agent add-credentials` binds the loopback listener first, opens the browser, relays once, and converges on the server's outcome by polling — tolerating a lost relay response instead of contradicting a credential that was actually stored. Provider tokens never reach the machine: the flow writes no file at all. Everything provider-specific comes from the connector manifest's `oauth2-authcode` driver, proven behaviourally (a second fake provider onboards through a manifest entry alone) and structurally (an AST scan asserts no provider name in any string literal or identifier of the broker's source).
## Evidence
- Commits: ab21a29296d403f49fdcfc3470432df164f687b1, 565602b0654996a795d898a154c7486926b1155a, 1c4142c4fb6cf0dc214de73d31e604c02a11dfd2, 6568e0bd4d003e17ecca08767a66065964d1df10, f457f26283e80b4e0ca87de6c17d2257d3afc05a, de654a3b1d5b8e14d2709396f2ccc6bfd25fd195, 83bd6f55b1d3ef87b5cd168cd5f6e4a25d290467, 853ce54e9aefcd6c05aa8aef2c4a20414b5763f2, f3f527efc8e3308b6c119da31ae488ed80c71267, 239f4bbd3b53017508aeb673d70ad75071bd2ec9
- Tests: go build ./..., go vet ./..., go test ./... -count=1, go test -race ./internal/... ./cmd/... -count=1, go test ./internal/server/credflow/ -count=5, scripts/emit-evidence.sh fn-1-homeplane-walking-skeleton-install.8 (307/307 assertions, 3 gates, pass, clean tree, at f3f527e)
- PRs: