# Runbook — the end-to-end walking-skeleton proof

One machine, one server, both real, driven end to end in the order a person
would drive them: install → enrol → vault → retrieval engine → skills →
harnesses → credential → connector → the reversible write → revocation →
status/healthz → the operator's audit review.

It lives in `test/e2e/`, behind the `live_e2e` build tag and an environment
guard, so `go test ./...` never builds it. What it needs is a deployment, not a
fixture.

```bash
test/e2e/run.sh                    # every stage, in order
test/e2e/run.sh enrol,vault        # only these
```

Stages: `install enrol vault vault-sync gno skills harnesses gno-retrieval
credentials connector calendar revocation truth-table audit`.

The evidence file is rewritten after **every** stage and carries earlier stages
forward, so an interrupted run loses nothing, a single leg can be re-run, and an
interactive proof can be finished in sittings.

## What it needs

- A deployed server on the tailnet (`deploy/server/README.md`) with its gateway
  running the connector workload, and ssh to that host for the OPERATOR surface
  (`admin audit`, `admin revoke-grant`) — which is server-local by design.
- This machine's own harnesses, installed and signed in. Claude Code must be
  able to run a non-interactive turn: check with
  `claude -p "say OK" --output-format json` and re-run `/login` if it reports an
  expired session.
- A human at a browser, once, for the `credentials` stage.

Coordinates live in `test/e2e/run.sh`; override any of them through the
environment (`HOMEPLANE_E2E_SERVER`, `HOMEPLANE_E2E_SSH_HOST`,
`HOMEPLANE_E2E_ACCOUNT`, `HOMEPLANE_E2E_CALENDAR_ID`, `HOMEPLANE_E2E_VAULT`).

## What settles a claim

**The server's audit log, read through the operator CLI on the server host.** A
harness's own account of what it did is recorded beside every connector
assertion and never believed on its own: a model can report a created event it
never created, and a model that declined to call a tool can leave an error
string that happens not to contain the summary the isolation check was looking
for. So the connector stages assert on the audit row — outcome, action class,
artifact id, `(machine, harness, grant)` — and the harness's prose is evidence of
provenance, not of outcome.

The Calendar test event is uniquely named (timestamp, harness, 64 bits of
CSPRNG), checked for absence before it is created, and deleted by a cleanup
armed BEFORE the create — because the step that can fail while the event
nevertheless exists is exactly the one that parses its id. The cleanup disarms
only once an after-listing shows neither the id nor the summary, and before
printing `DELETE IT BY HAND` it asks the audit whether that harness ever got a
create through at all.

## Driving the harnesses

Both harnesses invoke MCP tools only inside a model turn, so the proof runs one:
`claude -p` with a tool allowlist, and `codex exec`.

**Codex needs `--dangerously-bypass-approvals-and-sandbox`, and that is a
finding rather than a shortcut.** Codex 0.146 routes every MCP tool call through
its approval path, and in `codex exec` there is nobody to answer: with
`approval_policy="never"` the call returns `user cancelled MCP tool call` in
under a second, and disabling the guardian feature flag does not change it. The
exposure is bounded by the prompt instead — one named tool call, fixed
arguments, an explicit instruction to run no shell commands.

## Reading the evidence

`test/evidence/fn-1-homeplane-walking-skeleton-install.7.live.json` records, per
stage: every command with its exit code and output excerpt, and every assertion
with the observation that settles it. Two kinds of entry are worth knowing:

- `status: "partial"` means a stage passed what it ran and recorded a
  **limitation** — a leg that genuinely could not run here, with an owner. There
  are two, both deliberate: the headless sync client is exercised against a
  disposable vault rather than the real one (its owner keeps Obsidian.app as
  the operating sync client), and the retrieval engine runs in stdio mode
  because the pinned build allows one resident runtime per index.
- an assertion whose `ok` is false and whose detail starts with `LIMITATION` is
  one of those, not a failure.

A stage that FAILS is recorded with everything it ran, exactly like one that
passes. An evidence file that only shows successes is a demo.
