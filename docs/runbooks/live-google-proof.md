# Runbook — the live Google connector proof

The Google connector (Drive read-only + Calendar read/write, per D18) is a
manifest entry: `configs/connectors/google.json`. Everything about it that can
be decided without talking to Google is covered by ordinary tests that run on
every `go test ./...` — the mappings, the fail-closed refusals, the action
classes, the credential shape.

What ordinary tests cannot decide is whether the whole path works against real
Google: consent, custody, a real Drive read, a real Calendar round trip, a real
refusal. That is this runbook. It is behind the `live_google` build tag and an
environment guard, so nobody runs it by accident.

Everything below runs on ONE machine over loopback. The tailnet half (tsnet
WhoIs, cross-node machine binding, direct-gateway-bypass-fails) is proven
separately — `docs/decisions/d6-gateway.md` gate 1 and task .16.

## What you need

- `thv` (ToolHive) and a container runtime.
- A Google OAuth client of type **Desktop app** (its JSON download), for an app
  in OAuth **Testing** mode. Testing-mode refresh tokens expire after a week;
  re-running `add-credentials -replace` is the whole re-auth path.
- A Google account to consent as, and a hand on the keyboard: a real browser
  window opens and a human clicks through it.

## 1. Server state: the age key and Homeplane's own OAuth client

The client id and secret are Homeplane's, not the user's. They go into the
encrypted store, off argv (`ps` is world-readable) and out of shell history.

```bash
LIVE=~/.homeplane-live
mkdir -p "$LIVE/server-state" "$LIVE/workload-creds"
chmod 700 "$LIVE" "$LIVE/server-state" "$LIVE/workload-creds"

homeplane-server admin secret init-key -state-dir "$LIVE/server-state"
```

`admin secret import` needs the database to exist. The credential test below
creates it on its first run, so run step 3 once now: it stops at
`the server has no client_id_ref for provider "google"`, which is the expected
result and leaves `homeplane.db` behind.

Then split the downloaded client JSON into two 0600 files and import them:

Pass the downloaded client JSON's path explicitly — `open()` does not expand a
glob, and a wildcard here fails on a literal filename before anything is
imported:

```bash
CLIENT_JSON=~/Downloads/client_secret_1234-abcd.apps.googleusercontent.com.json

TMPD=$(mktemp -d); chmod 700 "$TMPD"
python3 - "$TMPD" "$CLIENT_JSON" <<'PY'
import json, os, sys

tmp, pattern = sys.argv[1], os.path.expanduser(sys.argv[2])
# Tolerate a glob, but never guess between two clients: importing the wrong
# OAuth app produces a consent screen that works and a connector that cannot
# refresh.
import glob
matches = glob.glob(pattern) if any(c in pattern for c in '*?[') else [pattern]
if len(matches) != 1:
    raise SystemExit(f'need exactly one client JSON, {len(matches)} matched {pattern!r}: {matches}')

d = json.load(open(matches[0]))['installed']
for name, key in (('id', 'client_id'), ('secret', 'client_secret')):
    fd = os.open(os.path.join(tmp, name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(d[key])
PY

homeplane-server admin secret import -state-dir "$LIVE/server-state" -file "$TMPD/id"     google/client-id
homeplane-server admin secret import -state-dir "$LIVE/server-state" -file "$TMPD/secret" google/client-secret
rm -f "$TMPD/id" "$TMPD/secret"; rmdir "$TMPD"
```

Note the flag order: the secret ref comes AFTER the flags.

## 2. The connector workload

The pinned connector is `workspace-mcp` v1.24.0, run through ToolHive's uvx
scheme. Two environment settings are load-bearing:

- `WORKSPACE_MCP_HOST=0.0.0.0` — the server binds `127.0.0.1` *inside its own
  container* by default, which ToolHive's ingress proxy cannot reach (the
  symptom is a 502 from the workload URL). The container is network-isolated by
  ToolHive and its proxy stays loopback-bound on the host, so the boundary is
  unchanged.
- `WORKSPACE_MCP_CREDENTIALS_DIR=/creds` plus a volume — this is where
  Homeplane delivers the brokered credential (step 3).

And one build-time dependency is equally load-bearing:

- `--build-with PySocks` — ToolHive isolates the container's network and routes
  its egress through a Squid proxy, advertised in `HTTP_PROXY`/`HTTPS_PROXY`.
  The Google client libraries reach the network through `httplib2`, which reads
  those variables **only when PySocks is importable** and otherwise silently
  attempts a direct connection. Without it every Google call fails with
  `[Errno 101] Network is unreachable` — a message that says nothing about
  proxies. Adding it keeps egress control on, which is the point of the
  isolation.

```bash
thv run --name homeplane-google --transport streamable-http --target-port 8000 \
  --build-with PySocks \
  -e WORKSPACE_MCP_HOST=0.0.0.0 \
  -e WORKSPACE_MCP_CREDENTIALS_DIR=/creds \
  -e MCP_SINGLE_USER_MODE=1 \
  --volume "$LIVE/workload-creds:/creds" \
  uvx://workspace-mcp@1.24.0 -- --transport streamable-http --tools drive calendar

thv list   # note the loopback URL, e.g. http://127.0.0.1:32017/mcp
```

`--tools drive calendar` is what makes the manifest's `tool_inventory` complete.
The manifest refuses to register if the connector advertises a tool it has
neither mapped nor excluded, so a change to this flag — or a connector upgrade —
surfaces as a refusal to start rather than as an unclassified tool.

Deliberately NOT narrowed further: the workload also advertises Drive's write
tools. That is what makes the D18 refusal a real proof — the tool exists, the
gateway would run it, and the manifest is what says no.

## 3. Consent, and where the credential ends up

```bash
HOMEPLANE_LIVE_GOOGLE=1 \
HOMEPLANE_LIVE_GOOGLE_STATE_DIR="$LIVE/server-state" \
HOMEPLANE_LIVE_GOOGLE_ACCOUNT=you@example.com \
HOMEPLANE_LIVE_GOOGLE_CRED_DIR="$LIVE/workload-creds" \
go test ./cmd/homeplane-agent/ -tags live_google -run TestLiveGoogleAddCredentials \
  -count=1 -v -timeout 15m
```

A browser window opens. Consent as the account above; the consent screen lists
`drive.readonly`, `calendar.events` and `calendar.readonly` and nothing else. In
Testing mode Google shows an "unverified app" interstitial — continue past it.

The test then asserts the two halves of custody: the credential IS in the
server's encrypted store, and NO file anywhere in the machine's agent state
directory contains either token. Finally it writes the credential into the
workload's credentials directory in the shape the manifest declares
(`credential_delivery.format`), 0600 in a 0700 directory, atomically.

If nobody consents in time the flow expires and NOTHING is stored — re-run the
same command.

## 4. The connector proof

```bash
HOMEPLANE_LIVE_GOOGLE=1 \
HOMEPLANE_LIVE_GOOGLE_GATEWAY=http://127.0.0.1:26295/mcp \
HOMEPLANE_LIVE_GOOGLE_ACCOUNT=you@example.com \
HOMEPLANE_LIVE_GOOGLE_CALENDAR_ID=primary \
go test ./internal/server/edge/ -tags live_google -run TestLiveGoogle -count=1 -v -timeout 10m
```

Optionally set `HOMEPLANE_LIVE_GOOGLE_DRIVE_FILE_ID` to a specific file id to
exercise the artifact-id path on `get_drive_file_content`.

The four tests are:

| Test | Proves |
|---|---|
| `TestLiveGoogleDriveReadThroughTheEdge` | a real Drive read reaches Google through the edge, audited read-class |
| `TestLiveGoogleDriveWriteIsRefused` | `create_drive_file` refused by the manifest before the gateway, audited as an `excluded_tool` policy violation (D18) |
| `TestLiveGoogleCalendarSixOp` | create → read back → update → verify → delete → verify cleanup on an isolated `homeplane-test-<ts>-<machine>-<harness>-<random>` event, with the delete audited delete-class |
| `TestLiveGoogleRevokedGrantIsRefusedImmediately` | a revoked grant is 401 on the next call, in well under a second |

The Calendar test checks that its event does not already exist before creating
it, and deletes it from a `t.Cleanup` armed BEFORE the create call. The cleanup
is disarmed only once step 6's after-listing shows neither the event id nor the
summary — a provider answering "deleted" has reported an intention, not a state,
so the retry stays armed until absence is observed. If the event's id could not
be parsed out of the connector's prose, the cleanup locates the event by its
unique summary instead; the cleanup then re-queries after its own delete and
prints `CLEANUP FAILED` / `CLEANUP INCOMPLETE` with the calendar and event id if
anything of ours remains.

**Every Calendar write passes `send_updates: "none"`.** The connector defaults it
to `"all"`, which emails every attendee, and the manifest guards that as
`connector.send` — which no harness holds. A call omitting it is refused before
it reaches Google (see `docs/decisions/d18-google-scopes.md`), so the proof uses
the same explicit form a real caller must.

### Evidence

Each live run is recorded in `test/evidence/<task-id>.live.json` and embedded
into the task's evidence artifact by `scripts/emit-evidence.sh`. Update it when
you re-run: the artifact is the acceptance record, and an unrecorded live run
proves nothing to anyone reading later.

Last full run: 2026-08-14 — all four green against real Google, recorded in
`test/evidence/fn-1-homeplane-walking-skeleton-install.12.live.json` with the
commands, timestamps, redacted environment, commit and per-assertion results.

**That run predates the `send_updates` guard**, and the file says so
(`attests_to_current_manifest: false`). Its Calendar legs called `manage_event`
without `send_updates`, which the current manifest refuses; the Drive, consent,
custody and revocation legs are unaffected because none of them touches
`manage_event`. The `manifest_revision` field is what a later reader checks to
know which manifest a run actually attests to.

**The guarded Calendar path was proven in task .7 — the deferral is discharged.**
The end-to-end proof (`test/e2e/`, `test/e2e/run.sh`) runs the guarded six-op
sequence from BOTH harnesses against the deployed server, and includes the
denial leg the inherited acceptance item required: a `manage_event` call without
`send_updates: "none"` refused as `capability_missing` (required capability
`connector.send`), audited. See
`test/evidence/fn-1-homeplane-walking-skeleton-install.7.live.json`.

That run also found two delivery faults that only appear an hour in, both now
fixed and both worth knowing about if you ever re-plumb this:

- **The connector resolves its OAuth CLIENT separately from the user
  credential** (`GOOGLE_CLIENT_SECRET_PATH`, or an env pair) and refuses to
  refresh without it. Everything works until the first access token expires,
  and then every call fails with *OAuth client credentials not found*. The
  server now delivers `client_secret.json` beside the credential.
- **The connector PERSISTS the refreshed token**, so a credential it can read
  and not rewrite dies at the same moment — with the connector reporting that
  the user must authenticate again, moments after the refresh succeeded. The
  credential is delivered `0660` to the connector's own group; the client
  configuration stays `0640`.

## 5. Tear down

```bash
thv stop homeplane-google && thv rm homeplane-google
rm -rf "$LIVE"        # the age key, the store, and the delivered credential
```

Revoking Homeplane's access on the Google side is separate, and worth doing when
the proof is finished: https://myaccount.google.com/permissions.

## Known limitations, recorded rather than hidden

- **The Calendar legs must be re-run after any manifest change that alters what
  a call must send.** The evidence file records the manifest revision each run
  attests to; the send_updates guard, for instance, changes the arguments a
  legitimate caller has to pass.
- **The create step's artifact id is `unknown`.** workspace-mcp returns prose,
  and the manifest's artifact extractor addresses JSON, so the created event's
  id cannot be extracted declaratively. That row carries an args digest instead;
  every later operation on the event names it in the request, where the
  extractor does reach it.
- **`calendar.readonly` is requested alongside `calendar.events`.** D18 pins
  Calendar to `calendar.events`, but the pinned connector's `get_events`
  requires `calendar.readonly` and does not treat `calendar.events` as covering
  it (`auth/scopes.py: SCOPE_HIERARCHY` — only the full `calendar` scope does).
  Reading events is inside D18's intent, so the read-only scope is requested and
  the full `calendar` scope still is not. Worth Daniel's explicit ratification.
- **Credential delivery is not yet wired into `homeplane-server serve`.**
  `internal/server/workloadcred` writes the file and is exercised by the live
  proof; starting the workload with it belongs to the deployment task (.15).
