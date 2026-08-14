# D18 addendum — the Google scope set, and notifications as send authority

**Status:** RATIFIED by Daniel, 2026-08-14. Recorded canonically in the epic's
Decision Context (D18, amended 2026-08-14); this file is the engineering detail
behind that amendment.
**Task:** fn-1-homeplane-walking-skeleton-install.12
**Applies to:** `configs/connectors/google.json`

## D18 as originally decided

Google Drive is **read-only** in Homeplane (its write tools stay unmapped, so
the fail-closed denial is the live proof of the policy) and Google Calendar
carries **read + write**. Scopes: `drive.readonly` + `calendar.events` ONLY —
in particular NOT the full `calendar` scope and NOT `drive.file`.

## Amendment 1 — `calendar.readonly` (ratified 2026-08-14)

The pinned connector (`workspace-mcp` v1.24.0) declares a required scope per
tool and refuses a tool whose scope the stored credential does not carry. Its
scope table (`auth/service_decorator.py`) maps the Calendar READ tool
`get_events` to `calendar_read` → `calendar.readonly`, and its scope hierarchy
(`auth/scopes.py: SCOPE_HIERARCHY`) treats only the FULL `calendar` scope as
covering `calendar.readonly`:

```python
CALENDAR_SCOPE: {CALENDAR_READONLY_SCOPE, CALENDAR_EVENTS_SCOPE}
```

`calendar.events` is therefore not treated as covering `calendar.readonly`, even
though Google's own API permits reading events under it. Under D18's original
scope set the connector refuses `get_events` locally — which removes steps 2, 4
and 6 of the six-op proof (read back, verify, verify cleanup).

The shipped manifest therefore requests three scopes:

```
https://www.googleapis.com/auth/drive.readonly
https://www.googleapis.com/auth/calendar.events
https://www.googleapis.com/auth/calendar.readonly
```

`calendar.readonly` is a READ scope on data D18 already grants write access to.
No write, delete or send authority is added, and the full `calendar` scope
(which would add calendar-level management) is still not requested.
`create_calendar` stays EXCLUDED in the manifest for exactly that reason.

The alternatives were both worse:

- **Omit the credential's scope list**, which makes the connector skip its own
  scope check entirely. That trades a truthful declaration for a bypassed
  defense-in-depth check.
- **Drop the read-back steps**, which guts the reversible-write proof: a write
  nobody read back is not a proof that the write happened.

## Amendment 2 — notifications are send authority (ratified 2026-08-14)

Found by review, and the more consequential half.

`manage_event` takes a `send_updates` argument and the connector defaults it to
`"all"` (`gcalendar/calendar_tools.py`: `send_updates=send_updates or "all"` on
the create, update, delete AND rsvp paths). Google's `sendUpdates=all` emails
every attendee. So a create, update or delete on an event with attendees reaches
third parties — which is **send** authority, arriving through a tool the action
class calls `write` or `delete`.

Left alone, a grant holding only `connector.write` could notify a room full of
people, and the audit row would call it a write. Neither skeleton harness holds
`connector.send` (`policy.Default()` grants read, write and delete only).

The manifest now declares a **capability guard** on `manage_event`:

```json
"capability_guards": [
  { "pointer": "$.send_updates", "unless_in": ["none"],
    "capability": "connector.send",
    "reason": "the connector defaults send_updates to \"all\", which emails every attendee; ..." }
]
```

A guard can only ever ADD a required capability, and it fires on doubt — absent,
non-scalar, or any value other than `"none"` all require `connector.send`. The
omitted case is precisely the connector's notify-everyone default, so failing
safe and failing closed coincide here.

`rsvp` was **removed from the action selector's cases** rather than guarded:
responding to an invitation messages the organizer and the connector offers no
silent form of it. An `action: "rsvp"` call now classifies as nothing and is
denied `unresolved_action` as a policy violation.

Every live write in the proof passes `send_updates: "none"` explicitly, so the
proof exercises the path a real caller must take.

### The guard's live proof is deferred to task .7 (Daniel-authorized, 2026-08-14)

The guard is proven in the unit and manifest tests, and every live write in the
task .12 proof now passes `send_updates: "none"` — but the recorded live run
predates the guard, so **no live run yet exercises the guarded path against real
Google**. Re-running the Calendar legs in .12 would need a fresh browser consent
and a rebuilt ToolHive workload after teardown, to prove a path that .7's
end-to-end run exercises anyway.

Daniel **explicitly authorized deferring that live leg into
`fn-1-homeplane-walking-skeleton-install.7`** on **2026-08-14** — the same
precedent as .15's deferred credential import. The acceptance item is
**inherited by .7, not dropped**:

> Inherited from .12 (Daniel-authorized deferral 2026-08-14): the guarded
> Calendar mutation path (`send_updates:"none"` + `connector.send` gating) is
> proven LIVE against real Google as part of this task's six-op run — including
> one denied `manage_event` call WITHOUT `send_updates:"none"` (or RSVP) audited
> as `capability_missing`.

The denial half matters as much as the allow half: a guard that has only ever
been observed permitting is not a guard anyone has watched refuse.

## Consequences

- The consent screen lists three scopes. Anyone auditing the grant at
  https://myaccount.google.com/permissions sees Drive (view-only) and Calendar.
- Calendar writes are silent-only for the skeleton's harnesses. A future grant
  carrying `connector.send` would be permitted to notify — the guard is a
  capability check, not a hard-coded refusal.
- If D18 is ever tightened back to two scopes, `get_events` must be replaced
  with a Calendar read path that runs under `calendar.events` — at v1.24.0 the
  pinned connector offers none.
