# D18 addendum — the Google scope set the shipped connector actually needs

**Status:** Proposed refinement of D18, pending Daniel's ratification.
**Date:** 2026-08-14
**Task:** fn-1-homeplane-walking-skeleton-install.12
**Applies to:** `configs/connectors/google.json`

## D18 as decided

Google Drive is **read-only** in Homeplane (its write tools stay unmapped, so
the fail-closed denial is the live proof of the policy) and Google Calendar
carries **read + write**. Scopes: `drive.readonly` + `calendar.events` ONLY —
in particular NOT the full `calendar` scope and NOT `drive.file`.

## What the pinned connector forces

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
though Google's own API permits reading events under it. Under D18's literal
scope set, the connector refuses `get_events` locally — which removes steps 2, 4
and 6 of the six-op proof (read back, verify, verify cleanup).

## The refinement

The shipped manifest requests three scopes:

```
https://www.googleapis.com/auth/drive.readonly
https://www.googleapis.com/auth/calendar.events
https://www.googleapis.com/auth/calendar.readonly
```

`calendar.readonly` is strictly a READ scope on data D18 already grants write
access to. It widens no authority: nothing becomes writable, deletable or
shareable that was not already, and the full `calendar` scope (which would add
calendar-level management) is still not requested. D18's intent — Drive
read-only, Calendar events read+write, nothing broader — is unchanged.

The alternatives were both worse:

- **Omit the credential's scope list**, which makes the connector skip its own
  scope check entirely. That trades a truthful declaration for a bypassed
  defense-in-depth check, and the request would still work only because Google
  allows it.
- **Drop the read-back steps**, which guts the reversible-write proof: a write
  nobody read back is not a proof that the write happened.

## Consequences

- The consent screen lists three scopes. Anyone auditing the grant at
  https://myaccount.google.com/permissions sees Drive (view-only) and Calendar.
- `create_calendar` stays EXCLUDED in the manifest: it needs the full `calendar`
  scope, which is still deliberately not granted.
- If D18 is ever tightened back to two scopes, `get_events` must be replaced
  with a Calendar read path that runs under `calendar.events` — at v1.24.0 the
  pinned connector offers none.
