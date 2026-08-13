---
title: "Verification must query current state, not the audit log of past events"
date: "2026-08-13"
track: bug
category: security
module: deploy/server/verify.sh
tags: [deployment, secrets, verification, audit, acceptance]
problem_type: security
symptoms: Deployment check reported green while both required provider credentials were missing from the store
root_cause: The check greped the audit log for any past secret_imported event instead of asking the store which refs it currently holds
resolution_type: fix
related_to: [bug/security/authoritative-audit-must-commit-with-2026-08-13]
---

## Problem
A deployment verification suite passed while the thing it verified was absent. The
check for "provider credentials are in the credential store" grepped the audit log
for any `secret_imported` event. A throwaway self-test import satisfied it, so the
suite reported green on a server missing both credentials the connector manifest
requires — the exact failure a verification step exists to prevent.

## What Didn't Work
Two weaker instincts, both rejected in review:
- Grepping the audit log. An audit row is a fact about the PAST ("an import
  happened"), not about current contents. A store restored from an empty state, or
  replaced entirely, keeps satisfying it forever.
- Counting `age-encryption.org/v1` headers in the raw database file. It proves
  *some* ciphertext exists; it associates nothing with any particular required row.

## Solution
Ask the store, per ref, through a purpose-built read-only surface:
`homeplane-server admin secret list` (cmd/homeplane-server/admin.go) over
`store.ListSecretMeta` (internal/store/sqlite.go), which returns metadata only —
ref, generation, ciphertext length, `encrypted` (secrets.LooksEncrypted: the bytes
are an age message), timestamps — and has no code path that can return a value.
deploy/server/verify.sh reads the required refs out of the DEPLOYED manifest
(`*_ref` driver params) rather than hardcoding them, and asserts each is present
AND encrypted.

For the credential that genuinely could not be imported (its OAuth app is a human's
action inside their own Google account), the check reports `pending` with a declared
reason via `--pending/--pending-reason`, and the run result becomes
`pass_with_pending` — never `pass`. The acceptance criterion was formally amended
with the authorization, and the item recorded as inherited by the downstream task.

## Prevention
- When a check asks "is X present?", make it query current state, not a log of past
  events. Logs answer a different question and answer it forever.
- A verification that cannot fail is not a verification. Before trusting a green
  check, delete the thing it checks and confirm it goes red.
- When something truly is blocked outside the machine, encode it as an explicit
  pending state with a reason — never weaken the assertion until it passes. The
  first is recorded and recoverable; the second silently stops verifying.
