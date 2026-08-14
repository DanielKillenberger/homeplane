---
title: "Authoritative audit must commit with its mutation, and denials must fail closed"
date: "2026-08-13"
track: bug
category: security
module: internal/store/sqlite.go
tags: [audit, transactions, fail-closed, security, sqlite]
problem_type: security
symptoms: Revocation/enrolment could succeed with no audit row; rejected calls denied without a record
root_cause: "Audit written as a separate best-effort call after the mutation, and best-effort on denial paths"
resolution_type: fix
---

## Problem
Homeplane's `AuditEvent` log is the authoritative record (D13), but the first
implementation wrote it fail-open on BOTH sides: lifecycle mutations (enrolment,
credential rotation, grant issuance/supersession, revocation, secret import)
committed first and then called `AppendAudit` separately, logging failures; and
rejected calls (invalid token, machine-mismatch replay, over-policy request)
were refused while their audit row was best-effort. A revocation could therefore
take effect with no record, and an attacker probing with stolen tokens could be
denied invisibly. Codex review (gpt-5.6-sol @ xhigh) flagged this P1 twice —
fixing only the mutation half left the denial half open for a second round.

## What Didn't Work
"Log the error and continue" reasoning — that dropping a request because the log
is broken turns an observability fault into an availability fault. That argument
is valid for incidental telemetry and invalid for an authoritative audit log:
if the log is the security record, an unrecorded action is worse than a failed one.

## Solution
Two mechanisms, both structural rather than conventional:
- Every mutating store method takes an audit callback whose events are written
  in the SAME transaction (`internal/store/sqlite.go`, `appendAuditTx`). A nil
  callback is an error, so opting out is always visible at the call site. A
  failed audit write rolls the mutation back.
- Denial paths route through one `deny` helper (`internal/server/server.go`)
  that writes the row first and returns 503 `unavailable` when it cannot. The
  request is refused either way; only the status differs.
Failure-injection tests per mutation type and per denial shape prove it: inject
an audit failure, assert the mutation did not happen / no data was served.

## Prevention
When a log is declared authoritative, treat "mutation without its record" as the
bug, not "request failed because logging failed". Ask early: can this write
commit while its audit row does not? If yes, the audit is decorative. Cover it
with failure injection — a passing test suite proves nothing about a path that
only executes when the log breaks.
