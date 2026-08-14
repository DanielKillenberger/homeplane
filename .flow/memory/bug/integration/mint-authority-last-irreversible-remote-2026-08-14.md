---
title: "Mint authority last: irreversible remote effects go after every local step that "
date: "2026-08-14"
track: bug
category: integration
module: internal/agent/harness/configure.go
tags: [grants, ordering, idempotence, locking, toml, parsers]
problem_type: integration
symptoms: A corrupt descriptor or a mis-scanned but valid TOML config revoked both harnesses' working grants and then wrote nothing
root_cause: "The grant request (a superseding, irreversible server-side effect) preceded local steps that can fail: descriptor conversion and config rewriting"
resolution_type: fix
---

## Problem
`configure-harnesses` requested a grant (which SUPERSEDES the harness's previous
grant server-side — an irreversible remote effect) and only afterwards did the
local work that can fail: converting the GNO endpoint descriptor into a config
entry, and rewriting the config file. Every local failure downstream of the
request therefore revoked a working harness and wrote nothing in its place.

Two independent findings were the same bug:
- A corrupt or inexpressible descriptor aborted AFTER issuance, so a purely
  local problem cost BOTH harnesses their connector access.
- The hand-rolled TOML span scanner read any line-initial `[` as a table header,
  so a valid nested array (`[1, 2],` inside a multi-line array) was reported as
  a malformed config — again after issuance. The operator saw "your config is
  malformed" about a perfectly good file, with a dead token in it.

## What Didn't Work
Ordering the steps by narrative convenience ("ask for the grant, then write it
down"). Each step's own error handling was correct; the ordering is what made
local failures remotely destructive, and no per-step test can see it.

## Solution
Move every step that can fail ahead of the step that moves authority:
- Load, validate AND CONVERT the descriptor once in `Configure`, before the
  per-harness loop; a fatal descriptor error returns before any issuance
  (`loadEngineEntry`, `internal/agent/harness/configure.go`).
- `Writer.Preflight()` parses the existing config without writing, so a
  malformed config is a skip that costs zero grants.
- Hold the agent state lock across issuance + write + record + state, so a
  second process cannot interleave its issuance between this one's issuance
  and its write (the "A issues, B issues, B writes, A writes" window leaves A's
  revoked token in the file with both runs reporting success).
Fix the scanner's actual defect too: track bracket/brace depth across lines, and
cross-check the scanner against a REAL parser (`BurntSushi/toml`) in a table
test — a fixture that the parser accepts and the scanner refuses is a bug.

## Prevention
- Ask of any remote mutation: what can still fail after this line? If anything
  local can, hoist it above. Prefer a "prepare everything, then commit" split to
  an interleaved sequence.
- A hand-rolled structural editor (span scanner, CST-lite, regex-over-syntax)
  needs an equivalence test against a real parser for the format, and its
  refusals must be reachable BEFORE any irreversible effect. Verify the write
  itself with the real parser too — `parse(after) − managed == parse(before) −
  managed` catches an editor bug as a failed write instead of a corrupted file.
- A superseding-grant lifecycle makes re-running the repair path. That is only
  true if a failed run's next run can still succeed — test the induced-failure
  path and then the convergence, not just the happy path.
