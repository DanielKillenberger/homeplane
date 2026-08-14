---
title: An acceptance gate that accepts 'partial' evidence stages verifies nothing
date: "2026-08-14"
track: bug
category: test-failures
module: scripts/final-gate.py
tags: [acceptance-gate, evidence, verification, false-negative]
problem_type: test-failure
symptoms: Gate reports 14/14 requirements pass while the live proof it rests on carries four false assertions; the same gate passes vacuously when handed no gates at all
root_cause: "Stage-level pass/partial labels were trusted instead of the assertions inside them, and required inputs were optional so all([]) returned True"
resolution_type: fix
---

## Problem
A spec's final acceptance gate mapped every requirement to its recorded evidence
artifact and reported 14/14 pass — while the live end-to-end proof it rested on
contained four FALSE assertions. The live-proof schema records limitations as
false assertions carrying their reason and owner (which is what keeps the
artifact honest), and marks such a stage `partial`. The gate accepted both
`pass` and `partial` and never looked inside, so a stage saying "the retrieval
engine is NOT running as a supervised daemon" still closed R4.

The same gate could also pass vacuously: `--gate` and `--deploy-verify` were
optional, so `all([])` over an empty gate list returned True. A run that
validated nothing reported `pass`.

## What Didn't Work
Trusting the artifact's own stage-level verdict. `partial` is the artifact
saying "something here is not what it claims to be" — treating it as a softer
`pass` inverts its meaning. Equally wrong would have been failing on every
`partial`: three of the four limitations are genuine, already-ratified product
decisions, and failing them would have blocked a correct gate.

## Solution
Separate "a limitation someone ratified" from "something broke", and make the
gate know each one BY NAME:

- a `RATIFIED_LIMITATIONS` table keyed on (artifact, stage, exact claim text),
  each entry citing the decision that ratifies it and mirrored in the spec's
  Boundaries;
- the gate ignores the stage's `pass`/`partial` label entirely and checks each
  false assertion against that table — an unmatched one fails the requirement,
  so a NEW limitation in a re-recorded artifact cannot slip through;
- run completeness is its own check: required gates must be SUPPLIED and green,
  the gate head's worktree clean, deployment verification present with zero
  pending and its caveat-closing check explicitly passing;
- a missing `working_tree_dirty` is never read as clean — gate-emitted artifacts
  must carry it, live proofs are exempt by declared `kind` and the exemption is
  recorded in the output.

## Prevention
Any gate that consumes evidence artifacts should be exercised against tampered
copies before it is trusted: missing artifact, non-ancestor commit, dirty
worktree, failed assertion, absent named test, absent named stage, unratified
false assertion, empty gate list. Each of those returning `fail` is the only
thing that distinguishes a gate from a formatter. Run that negative suite in
the same session that writes the gate — a green gate proves nothing until you
have watched it go red.
