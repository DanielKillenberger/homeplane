---
title: "Manifest membership is not ownership: check the live target too"
date: "2026-08-14"
track: bug
category: integration
module: internal/agent/skills/link.go
tags: [symlinks, ownership, idempotence, locking, durability, preservation]
problem_type: integration
symptoms: Provision repointed and refresh deleted symlinks the operator had taken over; a late failure left links no record claimed; concurrent runs lost each other's records
root_cause: "Ownership was keyed on the manifest record alone, and the manifest was saved once at the end of the run without holding the state lock"
resolution_type: fix
related_to: [bug/integration/mint-authority-last-irreversible-remote-2026-08-14]
---

## Problem
The skills provisioner recorded which harness symlinks it owned in a manifest,
and treated manifest membership ALONE as ownership. Two consequences the review
caught, both of them the preservation rule failing in the direction it exists to
prevent:

- An operator who repointed one of our links at their own copy still had it
  listed under `(harness, linkPath)`, so the next `provision` silently repointed
  it back and the next `refresh` deleted it outright.
- The manifest was saved once at the END of the run. Any later failure — a
  second harness's directory, an unwritable state dir — left real symlinks in
  the operator's harness that nothing claimed: `refresh` could never withdraw
  them, and a later `provision` read them as a stranger's entry and skipped
  forever. Two concurrent runs also lost each other's records outright, because
  the read-modify-write took no lock.

## What Didn't Work
Keying ownership on identity (`which path did we write?`) instead of on state
(`is that still the thing we wrote?`). It reads as sufficient because the
manifest is ours and nobody else writes it — but the manifest describes the
past, and the filesystem is where the operator disagrees with it.

## Solution
Ownership = the manifest record AND the live link still pointing at the recorded
target (`Manifest.owns`, `internal/agent/skills/link.go`). A differing target is
a takeover: report the drift, change nothing. The genuine "the vault moved" case
stays distinguishable for free, because there the link still points at the
recorded OLD target — so it is still ours to repoint, and the two cases never
need a flag to tell apart.

Durability, same file:
- Hold the agent state lock (`agent.Store.Lock`) across the whole run, as the
  harness configurator does.
- Prove the manifest is writable BEFORE the first link is created (a preflight
  save), and save again after every single mutation rather than once at the end.

## Prevention
- For any "we own this" record over a mutable external resource, the ownership
  predicate is record AND current state, never record alone. Ask: what does the
  code do if a human edited the thing between two runs? If the answer is
  "silently undo them", the predicate is too weak.
- A record of a side effect must be durable before the NEXT side effect is
  attempted. "Do all the work, then write the log" turns any late failure into
  untracked state. This is the same shape as `mint authority last` from .6:
  order the steps so nothing irreversible outruns its record.
- Concurrency: any read-modify-write of a shared state file takes the existing
  lock. There is already one in this repo; a new subsystem that skips it does
  not get a pass for being new.
