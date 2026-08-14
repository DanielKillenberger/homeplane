---
title: Decision pivots must be grep-swept into every flow artifact before review
date: "2026-08-13"
track: bug
category: integration
module: .flow/specs/fn-1-homeplane-walking-skeleton-install.md
tags: [spec-drift, review, flow-next, decision-propagation]
problem_type: integration
symptoms: impl-review keeps returning NEEDS_WORK citing task/spec text that contradicts the decision record
root_cause: superseding decision (D18) applied to some flow artifacts but not all bodies referencing the old design
resolution_type: fix
---

## Problem
The D6 spike's codex impl-review returned NEEDS_WORK/NEEDS_HUMAN across several rounds because a product-owner scope-policy pivot (D18: Drive read-only, Calendar read+write, six-op proof moved to a Calendar event) had been applied to SOME flow artifacts (spec D18 entry, .12, .7 title/acceptance) but not all: the .1 task gate text, .7's Approach body, the parent spec's D5 resolution, the manifest extractor note, and the Boundaries "only Drive goes live" line still described the superseded Drive-write proof. The reviewer (correctly) reviews the change against the task/spec text, so every stale line reads as a contradiction.

## What Didn't Work
Updating only the decision record and assuming the spec/task wording would be read "in spirit" — each remaining stale line cost a full review round.

## Solution
Grep-sweep ALL flow artifacts for the superseded concept's keywords (here: `drive.file`, `files.update`, "test folder", "only Drive goes live", "Drive extractor") and update every hit in one commit: .flow/tasks/*.md bodies (not just titles/acceptance), parent spec Decision Context (amend superseded D-entries with "amended by DXX"), Architecture/Boundaries prose, and Open Questions.

## Prevention
When a D-decision supersedes another, do a keyword sweep over .flow/specs/ + .flow/tasks/ + docs/decisions/ in the same change that records the new decision; treat "reviewer cites task text contradicting the record" as a propagation bug, not a review dispute.
