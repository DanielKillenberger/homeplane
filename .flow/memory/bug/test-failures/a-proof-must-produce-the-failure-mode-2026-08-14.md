---
title: A proof must PRODUCE the failure mode it claims to verify
date: "2026-08-14"
track: bug
category: test-failures
module: test/e2e/proof_test.go
tags: [e2e, assertions, false-positive, acceptance, truth-table]
problem_type: test-failure
symptoms: Truth-table stage reported green while three of its four failure modes were never produced
root_cause: "Assertions checked the shape of an outcome (non-zero exit, degraded component) without establishing that the cause under test produced it"
resolution_type: fix
---

## Problem
The end-to-end proof reported the R10 truth table green while three of its four
failure modes were never produced. `homeplane-agent status -server <dead>` used a
flag `status` does not have, so exit 64 (usage error) satisfied
`ExitCode != 0`. `gno deactivate` was called without `-execute`, so it printed
"nothing was changed" and the machine stayed exactly as it was — while the
assertion that the engine was down passed, because the component was already
degraded for an unrelated reason. The "missing vault" case only rejected a path
that had never existed. The evidence file recorded the contradicting output
verbatim, in the same stage it marked as passed.

## What Didn't Work
Asserting on the SHAPE of an outcome — a non-zero exit, a degraded component, an
absent string — without establishing that the cause under test is what produced
it. Every one of those assertions was true. None of them was about the thing it
claimed to be about.

## Solution
Produce the mode, then assert the consequence:
- an unreachable server and a missing vault against a COPY of the machine's own
  state directory, edited to point somewhere dead (a proof may not take the real
  vault away from a working machine);
- the engine genuinely deactivated with `-execute`, and restored afterwards;
- the gateway actually stopped on the server, so `curl -sf` MUST fail and the
  payload must NAME the degraded component.
Where the mode cannot be produced, record a limitation with an owner instead of
an assertion that passes.

The same fix applies to every step that trusted an agent's prose: settle it on
the SERVER's audit row (outcome, action class, artifact id, attribution), and
treat the harness's own account as evidence of provenance only.

## Prevention
- Before trusting a green assertion about a failure mode, break the mode
  deliberately and confirm the assertion goes red. If it stays green, it was
  never testing that.
- An assertion whose observation is "something non-zero happened" is a smell:
  name the specific state, the specific component, or the specific status code.
- When a command's own output contradicts the stage's verdict — "flag provided
  but not defined", "nothing was changed" — that is the test failing, not noise.
