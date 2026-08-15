# fn-5 Phone-home as Homeplane's escalation plane

## Outcome
Phone-home is re-founded as Homeplane's escalation plane: a server-side escalation service reachable through the existing edge as a grantable MCP capability with tiered authority (ordinary harnesses ask the steward only; the steward alone holds ask-daniel interrupt authority), audited under a ratified content policy, replacing the palantir-era bespoke client path - captured as one or more specs ready for planning.

## Notes
- Palantir bus live on clawniel: tmux `palantir`, http://100.82.79.48:8484, bearer /home/claw/.config/palantir/secret 0600 [ref: gno://daniel-os/archive/2026-07-16/CURRENT_CONTEXT-snapshot.md]
- phone-home v2 design exists: supervised-agent mode + Clawniel coordinator, message kinds as header lines [ref: gno://daniel-os/projects/phone-home/DESIGN.md rev:09fe7f64]
- Coordinator skill binds Clawniel behavior to bus turns (source=palantir:<author>) [ref: gno://daniel-os/skills/phone-home-coordinator/SKILL.md rev:01553953]
- Nenya->Hermes migration retained palantir + phone-home-coordinator as 'narrow Nenya utility temporarily'; phone-home-bridge.service disabled; Homeplane recorded as planned successor [ref: gno://daniel-os/projects/phone-home/log/2026-07-26-hermes-default-handover-msg130.md]
- Daniel-reported failure modes: transport fine; bespoke client integration unreliable; subagents poked Daniel directly instead of the coordinator; coordinator must itself be able to phone-home [ref: user 2026-08-15]
- STRATEGY.md boundary: Phone Home is a separate later module reusing Homeplane's identity/enrolment layer [ref: STRATEGY.md]
- Homeplane primitives available: per-harness grants, policy table, edge with machine-bound tokens, audit with actor model, capability guards [ref: docs/ARCHITECTURE.md]

## Decisions
<!-- the ledger: one line per resolved decision, append-only, D-IDs never reused -->

## Open Questions

- Build-handover trigger design (take over fn-N) rides escalation - separate spec atop this chart's outcome
- Cutover sequencing from palantir bus (migrate vs bridge vs hard retire)
- Retention/deletion policy details for escalation records
- Whether notify (fire-and-forget) and ask (blocking) are one capability or two
## Boundaries

