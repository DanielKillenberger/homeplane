---
satisfies: [R1, R2]
---
# fn-4-complete-the-google-workspace-connector.1 Contract capture + complete Google manifest

## Description
Contract capture of the expanded workspace-mcp surface + complete manifest authoring. Resolves D2 and D4; produces the scope-set candidate for D1.

**Size:** M
**Files:** `configs/connectors/google.json`, `deploy/server/manifest.json` (+ equality test), `internal/server/connectors/testdata/*` (captured shapes), `internal/server/connectors/google_manifest_test.go` (+ new tests), deploy config for the workload `--tools` flag, capture notes/decision doc `docs/decisions/fn4-google-surface.md`

### Approach
- PHASE A (schemas, no credential needed): run a LOCAL scratch instance of the pinned workspace-mcp 1.24.0 with the expanded `--tools` set and `tools/list` it — capture input SCHEMAS for the full surface without touching clawniel; form the D1 scope candidate with per-tool justification.
- PHASE B (interactive, two-stage manifest): author + deploy manifest STAGE-1 to clawniel: `credential_acquisition.scopes` expanded to the candidate set, `--tools` expanded, and every NEW tool listed in `excluded_tools` with reason "pending capture" (complete-registration satisfied; Drive/Calendar mappings untouched). NOTE the server builds the OAuth request exclusively from the deployed manifest's scopes — this stage exists precisely so consent acquires the FULL-scope credential. Then park for Daniel: ratify scopes, run `add-credentials google -replace` (his click; assert CAS semantics live). Record everything.
- PHASE C (empirical, full scopes): capture REAL response shapes operator-side against the gateway loopback on clawniel (ssh; fn-1's own capture path — the engine still excludes the new tools from harness reach during capture) (prose-vs-JSON is tool-specific; reply/forward draft-vs-send semantics; id formats vs the identifier-shape rule; empty-result shapes). Pinned 1.24.0 — no version bump.
- Author the COMPLETE Gmail inventory per the spec's REVISED R1 model: honest classes for the whole surface (reads read-class; draft-create/label/untrash write-class; trash delete-class; send/reply/forward → connector.send, refused for all current grants — platform supports, policy withholds; unclassifiable tools excluded with cited reasons). Docs/Sheets/Contacts read-only + write exclusions. Extractors from captured shapes only, unit-tested.
- Resolve R4's reversible write-proof PATH empirically: what does create_draft return; can search/read locate the created draft; do label ops accept its message id; does trash/delete clean it up (drafts are messages — verify, don't assume). Record the ratified proof path (or the closest-reversible path + residue) in the decision doc.
- PHASE D: author the fully-mapped manifest (both copies) from captured shapes — this is .1's final deliverable; it deploys in .3. Add the manifest-copies equality test (none exists today). Prove complete-registration refusal and the unrecognized-construct load behavior (D4).
- Record the D1 scope-set candidate (per-tool scope requirements from the capture) in the decision doc for Daniel's ratification in .3.
- Phase C's mutation experiments (create_draft/label/trash on the created artifact) are capture, done with proof discipline: own artifacts only, cleaned up by the best available path, outcomes recorded verbatim.

### Acceptance
- [ ] Every advertised tool in the expanded surface mapped or excluded-with-reason; load succeeds; incomplete-manifest refusal proven in tests
- [ ] Extractors match captured shapes (tests) — no fabricated IDs, args-digest fallback verified
- [ ] Both manifest copies byte-equal with an automated test; D4 verified (data-only vs binary, unrecognized-construct behavior)
- [ ] D1 candidate scope set recorded with per-tool justification; go build/vet/test green; evidence JSON emitted


## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
