---
satisfies: [R1, R2, R4]
---
# fn-3-add-grok-as-a-third-harness.2 Detect + configure + skills + policy entry per ratified contract

## Description
Implement detection, configuration, skills linking, and the policy-table entry per the .1-ratified contract. Touch only the seams repo-scout verified; the R12 falsification gate binds (any change beyond `internal/policy`'s table is a surfaced finding, not an implementation).

**Size:** M
**Files:** `internal/agent/harness/{harness,detect,configure,writer_grok}.go` (+tests), `internal/agent/skills/{skills,link,profile,verify}.go` (grok arms +tests), `internal/agent/status.go` (+tests), `cmd/homeplane-agent/` (detect/status output surfaces), `internal/policy/policy.go` (+test), `configs/skills/homeplane.skills.toml` (reference), `internal/agent/harness/testdata/*`

### Approach
- `harness.Known()` + `Grok` const; `Locator` grok fields + `Detect()` arm (binary probe + config surface; never-launched and version-drift verdicts per .1); GROK_HOME-equivalent env honored if .1 found one.
- Writer per .1's ratified mechanism (byte-span merge reusing tomledit.go, or a timeout-guarded CLI-verb writer with deliberately-specified backup/outcome semantics). Token path per D3 — git-containment test on the resolved destination, 0600, never argv/logs.
- **Two-phase configure transaction (restructures configureOne for ALL harnesses):** preflight — containment, entry validation, parse/renderability, preservation dry-merge, backup + writability, state-record validation — runs BEFORE IssueGrant (today issuance at configure.go:206 precedes Writer.Apply's checks at writer.go:81-205, so a bad GROK_HOME could supersede a working grant); after issuance only token/endpoint substitution + the race-checked atomic commit. Tests prove the issuer is never called when any local precondition fails. State-lock discipline unchanged.
- Semantic preservation proven against a seeded non-empty grok config (pre-existing MCP servers survive byte-for-byte where the mechanism allows; otherwise the .1-ratified preservation contract is the assertion).
- `skills.Known()` in lockstep; `SkillsDir()` grok arm; linker per .1's convention; **Verifier.Discover("grok") in verify.go** per .1's leader/fresh-process contract (tests: success, timeout, linked-but-not-discovered, unsupported-without-probe — without this, `skills provision -verify` fails the moment Known() includes grok); profile reader stays FAIL-CLOSED on unknown harness keys (profile.go:209-215 unchanged; typo-rejection test retained — warn-and-skip would fail open on misspelled keys) while the schema gains grok as a known key with absent-key defaults; `UnsupportedSkill` marking honest. The ACTIVE vault file edit stays in .3.
- `policy.Default()` grok row with the identical capability set (explicit test asserting set-equality with claude-code/codex).
- **Detection/support model + status (new modeling work):** Detection carries observed version + supported verdict + reason; unsupported gates before grant issuance in configureOne; status reconciles live detection with configuration records and live grants so not-detected / detected-unconfigured / detected-unsupported / configured / revoked render distinctly (status.go:478-504 currently derives only from the persisted configured list). R1's acceptance command is `configure-harnesses -detect` (existing read-only mode — no new subcommand); its machine-readable + human output includes the version/supported fields.

### Acceptance
- [ ] R1 detection verdicts incl. never-launched + version-drift via `configure-harnesses -detect`, version + supported verdict in both output forms (unit-tested against contract testdata)
- [ ] R2 configure: two-phase transaction (issuer never called on failed preflight — tested), preservation (seeded config), containment, backup/restore, idempotent re-run, rollback on write failure, partial-state repair — all unit/contract-tested
- [ ] R4 linking + verifier (all four outcome states tested) + grok as a known profile key (unknown keys still fail closed, typo test retained) per .1 convention; unsupported marking works; both Known() registries in lockstep (test that fails if one is missing grok)
- [ ] R6 status: five states render distinctly (not-detected / detected-unconfigured / detected-unsupported / configured / revoked), tested
- [ ] Policy entry capability-set-equal to existing harnesses (tested); no other server-side diff (`git diff --stat internal/server internal/store internal/cred internal/secrets` empty)
- [ ] `go build ./... && go vet ./... && go test ./...` green; evidence JSON emitted per fn-1 pattern

## Acceptance
- [ ] TBD

## Done summary
grok is a third harness end to end: detection with an observed version and a support verdict, a byte-span TOML writer that closes both compat cells (D4/D4b), skills linking + a fresh-process verifier, a policy row, and a five-state per-harness status. Configure is now a two-phase transaction for ALL harnesses — every local precondition is proven before IssueGrant, so a purely local failure can no longer supersede a harness's working grant.

R12 falsification gate: `git diff --stat internal/server internal/store internal/cred internal/secrets` from bab0835 is EMPTY — adding a harness was a policy row and nothing else server-side.

Real ~/.grok untouched: config.toml still sha256 9b8cdca9…19cd51 (the .1 snapshot), skills/ still empty. A first test run linked four skills into the real ~/.grok/skills through fixtures that did not pin GROK_HOME; they were removed and every fixture (harness, skills, cmd, e2e) now pins GrokHome/GROK_HOME.

stage: impl-review - ran [round 1 NEEDS_WORK (7 findings: 2×P1 status truthfulness/health integration, 1×P1 MCP-surface drift, 4×P2), round 2 SHIP]
stage: delegation - skipped(config: delegation off)
## Evidence
- Commits: a4a1581759357963f5a625c335662b3aa52b10ee, b666d55ee714579c1e8c98bca47213b7eba8e3c9, b5b19afca3df5810429f0fed9bd9a8a569e007e9, d37860d8fd820f563504a0b23752eaebce57fa5f
- Tests: go build ./..., go vet ./..., go test ./... -count=1 -json (981/981 assertions, artifact test/evidence/fn-3-add-grok-as-a-third-harness.2.json at b5b19af), git diff --stat internal/server internal/store internal/cred internal/secrets (R12 gate: empty)
- PRs: