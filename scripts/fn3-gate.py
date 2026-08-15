#!/usr/bin/env python3
"""fn3-gate.py — the fn-3 spec's acceptance gate (task .3).

fn-1's `final-gate.py` is that spec's historical record and is not touched. This
is the same discipline applied to fn-3's six requirements: every one is mapped
to the recorded evidence that closes it, and nothing is taken on trust.

An evidence artifact is accepted only when it

  * EXISTS;
  * records a commit that is an ANCESTOR of the gate head — an artifact recorded
    on a commit that never reached the shipped history attests to a tree nobody
    can check out;
  * says whether its worktree was clean, and was clean (live proofs are exempt
    from the flag and say so, because a person drove them rather than a test
    binary);
  * carries its own passing result, with zero failed assertions;
  * has, for every required live stage, no FALSE assertion that is not a
    limitation ratified BY NAME in this file. A `partial` stage is not waved
    through for being partial.

Two checks are fn-3's own, and neither exists in fn-1's gate:

  * ARTIFACT IDENTITY for grok's connector rows. A stage can be `pass` with
    every action class right and still record `ArtifactID:"unknown"` on all of
    it, which is a weaker proof than R3's.
  * THE R12 FALSIFICATION GATE. fn-3's central claim is that adding a harness
    touches detection, config writing and skills linking and nothing else. The
    gate checks that itself: the diff from the spec's branch point over
    `internal/server`, `internal/store`, `internal/cred` and `internal/secrets`
    must be EMPTY, with the policy table the one permitted exception — and that
    exception is verified to be a policy-table change rather than asserted.

And the gate demonstrates that it REJECTS TAMPERED EVIDENCE (`--tamper-check`,
on by default): the live artifact is copied, mutated in four ways that each
falsify a claim the gate rests on, and each mutation must be caught. A gate that
has never been shown refusing anything is a formatter.

Usage: scripts/fn3-gate.py --out <file.json> \
         --gate build=0 --gate vet=0 --gate test=0 \
         --gate-command build='go build ./...'
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import pathlib
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE = REPO / "test" / "evidence"
SPEC = "fn-3-add-grok-as-a-third-harness"

# The live artifact every R-ID leans on, named once.
LIVE = f"{SPEC}.3.live.json"

# Gates that must be supplied and green. An absent gate is a failure: a gate run
# that proves nothing must not be able to report `pass`.
REQUIRED_GATES = ("build", "vet", "test")

# The commit fn-3's work starts from — the last commit before the spec landed.
# The R12 falsification gate is measured from here.
FN3_BASE = "b261dbc"

# The server-side trees fn-3 claims it did not need to touch. `internal/policy`
# is deliberately NOT in this list: the spec's Boundaries name the policy-table
# entry as the ONE permitted server-side touch, and it is checked separately so
# the permission cannot quietly widen.
R12_UNTOUCHED = ("internal/server", "internal/store", "internal/cred", "internal/secrets")

# The one permitted server-side change, and the shape it is allowed to have.
R12_PERMITTED = "internal/policy"
R12_PERMITTED_FILES = ("internal/policy/policy.go", "internal/policy/policy_test.go")

LIVE_PROOF_KINDS = ("live_e2e_proof", "live_provider_proof", "live_harness_proof")

# Live proofs record limitations as FALSE assertions carrying their reason and
# owner. The gate must distinguish "a limitation somebody ratified" from
# "something broke", and it cannot do that from a stage's `partial` label — it
# has to know each one by name. Every entry is matched on (artifact, stage,
# exact claim); a false assertion matching nothing here fails its requirement.
#
# Adding an entry is a ratification, not a formality.
# It is EMPTY, and that is the strictest state this table has: with nothing
# ratified, every false assertion in a required stage fails its requirement. An
# entry appears here only when a live run produces a limitation somebody decided
# to accept, with the decision named. A `placeholder: True` entry never accepts
# anything and fails the run, so an unfinished ratification cannot ship as one.
RATIFIED_LIMITATIONS: list[dict] = []

# Artifact IDENTITY in the live audit rows.
#
# R3 asks grok's proof to name what it touched — the Drive file the read
# returned, the event the guarded sequence created, updated and deleted — not
# merely which tool was called.
#
#   "all" — at least one row, and none of them unidentified.
#   "any" — at least one identified row (a listing has no single artifact).
#
# Rows that were DENIED, or whose tool failed at the provider, are not counted:
# there is no artifact to name in either case.
ARTIFACT_IDENTITY = [
    {
        "artifact": LIVE,
        "stage": "grok-connector",
        "tool": "search_drive_files",
        "rule": "all",
        "why": "R3: grok's Drive read must name the file it read",
    },
    {
        "artifact": LIVE,
        "stage": "grok-calendar",
        "tool": "manage_event",
        "rule": "all",
        "why": "R3: grok's guarded create, update and delete must each audit the event they acted on",
    },
    {
        "artifact": LIVE,
        "stage": "grok-calendar",
        "tool": "get_events",
        "rule": "any",
        "why": "R3: the read-back must name the event (a summary-filtered listing legitimately does not)",
    },
]

ARTIFACT_UNKNOWN = "unknown"
RESULT_EVENT = "connector_tool_result"
TOOL_FAILED = "tool_failed"

REQUIREMENTS = [
    {
        "id": "R1",
        "what": "configure-harnesses -detect reports grok with an observed version and a support verdict; "
                "never-launched is detected rather than absent; unsupported gates before any grant; GROK_HOME honoured",
        "sources": [
            {"artifact": f"{SPEC}.2.json",
             "tests": ["TestGrokVersionVerdicts",
                       "TestNeverLaunchedGrokIsDetectedNotAbsent",
                       "TestGrokConfigPathHonoursGrokHome"]},
            {"artifact": LIVE, "stages": ["grok-harness"]},
        ],
    },
    {
        "id": "R2",
        "what": "The existing configure entrypoint wires grok with its OWN grant: both surfaces, byte-span merge "
                "preserving unrelated settings and comments, 0600, backup, idempotent, mint-authority-last",
        "sources": [
            {"artifact": f"{SPEC}.2.json",
             "tests": ["TestGrokWritePreservesCommentsAndUnrelatedConfiguration",
                       "TestGrokConfigIsCreatedAtOwnerOnlyFromNothing",
                       "TestGrokRewriteIsIdempotent",
                       "TestAPartiallyWrittenGrokEntryIsRepairedWholesale",
                       "TestTheGrokEntryCarriesNoEnvironmentIndirection",
                       "TestGrokEntryMatchesTheCapturedContractShape",
                       "TestNoGrantIsMintedWhenAnyLocalPreconditionFails",
                       "TestAHealthyGrokRunMintsExactlyOneGrantAndWrites"]},
            {"artifact": LIVE, "stages": ["grok-harness"]},
        ],
    },
    {
        "id": "R3",
        "what": "From a FRESH grok process: local GNO returns real vault content, and the edge performs a real Drive "
                "read and one guarded manage_event — audited under grok's own grant with real artifact ids",
        "sources": [
            {"artifact": LIVE, "stages": ["grok-gno", "grok-connector", "grok-calendar", "grok-audit"]},
        ],
    },
    {
        "id": "R4",
        "what": "A vault-authored skill is linked into grok and discovered by a fresh grok process through the product "
                "path; the ACTIVE profile names grok explicitly, gated on the enrolled-machine rollout check, and the "
                "key is proven READ rather than defaulted",
        "sources": [
            {"artifact": f"{SPEC}.2.json",
             "tests": ["TestGrokIsAKnownProfileKeyAndTyposStillFailClosed",
                       "TestGrokSkillsDirHonoursGrokHome",
                       "TestDiscoverGrokReadsTheSkillsSection",
                       "TestALinkGrokDoesNotEnumerateFailsVerification",
                       "TestTheGrokProbeCannotBeServedByAResidentLeader",
                       "TestRealVaultHarnessSpecificSkillsAreMarkedUnsupported"]},
            {"artifact": LIVE, "stages": ["grok-rollout-gate", "grok-skills"]},
        ],
    },
    {
        "id": "R5",
        "what": "Revocation asymmetry in BOTH directions with produced failures: revoking grok's grant denies grok "
                "while the other two keep working, and the inverse; audited; every grant restored",
        "sources": [
            {"artifact": LIVE, "stages": ["grok-revocation"]},
        ],
    },
    {
        "id": "R6",
        "what": "status includes grok through an explicit detection/support model, and the five states "
                "not-detected / detected-unconfigured / detected-unsupported / configured / revoked each render distinctly",
        "sources": [
            {"artifact": f"{SPEC}.2.json",
             "tests": ["TestTheFiveHarnessStatesRenderDistinctly",
                       "TestStatusReconcilesARevokedGrantLive",
                       "TestUnreadableRecordsAreSurfacedRatherThanReadAsUnconfigured"]},
            {"artifact": LIVE, "stages": ["grok-status-truth"]},
        ],
    },
]


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.strip()


def is_ancestor(commit: str, head: str) -> bool:
    return (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, head],
            cwd=REPO,
            capture_output=True,
        ).returncode
        == 0
    )


def audit_rows(stage: dict) -> list[dict]:
    """Every audit row the stage's steps captured.

    Live stages record `homeplane-server admin audit -json` output verbatim in
    each step's `stdout_excerpt`, one JSON object per line. A line that does not
    parse (an excerpt truncated mid-row) is skipped rather than guessed at — the
    checks below need rows to be PRESENT, so a dropped row can only ever make
    the gate stricter.
    """
    rows = []
    for step in stage.get("steps", []):
        for line in (step.get("stdout_excerpt") or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and "Event" in row:
                rows.append(row)
    return rows


def check_artifact_identity(artifact: str, stage_name: str, stage: dict) -> tuple[list[str], dict]:
    rules = [r for r in ARTIFACT_IDENTITY if r["artifact"] == artifact and r["stage"] == stage_name]
    if not rules:
        return [], {}

    rows = audit_rows(stage)
    problems: list[str] = []
    report: dict = {}
    for rule in rules:
        results = [
            r
            for r in rows
            if r.get("Event") == RESULT_EVENT
            and r.get("Tool") == rule["tool"]
            and r.get("Reason") != TOOL_FAILED
            and r.get("Harness") == "grok"
        ]
        identified = [r for r in results if r.get("ArtifactID") not in ("", ARTIFACT_UNKNOWN)]
        report[rule["tool"]] = {
            "rule": rule["rule"],
            "result_rows": len(results),
            "identified": len(identified),
            "why": rule["why"],
        }
        if not results:
            problems.append(
                f"stage {stage_name!r}: no grok {rule['tool']!r} result rows were captured, "
                f"so its artifact identities cannot be checked ({rule['why']})"
            )
            continue
        if not identified:
            problems.append(
                f"stage {stage_name!r}: no grok {rule['tool']!r} result row records an artifact id "
                f"({rule['why']})"
            )
            continue
        if rule["rule"] == "all" and len(identified) != len(results):
            unknown = len(results) - len(identified)
            problems.append(
                f"stage {stage_name!r}: {unknown} of {len(results)} grok {rule['tool']!r} result rows "
                f"record artifact id {ARTIFACT_UNKNOWN!r} ({rule['why']})"
            )
    return problems, report


def ratification_for(artifact: str, stage: str, claim: str) -> dict | None:
    for entry in RATIFIED_LIMITATIONS:
        if entry.get("placeholder"):
            continue
        if entry["artifact"] == artifact and entry["stage"] == stage and entry["claim"] == claim:
            return entry
    return None


def check_source(src: dict, head: str, evidence_dir: pathlib.Path) -> dict:
    """Verify one evidence artifact. Every failure mode is named, never swallowed."""
    name = src["artifact"]
    path = evidence_dir / name
    out: dict = {"artifact": f"test/evidence/{name}", "problems": []}

    if not path.exists():
        out["problems"].append("artifact is missing")
        out["verdict"] = "fail"
        return out

    doc = json.loads(path.read_text())
    commit = doc.get("commit")
    out["commit"] = commit
    out["recorded_result"] = doc.get("result")

    if not commit:
        out["problems"].append("artifact records no commit")
    elif not is_ancestor(commit, head):
        out["problems"].append(
            f"commit {str(commit)[:12]} is not an ancestor of the gate head — it attests to a tree that never shipped"
        )
    else:
        out["ancestor_of_gate_head"] = True

    dirty = doc.get("working_tree_dirty")
    if dirty is True:
        out["problems"].append("recorded on a dirty worktree — nobody else can check that tree out")
    elif dirty is None:
        kind = doc.get("kind")
        if kind in LIVE_PROOF_KINDS:
            out["worktree_cleanliness"] = (
                f"exempt: {kind} artifacts are recorded by the operator driving a deployment, "
                "not emitted by the test binary"
            )
            if doc.get("commit_note"):
                out["commit_note"] = doc["commit_note"]
        else:
            out["problems"].append(
                "artifact does not record whether its worktree was clean, and is not a live proof"
            )

    counts = doc.get("assertion_counts")
    if counts:
        out["assertions"] = counts
        if counts.get("failed", 0) != 0:
            out["problems"].append(f"{counts['failed']} failed assertion(s)")

    if "stages" in doc:
        by_stage = {s["stage"]: s for s in doc["stages"]}
        summary = doc.get("summary", {})
        out["stage_summary"] = summary
        wanted = src.get("stages", [])
        settled = {}
        for stage in wanted:
            s = by_stage.get(stage)
            if s is None:
                out["problems"].append(f"stage {stage!r} is not in this artifact")
                continue
            asserts = s.get("assertions", [])
            false_claims = [a["claim"] for a in asserts if not a.get("ok")]

            ratified, unratified = [], []
            for claim in false_claims:
                entry = ratification_for(name, stage, claim)
                if entry is None:
                    unratified.append(claim)
                else:
                    ratified.append(
                        {
                            "claim": claim,
                            "ratified_by": entry["ratified_by"],
                            "ratification": entry["ratification"],
                            "recorded_in": entry["recorded_in"],
                        }
                    )

            settled[stage] = {
                "status": s.get("status"),
                "assertions": len(asserts),
                "false_assertions": len(false_claims),
                "ratified_limitations": ratified,
            }
            if not asserts:
                out["problems"].append(
                    f"stage {stage!r} recorded no assertions — a stage that concluded nothing settles nothing"
                )

            id_problems, id_report = check_artifact_identity(name, stage, s)
            if id_report:
                settled[stage]["artifact_identity"] = id_report
            out["problems"].extend(id_problems)
            for claim in unratified:
                out["problems"].append(
                    f"stage {stage!r}: assertion {claim!r} is FALSE and is not a ratified limitation"
                )
            if s.get("status") not in ("pass", "partial"):
                out["problems"].append(f"stage {stage!r} is {s.get('status')!r}")
        out["stages"] = settled
    else:
        if doc.get("result") != "pass":
            out["problems"].append(f"recorded result is {doc.get('result')!r}, not 'pass'")
        for gate in doc.get("gates", []):
            if gate.get("exit_code") != 0:
                out["problems"].append(f"gate {gate['gate']} exited {gate['exit_code']}")

    wanted_tests = src.get("tests", [])
    if wanted_tests:
        by_test = {a.get("test"): a for a in doc.get("assertions", [])}
        found = {}
        for t in wanted_tests:
            a = by_test.get(t)
            if a is None:
                out["problems"].append(f"test {t!r} is not recorded in this artifact")
            elif a.get("result") != "pass":
                out["problems"].append(f"test {t!r} recorded {a.get('result')!r}")
            else:
                found[t] = "pass"
        out["tests"] = found

    out["verdict"] = "fail" if out["problems"] else "pass"
    return out


def check_r12(head: str) -> dict:
    """fn-3's falsification gate, computed rather than asserted.

    The spec's central claim is that a third harness costs detection, config
    writing and skills linking — and, server-side, one policy-table row. So the
    diff over the identity, custody, storage and edge trees must be EMPTY, and
    the permitted policy change must actually BE a policy-table change rather
    than a licence to edit anything under that directory.
    """
    out = {
        "what": "Adding a harness touched no server-side identity, storage, credential or edge code; "
                "the policy table is the one permitted server-side change",
        "base": FN3_BASE,
        "untouched": list(R12_UNTOUCHED),
        "problems": [],
    }
    try:
        base = git("rev-parse", FN3_BASE)
    except subprocess.CalledProcessError:
        out["problems"].append(f"the fn-3 base commit {FN3_BASE} is not in this repository")
        out["verdict"] = "fail"
        return out
    out["base_commit"] = base
    if not is_ancestor(base, head):
        out["problems"].append(f"the fn-3 base {base[:12]} is not an ancestor of the gate head")

    changed = git("diff", "--name-only", f"{base}..{head}", "--", *R12_UNTOUCHED)
    files = [f for f in changed.splitlines() if f.strip()]
    out["changed_in_untouched_trees"] = files
    if files:
        out["problems"].append(
            "fn-3 changed server-side code it claims a harness never needs: " + ", ".join(files)
        )

    permitted = git("diff", "--name-only", f"{base}..{head}", "--", R12_PERMITTED)
    permitted_files = [f for f in permitted.splitlines() if f.strip()]
    out["policy_changes"] = permitted_files
    unexpected = [f for f in permitted_files if f not in R12_PERMITTED_FILES]
    if unexpected:
        out["problems"].append(
            "the permitted policy change reaches beyond the policy table: " + ", ".join(unexpected)
        )

    out["verdict"] = "fail" if out["problems"] else "pass"
    return out


# ── tamper demonstration ────────────────────────────────────────────────────

def _first_true_assertion(doc: dict, stage: str) -> tuple[int, int] | None:
    for i, s in enumerate(doc.get("stages", [])):
        if s.get("stage") != stage:
            continue
        for j, a in enumerate(s.get("assertions", [])):
            if a.get("ok"):
                return i, j
    return None


def tamper_mutations(doc: dict) -> list[tuple[str, dict]]:
    """Four ways to falsify the live artifact, each targeting a different check."""
    out: list[tuple[str, dict]] = []

    flip = copy.deepcopy(doc)
    where = _first_true_assertion(flip, "grok-revocation") or _first_true_assertion(flip, "grok-harness")
    if where:
        i, j = where
        flip["stages"][i]["assertions"][j]["ok"] = False
        out.append(("a passing assertion is flipped to FALSE without a ratification", flip))

    wrong_commit = copy.deepcopy(doc)
    wrong_commit["commit"] = "0" * 40
    out.append(("the recorded commit is replaced with one that never reached the history", wrong_commit))

    failed_stage = copy.deepcopy(doc)
    for s in failed_stage.get("stages", []):
        if s.get("stage") == "grok-skills":
            s["status"] = "fail"
    out.append(("a required stage is marked failed", failed_stage))

    blanked = copy.deepcopy(doc)
    blanked_any = False
    for s in blanked.get("stages", []):
        if s.get("stage") != "grok-calendar":
            continue
        for step in s.get("steps", []):
            lines = (step.get("stdout_excerpt") or "").splitlines()
            new = []
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("{"):
                    try:
                        row = json.loads(stripped)
                    except json.JSONDecodeError:
                        new.append(line)
                        continue
                    if (
                        row.get("Event") == RESULT_EVENT
                        and row.get("Tool") == "manage_event"
                        and row.get("Harness") == "grok"
                        and row.get("ArtifactID") not in ("", ARTIFACT_UNKNOWN)
                    ):
                        row["ArtifactID"] = ARTIFACT_UNKNOWN
                        blanked_any = True
                        new.append(json.dumps(row))
                        continue
                new.append(line)
            step["stdout_excerpt"] = "\n".join(new)
    if blanked_any:
        out.append(("a calendar mutation's audited artifact id is blanked to 'unknown'", blanked))
    return out


def tamper_check(head: str) -> list[dict]:
    """Show the gate refusing evidence that has been altered.

    Each mutation is written into a throwaway evidence directory and re-checked
    through the SAME code path the real run uses. A mutation that is not caught
    is reported, and fails the gate: a check nobody has watched refuse is not a
    check.
    """
    live_path = EVIDENCE / LIVE
    if not live_path.exists():
        return [{"mutation": "(none run)", "rejected": False,
                 "problems": [f"{LIVE} is missing, so tamper rejection cannot be demonstrated"]}]

    doc = json.loads(live_path.read_text())
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)
        for label, mutated in tamper_mutations(doc):
            (tmpdir / LIVE).write_text(json.dumps(mutated, indent=2) + "\n")
            problems: list[str] = []
            for req in REQUIREMENTS:
                for src in req["sources"]:
                    if src["artifact"] != LIVE:
                        continue
                    problems.extend(check_source(src, head, tmpdir)["problems"])
            results.append({"mutation": label, "rejected": bool(problems), "problems": problems[:4]})
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--gate", action="append", default=[], metavar="NAME=EXIT")
    ap.add_argument("--gate-command", action="append", default=[], metavar="NAME=CMD")
    ap.add_argument("--no-tamper-check", action="store_true",
                    help="skip the tamper demonstration (it then fails the run, and says so)")
    args = ap.parse_args()

    head = git("rev-parse", "HEAD")
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"], cwd=REPO, capture_output=True, text=True
        ).stdout.strip()
    )

    commands = dict(c.split("=", 1) for c in args.gate_command)
    revalidation = []
    for spec in args.gate:
        name, code = spec.split("=", 1)
        revalidation.append(
            {"gate": name, "command": commands.get(name, name), "exit_code": int(code)}
        )

    results = []
    for req in REQUIREMENTS:
        srcs = [check_source(s, head, EVIDENCE) for s in req["sources"]]
        entry = {"id": req["id"], "what": req["what"], "sources": srcs}
        entry["verdict"] = "pass" if all(s["verdict"] == "pass" for s in srcs) else "fail"
        results.append(entry)

    run_problems = []
    supplied = {g["gate"] for g in revalidation}
    for name in REQUIRED_GATES:
        if name not in supplied:
            run_problems.append(f"required gate {name!r} was not supplied")
    for g in revalidation:
        if g["exit_code"] != 0:
            run_problems.append(f"gate {g['gate']!r} exited {g['exit_code']}")
    if dirty:
        run_problems.append("the gate head's own worktree is dirty")

    # A ratification left as a placeholder is an unfinished decision, not a
    # ratification, and it must never be able to accept anything.
    for entry in RATIFIED_LIMITATIONS:
        if entry.get("placeholder"):
            run_problems.append(
                f"RATIFIED_LIMITATIONS still holds a placeholder for stage {entry['stage']!r} — "
                "ratify it with a decision and an owner, or delete it"
            )

    r12 = check_r12(head)
    if r12["verdict"] != "pass":
        run_problems.extend(r12["problems"])

    tamper: list[dict] = []
    if args.no_tamper_check:
        run_problems.append("the tamper demonstration was skipped, so this gate has not been shown refusing anything")
    else:
        tamper = tamper_check(head)
        if not tamper:
            run_problems.append("the tamper demonstration produced no mutations to check")
        for t in tamper:
            if not t["rejected"]:
                run_problems.append(f"tamper NOT rejected: {t['mutation']}")

    reqs_green = all(r["verdict"] == "pass" for r in results)

    doc = {
        "schema_version": 1,
        "kind": "final_acceptance_gate",
        "what_this_is": (
            "fn-3's acceptance gate. Every requirement of the grok spec is mapped to the recorded "
            "evidence that closes it, and each artifact is re-checked here rather than trusted: it must "
            "exist, its commit must be an ancestor of the gate head, it must have been recorded on a "
            "clean worktree, and its own result must be passing. False assertions are accepted only "
            "where a limitation was ratified by name. The R12 falsification gate is COMPUTED from the "
            "repository, not asserted, and the gate demonstrates that it rejects tampered evidence. "
            "fn-1's own gate is untouched: it is that spec's historical record."
        ),
        "spec": SPEC,
        "task": f"{SPEC}.3",
        "gate_head": head,
        "gate_head_worktree_dirty": dirty,
        "checked_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "revalidation": revalidation,
        "r12_falsification": r12,
        "tamper_rejection": tamper,
        "run_problems": run_problems,
        "ratified_limitations": [e for e in RATIFIED_LIMITATIONS if not e.get("placeholder")],
        "requirements": results,
        "counts": {
            "total": len(results),
            "passed": sum(1 for r in results if r["verdict"] == "pass"),
            "failed": sum(1 for r in results if r["verdict"] == "fail"),
        },
        "result": "pass" if (not run_problems and reqs_green) else "fail",
    }

    pathlib.Path(args.out).write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n")

    for r in results:
        print(f"{r['id']:<4} {'PASS' if r['verdict'] == 'pass' else 'FAIL'}")
        for s in r["sources"]:
            for p in s["problems"]:
                print(f"       {s['artifact']}: {p}")
            for lim in (v for st in s.get("stages", {}).values() for v in st["ratified_limitations"]):
                print(f"       ratified limitation: {lim['claim']}")
    print(f"R12  {'PASS' if r12['verdict'] == 'pass' else 'FAIL'} (falsification gate, computed from {FN3_BASE})")
    for t in tamper:
        print(f"TAMPER {'rejected' if t['rejected'] else 'ACCEPTED — BAD'}: {t['mutation']}")
    for p in run_problems:
        print(f"RUN  FAIL {p}")
    print(f"\ngate head: {head}")
    print(f"result:    {doc['result']}")
    return 0 if doc["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
