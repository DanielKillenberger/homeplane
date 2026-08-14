#!/usr/bin/env python3
"""final-gate.py — the spec's final acceptance gate (task .14).

Maps every executable requirement of the walking-skeleton spec to the recorded
evidence that closes it, and REFUSES to call the gate green on anything it
cannot verify itself:

  * the evidence artifact must EXIST;
  * its recorded commit must be an ANCESTOR of the gate head — an artifact
    recorded on a commit that never reached the shipped history attests to a
    tree nobody can check out;
  * it must SAY whether its worktree was clean, and it must have been clean;
  * its own result must be `pass`, with zero failed assertions;
  * every FALSE assertion in a required live stage must match an entry in
    RATIFIED_LIMITATIONS below. A `partial` stage is not waved through for
    being partial: it is accepted only when each of its false assertions is a
    limitation someone ratified, by name, in this file. A new limitation
    appearing in a re-recorded artifact fails the gate.

A requirement whose sources are all verifiable and passing is `pass`. Anything
else is `fail`, and one failing requirement fails the gate. Nothing here is
allowed to downgrade a failure into a note.

The run itself must also be complete, or it is not a gate:

  * all three repository gates (build, vet, test) must be supplied and green —
    an empty gate list is a failure, not a vacuous pass;
  * the gate head's own worktree must be clean;
  * the deployment verification must be supplied, `pass`, with zero pending
    checks and `provider_secret_refs_present` explicitly passing (the .15 → .12
    evidence-chain caveat this spec carries).

Re-validation of `go build`/`go vet`/`go test` at the gate head is passed in
rather than re-run, so the caller records the exact commands it ran.

Usage: scripts/final-gate.py --out <file.json> \
         --gate build=0 --gate vet=0 --gate test=0 --deploy-verify <file.json>
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE = REPO / "test" / "evidence"
SPEC = "fn-1-homeplane-walking-skeleton-install"

# Gates that must be supplied and green. An absent gate is a failure: a gate
# run that proves nothing must not be able to report `pass`.
REQUIRED_GATES = ("build", "vet", "test")

# The deployment check that closes the .15 → .12 credential-import caveat. It
# is named here rather than left to the deployment script's overall verdict,
# because `--pending` can turn that verdict into `pass_with_pending`.
REQUIRED_DEPLOY_CHECKS = ("provider_secret_refs_present",)

# Artifact kinds that cannot carry a `working_tree_dirty` flag because no test
# binary emitted them — a human or agent drove a real deployment and recorded
# what happened. They must still name a commit that reached the shipped
# history; only the cleanliness flag is exempt, and the exemption is reported.
LIVE_PROOF_KINDS = ("live_e2e_proof", "live_provider_proof", "live_harness_proof")

# Live proofs record limitations as FALSE assertions carrying their reason and
# owner — that is how the artifact stays honest instead of quietly dropping
# what it could not show. The gate must therefore distinguish "a limitation
# somebody ratified" from "something broke", and it cannot do that by reading a
# stage's `partial` status: it has to know each one by name.
#
# Every entry below is matched on (artifact, stage, exact claim). A false
# assertion that matches nothing here FAILS its requirement, so re-recording a
# live artifact with a new limitation cannot slip through.
#
# Adding an entry is a ratification, not a formality: it needs a decision that
# already exists, cited, and it belongs in the spec's Boundaries.
RATIFIED_LIMITATIONS = [
    {
        "artifact": f"{SPEC}.7.live.json",
        "stage": "vault-sync",
        "claim": "the headless client was exercised against a disposable vault",
        "ratified_by": "Daniel",
        "ratification": (
            "Detect-only vault handling: Daniel keeps Obsidian.app as the vault's operating "
            "sync client, so Homeplane detects the vault and never writes to it. The headless "
            "rehearsal needs a Sync login and a throwaway remote vault, neither of which this "
            "arrangement wants. R14's index-locality half is closed by .11 and by the live "
            "`gno` stage; the supervised-sync half is not exercised on this machine by choice."
        ),
        "recorded_in": "test/evidence/%s.7.live.json (the assertion's own detail); docs/RUNBOOK.md §1" % SPEC,
        "affects": ["R14"],
    },
    {
        "artifact": f"{SPEC}.7.live.json",
        "stage": "gno",
        "claim": "the retrieval engine runs in stdio mode, not as a supervised daemon",
        "ratified_by": "Daniel (open decision, D8 follow-up)",
        "ratification": (
            "gno 1.29.6 allows one resident runtime per index, so the daemon and a harness "
            "stdio launch cannot coexist. The stdio half — the one harnesses use — wins, and "
            "`status` reports the cost as degraded rather than rounding it up. R4 requires the "
            "lifecycle semantics of the mode actually in use, and the stdio mode's semantics "
            "(per-launch history, no pid claim) are exactly what the artifact shows."
        ),
        "recorded_in": "docs/decisions/d8-gno.md §8 (UNRESOLVED); docs/RUNBOOK.md §7",
        "affects": ["R4"],
    },
    {
        "artifact": f"{SPEC}.7.live.json",
        "stage": "calendar",
        "claim": "Claude Code step 6a: the direct get cannot express cancellation",
        "ratified_by": "connector limitation, absence proven twice over",
        "ratification": (
            "workspace-mcp 1.24.0 renders a cancelled event exactly like a live one. Step 6's "
            "cleanup verification is therefore settled by the filtered listing (6b, no "
            "non-cancelled match) and by the provider answering HTTP 410 Gone to a second "
            "delete (6c) — both recorded passing. R8 asks that cleanup be verified, not that a "
            "particular tool express it."
        ),
        "recorded_in": "test/evidence/%s.7.live.json (steps 6b and 6c)" % SPEC,
        "affects": ["R8"],
    },
    {
        "artifact": f"{SPEC}.7.live.json",
        "stage": "calendar",
        "claim": "Codex step 6a: the direct get cannot express cancellation",
        "ratified_by": "connector limitation, absence proven twice over",
        "ratification": "As above, for the Codex half of the same six-op sequence.",
        "recorded_in": "test/evidence/%s.7.live.json (steps 6b and 6c)" % SPEC,
        "affects": ["R8"],
    },
]


def ratification_for(artifact: str, stage: str, claim: str) -> dict | None:
    for entry in RATIFIED_LIMITATIONS:
        if (
            entry["artifact"] == artifact
            and entry["stage"] == stage
            and entry["claim"] == claim
        ):
            return entry
    return None

# Each requirement names the artifacts that close it and, where the claim is
# settled by a specific live stage or a specific test, names that too. The
# `settled_by` strings are checked against the artifact when they are stage
# names or test names, so this table cannot drift into decoration.
REQUIREMENTS = [
    {
        "id": "R1",
        "what": "One-command install from checksummed release-form artifacts; unsupported init systems rejected before installing; Node 22 + Bun 1.3 provisioned deterministically",
        "sources": [
            {"artifact": f"{SPEC}.4.json"},
            {"artifact": f"{SPEC}.7.live.json", "stages": ["install"]},
        ],
    },
    {
        "id": "R2",
        "what": "Enrolment over Tailnet; identity-preserving rotation; server records it; authorization invariants",
        "sources": [
            {"artifact": f"{SPEC}.2.json"},
            {"artifact": f"{SPEC}.4.json"},
            {"artifact": f"{SPEC}.7.live.json", "stages": ["enrol"]},
        ],
    },
    {
        "id": "R3",
        "what": "Vault detected or retrieved via Obsidian Sync; recorded in agent config; ambiguity requires explicit selection",
        "sources": [
            {"artifact": f"{SPEC}.5.json"},
            {"artifact": f"{SPEC}.7.live.json", "stages": ["vault"]},
        ],
    },
    {
        "id": "R4",
        "what": "Retrieval engine installed, configured, supervised per the D8-resolved lifecycle; reachable as a local MCP server; degraded states named",
        "sources": [
            {"artifact": f"{SPEC}.11.json"},
            {"artifact": f"{SPEC}.7.live.json", "stages": ["gno"]},
        ],
    },
    {
        "id": "R5",
        "what": "Both harnesses configured with local engine + connector endpoint using their OWN grant token; semantic preservation; timestamped backups; 0600 token hygiene",
        "sources": [
            {"artifact": f"{SPEC}.6.json"},
            {"artifact": f"{SPEC}.7.live.json", "stages": ["harnesses"]},
        ],
    },
    {
        "id": "R6",
        "what": "From each configured harness, an MCP call to the local retrieval engine returns real vault content",
        "sources": [
            {"artifact": f"{SPEC}.7.live.json", "stages": ["gno-retrieval"]},
            {"artifact": f"{SPEC}.11.json"},
        ],
    },
    {
        "id": "R7",
        "what": "From each harness, Drive READ and Calendar read via the server; Drive write denied fail-closed; provider credential resident only on the server; machine-bound tokens",
        "sources": [
            {"artifact": f"{SPEC}.7.live.json", "stages": ["connector", "credentials", "calendar"]},
            {"artifact": f"{SPEC}.16.json"},
            {"artifact": f"{SPEC}.12.json"},
        ],
    },
    {
        "id": "R8",
        "what": "Six-step reversible-write proof on an isolated Calendar event, every step audited with action class and (machine, harness, grant), metadata only",
        "sources": [
            {"artifact": f"{SPEC}.7.live.json", "stages": ["calendar", "audit"]},
        ],
    },
    {
        "id": "R9",
        "what": "Revoking one harness's grant refuses it within a token-validation interval while the other keeps working; audited; idempotent; unknown grant is an error",
        "sources": [
            {"artifact": f"{SPEC}.7.live.json", "stages": ["revocation"]},
            {"artifact": f"{SPEC}.2.json"},
        ],
    },
    {
        "id": "R10",
        "what": "status reports machine-side state and /healthz server-side components, each truthful for the failure modes the demo path hits; machine-local failures never reach /healthz",
        "sources": [
            {"artifact": f"{SPEC}.7.live.json", "stages": ["truth-table"]},
            {"artifact": f"{SPEC}.2.json"},
            {"artifact": f"{SPEC}.4.json"},
        ],
    },
    {
        "id": "R12",
        "what": "Connector-agnostic architecture and manifest: a second connector is a manifest entry plus credentials, with zero changes to enrolment/identity/custody/authorization/audit/revocation/harness config",
        "sources": [
            {
                "artifact": f"{SPEC}.3.json",
                "tests": ["TestSecondConnectorRegistersFromAManifestEntryAlone"],
            },
            {
                "artifact": f"{SPEC}.8.json",
                "tests": ["TestSecondProviderOnboardsThroughTheManifestAlone"],
            },
            {"artifact": f"{SPEC}.16.json"},
        ],
        # Verified, not asserted: the decision document must exist and the SHIP
        # receipt must be resolvable from tracker state with this exact task,
        # kind, verdict, head SHA and artifact hash — and that head must be an
        # ancestor of the gate head.
        "design_review": {
            "what": "R12 is verified in the skeleton by design review of the manifest/registration path (a second live connector is out of scope).",
            "decision_doc": "docs/decisions/d6-gateway.md",
            "expect_receipt": {
                "task": f"{SPEC}.1",
                "kind": "impl",
                "verdict": "SHIP",
                "head_sha": "394299f36c50dfe027583b132e4d549255e87abd",
                "artifact_sha256": "aeea68c2a4ed31eb903bb31e60a7660f209f4aa099a7a407e1c3c41a92bb4cac",
            },
        },
    },
    {
        "id": "R13",
        "what": "add-credentials runs the server-brokered OAuth flow; credential stored only on the server and immediately usable by every enrolled client's grants; atomic replacement; no silent overwrite",
        "sources": [
            {"artifact": f"{SPEC}.8.json"},
            {"artifact": f"{SPEC}.12.json"},
            {"artifact": f"{SPEC}.7.live.json", "stages": ["credentials"]},
        ],
    },
    {
        "id": "R14",
        "what": "Vault stays synchronized under supervision with a pinned CLI and a pre-activation snapshot; the index stays machine-local, disposable, and never inside a synchronized tree",
        "sources": [
            {"artifact": f"{SPEC}.5.json"},
            {"artifact": f"{SPEC}.11.json"},
            {"artifact": f"{SPEC}.7.live.json", "stages": ["vault-sync", "gno"]},
        ],
    },
    {
        "id": "R15",
        "what": "At least one real vault skill discovered, assigned via a profile, and linked into BOTH harnesses with no editable copies; proven in a fresh harness process; harness-specific skills marked unsupported",
        "sources": [
            {"artifact": f"{SPEC}.9.json"},
            {"artifact": f"{SPEC}.9.live.json"},
            {"artifact": f"{SPEC}.7.live.json", "stages": ["skills"]},
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


def check_source(src: dict, head: str) -> dict:
    """Verify one evidence artifact. Every failure mode is named, never swallowed."""
    name = src["artifact"]
    path = EVIDENCE / name
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
            f"commit {commit[:12]} is not an ancestor of the gate head — it attests to a tree that never shipped"
        )
    else:
        out["ancestor_of_gate_head"] = True

    dirty = doc.get("working_tree_dirty")
    if dirty is True:
        out["problems"].append("recorded on a dirty worktree — nobody else can check that tree out")
    elif dirty is None:
        # A missing flag is never read as "clean". Gate-emitted artifacts
        # (`scripts/emit-evidence.sh`) always carry it, so its absence there is
        # a gap and fails. Live proofs cannot: they are recorded by whoever
        # drove a deployment, not by the test binary, and they anchor
        # themselves with a commit note instead. That exemption is declared
        # here and RECORDED in the output rather than applied silently.
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

    # Live proofs carry per-stage status instead of a single result.
    if "stages" in doc:
        by_stage = {s["stage"]: s for s in doc["stages"]}
        summary = doc.get("summary", {})
        out["stage_summary"] = summary
        if summary.get("stages_failed", 0) != 0:
            out["problems"].append(f"{summary['stages_failed']} failed stage(s)")
        wanted = src.get("stages", [])
        settled = {}
        for stage in wanted:
            s = by_stage.get(stage)
            if s is None:
                out["problems"].append(f"stage {stage!r} is not in this artifact")
                continue
            asserts = s.get("assertions", [])
            false_claims = [a["claim"] for a in asserts if not a.get("ok")]

            # A false assertion is only tolerable if somebody ratified that
            # exact limitation. Everything else fails the requirement — the
            # stage's own `partial`/`pass` label is not what decides this.
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

    # Named tests must actually appear, passing, in the artifact.
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


def check_design_review(dr: dict, head: str) -> dict:
    """Resolve a design-review row against the tracker instead of restating it.

    The decision document must exist, and the tracker must hold a review attempt
    with exactly the task, kind, verdict, head SHA and artifact hash claimed —
    on a commit that reached the shipped history. Deleting or editing the
    recorded review breaks this, which is the whole point.
    """
    out = {"what": dr["what"], "decision_doc": dr["decision_doc"], "problems": []}

    doc_path = REPO / dr["decision_doc"]
    if not doc_path.exists():
        out["problems"].append(f"decision document {dr['decision_doc']} is missing")

    want = dr["expect_receipt"]
    state = REPO / ".flow" / "specs" / f"{SPEC}.json"
    if not state.exists():
        out["problems"].append(f"tracker state {state.name} is missing")
        out["verdict"] = "fail"
        return out

    attempts = json.loads(state.read_text()).get("review_attempts", [])
    match = None
    for a in attempts:
        if (
            a.get("task") == want["task"]
            and a.get("kind") == want["kind"]
            and a.get("verdict") == want["verdict"]
            and a.get("head_sha") == want["head_sha"]
            and a.get("artifact_sha256") == want["artifact_sha256"]
        ):
            match = a
            break

    if match is None:
        out["problems"].append(
            f"tracker holds no {want['verdict']} {want['kind']} review for {want['task']} "
            f"at head {want['head_sha'][:12]} with artifact {want['artifact_sha256'][:12]}"
        )
    else:
        if not is_ancestor(match["head_sha"], head):
            out["problems"].append(
                f"the reviewed head {match['head_sha'][:12]} is not an ancestor of the gate head"
            )
        out["receipt"] = {
            "task": match["task"],
            "kind": match["kind"],
            "backend": match.get("backend"),
            "verdict": match["verdict"],
            "head_sha": match["head_sha"],
            "artifact_sha256": match["artifact_sha256"],
            "timestamp": match.get("timestamp"),
        }

    out["verdict"] = "fail" if out["problems"] else "pass"
    return out


def check_deploy(doc: dict) -> list[str]:
    problems = []
    if doc.get("result") != "pass":
        problems.append(f"deployment verification result is {doc.get('result')!r}, not 'pass'")
    if doc.get("pending_count", -1) != 0:
        problems.append(f"deployment verification has {doc.get('pending_count')} pending check(s)")
    by_check = {c["check"]: c for c in doc.get("checks", [])}
    for name in REQUIRED_DEPLOY_CHECKS:
        c = by_check.get(name)
        if c is None:
            problems.append(f"deployment check {name!r} was not run")
        elif c.get("result") != "pass":
            problems.append(f"deployment check {name!r} is {c.get('result')!r}, not 'pass'")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--gate", action="append", default=[], metavar="NAME=EXIT")
    ap.add_argument("--gate-command", action="append", default=[], metavar="NAME=CMD")
    ap.add_argument("--deploy-verify")
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
        srcs = [check_source(s, head) for s in req["sources"]]
        ok = all(s["verdict"] == "pass" for s in srcs)
        entry = {"id": req["id"], "what": req["what"], "sources": srcs}
        if "design_review" in req:
            dr = check_design_review(req["design_review"], head)
            entry["design_review"] = dr
            ok = ok and dr["verdict"] == "pass"
        entry["verdict"] = "pass" if ok else "fail"
        results.append(entry)

    # Run completeness. A gate that was handed nothing must not report `pass`.
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

    deploy = None
    if not args.deploy_verify:
        run_problems.append("no deployment verification was supplied")
    else:
        deploy = json.loads(pathlib.Path(args.deploy_verify).read_text())
        run_problems.extend(check_deploy(deploy))

    reqs_green = all(r["verdict"] == "pass" for r in results)

    doc = {
        "schema_version": 1,
        "kind": "final_acceptance_gate",
        "what_this_is": (
            "The spec's final acceptance gate. Every executable requirement is mapped to the "
            "recorded evidence that closes it, and each artifact is re-checked here rather than "
            "trusted: it must exist, its commit must be an ancestor of the gate head, it must "
            "have been recorded on a clean worktree, and its own result must be passing. The "
            "repository gates are re-run at the gate head by the caller and recorded verbatim. "
            "Deferred-hardening items in the spec's Boundaries are NOT gate obligations."
        ),
        "spec": SPEC,
        "task": f"{SPEC}.14",
        "gate_head": head,
        "gate_head_worktree_dirty": dirty,
        "checked_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "revalidation": revalidation,
        "deployment_verify": deploy,
        "run_problems": run_problems,
        "ratified_limitations": RATIFIED_LIMITATIONS,
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
        mark = "PASS" if r["verdict"] == "pass" else "FAIL"
        print(f"{r['id']:<4} {mark}")
        for s in r["sources"]:
            for p in s["problems"]:
                print(f"       {s['artifact']}: {p}")
            for lim in (v for st in s.get("stages", {}).values() for v in st["ratified_limitations"]):
                print(f"       ratified limitation: {lim['claim']}")
        dr = r.get("design_review")
        if dr:
            for p in dr["problems"]:
                print(f"       design review: {p}")
    for p in run_problems:
        print(f"RUN  FAIL {p}")
    print(f"\ngate head: {head}")
    print(f"result:    {doc['result']}")
    return 0 if doc["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
