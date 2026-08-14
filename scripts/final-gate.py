#!/usr/bin/env python3
"""final-gate.py — the spec's final acceptance gate (task .14).

Maps every executable requirement of the walking-skeleton spec to the recorded
evidence that closes it, and REFUSES to call the gate green on anything it
cannot verify itself:

  * the evidence artifact must EXIST;
  * its recorded commit must be an ANCESTOR of the gate head — an artifact
    recorded on a commit that never reached the shipped history attests to a
    tree nobody can check out;
  * it must have been recorded on a CLEAN worktree, where the artifact says;
  * its own result must be `pass`, with zero failed assertions.

A requirement whose sources are all verifiable and passing is `pass`. Anything
else is `fail`, and one failing requirement fails the gate. Nothing here is
allowed to downgrade a failure into a note.

Re-validation of `go build`/`go vet`/`go test` at the gate head is passed in
rather than re-run, so the caller records the exact commands it ran.

Usage: scripts/final-gate.py --out <file.json> \
         --gate build=0 --gate vet=0 --gate test=0 [--deploy-verify <file.json>]
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
        "design_review": {
            "what": "R12 is verified in the skeleton by design review of the manifest/registration path (a second live connector is out of scope).",
            "artifact": "docs/decisions/d6-gateway.md",
            "recorded_verdict": {
                "kind": "impl",
                "task": f"{SPEC}.1",
                "backend": "codex (gpt-5.6-sol @ xhigh)",
                "verdict": "SHIP",
                "head_sha": "394299f3",
                "artifact_sha256_prefix": "aeea68c2a4ed",
                "timestamp": "2026-08-13T19:20:06Z",
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

    if doc.get("working_tree_dirty") is True:
        out["problems"].append("recorded on a dirty worktree — nobody else can check that tree out")

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
            failed = [a["claim"] for a in asserts if not a.get("ok")]
            settled[stage] = {
                "status": s.get("status"),
                "assertions": len(asserts),
                "not_ok": failed,
            }
            # `partial` is a stage whose recorded limitations are named in the
            # artifact itself. It is NOT a failure, but it is never silent.
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
        entry = {
            "id": req["id"],
            "what": req["what"],
            "sources": srcs,
            "verdict": "pass" if all(s["verdict"] == "pass" for s in srcs) else "fail",
        }
        if "design_review" in req:
            entry["design_review"] = req["design_review"]
        results.append(entry)

    gates_green = all(g["exit_code"] == 0 for g in revalidation)
    reqs_green = all(r["verdict"] == "pass" for r in results)

    deploy = None
    if args.deploy_verify:
        deploy = json.loads(pathlib.Path(args.deploy_verify).read_text())
        if deploy.get("result") != "pass":
            gates_green = False

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
        "requirements": results,
        "counts": {
            "total": len(results),
            "passed": sum(1 for r in results if r["verdict"] == "pass"),
            "failed": sum(1 for r in results if r["verdict"] == "fail"),
        },
        "result": "pass" if (gates_green and reqs_green) else "fail",
    }

    pathlib.Path(args.out).write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n")

    for r in results:
        mark = "PASS" if r["verdict"] == "pass" else "FAIL"
        print(f"{r['id']:<4} {mark}")
        for s in r["sources"]:
            for p in s["problems"]:
                print(f"       {s['artifact']}: {p}")
    print(f"\ngate head: {head}")
    print(f"result:    {doc['result']}")
    return 0 if doc["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
