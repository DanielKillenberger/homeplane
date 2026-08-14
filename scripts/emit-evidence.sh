#!/usr/bin/env bash
# emit-evidence.sh — run the repository gates and record a versioned evidence
# artifact at test/evidence/<task-id>.json.
#
# The artifact exists so a later reviewer (or the spec's final gate, task .14)
# can see WHICH assertions passed, at WHICH commit, on WHICH platform — rather
# than trusting a prose claim that "tests pass". It records the commands, their
# exit codes, every passing test name, and timestamps.
#
# Run it from a CLEAN worktree at the implementation commit: the artifact
# attests to a reproducible commit, so `working_tree_dirty: true` means the
# evidence describes a state nobody else can check out. The evidence directory
# itself is excluded from that check — this script is what changes it — so the
# normal flow is: commit the implementation, run this, commit the artifact.
#
# Tag-gated proofs (live provider runs behind a build tag) cannot be re-executed
# here — they need credentials, consent and a running gateway. A task that has
# them records its run in test/evidence/<task-id>.live.json, and this script
# EMBEDS that file under the artifact's "live" key so the acceptance record is
# one artifact rather than two. The file is written by whoever ran the proof;
# nothing here can vouch for it, so it carries its own commit and timestamps.
#
# Usage: scripts/emit-evidence.sh <task-id>
# Requires: go, git, python3.
set -euo pipefail

TASK_ID="${1:-}"
if [[ -z "$TASK_ID" ]]; then
  echo "usage: scripts/emit-evidence.sh <task-id>" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"

OUT_DIR="test/evidence"
OUT_FILE="$OUT_DIR/$TASK_ID.json"
mkdir -p "$OUT_DIR"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

run_gate() {
  local name="$1"; shift
  local log="$WORK/$name.log"
  local rc=0
  "$@" >"$log" 2>&1 || rc=$?
  printf '%s\t%s\t%d\n' "$name" "$*" "$rc" >>"$WORK/gates.tsv"
  if [[ $rc -ne 0 ]]; then
    echo "gate '$name' failed (exit $rc):" >&2
    cat "$log" >&2
  fi
  return $rc
}

FAILED=0
run_gate build go build ./... || FAILED=1
run_gate vet go vet ./... || FAILED=1
# -json gives per-test outcomes; the human-readable log stays in $WORK.
run_gate test go test ./... -count=1 -json || FAILED=1

FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

TASK_ID="$TASK_ID" \
STARTED_AT="$STARTED_AT" \
FINISHED_AT="$FINISHED_AT" \
COMMIT="$(git rev-parse HEAD)" \
DIRTY="$(if [[ -n "$(git status --porcelain -- . ":(exclude)$OUT_DIR")" ]]; then echo true; else echo false; fi)" \
GO_VERSION="$(go version)" \
GOOS="$(go env GOOS)" \
GOARCH="$(go env GOARCH)" \
UNAME="$(uname -srm)" \
WORK="$WORK" \
FAILED="$FAILED" \
LIVE_FILE="$OUT_DIR/$TASK_ID.live.json" \
python3 - "$OUT_FILE" <<'PY'
import json, os, sys

out_file = sys.argv[1]
work = os.environ["WORK"]

gates = []
with open(os.path.join(work, "gates.tsv"), encoding="utf-8") as fh:
    for line in fh:
        name, command, rc = line.rstrip("\n").split("\t")
        gates.append({"gate": name, "command": command, "exit_code": int(rc)})

assertions = []
test_log = os.path.join(work, "test.log")
if os.path.exists(test_log):
    with open(test_log, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("Action") in ("pass", "fail") and event.get("Test"):
                assertions.append({
                    "package": event.get("Package", ""),
                    "test": event["Test"],
                    "result": event["Action"],
                    "elapsed_seconds": event.get("Elapsed", 0),
                })

assertions.sort(key=lambda a: (a["package"], a["test"]))
passed = sum(1 for a in assertions if a["result"] == "pass")

artifact = {
    "schema_version": 1,
    "task": os.environ["TASK_ID"],
    "commit": os.environ["COMMIT"],
    "working_tree_dirty": os.environ["DIRTY"] == "true",
    "platform": {
        "go_version": os.environ["GO_VERSION"],
        "goos": os.environ["GOOS"],
        "goarch": os.environ["GOARCH"],
        "uname": os.environ["UNAME"],
    },
    "started_at": os.environ["STARTED_AT"],
    "finished_at": os.environ["FINISHED_AT"],
    "gates": gates,
    "assertion_counts": {
        "total": len(assertions),
        "passed": passed,
        "failed": len(assertions) - passed,
    },
    "assertions": assertions,
    "result": "pass" if os.environ["FAILED"] == "0" else "fail",
}

# Tag-gated live evidence, recorded by whoever ran the proof. It is embedded
# verbatim: this script did not run it and must not imply that it did. A
# malformed file is a loud failure rather than a silently missing record.
live_file = os.environ.get("LIVE_FILE", "")
if live_file and os.path.exists(live_file):
    with open(live_file, encoding="utf-8") as fh:
        try:
            artifact["live"] = json.load(fh)
        except json.JSONDecodeError as err:
            raise SystemExit(f"{live_file} is not valid JSON: {err}")

with open(out_file, "w", encoding="utf-8") as fh:
    json.dump(artifact, fh, indent=2, sort_keys=False)
    fh.write("\n")

live_note = ""
if "live" in artifact:
    live_assertions = artifact["live"].get("assertions", [])
    live_note = f", {len(live_assertions)} embedded live assertions"

print(f"wrote {out_file}: {artifact['result']} "
      f"({passed}/{len(assertions)} assertions, {len(gates)} gates{live_note}) "
      f"at {artifact['commit'][:8]}"
      f"{' [DIRTY WORKTREE]' if artifact['working_tree_dirty'] else ''}")

if artifact["working_tree_dirty"]:
    print("warning: the worktree was dirty; this artifact does not attest to a "
          "reproducible commit. Commit the implementation and re-run.",
          file=sys.stderr)
PY

exit "$FAILED"
