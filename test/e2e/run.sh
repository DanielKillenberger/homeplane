#!/usr/bin/env bash
# run.sh — drive the end-to-end proof against THIS deployment.
#
# The proof needs a live deployment, this machine's own harnesses and — for the
# credentials stage — a human at a browser, so it is never part of
# `go test ./...`. This script carries the one deployment's coordinates so a
# re-run is a command rather than a paragraph of environment variables.
#
#   test/e2e/run.sh                     # every stage, in order
#   test/e2e/run.sh enrol,vault         # only these stages
#
# Stages: install enrol vault gno skills harnesses gno-retrieval credentials
#         connector calendar revocation truth-table audit
#
# The evidence file is updated after every stage and carries earlier stages
# forward, so an interrupted run loses nothing and a single leg can be re-run.
set -euo pipefail

cd "$(dirname "$0")/../.."

export HOMEPLANE_E2E=1
export HOMEPLANE_E2E_SERVER="${HOMEPLANE_E2E_SERVER:-http://homeplane.tailab4e9b.ts.net}"
export HOMEPLANE_E2E_SSH_HOST="${HOMEPLANE_E2E_SSH_HOST:-clawniel}"
export HOMEPLANE_E2E_SERVER_PREFIX="${HOMEPLANE_E2E_SERVER_PREFIX:-/home/claw/homeplane}"
export HOMEPLANE_E2E_SERVER_STATE_DIR="${HOMEPLANE_E2E_SERVER_STATE_DIR:-/home/claw/homeplane/var}"
export HOMEPLANE_E2E_ACCOUNT="${HOMEPLANE_E2E_ACCOUNT:-daniel.killenberger@gmail.com}"
export HOMEPLANE_E2E_CALENDAR_ID="${HOMEPLANE_E2E_CALENDAR_ID:-primary}"
export HOMEPLANE_E2E_VAULT="${HOMEPLANE_E2E_VAULT:-$HOME/Documents/daniel-os}"

if [[ $# -gt 0 ]]; then
  export HOMEPLANE_E2E_STAGES="$1"
fi

exec go test ./test/e2e/ -tags live_e2e -run TestEndToEndProof -count=1 -v -timeout 240m
