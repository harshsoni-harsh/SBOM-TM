#!/usr/bin/env bash
set -euo pipefail

MODE="${INPUT_MODE:-auto}"
BASE="${INPUT_BASE:-}"
PROJECT="${INPUT_PROJECT:-default}"
OFFLINE="${INPUT_OFFLINE:-false}"
REPORT_PATH="${INPUT_REPORT_PATH:-sbom-tm-report.md}"

WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
EVENT_NAME="${GITHUB_EVENT_NAME:-}"

cd "$WORKSPACE"

OFFLINE_FLAG=()
[[ "$OFFLINE" == "true" ]] && OFFLINE_FLAG+=(--offline)

EXIT_CODE=0

run_scan() {
  sbom-tm scan . --project "$PROJECT" "${OFFLINE_FLAG[@]}" || EXIT_CODE=$?
}

run_diff() {
  cmd=(sbom-tm diff --git --project "$PROJECT" "${OFFLINE_FLAG[@]}")
  [[ -n "$BASE" ]] && cmd+=(--base "$BASE")
  "${cmd[@]}" || EXIT_CODE=$?
}

if [[ "$MODE" == "scan" ]]; then
    run_scan
elif [[ "$MODE" == "diff" ]]; then
    run_diff
else
    [[ "$EVENT_NAME" == "pull_request" ]] && run_diff || run_scan
fi

exit "$EXIT_CODE"
