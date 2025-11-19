#!/usr/bin/env bash
set -euo pipefail

# Inputs mapped from action.yml
MODE="${INPUT_MODE:-auto}"
BASE="${INPUT_BASE:-}"
PROJECT="${INPUT_PROJECT:-default}"
OFFLINE="${INPUT_OFFLINE:-false}"
REPORT_PATH="${INPUT_REPORT_PATH:-sbom-tm-report.md}"

WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
EVENT_NAME="${GITHUB_EVENT_NAME:-}"

cd "$WORKSPACE"

OFFLINE_FLAG=()
if [[ "$OFFLINE" == "true" ]]; then
  OFFLINE_FLAG+=(--offline)
fi

EXIT_CODE=0

run_scan() {
  sbom-tm scan . --project "$PROJECT" "${OFFLINE_FLAG[@]}" || EXIT_CODE=$?
}

run_diff() {
  cmd=(sbom-tm diff --git --project "$PROJECT" "${OFFLINE_FLAG[@]}")
  if [[ -n "$BASE" ]]; then
    cmd+=(--base "$BASE")
  fi
  "${cmd[@]}" || EXIT_CODE=$?
}

case "$MODE" in
  scan)
    run_scan
    ;;
  diff)
    run_diff
    ;;
  auto)
    if [[ "$EVENT_NAME" == "pull_request" ]]; then
      run_diff
    else
      run_scan
    fi
    ;;
  *)
    echo "::error::Invalid mode '$MODE'"
    exit 1
    ;;
esac

exit "$EXIT_CODE"
