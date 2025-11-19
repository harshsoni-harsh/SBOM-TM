# #!/usr/bin/env bash
# set -euo pipefail

# # Unified entrypoint for the container action.
# # - installs package
# # - runs sbom-tm (diff/scan/etc) with provided args/inputs
# # - searches common cache/data locations for markdown diff reports and copies the first found

# COMMAND="${1:-}"
# ARGS="${2:-}"
# PROJECT="${3:-default}"

# # Inputs mapped from action.yml via env vars
# MODE="${INPUT_MODE:-auto}"
# BASE="${INPUT_BASE:-}"
# OFFLINE="${INPUT_OFFLINE:-false}"
# REPORT_PATH="${INPUT_REPORT_PATH:-sbom-tm-report.md}"
# WORKSPACE="${GITHUB_WORKSPACE:-/work}"
# EVENT_NAME="${GITHUB_EVENT_NAME:-}"

# cd "$WORKSPACE" || exit 1

# echo "[entrypoint] running in workspace=$WORKSPACE mode=$MODE event=$EVENT_NAME project=$PROJECT"

# # Ensure package is available inside image
# echo "[entrypoint] installing package..."
# python -m pip install --upgrade pip >/dev/null || true
# pip install . >/dev/null || true

# EXIT_CODE=0

# run_scan() {
#   echo "[entrypoint] running: sbom-tm scan . --project \"$PROJECT\""
#   sbom-tm scan . --project "$PROJECT" || EXIT_CODE=$?
# }

# run_diff() {
#   local cmd=(sbom-tm diff --git --project "$PROJECT")
#   if [ -n "$BASE" ]; then
#     cmd+=(--base "$BASE")
#   fi
#   echo "[entrypoint] running: ${cmd[*]}"
#   "${cmd[@]}" || EXIT_CODE=$?
# }

# if [ -n "$COMMAND" ]; then
#   # allow direct passthrough: `docker run image diff --git`
#   if [ "$COMMAND" = "sbom-tm" ]; then
#     shift 1
#     COMMAND="${1:-}"
#     ARGS="${2:-}"
#     PROJECT="${3:-$PROJECT}"
#   fi
#   if [ -z "${ARGS// }" ]; then
#     sbom-tm "$COMMAND" --project "$PROJECT" || EXIT_CODE=$?
#   else
#     # shell-split ARGS into positional words
#     eval sbom-tm $COMMAND $ARGS --project "$PROJECT" || EXIT_CODE=$?
#   fi
# else
#   case "$MODE" in
#     scan)
#       run_scan
#       ;;
#     diff)
#       run_diff
#       ;;
#     auto)
#       if [ "$EVENT_NAME" = "pull_request" ]; then
#         run_diff
#       else
#         run_scan
#       fi
#       ;;
#     *)
#       echo "::error::Unknown mode '$MODE' (expected auto|scan|diff)"
#       exit 1
#       ;;
#   esac
# fi

# echo "[entrypoint] sbom-tm exit code: ${EXIT_CODE}"

# # Locate markdown report produced by sbom-tm and copy into workspace
# REPORT_SRC=""

# # candidate patterns to try (project-specific then generic)
# try_paths=(
#   "$HOME/.cache/sbom-tm/reports/${PROJECT}_sbom_diff.md"
#   "$WORKSPACE/.cache/sbom-tm/reports/${PROJECT}_sbom_diff.md"
#   "$WORKSPACE/data/cache/reports/${PROJECT}_sbom_diff.md"
#   "$HOME/.cache/sbom-tm/reports/default_sbom_diff.md"
#   "$WORKSPACE/.cache/sbom-tm/reports/default_sbom_diff.md"
#   "$WORKSPACE/data/cache/reports/default_sbom_diff.md"
# )

# for p in "${try_paths[@]}"; do
#   if [ -f "$p" ]; then
#     REPORT_SRC="$p"
#     break
#   fi
# done

# if [ -z "$REPORT_SRC" ]; then
#   # search workspace for matching files
#   if [ -d "$WORKSPACE" ]; then
#     REPORT_SRC=$(find "$WORKSPACE" -type f -name '*_sbom_diff.md' -print -quit 2>/dev/null || true)
#   fi
# fi

# if [ -z "$REPORT_SRC" ]; then
#   # search common package installation data locations (e.g., /usr/local/lib/.../data/cache/reports)
#   REPORT_SRC=$(find /usr/local/lib -type f -path '*/data/cache/reports/*_sbom_diff.md' -print -quit 2>/dev/null || true)
# fi

# if [ -n "$REPORT_SRC" ] && [ -f "$REPORT_SRC" ]; then
#   cp "$REPORT_SRC" "$WORKSPACE/$REPORT_PATH" || echo "[entrypoint] failed to copy report from $REPORT_SRC to $WORKSPACE/$REPORT_PATH"
#   echo "[entrypoint] copied markdown report to $WORKSPACE/$REPORT_PATH (source=$REPORT_SRC)"
#   # expose output for GitHub Actions
#   if [ -n "${GITHUB_OUTPUT:-}" ]; then
#     echo "report_path=$REPORT_PATH" >> "$GITHUB_OUTPUT"
#   fi
# else
#   echo "[entrypoint] no markdown diff report found (checked cache and /usr/local/lib)."
# fi

# exit "$EXIT_CODE"
# #!/usr/bin/env bash
# set -euo pipefail

# # Simple wrapper to run the installed `sbom-tm` CLI inside an action
# # Usage: ./entrypoint.sh <command> "<args>" <project>

# COMMAND="${1:-}"
# ARGS="${2:-}"
# PROJECT="${3:-}"

# # If the caller passed the full CLI name (e.g. `sbom-tm diff --git`) as args
# # (this happens when users run `docker run ... sbom-tm diff --git`), accept
# # that form by shifting off the leading `sbom-tm` token so the wrapper works
# # with either `diff --git` or `sbom-tm diff --git`.
# if [ "${COMMAND}" = "sbom-tm" ]; then
#   # shift positional parameters left by one
#   shift 1
#   COMMAND="${1:-}"
#   ARGS="${2:-}"
#   PROJECT="${3:-}"
# fi

# echo "[entrypoint] running sbom-tm ${COMMAND} ${ARGS} (project=${PROJECT})"

# # ensure package is installed (in case action didn't install earlier)
# python -m pip install --upgrade pip >/dev/null
# pip install . >/dev/null

# if [ "${COMMAND}" = "diff" ]; then
#   # run diff (use --git by default when in CI)
#   if [ -z "${ARGS// }" ]; then
#     sbom-tm diff --git --project "${PROJECT}"
#   else
#     sbom-tm diff ${ARGS} --project "${PROJECT}"
#   fi
# else
#   # generic passthrough (scan/generate/etc)
#   if [ -z "${ARGS// }" ]; then
#     sbom-tm ${COMMAND} --project "${PROJECT}"
#   else
#     sbom-tm ${COMMAND} ${ARGS} --project "${PROJECT}"
#   fi
# fi

# exit_code=$?
# echo "[entrypoint] sbom-tm exited with ${exit_code}"
# exit ${exit_code}
# #!/usr/bin/env bash
# set -euo pipefail

# # Inputs from action.yml (GitHub maps inputs → env: INPUT_<UPPERCASE_NAME>)
# MODE="${INPUT_MODE:-auto}"                 # auto | scan | diff
# BASE="${INPUT_BASE:-}"                     # base ref for diff (optional)
# PROJECT="${INPUT_PROJECT:-default}"        # used in report filenames
# OFFLINE="${INPUT_OFFLINE:-false}"          # true → --offline
# REPORT_PATH="${INPUT_REPORT_PATH:-sbom-tm-report.md}"

# WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
# EVENT_NAME="${GITHUB_EVENT_NAME:-}"

# cd "$WORKSPACE"

# echo "[sbom-tm-action] mode=$MODE event=$EVENT_NAME base=$BASE project=$PROJECT"

# OFFLINE_FLAG=()
# if [ "$OFFLINE" = "true" ]; then
#   OFFLINE_FLAG+=(--offline)
# fi

# EXIT_CODE=0

# run_scan() {
#   echo "[sbom-tm-action] running: sbom-tm scan . --project \"$PROJECT\" ${OFFLINE_FLAG[*]}"
#   sbom-tm scan . --project "$PROJECT" "${OFFLINE_FLAG[@]}" || EXIT_CODE=$?
# }

# run_diff() {
#   local cmd=(sbom-tm diff --git --project "$PROJECT" "${OFFLINE_FLAG[@]}")
#   if [ -n "$BASE" ]; then
#     cmd+=(--base "$BASE")
#   fi
#   echo "[sbom-tm-action] running: ${cmd[*]}"
#   "${cmd[@]}" || EXIT_CODE=$?
# }

# case "$MODE" in
#   scan)
#     run_scan
#     ;;
#   diff)
#     run_diff
#     ;;
#   auto)
#     if [ "$EVENT_NAME" = "pull_request" ]; then
#       # On PRs: compare HEAD vs base commit
#       run_diff
#     else
#       # On pushes: just scan the tree
#       run_scan
#     fi
#     ;;
#   *)
#     echo "::error::Unknown mode '$MODE' (expected auto|scan|diff)"
#     exit 1
#     ;;
# esac

# # Try to locate Markdown diff report produced by sbom-tm (for PR comment)
# REPORT_SRC=""
# # Check common locations in order of likelihood:
# # 1) user cache (~/.cache/sbom-tm/reports)
# # 2) mounted workspace cache ($WORKSPACE/.cache/sbom-tm/reports)
# # 3) workspace data/cache (when package writes into project tree)
# # 4) package installation data cache (e.g. /usr/local/lib/.../data/cache/reports)

# try_paths=(
#   "$HOME/.cache/sbom-tm/reports/${PROJECT}_sbom_diff.md"
#   "$WORKSPACE/.cache/sbom-tm/reports/${PROJECT}_sbom_diff.md"
#   "$WORKSPACE/data/cache/reports/${PROJECT}_sbom_diff.md"
# )

# for p in "${try_paths[@]}"; do
#   if [ -f "$p" ]; then
#     REPORT_SRC="$p"
#     break
#   fi
# done

# if [ -z "$REPORT_SRC" ]; then
#   # search the workspace for any matching report file
#   if [ -d "$WORKSPACE" ]; then
#     REPORT_SRC="$(find "$WORKSPACE" -type f -name '*_sbom_diff.md' -print -quit 2>/dev/null || true)"
#   fi
# fi

# if [ -z "$REPORT_SRC" ]; then
#   # fall back to searching typical package data locations
#   REPORT_SRC="$(find /usr/local/lib -type f -path '*/data/cache/reports/*_sbom_diff.md' -print -quit 2>/dev/null || true)"
# fi

# if [ -n "$REPORT_SRC" ] && [ -f "$REPORT_SRC" ]; then
#   # copy to workspace report path
#   cp "$REPORT_SRC" "$WORKSPACE/$REPORT_PATH"
#   echo "[sbom-tm-action] copied markdown report to $WORKSPACE/$REPORT_PATH (source=$REPORT_SRC)"
#   # expose to other steps as output (GitHub actions)
#   if [ -n "${GITHUB_OUTPUT:-}" ]; then
#     echo "report_path=$REPORT_PATH" >> "$GITHUB_OUTPUT"
#   fi
# else
#   echo "[sbom-tm-action] no markdown diff report found (this is OK if scan mode only)."
# fi

# exit "$EXIT_CODE"
#!/usr/bin/env bash
set -euo pipefail

# If running in GitHub Actions (INPUT_MODE exists)
if [[ -n "${INPUT_MODE:-}" ]]; then
    exec /github-action-entrypoint.sh "$@"
fi

# Otherwise normal CLI mode:
exec sbom-tm "$@"
