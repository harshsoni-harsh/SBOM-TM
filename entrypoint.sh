#!/usr/bin/env bash
set -euo pipefail

COMMAND="${1:-}"
shift || true

echo "[entrypoint] running: sbom-tm ${COMMAND} $*"

# Commands that accept --project
PROJECT_CMDS=("scan" "diff" "html" "report")

# If COMMAND is one of the project commands
needs_project=false
for c in "${PROJECT_CMDS[@]}"; do
    if [[ "$COMMAND" == "$c" ]]; then
        needs_project=true
        break
    fi
done

if $needs_project; then
    sbom-tm "$COMMAND" "$@" --project "${INPUT_PROJECT:-default}"
else
    # help, version, bad args → run exactly as user asked
    sbom-tm "$COMMAND" "$@"
fi
