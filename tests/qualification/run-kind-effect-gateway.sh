#!/usr/bin/env bash
set -euo pipefail

# The live gate uses extracted production binaries, not a second source/test-hook journey.
exec python3 "$(dirname -- "${BASH_SOURCE[0]}")/run_kind_agent_action_workflow.py" "$@"
