#!/usr/bin/env sh
set -eu
cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
. ./tools/dev/dev-tools.sh
export PRETTIER RUFF PYRIGHT SHFMT SHELLCHECK
exec python3 tools/dev/run_checks.py "$@"
