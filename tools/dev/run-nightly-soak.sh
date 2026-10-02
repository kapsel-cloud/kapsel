#!/usr/bin/env sh
set -eu
root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
# Simulation-only sweep. Fuzz exploration is explicitly queued through the Python owner.
exec python3 "$root_dir/tools/dev/run_robustness.py" soak "$@"
