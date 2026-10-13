#!/usr/bin/env sh
set -eu
root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
# Independent simulation job; select a new --output and explicit --seed values.
exec python3 "$root_dir/tools/dev/run_robustness.py" simulation "$@"
