#!/usr/bin/env sh
set -eu
root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# Smoke uses a temporary corpus. Persistent exploration requires a separate explicit mode.
exec python3 "$root_dir/tools/dev/run_robustness.py" fuzz-smoke "$@"
