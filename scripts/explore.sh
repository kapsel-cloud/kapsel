#!/usr/bin/env sh
set -eu
cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
case "${1:-}" in
sim) mode=simulation ;;
fuzz) mode=fuzz ;;
*)
  echo 'usage: cargo xtask explore sim|fuzz [bounded runner arguments]' >&2
  exit 2
  ;;
esac
shift
exec python3 tools/dev/run_robustness.py "$mode" "$@"
