#!/usr/bin/env sh
# Temporary workflow aliases share the completion router's maintained owner mapping.
set -eu
cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
[ "$#" -le 1 ] || {
  echo 'usage: scripts/ci.sh [all|static|rust|doc]' >&2
  exit 2
}
case "${1:-all}" in
all) exec sh scripts/check.sh check ;;
static | rust | doc) exec sh scripts/check.sh "ci-$1" ;;
*)
  echo 'usage: scripts/ci.sh [all|static|rust|doc]' >&2
  exit 2
  ;;
esac
