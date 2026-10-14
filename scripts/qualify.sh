#!/usr/bin/env sh
set -eu
cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
boundary=${1:-}
[ "$#" -gt 0 ] && shift
case "$boundary" in
storage) exec python3 tests/qualification/run_storage_enospc.py "$@" ;;
security) exec python3 tools/checks/scan_source_security.py "$@" ;;
artifact | reproducibility | kubernetes | git | native)
  archive=
  expect_archive=0
  for argument in "$@"; do
    if [ "$expect_archive" = 1 ]; then
      archive=$argument
      expect_archive=0
    elif [ "$argument" = --archive ]; then
      expect_archive=1
    fi
  done
  [ -n "$archive" ] && [ "$expect_archive" = 0 ] && [ -f "$archive" ] || {
    echo 'Qualification requires --archive A naming an existing selected archive; no implicit assembly.' >&2
    exit 2
  }
  case "$boundary" in
  artifact) exec python3 tools/release/test_artifact.py "$@" ;;
  kubernetes) exec python3 tests/qualification/run_kind_agent_action_workflow.py "$@" ;;
  git) exec python3 tests/qualification/run_git_artifact.py "$@" ;;
  reproducibility)
    [ "$#" = 2 ] && [ "$1" = --archive ] || {
      echo 'usage: cargo xtask qualify reproducibility --archive A' >&2
      exit 2
    }
    exec python3 tools/release/test_reproducibility.py --reference-archive "$archive"
    ;;
  native)
    exec python3 tools/dev/qualify_native.py "$@"
    ;;
  esac
  ;;
*)
  echo 'usage: cargo xtask qualify storage|artifact|reproducibility|kubernetes|git|native|security [owner arguments]' >&2
  exit 2
  ;;
esac
