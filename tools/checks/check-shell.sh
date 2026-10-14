#!/usr/bin/env sh
# Keep enumeration failure separate from lint success; POSIX pipelines lack pipefail.
set -eu
. ./tools/dev/dev-tools.sh
files=$(mktemp)
trap 'rm -f "$files"' 0
"$SHFMT" -f=0 . >"$files"
xargs -0 "$SHELLCHECK" -x <"$files"
