#!/usr/bin/env sh
set -eu

# Rustfmt's max_width is advisory. Check tracked Rust source independently so
# macros, literals, and method chains cannot silently exceed the repository limit.
git ls-files -z -- '*.rs' | LC_ALL=C xargs -0 awk -v max_width=100 '
  length($0) > max_width {
    printf "%s:%d: line is %d bytes (maximum %d)\n", FILENAME, FNR, length($0), max_width
    found = 1
  }
  END { if (found) exit 1 }
'
