#!/usr/bin/env sh
set -eu

case "${1:-write}" in
  write)
    cargo +nightly-2026-07-03 fmt --all -- --config-path rustfmt-nightly.toml
    if [ -f fuzz/Cargo.toml ]; then
      cargo +nightly-2026-07-03 fmt --manifest-path fuzz/Cargo.toml -- --config-path rustfmt-nightly.toml
    fi
    prettier_mode=--write
    ;;
  check | --check)
    cargo +nightly-2026-07-03 fmt --all -- --config-path rustfmt-nightly.toml --check
    if [ -f fuzz/Cargo.toml ]; then
      cargo +nightly-2026-07-03 fmt --manifest-path fuzz/Cargo.toml -- --config-path rustfmt-nightly.toml --check
    fi
    prettier_mode=--check
    ;;
  *)
    printf '%s\n' "usage: $0 [write|check]" >&2
    exit 2
    ;;
esac

prettier_version=$(prettier --version 2>/dev/null) || {
  printf '%s\n' "format: Prettier 3.6.2 is required" >&2
  exit 1
}
if [ "$prettier_version" != "3.6.2" ]; then
  printf '%s\n' "format: Prettier 3.6.2 is required; found $prettier_version" >&2
  exit 1
fi
prettier "$prettier_mode" --no-config --ignore-path .gitignore --print-width 100 \
  --prose-wrap always --tab-width 2 '**/*.md'
