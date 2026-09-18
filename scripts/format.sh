#!/usr/bin/env sh
set -eu

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

case "${1:-write}" in
  write)
    prettier_mode=--write
    check_mode=
    ;;
  check | --check)
    prettier_mode=--check
    check_mode=--check
    ;;
  *)
    printf '%s\n' "usage: $0 [write|check]" >&2
    exit 2
    ;;
esac

# Check every formatter before any source is rewritten.
. ./scripts/dev-tools.sh
check_formatters
cargo +"$FORMAT_TOOLCHAIN" fmt --version >/dev/null
"$RUFF" check --no-cache --config ruff.toml --show-settings scripts/check-markdown-links.py >/dev/null

"$PRETTIER" "$prettier_mode" --no-config --ignore-path .gitignore --print-width 100 \
  --prose-wrap always --tab-width 2 '**/*.md'
cargo +"$FORMAT_TOOLCHAIN" fmt --all -- --config-path rustfmt-nightly.toml ${check_mode:+"$check_mode"}
if [ -f fuzz/Cargo.toml ]; then
  cargo +"$FORMAT_TOOLCHAIN" fmt --manifest-path fuzz/Cargo.toml -- \
    --config-path rustfmt-nightly.toml ${check_mode:+"$check_mode"}
fi
"$RUFF" format --no-cache --config ruff.toml ${check_mode:+"$check_mode"} .
