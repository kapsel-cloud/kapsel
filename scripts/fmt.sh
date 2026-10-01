#!/usr/bin/env sh
set -eu

cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

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

. ./tools/dev/dev-tools.sh
check_formatters
# Cargo otherwise honors an ambient RUSTFMT override even with an explicit toolchain.
RUSTFMT=$(rustup which --toolchain "$FORMAT_TOOLCHAIN" rustfmt)
export RUSTFMT
cargo +"$FORMAT_TOOLCHAIN" fmt --version >/dev/null
"$RUFF" check --no-cache --config ruff.toml --show-settings tools/checks/check_markdown_links.py >/dev/null

"$PRETTIER" "$prettier_mode" --ignore-path .gitignore '**/*.{md,json,jsonc,yaml,yml}'
cargo +"$FORMAT_TOOLCHAIN" fmt --all -- --config-path rustfmt-nightly.toml ${check_mode:+"$check_mode"}
if [ -f fuzz/Cargo.toml ]; then
  cargo +"$FORMAT_TOOLCHAIN" fmt --manifest-path fuzz/Cargo.toml -- \
    --config-path rustfmt-nightly.toml ${check_mode:+"$check_mode"}
fi
if [ -n "$check_mode" ]; then
  "$RUFF" check --no-cache --config ruff.toml --select I .
else
  "$RUFF" check --no-cache --config ruff.toml --select I --fix .
fi
"$RUFF" format --no-cache --config ruff.toml ${check_mode:+"$check_mode"} .
git ls-files -z --cached --others --exclude-standard '*.toml' |
  xargs -0 "$TAPLO" fmt ${check_mode:+"$check_mode"}
if [ -n "$check_mode" ]; then
  "$SHFMT" -i 2 -d .
else
  "$SHFMT" -i 2 -w .
fi
