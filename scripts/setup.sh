#!/usr/bin/env sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. ./scripts/dev-tools.sh

case "${1:-install}" in
  install|--check) mode=${1:-install} ;;
  *) printf '%s\n' "usage: $0 [--check]" >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { printf '%s\n' "usage: $0 [--check]" >&2; exit 2; }

missing=0
for tool in git cc rustup python3 node npm; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'Missing host prerequisite: %s\n' "$tool" >&2
    missing=1
  fi
done
[ "$missing" = 0 ] || exit 1
python3 -c 'import sys, venv, ensurepip; sys.exit(sys.version_info < (3, 11))' || {
  printf '%s\n' 'Python 3.11+ with venv and ensurepip is required.' >&2; exit 1;
}
node -e 'process.exit(Number(process.versions.node.split(".")[0]) < 24 ? 1 : 0)' || {
  printf '%s\n' 'Node.js 24+ is required.' >&2; exit 1;
}

# Read the compiler pin rather than duplicating it in setup or CI.
toolchain=$(python3 -c 'import tomllib; print(tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"]["channel"])')
if [ "$mode" = install ]; then
  rustup toolchain install --no-self-update
  rustup toolchain install "$FORMAT_TOOLCHAIN" --profile minimal --component rustfmt --no-self-update
  if [ "$("$RUFF" --version 2>/dev/null || :)" != "ruff $RUFF_VERSION" ]; then
    python3 -m venv "$RUFF_HOME"
    "$RUFF_HOME/bin/python" -m pip install --disable-pip-version-check "ruff==$RUFF_VERSION"
  fi
  if [ "$("$PRETTIER" --version 2>/dev/null || :)" != "$PRETTIER_VERSION" ]; then
    npm install --prefix "$PRETTIER_HOME" --no-save --package-lock=false \
      --ignore-scripts --no-audit --no-fund "prettier@$PRETTIER_VERSION"
  fi
fi
check_formatters
# Avoid even creating rustup's home during read-only diagnosis.
[ -d "${RUSTUP_HOME:-$HOME/.rustup}/toolchains" ] || {
  printf '%s\n' 'Rust toolchain missing. Run ./scripts/setup.sh.' >&2; exit 1;
}
# rustup run does not install a missing toolchain.
rustup run "$toolchain" cargo --version
rustup run "$FORMAT_TOOLCHAIN" rustfmt --version
rustup run "$toolchain" cargo-clippy --version
printf '%s\n' 'Contributor tools ready. No activation or hooks required.'
