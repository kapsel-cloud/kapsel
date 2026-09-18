# Sourced by setup, formatting and the static gate. No PATH or shell-profile changes.
PRETTIER_VERSION=3.9.6
RUFF_VERSION=0.16.6
FORMAT_TOOLCHAIN=nightly-2026-07-03
DEV_TOOLS="${HOME}/.local/share/kapsel/dev-tools"
PRETTIER_HOME="$DEV_TOOLS/prettier-$PRETTIER_VERSION"
RUFF_HOME="$DEV_TOOLS/ruff-$RUFF_VERSION"
PRETTIER="$PRETTIER_HOME/node_modules/.bin/prettier"
RUFF="$RUFF_HOME/bin/ruff"

check_formatters() {
  formatter_status=0
  if [ ! -x "$PRETTIER" ]; then
    printf '%s\n' "Prettier missing: $PRETTIER" >&2
    formatter_status=1
  elif [ "$("$PRETTIER" --version 2>/dev/null || :)" != "$PRETTIER_VERSION" ]; then
    printf '%s\n' "Prettier unavailable or mismatched: expected $PRETTIER_VERSION" >&2
    formatter_status=1
  fi
  if [ ! -x "$RUFF" ]; then
    printf '%s\n' "Ruff missing: $RUFF" >&2
    formatter_status=1
  elif [ "$("$RUFF" --version 2>/dev/null || :)" != "ruff $RUFF_VERSION" ]; then
    printf '%s\n' "Ruff unavailable or mismatched: expected $RUFF_VERSION" >&2
    formatter_status=1
  fi
  if [ "$formatter_status" != 0 ]; then
    printf '%s\n' 'Run ./scripts/setup.sh to prepare the pinned tools.' >&2
  fi
  return "$formatter_status"
}
