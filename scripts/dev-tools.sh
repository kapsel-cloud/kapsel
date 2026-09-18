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
  if [ "$("$PRETTIER" --version 2>/dev/null)" != "$PRETTIER_VERSION" ] ||
      [ "$("$RUFF" --version 2>/dev/null)" != "ruff $RUFF_VERSION" ]; then
    printf '%s\n' 'Pinned contributor tools unavailable. Run ./scripts/setup.sh.' >&2
    return 1
  fi
}
