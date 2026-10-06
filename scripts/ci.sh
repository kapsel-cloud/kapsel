#!/usr/bin/env sh
set -eu
cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
. ./tools/dev/dev-tools.sh

run_static_checks() {
  echo "==> Markdown, Rust, Python, and shell format"
  ./scripts/fmt.sh --check

  printf '%s\n' "==> Shell lint"
  "$SHFMT" -f=0 . | xargs -0 "$SHELLCHECK" -x

  printf '%s\n' "==> Python lint"
  "$RUFF" check --no-cache --config ruff.toml .

  printf '%s\n' "==> Python types (3.11, Linux and macOS)"
  check_type_checker
  "$PYRIGHT" --project pyrightconfig.json --warnings
  "$PYRIGHT" --project pyrightconfig.json --pythonplatform Darwin --warnings

  printf '%s\n' "==> Formatting pipeline regressions"
  python3 tools/dev/test_format.py
  python3 tools/dev/test_dev_tools.py
  python3 tools/dev/test_robustness.py

  printf '%s\n' "==> Qualification runner regressions"
  python3 tests/qualification/test_storage_enospc.py
  python3 tests/qualification/test_git_artifact.py
  python3 tests/qualification/test_git_service.py
  python3 tests/qualification/test_kind_agent_action_exercise.py
  python3 tools/release/test_artifact.py --archive /tmp/unused.tar.gz ReleaseVerifierTests

  printf '%s\n' "==> Rust line width"
  ./tools/checks/check-rust-width.sh

  printf '%s\n' "==> Source privacy and security regressions"
  python3 tools/checks/test_source_checks.py

  printf '%s\n' "==> Source privacy"
  python3 tools/checks/check_source_privacy.py

  printf '%s\n' "==> Markdown link checker regressions"
  ./tools/checks/test_check_markdown_links.py

  printf '%s\n' "==> Markdown links"
  ./tools/checks/check_markdown_links.py

}

run_rust_checks() {
  echo "==> locked fuzz dependency graph"
  cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 >/dev/null

  echo "==> clippy"
  cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
  cargo clippy --locked --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings

  echo "==> rustdoc"
  RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps

  echo "==> deterministic Rust tests"
  cargo test --locked --workspace --lib --bins --tests

  echo "==> hostile-input corpus and semantic oracles (no exploration)"
  cargo test --locked --manifest-path fuzz/Cargo.toml --test corpus
  cargo run --locked --manifest-path fuzz/Cargo.toml --example seed_corpus -- --check
}

run_documentation_tests() {
  echo "==> documentation tests"
  cargo test --locked --doc --workspace
}

case "${1:-all}" in
all)
  run_static_checks
  run_rust_checks
  run_documentation_tests
  echo "==> Kapsel default gate passed"
  ;;
static)
  run_static_checks
  echo "==> Static checks passed"
  ;;
rust)
  run_rust_checks
  echo "==> Rust checks and deterministic tests passed"
  ;;
doc)
  run_documentation_tests
  echo "==> Documentation tests passed"
  ;;
*)
  printf '%s\n' "usage: $0 [all|static|rust|doc]" >&2
  exit 2
  ;;
esac
