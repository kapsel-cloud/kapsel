#!/usr/bin/env sh
set -eu

run_static_checks() {
  echo "==> Rust format"
  cargo fmt --all --check
  if [ -f fuzz/Cargo.toml ]; then
    cargo fmt --manifest-path fuzz/Cargo.toml --check
  fi

  printf '%s\n' "==> Rust line width"
  ./scripts/check-rust-width.sh

  printf '%s\n' "==> tidy"
  if [ -f crates/kapsel-dev/Cargo.toml ]; then
    cargo run --quiet --locked -p kapsel-dev --bin kapsel-tidy -- tidy
  elif [ -f .cargo_vcs_info.json ]; then
    printf '%s\n' "tidy: skipped in packaged source without repository-only tooling"
  else
    printf '%s\n' "tidy: missing crates/kapsel-dev/Cargo.toml" >&2
    exit 1
  fi

  echo "==> Markdown format"
  prettier --check --no-config --ignore-path .gitignore --print-width 100 --prose-wrap always \
    --tab-width 2 '**/*.md'

  printf '%s\n' "==> Markdown link checker regressions"
  ./scripts/test-check-markdown-links.py

  printf '%s\n' "==> Markdown links"
  ./scripts/check-markdown-links.py

  printf '%s\n' "==> Sandbox contract fixtures"
  ./scripts/test-sandbox-contract.py
}

run_rust_checks() {
  echo "==> clippy"
  cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

  echo "==> rustdoc"
  RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps

  echo "==> deterministic Rust tests"
  cargo test --locked --workspace --lib --bins --tests \
    --features kapsel-sandbox/state-root-test-harness
}

run_documentation_tests() {
  echo "==> documentation tests"
  cargo test --locked --doc --workspace
}

case "${1:-all}" in
  all | check)
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
    printf '%s\n' "usage: $0 [all|check|static|rust|doc]" >&2
    exit 2
    ;;
esac
