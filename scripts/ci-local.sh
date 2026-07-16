#!/usr/bin/env sh
set -eu

echo "==> Rust format"
cargo fmt --all --check

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

echo "==> clippy"
cargo clippy --locked --workspace --lib --bins --all-features -- -D warnings

echo "==> rustdoc"
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps

echo "==> unit tests"
cargo test --locked --lib --bins --workspace

echo "==> documentation tests"
cargo test --locked --doc --workspace

echo "==> Kapsel default gate passed"
