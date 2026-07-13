#!/usr/bin/env sh
set -eu

echo "==> Rust format"
cargo fmt --all --check

printf '%s\n' "==> Rust line width"
./scripts/check-rust-width.sh

echo "==> Markdown format"
prettier --check --no-config --ignore-path .gitignore --print-width 100 --prose-wrap always \
  --tab-width 2 '**/*.md'

printf '%s\n' "==> Markdown link checker regressions"
./scripts/test-check-markdown-links.py

printf '%s\n' "==> Markdown links"
./scripts/check-markdown-links.py

echo "==> clippy"
cargo clippy --locked --workspace --lib --bins --all-features -- -D warnings

echo "==> unit tests"
cargo test --locked --lib --bins --workspace

echo "==> documentation tests"
cargo test --locked --doc --workspace

echo "==> Kapsel default gate passed"
