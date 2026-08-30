#!/usr/bin/env sh
set -eu

corpus_directory=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-fuzz-corpus.XXXXXX")
trap 'rm -rf "$corpus_directory"' EXIT HUP INT TERM
cp fuzz/corpus/inspect_receipt/canonical-receipt-and-trust "$corpus_directory/"
cd fuzz
rustup run nightly-2026-07-03 cargo fuzz run --dev inspect_receipt "$corpus_directory" -- \
  -runs=10000 -seed=2118243591
