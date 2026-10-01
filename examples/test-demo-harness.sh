#!/usr/bin/env sh
set -eu

python3 examples/test_demo_kind_crash_recovery.py
cargo test --locked -p kapsel --features demo-harness --test e2e_demo_recovery
