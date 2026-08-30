#!/usr/bin/env sh
set -eu

python3 scripts/test-demo-kind-crash-recovery.py
cargo test --locked -p kapsel --features demo-harness --test e2e_demo_recovery
