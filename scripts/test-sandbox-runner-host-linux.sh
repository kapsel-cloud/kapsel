#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE='rust@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663'
TARGET=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-runner-host-linux.XXXXXX")
HOST_CARGO_HOME=${CARGO_HOME:-"$HOME/.cargo"}
trap 'rm -rf "$TARGET"' EXIT HUP INT TERM

docker image inspect "$IMAGE" >/dev/null
docker run --rm --network none --platform linux/amd64 \
  --privileged --cgroupns=private \
  --volume "$ROOT:/workspace:ro" \
  --volume "$TARGET:/target" \
  --volume "$HOST_CARGO_HOME:/cargo-host:ro" \
  --workdir /workspace \
  --env CARGO_TARGET_DIR=/target \
  --env CARGO_HOME=/cargo-host \
  --env RUSTUP_HOME=/usr/local/rustup \
  --env RUSTUP_TOOLCHAIN=1.96.1-x86_64-unknown-linux-gnu \
  "$IMAGE" \
  sh -eu -c '
    test "$(id -u)" = 0
    cargo test --locked --offline -p kapsel-sandbox --lib runner_host::tests -- \
      --include-ignored --test-threads=1
    cargo test --locked --offline -p kapsel-sandbox --test runner_handoff production_runner_process
    cargo test --locked --offline -p kapsel-sandbox --test runner_handoff \
      production_runner_preserves_unknown_receipt_and_separate_classifier_meaning -- --exact
    cargo test --locked --offline -p kapsel-sandbox --test runner_handoff \
      production_process_loss_matrix_converges_at_owned_handoff_seams -- --exact
  '
