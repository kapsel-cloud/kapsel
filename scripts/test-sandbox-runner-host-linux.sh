#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE='rust@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663'
TARGET_TOKEN=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-runner-host-linux.XXXXXX")
TARGET_VOLUME=$(basename "$TARGET_TOKEN")
rmdir "$TARGET_TOKEN"
HOST_CARGO_HOME=${CARGO_HOME:-"$HOME/.cargo"}
trap 'docker volume rm -f "$TARGET_VOLUME" >/dev/null 2>&1 || true' EXIT HUP INT TERM

docker image inspect "$IMAGE" >/dev/null
if docker volume inspect "$TARGET_VOLUME" >/dev/null 2>&1; then
  echo "refusing pre-existing runner-host target volume: $TARGET_VOLUME" >&2
  exit 1
fi
docker volume create "$TARGET_VOLUME" >/dev/null
docker run --rm --network none --platform linux/amd64 \
  --privileged --cgroupns=private \
  --volume "$ROOT:/workspace:ro" \
  --volume "$TARGET_VOLUME:/target" \
  --volume "$HOST_CARGO_HOME:/cargo-host:ro" \
  --workdir /workspace \
  --env CARGO_TARGET_DIR=/target \
  --env CARGO_HOME=/cargo-host \
  --env RUSTUP_HOME=/usr/local/rustup \
  --env RUSTUP_TOOLCHAIN=1.96.1-x86_64-unknown-linux-gnu \
  "$IMAGE" \
  sh -eu -c '
    test "$(id -u)" = 0
    test "$(cc --version | sed -n "1p")" = "cc (Debian 12.2.0-14+deb12u1) 12.2.0"
    test "$(sha256sum crates/kapsel-sandbox/src/runner_pre_exec.c | cut -d " " -f 1)" = \
      "daca55a67efb22a8644f0e86243e5d067c03787674340405a57021b4569bf970"
    cc -std=c11 -O2 -Wall -Wextra -Werror \
      crates/kapsel-sandbox/tests/runner_pre_exec_matrix.c \
      -o /target/runner-pre-exec-capability-matrix
    /target/runner-pre-exec-capability-matrix
    cargo test --locked --offline -p kapsel-sandbox --lib runner_host::tests -- \
      --include-ignored --test-threads=1
    cargo test --locked --offline -p kapsel-sandbox --test runner_handoff \
      production_runner_process -- --test-threads=1
    cargo test --locked --offline -p kapsel-sandbox --test runner_handoff \
      production_runner_preserves_unknown_receipt_and_separate_classifier_meaning -- \
      --exact --test-threads=1
    cargo test --locked --offline -p kapsel-sandbox --test runner_handoff \
      production_process_loss_matrix_converges_at_owned_handoff_seams -- \
      --exact --test-threads=1
    set -- $(find /target/debug/build -path "*/out/kapsel-sandbox-runner-pre-exec" -type f)
    test "$#" = 1
    helper=$1
    test -x /target/debug/kapsel-sandbox
    sha256sum crates/kapsel-sandbox/src/runner_pre_exec.c "$helper" \
      /target/debug/kapsel-sandbox >/target/runner-bundle-input-identities.sha256
    test "$(wc -l </target/runner-bundle-input-identities.sha256)" = 3
    cat /target/runner-bundle-input-identities.sha256
  '
