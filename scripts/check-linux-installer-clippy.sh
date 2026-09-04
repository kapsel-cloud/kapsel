#!/bin/sh
set -eu

builder_image='rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922'
repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

command -v docker >/dev/null 2>&1 || {
  printf '%s\n' 'Docker is required to lint the Linux-only installer on this host.' >&2
  exit 1
}
docker info >/dev/null

printf '%s\n' '==> Linux installer clippy'
docker run --rm \
  --platform linux/amd64 \
  --volume "$repository:/workspace:ro" \
  --volume kapsel-linux-clippy-rustup:/usr/local/rustup \
  --volume kapsel-linux-clippy-registry:/usr/local/cargo/registry \
  --volume kapsel-linux-clippy-target:/target \
  --workdir /workspace \
  --env CARGO_TARGET_DIR=/target \
  "$builder_image" \
  cargo clippy --locked -p kapsel-installer --all-targets --all-features -- -D warnings
