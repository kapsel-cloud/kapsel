#!/bin/sh
set -eu

readonly image='kapsel-sandbox:gate2-amd64-candidate-test'
readonly runtime='gcr.io/distroless/cc-debian12@sha256:471dbca9cad607b9a32c10e9c31fb09ffaeb2d460e0afbff86c27abbc80b1b98'
readonly maximum_size_bytes=67108864
readonly expected_usage='kapsel-sandbox: usage: kapsel-sandbox <init|serve> --database <absolute-path> --receipts <absolute-directory> --digest-key-file <absolute-path> [--origin <https-origin>] [--listen <socket-address>]; or kapsel-sandbox <stop|clear-stop> --database <absolute-path>'

for command_name in docker cosign trivy; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf '%s\n' "missing required command: $command_name" >&2
    exit 2
  fi
done

if ! docker info >/dev/null 2>&1; then
  printf '%s\n' 'Docker is unavailable.' >&2
  exit 2
fi

work_directory=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-gate2-image.XXXXXX")
cleanup() {
  docker image rm "$image" >/dev/null 2>&1 || true
  rm -rf "$work_directory"
}
trap cleanup EXIT HUP INT TERM

cosign verify \
  "$runtime" \
  --certificate-oidc-issuer https://accounts.google.com \
  --certificate-identity keyless@distroless.iam.gserviceaccount.com \
  >"$work_directory/cosign.json"

docker build \
  --pull=false \
  --platform linux/amd64 \
  -f deploy/sandbox/Containerfile.gate2-candidate \
  -t "$image" \
  .

platform=$(docker image inspect "$image" --format '{{.Os}}/{{.Architecture}}')
if [ "$platform" != 'linux/amd64' ]; then
  printf '%s\n' "unexpected image platform: $platform" >&2
  exit 1
fi

size_bytes=$(docker image inspect "$image" --format '{{.Size}}')
if [ "$size_bytes" -gt "$maximum_size_bytes" ]; then
  printf '%s\n' "image exceeds $maximum_size_bytes bytes: $size_bytes" >&2
  exit 1
fi

set +e
docker run --rm --platform linux/amd64 "$image" \
  >"$work_directory/stdout" 2>"$work_directory/stderr"
run_status=$?
set -e
if [ "$run_status" -ne 2 ] || [ -s "$work_directory/stdout" ]; then
  printf '%s\n' "unexpected no-argument result: status=$run_status" >&2
  exit 1
fi
if [ "$(cat "$work_directory/stderr")" != "$expected_usage" ]; then
  printf '%s\n' 'unexpected no-argument diagnostic' >&2
  exit 1
fi

trivy image \
  --exit-code 1 \
  --severity HIGH,CRITICAL \
  --scanners vuln \
  --quiet \
  "$image"

image_id=$(docker image inspect "$image" --format '{{.Id}}')
printf '%s\n' \
  "candidate_image_id=$image_id" \
  "candidate_image_platform=$platform" \
  "candidate_image_size_bytes=$size_bytes" \
  "candidate_runtime_signature=verified" \
  "candidate_high_critical_vulnerabilities=0"
