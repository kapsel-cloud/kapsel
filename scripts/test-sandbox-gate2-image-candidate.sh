#!/bin/sh
set -eu

readonly image='kapsel-sandbox:gate2-amd64-candidate-test'
readonly source_revision='86680191767c550a84a9fca872a928198ec8112e'
readonly builder='rust@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663'
readonly runtime='gcr.io/distroless/cc-debian12@sha256:471dbca9cad607b9a32c10e9c31fb09ffaeb2d460e0afbff86c27abbc80b1b98'
readonly certificate_oidc_issuer='https://accounts.google.com'
readonly certificate_identity='keyless@distroless.iam.gserviceaccount.com'
readonly maximum_size_bytes=67108864
readonly expected_usage='kapsel-sandbox: usage: kapsel-sandbox <init|serve> --database <absolute-path> --receipts <absolute-directory> --digest-key-file <absolute-path> [--origin <https-origin>] [--listen <socket-address>]; or kapsel-sandbox <stop|clear-stop> --database <absolute-path>'

for command_name in docker cosign trivy python3; do
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

if ! git cat-file -e "$source_revision^{commit}"; then
  printf '%s\n' "missing candidate source revision: $source_revision" >&2
  exit 2
fi
mkdir "$work_directory/source"
git archive "$source_revision" | tar -x -C "$work_directory/source"
containerfile="$work_directory/source/deploy/sandbox/Containerfile.gate2-candidate"
if ! grep -Fqx "FROM $builder AS builder" "$containerfile" ||
  ! grep -Fqx "FROM $runtime" "$containerfile"; then
  printf '%s\n' 'candidate source does not contain the locked builder and runtime' >&2
  exit 1
fi

cosign verify \
  "$runtime" \
  --certificate-oidc-issuer "$certificate_oidc_issuer" \
  --certificate-identity "$certificate_identity" \
  >"$work_directory/cosign.json"

docker build \
  --pull=false \
  --platform linux/amd64 \
  -f "$containerfile" \
  -t "$image" \
  "$work_directory/source"

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
cosign_version=$(cosign version 2>/dev/null | awk '/GitVersion:/ { sub(/^v/, "", $2); print $2 }')
trivy_metadata=$(trivy version --format json)
trivy_version=$(printf '%s' "$trivy_metadata" | python3 -c 'import json, sys; print(json.load(sys.stdin)["Version"])')
trivy_database_updated_at=$(printf '%s' "$trivy_metadata" | python3 -c 'import json, sys; print(json.load(sys.stdin)["VulnerabilityDB"]["UpdatedAt"])')
python3 - \
  "$source_revision" "$builder" "$runtime" "$image_id" "$platform" "$size_bytes" \
  "$cosign_version" "$certificate_oidc_issuer" "$certificate_identity" \
  "$trivy_version" "$trivy_database_updated_at" <<'PY'
import datetime
import json
import sys

(
    source_revision,
    builder,
    runtime,
    image_id,
    platform,
    size_bytes,
    cosign_version,
    certificate_oidc_issuer,
    certificate_identity,
    trivy_version,
    trivy_database_updated_at,
) = sys.argv[1:]
evidence = json.load(open("deploy/sandbox/gate2-image-candidate.json", encoding="utf-8"))
assert evidence["source_revision"] == source_revision
assert evidence["builder_image"] == builder
assert evidence["runtime_image"] == runtime
assert evidence["runtime_signature"]["status"] == "verified"
assert evidence["runtime_signature"]["cosign_version"] == cosign_version
assert evidence["runtime_signature"]["certificate_oidc_issuer"] == certificate_oidc_issuer
assert evidence["runtime_signature"]["certificate_identity"] == certificate_identity
assert evidence["local_image"]["image_id"] == image_id
assert evidence["local_image"]["platform"] == platform
assert evidence["local_image"]["size_bytes"] == int(size_bytes)
assert evidence["local_image"]["maximum_size_bytes"] == 67_108_864
assert evidence["vulnerability_scan"]["scanner_version"] == trivy_version
assert evidence["vulnerability_scan"]["detected_high"] == 0
assert evidence["vulnerability_scan"]["detected_critical"] == 0
minimum_database_updated_at = datetime.datetime.fromisoformat(
    evidence["vulnerability_scan"]["minimum_database_updated_at"].replace("Z", "+00:00")
)
actual_database_updated_at = datetime.datetime.fromisoformat(
    trivy_database_updated_at.replace("Z", "+00:00")
)
assert actual_database_updated_at >= minimum_database_updated_at
PY
printf '%s\n' \
  "candidate_image_id=$image_id" \
  "candidate_image_platform=$platform" \
  "candidate_image_size_bytes=$size_bytes" \
  "candidate_runtime_signature=verified" \
  "candidate_high_critical_vulnerabilities=0"
