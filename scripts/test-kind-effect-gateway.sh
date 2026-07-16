#!/usr/bin/env bash
set -euo pipefail

cluster_name="kapsel-kap0038-test-$$-${RANDOM}"
node_image="kindest/node:v1.33.12@sha256:3f5c8443c620245e4d355cfe09e96a91ead32ceaa569d3f1ca9edf0cb2fe2ff4"
fixture_image="registry.k8s.io/pause:3.10.1"
target_image="registry.k8s.io/pause@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
log_directory="${TMPDIR:-/tmp}/kapsel-kind-logs-$$"
cluster_owned=0

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ $status -ne 0 && $cluster_owned -eq 1 ]]; then
    mkdir -p "$log_directory"
    if kind export logs "$log_directory" --name "$cluster_name"; then
      printf 'kind failure logs: %s\n' "$log_directory" >&2
    else
      printf 'could not export kind failure logs: %s\n' "$log_directory" >&2
    fi
  fi
  if [[ $cluster_owned -eq 1 ]] && ! kind delete cluster --name "$cluster_name"; then
    printf 'could not delete owned kind cluster: %s\n' "$cluster_name" >&2
    if [[ $status -eq 0 ]]; then
      status=1
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker info >/dev/null
kind_version=$(kind version)
if [[ ! $kind_version =~ ^kind\ v([0-9]+)\.([0-9]+)\.([0-9]+)([[:space:]]|$) ]]; then
  printf 'cannot parse kind version: %s\n' "$kind_version" >&2
  exit 1
fi
kind_major=${BASH_REMATCH[1]}
kind_minor=${BASH_REMATCH[2]}
if ((kind_major == 0 && kind_minor < 32)); then
  printf 'kind 0.32 or newer is required; found: %s\n' "$kind_version" >&2
  exit 1
fi
if ! existing_clusters=$(kind get clusters); then
  printf 'could not enumerate kind clusters; refusing to create one\n' >&2
  exit 1
fi
if grep -Fqx "$cluster_name" <<<"$existing_clusters"; then
  printf 'refusing to use existing kind cluster: %s\n' "$cluster_name" >&2
  exit 1
fi
cargo test --locked -p kapsel --no-run
cluster_owned=1
kind create cluster \
  --name "$cluster_name" \
  --image "$node_image" \
  --wait 120s

docker exec "${cluster_name}-control-plane" crictl pull "$fixture_image"
docker exec "${cluster_name}-control-plane" crictl pull "$target_image"

KAPSEL_KIND_TEST=1 cargo test --locked \
  -p kapsel \
  kind_tests::kind_changes_exactly_one_container_through_the_gateway \
  -- \
  --ignored \
  --exact \
  --nocapture

KAPSEL_KIND_TEST=1 cargo test --locked \
  -p kapsel \
  kind_tests::kind_failed_rollout_recovers_and_inspects_classifier_complete_receipt \
  -- \
  --ignored \
  --exact \
  --nocapture
