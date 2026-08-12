#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
  echo "fixed staging identity lane requires Linux" >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "fixed staging identity lane requires root" >&2
  exit 2
fi
for command in cc unshare python3 sha256sum; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 2
  }
done

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"
export CARGO_NET_OFFLINE=true
temporary="$(mktemp -d /tmp/kapsel-fixed-staging-identities.XXXXXX)"
cleanup() {
  chmod -R u+rwX "$temporary" 2>/dev/null || true
  rm -rf "$temporary"
}
trap cleanup EXIT
chmod 0755 "$temporary"

launcher="$temporary/fixed-staging-identity-exec"
cc -std=c11 -Wall -Wextra -Werror -O2 \
  scripts/fixed-staging-identity-exec.c -o "$launcher"

cargo build --locked --offline --release -p kapsel-sandbox
production_binary="$repository_root/target/release/kapsel-sandbox"
[[ -x "$production_binary" ]] || {
  echo "could not locate kapsel-sandbox production binary" >&2
  exit 2
}
if ! cargo test --locked --offline -p kapsel-sandbox --lib --no-run --message-format=json \
  >"$temporary/cargo-messages.jsonl"; then
  cargo test --locked --offline -p kapsel-sandbox --lib --no-run
  exit 1
fi
test_binary="$(python3 - "$temporary/cargo-messages.jsonl" <<'PY'
import json
import sys
for line in open(sys.argv[1], encoding="utf-8"):
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        continue
    target = message.get("target", {})
    if message.get("reason") == "compiler-artifact" and "lib" in target.get("kind", []):
        executable = message.get("executable")
        if executable:
            print(executable)
            break
PY
)"
[[ -n "$test_binary" && -x "$test_binary" ]] || {
  echo "could not locate kapsel-sandbox library test binary" >&2
  exit 2
}

controller_uid=65530
controller_gid=65530
staging_uid=65531
staging_gid=65531
root="$temporary/authority"
mkdir -m 0700 "$root"
mkdir -m 0700 "$root/incoming" "$root/generations" "$root/dispatch"
chown "$controller_uid:$controller_gid" "$root" "$root/generations" "$root/dispatch"
chown "$staging_uid:$staging_gid" "$root/incoming"

test_name="fixed_staging::tests::production_distinct_identity_installs_and_reads"
common_environment=(
  "KAPSEL_STAGING_TEST_ROOT=$root"
  "KAPSEL_CONTROLLER_UID=$controller_uid"
  "KAPSEL_CONTROLLER_GID=$controller_gid"
  "KAPSEL_STAGING_UID=$staging_uid"
  "KAPSEL_STAGING_GID=$staging_gid"
)

unshare --net env "${common_environment[@]}" KAPSEL_STAGING_TEST_ROLE=prepare \
  "$launcher" "$staging_uid" "$staging_gid" 1 \
  "$test_binary" --exact "$test_name" --ignored --nocapture
unshare --net "$launcher" "$staging_uid" "$staging_gid" 1 \
  "$production_binary" stage-authority \
  --authority-root "$root" \
  --controller-uid "$controller_uid" --controller-gid "$controller_gid" \
  --staging-uid "$staging_uid" --staging-gid "$staging_gid"
unshare --net env "${common_environment[@]}" KAPSEL_STAGING_TEST_ROLE=reader \
  "$launcher" "$controller_uid" "$controller_gid" 0 \
  "$test_binary" --exact "$test_name" --ignored --nocapture
state_parent="$temporary/controller-state-parent"
state="$state_parent/state"
mkdir -m 0700 "$state_parent"
touch "$state_parent/.kapsel-sandbox-state.lock"
chmod 0600 "$state_parent/.kapsel-sandbox-state.lock"
chown -R "$controller_uid:$controller_gid" "$state_parent"
if unshare --net "$launcher" "$controller_uid" "$controller_gid" 0 \
  "$production_binary" init \
  --state-root "$state" \
  --authority-root "$root" \
  --controller-uid 65529 --controller-gid "$controller_gid" \
  --staging-uid "$staging_uid" --staging-gid "$staging_gid"; then
  echo "production init unexpectedly accepted a non-fixed controller identity" >&2
  exit 1
fi
unshare --net "$launcher" "$controller_uid" "$controller_gid" 0 \
  "$production_binary" init \
  --state-root "$state" \
  --authority-root "$root" \
  --controller-uid "$controller_uid" --controller-gid "$controller_gid" \
  --staging-uid "$staging_uid" --staging-gid "$staging_gid"
python3 - "$state/deployment.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="ascii") as source:
    deployment = json.load(source)
if deployment["target"] != "x86_64-linux":
    raise SystemExit("production deployment did not record x86_64-linux")
PY
chown "$staging_uid:$staging_gid" "$state/readiness.json"
if unshare --net "$launcher" "$controller_uid" "$controller_gid" 0 \
  "$production_binary" stop --state-root "$state"; then
  echo "production stop unexpectedly accepted wrong readiness ownership" >&2
  exit 1
fi
chown "$controller_uid:$controller_gid" "$state/readiness.json"

negative_root="$temporary/authority-without-installer-caps"
mkdir -m 0700 "$negative_root"
mkdir -m 0700 "$negative_root/incoming" "$negative_root/generations" "$negative_root/dispatch"
chown "$controller_uid:$controller_gid" "$negative_root" "$negative_root/generations" "$negative_root/dispatch"
chown "$staging_uid:$staging_gid" "$negative_root/incoming"
unshare --net env \
  "KAPSEL_STAGING_TEST_ROOT=$negative_root" \
  "KAPSEL_CONTROLLER_UID=$controller_uid" \
  "KAPSEL_CONTROLLER_GID=$controller_gid" \
  "KAPSEL_STAGING_UID=$staging_uid" \
  "KAPSEL_STAGING_GID=$staging_gid" \
  KAPSEL_STAGING_TEST_ROLE=prepare \
  "$launcher" "$staging_uid" "$staging_gid" 1 \
  "$test_binary" --exact "$test_name" --ignored --nocapture
if unshare --net "$launcher" "$staging_uid" "$staging_gid" 0 \
  "$production_binary" stage-authority \
  --authority-root "$negative_root" \
  --controller-uid "$controller_uid" --controller-gid "$controller_gid" \
  --staging-uid "$staging_uid" --staging-gid "$staging_gid"; then
  echo "installer unexpectedly succeeded without its bounded capabilities" >&2
  exit 1
fi

sha256sum scripts/fixed-staging-identity-exec.c "$launcher"
echo "network namespace: isolated (--net), no configured endpoint or traffic"
echo "controller identity: $controller_uid:$controller_gid"
echo "staging identity: $staging_uid:$staging_gid"
echo "fixed staging distinct-identity lane passed"
