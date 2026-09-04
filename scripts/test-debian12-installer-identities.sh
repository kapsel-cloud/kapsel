#!/bin/sh
# Exercise the approved installer identity argv in a disposable Debian 12 x86-64 container.
set -eu

image='debian:12-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171'

docker run --rm --platform linux/amd64 -i "$image" sh -eu -s <<'CONTAINER'
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null
apt-get install -y --no-install-recommends sudo >/dev/null

transaction_id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

snapshot_etc() {
  find /etc -xdev -type f -exec sha256sum {} + | LC_ALL=C sort -k2 >"$1"
}

snapshot_logs() {
  : >"$1"
  for path in /var/log/lastlog /var/log/faillog; do
    if [ -f "$path" ]; then
      sha256sum "$path" >>"$1"
    fi
  done
}

changed_paths() {
  diff -U0 "$1" "$2" 2>/dev/null |
    sed -n 's/^[+-][0-9a-f][0-9a-f]*  \(\/.*\)$/\1/p' |
    LC_ALL=C sort -u
}

expect_changed_paths() {
  before=$1
  after=$2
  expected=$3
  actual=$(changed_paths "$before" "$after")
  if [ "$actual" != "$expected" ]; then
    printf 'unexpected changed paths between %s and %s:\n%s\n' "$before" "$after" "$actual" >&2
    exit 1
  fi
}

# Retain one byte beyond the contract limit as an over-limit sentinel. The raw observation stays
# in a file so command substitution cannot discard trailing newlines or merge records.
observe_bounded() {
  output=$1
  shift
  status_file="$output.status"
  rm -f "$output" "$status_file"

  set +e
  (
    set +e
    /usr/bin/timeout --signal=KILL 10s "$@" 2>/dev/null
    command_status=$?
    printf '%s\n' "$command_status" >"$status_file"
  ) | /usr/bin/head -c 4097 >"$output"
  collector_status=$?
  set -e

  query_class=ambiguous/partial
  query_status=unavailable
  [ "$collector_status" -eq 0 ] || return 0
  [ -f "$status_file" ] || return 0
  query_status=$(cat "$status_file")
  case "$query_status" in
    '' | *[!0-9]*) return 0 ;;
  esac
  query_bytes=$(wc -c <"$output")
  [ "$query_bytes" -le 4096 ] || return 0
  case "$query_status" in
    0) query_class=present ;;
    2) query_class=absent ;;
  esac
}

observe_nss() {
  output=$1
  database=$2
  key=$3
  observe_bounded "$output" /usr/bin/getent "$database" "$key"
}

expect_exact_line() {
  output=$1
  expected=$2
  expected_file="$output.expected"
  printf '%s\n' "$expected" >"$expected_file"
  cmp -s "$expected_file" "$output"
}

expect_group_complete() {
  name=$1
  gid=$2
  expected="$name:x:$gid:"
  observe_nss /tmp/group-by-name group "$name"
  [ "$query_class" = present ] && expect_exact_line /tmp/group-by-name "$expected"
  observe_nss /tmp/group-by-gid group "$gid"
  [ "$query_class" = present ] && expect_exact_line /tmp/group-by-gid "$expected"
}

expect_passwd_absent() {
  name=$1
  uid=$2
  observe_nss /tmp/passwd-by-name passwd "$name"
  [ "$query_class" = absent ] && [ ! -s /tmp/passwd-by-name ]
  observe_nss /tmp/passwd-by-uid passwd "$uid"
  [ "$query_class" = absent ] && [ ! -s /tmp/passwd-by-uid ]
  observe_nss /tmp/shadow-by-name shadow "$name"
  [ "$query_class" = absent ] && [ ! -s /tmp/shadow-by-name ]
}

classify_shadow_record() {
  output=$1
  expected_name=$2
  shadow_class=ambiguous/partial
  [ "$(wc -l <"$output")" -eq 1 ] || return 0
  if LC_ALL=C awk -F: -v expected_name="$expected_name" '
    NR != 1 || NF != 9 { exit 1 }
    $1 != expected_name || $2 != "!" || $3 !~ /^[0-9]+$/ { exit 1 }
    $4 != "" || $5 != "" || $6 != "" || $7 != "" || $8 != "" || $9 != "" { exit 1 }
    END { if (NR != 1) exit 1 }
  ' "$output"; then
    shadow_class=complete
  fi
}

expect_passwd_complete() {
  name=$1
  uid=$2
  gid=$3
  home=$4
  expected="$name:x:$uid:$gid:$transaction_id:$home:/usr/sbin/nologin"

  observe_nss /tmp/passwd-by-name passwd "$name"
  [ "$query_class" = present ] && expect_exact_line /tmp/passwd-by-name "$expected"
  observe_nss /tmp/passwd-by-uid passwd "$uid"
  [ "$query_class" = present ] && expect_exact_line /tmp/passwd-by-uid "$expected"
  observe_nss /tmp/shadow-by-name shadow "$name"
  [ "$query_class" = present ]
  classify_shadow_record /tmp/shadow-by-name "$name"
  [ "$shadow_class" = complete ]
  [ "$(passwd -S "$name" | awk '{print $2}')" = L ]
}

expect_ambiguous_without_identity_change() {
  label=$1
  shift
  snapshot_etc "/tmp/etc.before-$label"
  observe_bounded "/tmp/observation-$label" "$@"
  [ "$query_class" = ambiguous/partial ]
  snapshot_etc "/tmp/etc.after-$label"
  cmp -s "/tmp/etc.before-$label" "/tmp/etc.after-$label"
}

# Make ambient defaults hostile. Every resulting identity fact must still come from argv.
sed -i 's|^SHELL=.*|SHELL=/bin/bash|' /etc/default/useradd
sed -i 's|^HOME=.*|HOME=/tmp/hostile-useradd-home|' /etc/default/useradd
sed -i 's/^CREATE_HOME[[:space:]].*/CREATE_HOME yes/' /etc/login.defs
sed -i 's/^USERGROUPS_ENAB[[:space:]].*/USERGROUPS_ENAB yes/' /etc/login.defs

snapshot_etc /tmp/etc.0
snapshot_logs /tmp/logs.0

# Timeout, signal termination, and a 4,097th stdout byte are observation failures. They cannot
# mutate identity state or activate rollback.
expect_ambiguous_without_identity_change timeout /bin/sh -c 'sleep 30'
expect_ambiguous_without_identity_change signal /bin/sh -c 'kill -TERM "$$"'
expect_ambiguous_without_identity_change over-limit /usr/bin/head -c 4097 /dev/zero

printf 'kapsel:!:123::::::\nkapsel:!:123::::::\n' >/tmp/shadow-extra-record
classify_shadow_record /tmp/shadow-extra-record kapsel
[ "$shadow_class" = ambiguous/partial ]
printf 'kapsel:!:123::::::x\n' >/tmp/shadow-extra-byte
classify_shadow_record /tmp/shadow-extra-byte kapsel
[ "$shadow_class" = ambiguous/partial ]
printf 'kapsel:!:123x::::::\n' >/tmp/shadow-nondecimal-last-change
classify_shadow_record /tmp/shadow-nondecimal-last-change kapsel
[ "$shadow_class" = ambiguous/partial ]

/usr/bin/timeout --signal=KILL 10s /usr/sbin/groupadd --system --gid 999 kapsel
snapshot_etc /tmp/etc.1
snapshot_logs /tmp/logs.1
expect_changed_paths /tmp/etc.0 /tmp/etc.1 '/etc/group
/etc/group-
/etc/gshadow
/etc/gshadow-'
cmp -s /tmp/logs.0 /tmp/logs.1

/usr/bin/timeout --signal=KILL 10s /usr/sbin/groupadd --system --gid 998 kapsel-service-callers
snapshot_etc /tmp/etc.2
snapshot_logs /tmp/logs.2
expect_changed_paths /tmp/etc.1 /tmp/etc.2 '/etc/group
/etc/group-
/etc/gshadow
/etc/gshadow-'
cmp -s /tmp/logs.1 /tmp/logs.2

/usr/bin/timeout --signal=KILL 10s /usr/sbin/useradd \
  --system --uid 997 --gid 999 --no-create-home --home-dir /var/lib/kapsel \
  --shell /usr/sbin/nologin --comment "$transaction_id" --no-user-group \
  --no-log-init --password '!' kapsel
snapshot_etc /tmp/etc.3
snapshot_logs /tmp/logs.3
expect_changed_paths /tmp/etc.2 /tmp/etc.3 '/etc/passwd
/etc/passwd-
/etc/shadow
/etc/shadow-'
cmp -s /tmp/logs.2 /tmp/logs.3
expect_passwd_complete kapsel 997 999 /var/lib/kapsel
[ ! -e /var/lib/kapsel ]
expect_group_complete kapsel 999

# Duplicate name and duplicate UID are conflicts. Exit status is recorded but not used as
# evidence of no effect. Complete database observations below establish that neither altered state.
cp /tmp/etc.3 /tmp/etc.before-duplicates
set +e
/usr/bin/timeout --signal=KILL 10s /usr/sbin/useradd \
  --system --uid 995 --gid 999 --no-create-home --home-dir /var/lib/kapsel \
  --shell /usr/sbin/nologin --comment "$transaction_id" --no-user-group \
  --no-log-init --password '!' kapsel >/dev/null 2>&1
name_duplicate_status=$?
/usr/bin/timeout --signal=KILL 10s /usr/sbin/useradd \
  --system --uid 997 --gid 998 --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin --comment "$transaction_id" --no-user-group \
  --no-log-init --password '!' kapsel-duplicate-uid >/dev/null 2>&1
uid_duplicate_status=$?
set -e
snapshot_etc /tmp/etc.after-duplicates
cmp -s /tmp/etc.before-duplicates /tmp/etc.after-duplicates
expect_passwd_complete kapsel 997 999 /var/lib/kapsel
expect_passwd_absent kapsel-duplicate-uid 995

# Inject a pre-exec delay so timeout wins. Observation, not status 137, classifies exact absence.
set +e
/usr/bin/timeout --signal=KILL 1s /bin/sh -c '
  sleep 5
  exec /usr/sbin/useradd --system --uid 995 --gid 998 --no-create-home \
    --home-dir /nonexistent --shell /usr/sbin/nologin --comment "$1" \
    --no-user-group --no-log-init --password "!" kapsel-timeout
' injected "$transaction_id" >/dev/null 2>&1
timeout_status=$?
set -e
expect_passwd_absent kapsel-timeout 995

# Lose the parent after the exact mutation returns but before it can publish an observation.
/bin/sh -c '
  /usr/bin/timeout --signal=KILL 10s /usr/sbin/useradd \
    --system --uid 996 --gid 998 --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin --comment "$1" --no-user-group \
    --no-log-init --password "!" kapsel-service-caller
  kill -STOP $$
' process-loss "$transaction_id" &
parent=$!
for _ in $(seq 1 500); do
  state=$(ps -o stat= -p "$parent" 2>/dev/null || true)
  case "$state" in *T*) break ;; esac
  kill -0 "$parent" 2>/dev/null || break
  sleep 0.01
done
kill -KILL "$parent" 2>/dev/null || true
set +e
wait "$parent" 2>/dev/null
process_loss_status=$?
set -e
snapshot_etc /tmp/etc.4
snapshot_logs /tmp/logs.4
expect_changed_paths /tmp/etc.after-duplicates /tmp/etc.4 '/etc/passwd
/etc/passwd-
/etc/shadow
/etc/shadow-'
cmp -s /tmp/logs.3 /tmp/logs.4
expect_passwd_complete kapsel-service-caller 996 998 /nonexistent
[ ! -e /nonexistent ]
expect_group_complete kapsel-service-callers 998
[ "$(id -u kapsel-service-caller)" = 996 ]
[ "$(id -g kapsel-service-caller)" = 998 ]
[ "$(id -G kapsel-service-caller)" = 998 ]
[ "$(sudo -n -u kapsel-service-caller -g kapsel-service-callers -- id -u)" = 996 ]
[ "$(sudo -n -u kapsel-service-caller -g kapsel-service-callers -- id -g)" = 998 ]
[ "$(sudo -n -u kapsel-service-caller -g kapsel-service-callers -- id -G)" = 998 ]

# Inject one half of an account to make the partial class concrete. This is deliberately not
# repaired or removed. The whole container is the disposable-host boundary.
printf '%s\n' \
  "kapsel-partial:x:994:998:$transaction_id:/nonexistent:/usr/sbin/nologin" >>/etc/passwd
observe_nss /tmp/partial-passwd passwd kapsel-partial
[ "$query_class" = present ]
expect_exact_line /tmp/partial-passwd \
  "kapsel-partial:x:994:998:$transaction_id:/nonexistent:/usr/sbin/nologin"
observe_nss /tmp/partial-shadow shadow kapsel-partial
[ "$query_class" = absent ] && [ ! -s /tmp/partial-shadow ]

printf 'platform=%s os=%s image=%s\n' "$(uname -m)" "$(. /etc/os-release; printf '%s' "$PRETTY_NAME")" \
  'debian:12-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171'
printf 'packages passwd=%s libc-bin=%s sudo=%s\n' \
  "$(dpkg-query -W -f='${Version}' passwd)" \
  "$(dpkg-query -W -f='${Version}' libc-bin)" \
  "$(dpkg-query -W -f='${Version}' sudo)"
printf 'success=exactly-complete duplicate-name=conflict(status=%s) duplicate-uid=conflict(status=%s)\n' \
  "$name_duplicate_status" "$uid_duplicate_status"
printf 'timeout=exactly-absent(status=%s) process-loss=exactly-complete(status=%s) injected=ambiguous/partial\n' \
  "$timeout_status" "$process_loss_status"
printf 'bounded-observation timeout=ambiguous/partial signal=ambiguous/partial over-limit=ambiguous/partial limit=4096 deadline=10s\n'
printf 'shadow-rejection extra-record=ambiguous/partial extra-byte=ambiguous/partial nondecimal-last-change=ambiguous/partial\n'
printf 'groupadd-touched=/etc/group,/etc/group-,/etc/gshadow,/etc/gshadow-\n'
printf 'useradd-touched=/etc/passwd,/etc/passwd-,/etc/shadow,/etc/shadow-\n'
printf 'useradd-unchanged=/etc/group,/etc/group-,/etc/gshadow,/etc/gshadow-,/etc/subuid,/etc/subgid,/var/log/lastlog,/var/log/faillog\n'
printf 'caller=uid:996 primary-gid:998 supplementary-members:empty sudo-effective-gid:998\n'
CONTAINER
