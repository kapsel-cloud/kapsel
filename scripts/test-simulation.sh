#!/usr/bin/env sh
set -eu

log_directory=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-simulation-logs.XXXXXX")
trap 'rm -rf "$log_directory"' EXIT HUP INT TERM
cargo test --release --locked -p kapsel --lib --no-run
pids=""
for shard in 0 1 2 3 4 5 6 7; do
  KAPSEL_SIMULATION_SHARDS=8 KAPSEL_SIMULATION_SHARD_INDEX=$shard \
    cargo test --release --locked -p kapsel --lib \
      simulation_tests::seeded_lifecycle_crash_simulation_preserves_invariants -- \
      --ignored --exact --nocapture >"$log_directory/$shard.log" 2>&1 &
  pids="$pids $!"
done
status=0
for pid in $pids; do
  if ! wait "$pid"; then
    status=1
  fi
done
for shard in 0 1 2 3 4 5 6 7; do
  cat "$log_directory/$shard.log"
done
exit "$status"
