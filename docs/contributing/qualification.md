# Qualification commands

Use these lanes when a change needs evidence beyond the everyday deterministic gate. Run commands
from the checkout root after [contributor setup](build.md#prepare-contributor-tools). Each section
states its additional prerequisites and environment ownership. [Testing](testing.md) explains
evidence classes. The [evidence map](evidence.md) connects guarantees to maintained checks.

## Choose a lane

- Service startup or runtime: [Linux process tests](#kapsel-service-candidate).
- Receiver rules: [Kubernetes](#live-kubernetes-gate) or [Git](#git-transition-service).
- Storage: [accepted layouts](#accepted-journal-layouts),
  [ENOSPC](#bounded-storage-failure-qualification), and
  [version rejection](#journal-version-rejection).
- Hostile input and lifecycle exploration: [robustness](#robustness-lanes).
- Release candidate: [source scan](#source-privacy-and-security), [artifact](#release-artifact), and
  [packaged receiver workflow](#packaged-service-live-workflow), under the
  [release process](release_process.md).

A source, container, live-receiver, and native-installation pass establish different facts. Preserve
those distinctions when recording results. Do not run a privileged lane against existing resources.

## Contributor tooling details

### Python type checking

[`pyrightconfig.json`](../../pyrightconfig.json) selects Python 3.11, standard checking, and script
directory import roots. The static gate runs the pinned Pyright on Linux and macOS targets,
independent of the host interpreter. `tools/checks/check_source_privacy.py` uses strict checking.
The checked scope includes source checks, release tooling and fixtures, developer tooling, the
maintained fresh-session caller and its tests, and the selected Git and Kubernetes qualification
runners and their extracted fixtures. Other qualification lanes are not yet in the checked scope.

Extracted journey programs remain standalone source. Runners stream their bytes into disposable
containers rather than importing repository modules there. The Git and Kubernetes runners retain the
exact executed source and its digest with their private qualification evidence. The distributed
release verifier remains independent of repository imports and retains its 64-KiB limit.

## Fresh-session caller checks

To run the caller fixture against the real MCP bridge and a scripted socket (not Kubernetes), build
the test-harness binary first:

```sh
cargo build --locked -p kapsel-daemon --features test-harness --bin kapsel-service-mcp
cargo build --locked --bin kapsel
env KAPSEL_TEST_BRIDGE="$PWD/target/debug/kapsel-service-mcp" \
  KAPSEL_TEST_INSPECT="$PWD/target/debug/kapsel" \
  python3 examples/test_fresh_session_caller.py
```

## Live Kubernetes gate

Requires Docker, kind 0.32+, kubectl 1.30+, Python 3.11+, and OpenSSL:

```sh
./tests/qualification/run-kind-effect-gateway.sh
```

The script creates and removes its own uniquely named cluster and exports failure logs. It records
the base revision and working-tree diff digest, and refuses untracked files that cannot be included
in that evidence. This lane is separate from deterministic CI. See
[Live Kubernetes and demonstration](evidence.md#live-kubernetes-and-demonstration) for the gateway,
strategic-patch admission, exact-snapshot and service observation cases.

## Packaged-service live workflow

Use this lane to check production binaries against a real Kubernetes receiver, including caller
loss, service loss and same-ID recovery. The model-driven healthy action is an optional addition.

1. Prepare Docker, kind 0.32+, kubectl 1.30+ and Python 3.11+.
2. Select an exact accepted clean release archive, matching sidecars and source revision. Set
   `archive` and `revision` to those identities.
3. Run the scripted workflow below, or add the [model lane](#model-driven-healthy-action).
4. Check the retained results against [expected evidence](#packaged-workflow-evidence).
5. Check [cleanup and retained private state](#packaged-workflow-cleanup), including on failure.

This is a privileged **disposable test environment**, not permission to use an existing cluster:

```sh
python3 tests/qualification/run_kind_agent_action_workflow.py \
  --archive "$archive" --revision "$revision"
```

### Packaged workflow evidence

The runner creates one uniquely named, pinned kind cluster and an isolated Linux service container.
It transfers only extracted production binaries, their public key-generation procedure and scoped
fixture authority into the operating environment. It never builds a test-feature binary or uses a
private product pause hook. Distinct operator/service/caller identities own preparation, execution
and selection. The caller selects approved IDs from one catalog, with no per-action configuration
switching. The fixture operator owns the disposable Deployments' desired state. No existing
reconciler is disabled.

The cases cover a healthy action, deliberately stale snapshot, service SIGKILL after the live image
change followed by explicit same-ID resumption, and caller loss before acknowledgement during a
rollout that exceeds the observation window. Independent B remains selectable after A's frozen
`UNKNOWN`. A conflicting follow-on ID was never provisioned and must remain unavailable to a hostile
caller before and after cold replacement. The service-loss case also kills the service after
terminal status but before the caller's first receipt export. It compares independently read
format-6 grant/receipt/signer bytes through cold signing-key rotation, original-byte export and
repeated same-ID selection. Original receipts remain retrievable after catalog withdrawal.
API-server audit independently counts product PATCH requests, excluding explicitly identified
fixture writes used to prepare the faults.

The runner probes private-file and executable custody under the caller identity before submission.
Private fixture credentials and evidence are copied into container-owned directories, not exposed
through host bind mounts whose permission behavior can differ across Docker environments. The
extracted public artifact is the only host bind. These probes are finite process-level evidence, not
a general host-security certification.

### Model-driven healthy action

Supply an independently accepted Linux x86-64 Codex 0.155.1 executable, its matching
`codex-code-mode-host` sibling, and existing model authentication. The runner does not install or
update Codex. The default scripted lane requires no model account or call.

Read the custody and supervision requirements below before running the model lane.

The optional lane copies only the model's `~/.codex/auth.json` into a private caller-owned directory
inside the disposable container. An operator can select another private model-auth file with
`--codex-auth`. No host home directory, agent configuration, Kubernetes authority or Docker socket
is exposed to the model. The source auth file must be private, owned, regular and single-link. It is
not modified or synchronized back. The container copy is removed after the call, and container
cleanup removes any remaining local model state.

Codex runs as UID 61001, distinct from both root preparation and the Kapsel service identity. It
uses the packaged `/usr/bin/kapsel-service-mcp` through its caller-owned Codex configuration to list
actual approvals, submit the existing `healthy` ID, read status and retrieve the receipt. The
independent driver still uses the fixed service client to verify the retained action. Before
starting Codex, the runner must pass the caller's OS custody probes. Codex's inner approval prompts
and sandbox are explicitly bypassed **only inside this externally isolated disposable caller**. The
container's `no-new-privileges`, absent private host mounts and OS identities are the boundary, not
prompt advice or confirmation dialogs. Never copy that bypass flag into a host or operator
invocation.

The agent container has a 4 GiB memory ceiling. The driver waits up to 120 seconds for Codex, then
requires all remaining caller-UID processes to retire before checking evidence or starting scripted
cases. Killing the host `docker exec` process alone is not sufficient. Only the explicit disposable
caller configuration is loaded, with the fixed MCP command and no host user settings. Exec-policy
rules are not loaded, and session persistence is disabled. This tests specific product custody
boundaries, not comprehensive hostile-code containment. The model can read its own model
authentication and has network access.

Run with the same accepted artifact identity:

```sh
python3 tests/qualification/run_kind_agent_action_workflow.py \
  --archive "$archive" --revision "$revision" \
  --agent --codex-binary /absolute/path/to/verified/codex
```

The driver checks product state independently of model prose and refuses success if another fixture
action was admitted. Status comes from the installed native client with its fixed socket. Python
supervision and receipt readers use isolated mode to exclude model-writable imports. The driver
snapshots two bounded, regular, non-symlink independent client exports and compares the original
bytes and digest. It does not treat the model's prose as receipt proof. It records CLI identity,
both executable digests and token usage, not raw model sessions. There is no provider SDK, agent
framework or new product command.

This is one model-driven healthy action. The remaining fault and recovery cases are deterministic
caller programs, not model-driven troubleshooting or evidence of useful action selection. Neither
mode qualifies native systemd installation, application quality, publication, or a cumulative
observation deadline across interruptions.

### Packaged workflow cleanup

The printed private workspace retains result summaries, bounded output, and fixture inputs. It also
contains a cluster-admin kubeconfig and an expiring scoped token. **Do not publish that directory.**
The runner removes its container and cluster. If cleanup fails, inspect those named resources. Do
not run broad Docker or kind cleanup. The native example separately retains its stopped host state.

## Receiver-recovery regressions

These eight deterministic Kapsel scenarios need only the repository Rust toolchain, not Docker or
credentials. Run the complete matrix without a reduced-case selection:

```sh
unset KAPSEL_RECEIVER_ONLY
cargo test --locked -p kapsel --lib gateway::receiver_recovery_tests -- --nocapture
```

For a reduced pre-send replay:

```sh
KAPSEL_RECEIVER_ONLY=pre-send cargo test --locked -p kapsel --lib \
  gateway::receiver_recovery_tests::receiver_recovery_scenarios -- --exact --nocapture
```

Kapsel runs against an independent HTTP service fixture with exact PATCH assertions, real process
exits and frozen-evidence reconnect checks. The full matrix is included in the default gate. These
regressions check current Kapsel behavior. They do not show equivalence with another tool.

### Initial observation policy

The live gate also runs `kind_tests::observation_experiment::kind_service_observation_policy`. It
creates two healthy original Deployments with 60- and 210-second minimum readiness periods, then
selects exact approvals through `ServiceApplication`. It exercises an interrupted observation and
explicit same-ID resumption, reconnects stored reads while the worker survives, verifies B is
`BUSY`, and preserves the frozen `UNKNOWN` after the slower rollout eventually becomes available.
API-server audit independently counts PATCHes and execution-window GETs. The log records readiness,
elapsed time, worker occupancy and stored-read latency. This is the actual service application with
a live receiver, not installed-socket or native-host qualification. Linux process tests separately
own socket and process-loss evidence.

Focused deterministic observation checks:

```sh
cargo test --locked -p kapsel gateway::kubernetes
cargo test --locked -p kapsel --test application_retry observation_pass
cargo test --locked -p kapsel --lib gateway::receiver_recovery_tests::receiver_recovery_scenarios
```

Paused-clock tests distinguish the read ceiling (180 instantaneous reads over 179 one-second waits)
from the elapsed ceiling (180 seconds including stalled reads). Real I/O can exhaust elapsed time
before all reads occur. Per-pass bounds do not promise a cumulative ceiling across interrupted
explicit resumptions. The [gateway contract](../reference/kubernetes_effect.md#result-meaning)
defines that policy.

## Git transition service

The Git lane requires an explicitly selected Git 2.55.0. Receiver fixtures copy it into private
custody rather than discovering it through ambient PATH. Run the core recovery matrix on macOS or
Linux:

```sh
(umask 077; KAPSEL_TEST_GIT=/absolute/path/to/git \
  cargo test --locked -p kapsel --lib gateway::git::tests -- --include-ignored --test-threads=1)
```

On Linux, exercise real service-process loss and the maintained caller through the fixed-root test
harness, without installation or a live repository:

```sh
cargo build --locked -p kapsel --bin kapsel
cargo build --locked -p kapsel-daemon --features test-harness
python3 tests/qualification/run_git_service.py --git /absolute/path/to/git
```

For the production-artifact journey, use an exact accepted clean archive and an independently
accepted Linux Git 2.55.0 executable compatible with the pinned Debian 12 runner:

```sh
python3 tests/qualification/run_git_artifact.py \
  --archive "$archive" --revision "$revision" --git /absolute/path/to/git
```

This lane creates one isolated, network-disabled container per case. Only extracted production
binaries and the selected Git executable enter the operating environment. Separate service and
caller identities enforce private-material custody. Receiver hooks supply acknowledgement-loss and
service-crash windows without a product test hook. The cases check exact ref and hook inputs,
observation-only same-ID recovery, original receipt retrieval after catalog/material withdrawal, and
detached inspection. Hook inputs are not packet counts or proof of complete hook delivery. The
runner removes the containers and retains the printed private evidence workspace. This is not native
systemd, power-loss, or live-repository qualification. Current-release restart/reconnect evidence is
required. A prior-artifact replacement matrix is not a release gate.

See the [Git service example](../guides/git_transition.md) for material, semantics and evidence
limits. Run `cargo xtask ci` as the deterministic gate. Service startup or protocol composition
changes also require the Linux process gate below.

## Kapsel service candidate

The focused package command above includes the service's private harness. On Linux, run the process
tests:

```sh
cargo test --locked -p kapsel-daemon --features test-harness --test linux_process
```

For the fresh-session caller's retained-identity delta, run the real Linux bridge/service fixture
with independent HTTP mutation counting and detached CLI inspection (no Kubernetes cluster):

```sh
cargo build --locked --bin kapsel
KAPSEL_TEST_INSPECT="$PWD/target/debug/kapsel" \
  cargo test --locked -p kapsel-daemon --features test-harness --test linux_process \
  mcp_bridge_loss_at_admission_and_completion_retains_one_receiver_mutation -- --exact
```

With `sg`, Python 3 and an existing `docker` group that the test user may activate through `sg`,
include the ignored distinct-effective-group case. The group must differ from the server's effective
GID. In a disposable root-owned test container, provision that fixture group inside the container,
not on the development host. The test uses only the group identity, not Docker daemon access:

```sh
cargo test --locked -p kapsel-daemon --features test-harness --test linux_process \
  distinct_effective_gid_is_denied_before_frame_read -- --ignored --exact
```

Cold publication validation also runs at the shared application owner:

```sh
cargo test --locked -p kapsel --test service_application_contract cold_validation
cargo test --locked -p kapsel-daemon --features test-harness
```

Linux startup/publication tests cover private lock custody, owned temporary cleanup and publication
fault outcomes. Per-instance barriers cover startup termination, blocked storage retirement,
receiver waiting and lifecycle contention. Process tests preserve original history/receipt bytes
through catalog and key removal. These are deterministic source/process checks, not disk-full,
power-loss, native-host or live-Kubernetes qualification. Never mutate source during a
read-only-mounted container gate, and archive untracked source files alongside its diff.

See [Kapsel service](../reference/service.md) for the current boundary and
[service testing](evidence.md#kapsel-service) for evidence coverage.

## Accepted journal layouts

Run the shared writable/read-only physical-layout regressions and retained-charge arithmetic:

```sh
cargo test --locked -p kapsel --lib gateway::tests::capacity_layout
cargo test --locked -p kapsel --lib gateway::journal::capacity
```

These use bundled SQLite records, long retained keys, padded schema SQL and bounded sparse-tree
fixtures to check [completion accounting](../reference/storage.md#completion-accounting). They prove
encoded-payload rejection and legitimate completion/reopen, not transient-allocation peaks,
filesystem reservation, ENOSPC, power-loss or native/live qualification. The owning broader gate is
`cargo test --locked -p kapsel`.

## Bounded storage failure qualification

The normal package gate includes source-named SQLite write-plan checks, rollback-record accounting,
concurrent admission at 31 unfinished identities, and three full-capacity receipt tests, one per
insertion order. Each covers all three pending phases, retaining nine combinations. Closed,
production-generated baseline histories are copied into isolated cases rather than rebuilding
unchanged completed operations. The cases use maximal legal fields and valid fragmented freelists at
16,384 pages, and compare all retained rows without repeatedly verifying unchanged signatures.
Focused commands:

```sh
cargo test --locked -p kapsel --lib gateway::tests::storage -- --nocapture
cargo test --locked -p kapsel --lib full_identity_capacity
cargo test --locked -p kapsel --lib concurrent_submissions_at_31_unfinished
```

The separate genuine-ENOSPC lane requires Docker and Python 3.11 or later:

```sh
python3 tests/qualification/run_storage_enospc.py
```

The runner creates a disposable pinned Linux container with a read-only source bind, no additional
capabilities, a 2-GiB memory ceiling, a 96-MiB tmpfs and an 1,800-second command timeout. Build
output and controls stay outside the full mount, inside the container. The runner saves logs and a
complete dirty-source snapshot in the printed host temporary directory. It changes no host
configuration and fills no host filesystem. The fixture verifies the exact tmpfs mount/type/size and
caps actual filler writes at 128 MiB even if its mount precondition is wrong. It explicitly runs the
otherwise ignored test and requires evidence that all three cases executed, rather than accepting an
empty test selection.

An admission case first exhausts the tmpfs before inserting a new identity. It requires a storage
error without admission acknowledgement, preserved earlier receipt/history bytes and explicit
same-ID admission after removing only its owned filler. At 504 retained identities/32 observed
pending operations, the next case exhausts space before receipt SQL can complete. The second fills
only after receipt SQL executes, with `dbstat` locating new destination pages and Linux `SEEK_HOLE`
confirming they still require filesystem allocation. Page 1 is already in the rollback journal at
that checkpoint. Commit then reports SQLite disk-full under actual OS ENOSPC, not the configured
page ceiling. Both cases remove only their owned filler, recover original rows/grants/frozen
facts/earlier receipts, and complete without another mutation or observation. The main journal
length observed before commit is finite evidence, not a sampled universal peak measurement.

Default deterministic gates never start this container. Process-kill tests cover before receipt SQL,
SQL-executed/precommit and after commit. None observes a kill inside SQLite commit. This lane uses
real tmpfs exhaustion, not disk-backed durability, power loss, a native installation or live
Kubernetes. See [completion accounting](../reference/storage.md#completion-accounting) for the
separate source-backed page and main-rollback arguments.

## Journal version rejection

Journal format 6 rejects older versions without migration. Run the rejection proof:

```sh
cargo test --locked -p kapsel --lib \
  gateway::tests::v011_upgrade::older_journal_versions_are_rejected_without_touching_rows -- --exact
```

See [journal retention](../guides/journal_retention.md) before replacing a binary or moving existing
history.

## Robustness lanes

Fuzzing additionally requires cargo-fuzz 0.13+ and uses nightly for sanitizer instrumentation. The
pinned nightly is already installed by contributor setup. Cargo-fuzz is not needed for formatting or
the deterministic gate. Check the target without starting exploration:

```sh
rustup run nightly-2026-07-03 cargo fuzz check --fuzz-dir fuzz
cargo test --locked --manifest-path fuzz/Cargo.toml --test corpus
cargo run --locked --manifest-path fuzz/Cargo.toml --example seed_corpus -- --check
```

The fuzz workspace maintains five distinct targets:

| Target                    | Production entry point and fixture input                                    |
| ------------------------- | --------------------------------------------------------------------------- |
| `inspect_receipt`         | Kubernetes receipt inspection; four-byte big-endian split, receipt, trust   |
| `inspect_git_receipt`     | Git receipt inspection; the same explicit receipt/trust split               |
| `verify_kubernetes_grant` | Kubernetes grant verification; raw v1/v2 envelope, fixed fixture trust      |
| `verify_git_grant`        | Git grant verification; raw envelope, fixed fixture trust                   |
| `service_document`        | Service-document parsing; raw JSON, fixed operator-owned inert journal path |

Receipt targets evaluate at time 150, trust-window boundaries and extreme times. They also exercise
lower legal byte, statement and text limits. Grant targets appoint `owner` and the public key from
fixture seed `[7; 32]` externally. Drivers never open the supplied journal path or contact
receivers. They inspect raw signatures and separately re-sign bounded mutated statements with the
fixture key. Re-signing reaches semantic parser branches without authenticating hostile input for
execution. `seed_corpus` regenerates maintained valid/invalid seeds only when invoked without
`--check`. The deterministic gate checks their exact bytes and acceptance through production entry
points.

The shell runners require Python 3.11+, a clean committed checkout, and two existing private (0700),
user-owned directories outside the checkout. Select absolute paths without symlink components. State
and scratch roots must be disjoint. Neither runner updates source. Ordinary contributor Cargo builds
and deterministic tests still accept a dirty checkout.

Supply your owned roots before invoking smoke or simulation:

```sh
export KAPSEL_SOAK_STATE_DIR=/absolute/owned/robustness-state
export KAPSEL_SCRATCH_ROOT=/absolute/owned/robustness-scratch
./fuzz/smoke.sh --fuzz-target inspect_receipt --fuzz-seconds 30
./tests/qualification/run-simulation.sh --seed 21182435914953528 --cases 1000 --shards 2
```

Smoke defaults to 10,000 fuzz iterations and an ephemeral corpus. It removes scratch only on
success. Failed scratch and libFuzzer artifacts remain available. `KAPSEL_FUZZ_RUNS` selects the
smoke iteration maximum. `KAPSEL_FUZZ_MAX_TIME` or `--fuzz-seconds` selects its time maximum. A time
maximum is not a promise to run for that duration.

For persistent exploration, queue this separate lane instead of extending smoke:

```sh
python3 tools/dev/run_robustness.py fuzz --seed 2118243591 --fuzz-seconds 1800 --timeout 3600
```

Select another decoder with `--fuzz-target`. The default remains `inspect_receipt`. Run all five
smokes or explorations explicitly, rather than treating one decoder's pass as coverage of the
others:

```sh
for target in inspect_receipt inspect_git_receipt verify_kubernetes_grant verify_git_grant service_document; do
  ./fuzz/smoke.sh --fuzz-target "$target" --seed 2118243591 --fuzz-seconds 10
  python3 tools/dev/run_robustness.py fuzz --fuzz-target "$target" \
    --seed 2118243591 --fuzz-seconds 300 --timeout 3600
done
```

Exploration uses `-runs=-1`. Kubernetes keeps the existing `state/corpus`. Other targets retain
`state/corpus-TARGET`. Maintained seeds are added without replacing discoveries. Each invocation
preserves its exact starting corpus, hashes, seed, command, and failure artifacts. It records the
selected nightly compiler and cargo-fuzz versions. After compilation, the runner launches the built
libFuzzer executable directly and records its digest. This avoids cargo-fuzz's default
artifact-directory creation in the source checkout. Build output stays in the owned scratch root.
Each target has a maximum input length at its production ceiling plus one sentinel byte (and receipt
split framing). LibFuzzer uses a ten-second per-input timeout and a 2-GiB sampled RSS limit. These
do not replace host isolation or storage supervision. The overall timeout includes compilation.
Simulation explicitly selects `scratch/run-*/simulation-build` as its Cargo target directory,
overriding ambient `CARGO_TARGET_DIR`. It builds once and directly invokes the resulting libtest
executable per shard. A pass requires each shard's expected case-count marker and one passed test,
not merely a zero process exit.

### Background sweep and retained evidence

For the shared atomic-record simulator, use the existing private state and scratch roots:

```sh
python3 tools/dev/run_robustness.py exploration \
  --seed 21182435931731969 --cases 1000 --shards 2 --timeout 1800
```

`exploration`, `simulation` and `soak` use the same simulator. Existing shell commands and
`KAPSEL_SIMULATION_*` seed/case/shard defaults remain accepted; `--simulation-engine kernel` selects
the same owner explicitly. The supervisor preserves source checks, storage budgets, locking, command
retirement, shard accounting and Rust-owned directory replay.

Generated schedules interleave 48 steps across three distinct identities under Kubernetes-only,
Git-only and mixed assignments. Suspended custody and cancellation events precede those steps;
healthy suffixes are additional. Every event checks all peers through real service selection and
virtual atomic records. Defect inputs use the separate local detection route, not this healthy
sweep. Cases are bounded to 10,000 per seed. This lane does not qualify actual Git transport,
physical jobs, SQLite OS failures, live receivers or installed artifacts.

These modes share the simulation lane's custody lock and unresolved-finding stop rule. The
supervisor builds once in owned scratch and retains every full trace before execution. It checks
each shard's completion count, trace identities and content hashes. Then the owning Rust parser and
oracle deserialize and replay every retained document. Missing documents, failed replay or missing
markers do not pass. The 1,800-second overall limit includes compilation and replay; completion need
not take 30 minutes. Infrastructure must enforce the two-CPU/4-GiB ceilings described below. Clean
committed source remains required.

[The soak runner](../../tools/dev/run-nightly-soak.sh) is simulation-only: three recorded random
seeds, 1,000 total cases per seed, two concurrent shards, and a 3,600-second overall timeout
including compilation. Repeat `--seed` to select an exact sweep. Each shard consumes the same
generated case sequence and runs its assigned cases.

```sh
./tools/dev/run-nightly-soak.sh --timeout 3600 --cases 1000 --shards 2
```

[The runner](../../tools/dev/run_robustness.py) holds one nonblocking OS advisory lock in the state
root. It never unlinks that lock or uses a PID file as identity. Launched commands inherit the lock
descriptor. Each command owns a process group, which the runner kills on failure, timeout,
cancellation, or command completion to retire leftover descendants. Host isolation must prevent
process-group escape and supervise the entire job on supervisor SIGKILL or reboot. These process
groups are not a hostile-code sandbox. Signal handlers request cancellation. Safe checkpoints handle
it after child registration and retire the commands completely. Cancellation during final scratch
cleanup is classified, but cleanup already in progress can finish. The runner chooses its terminal
result after cleanup. Later signals do not change that result.

The printed `state/run-*/` directory contains:

- `result.json`: full source SHA, toolchain identity, selected workload, scratch path, status,
  timestamps, and runner exit status;
- `commands.json` and `command-*.log`: exact argument vectors, lane environment, process exit
  statuses, and output (at most 8 MiB per command);
- `exploration.json`, `simulation-tests`, `source.tar`, `traces-SEED-SHARD/`, and
  `traces-SEED-SHARD.json`: selected engine, retained executed test binary, committed-source
  archive, their digests, full/minimized event documents, and full-trace content hashes; or
- `fuzz.json`, `corpus-before/`, `corpus-after.json`, and `artifacts/`: fuzz replay evidence.

Simulation invokes the retained `simulation-tests` binary directly. Successful scratch cleanup does
not remove that executable or `source.tar`. Replay a kernel shard with that exact executable:

```sh
KAPSEL_KERNEL_REPLAY_DIRECTORY=/absolute/owned/state/run-EXAMPLE/traces-SEED-SHARD \
  /absolute/owned/state/run-EXAMPLE/simulation-tests \
  kernel_simulation_tests::kernel_trace_exploration_or_replay --ignored --exact --nocapture
```

Check the paths and digests in `exploration.json` first. These identities and a source archive are
not build attestations. Rebuilding exercises retained inputs against a new binary.

The runner stops rather than silently truncating and passing. It refuses new runs near its 1 GiB
retained-state budget or below 128 MiB free space, and checks retained storage during command
execution. This is not a filesystem reservation or hard allocation ceiling. Infrastructure must
supply bounded scratch and evidence storage, CPU/memory ceilings, credential-free execution, and
whole-job supervision. Keep source read-only during execution and provide writable Cargo caches and
simulation build output outside source. Use a credential-free home, with no personal home mounts,
SSH agents, signing material, service state, or Docker socket. The provisional sweep budget is two
logical CPUs and approximately 4 GiB host memory. Useful throughput and compilation peaks still need
measurement.

| Runner status | Exit | Meaning                                                                 |
| ------------- | ---- | ----------------------------------------------------------------------- |
| `PASSED`      | 0    | Every selected test and expected case completed; owned scratch removed  |
| `FINDING`     | 1    | Test failure or fuzz failure diagnostic; replay evidence retained       |
| `INCOMPLETE`  | 2    | Setup, timeout, missing execution, storage, or evidence failure         |
| `CANCELLED`   | 130  | Handled cancellation; owned command groups retired                      |
| `RUNNING`     | none | No terminal result; treat an abandoned run as interrupted, never passed |

A preflight failure exits 2 and may have no run directory. An interrupted write may leave temporary
JSON files. They are not terminal results. No previous scratch directory is automatically removed.
Failures stop the affected lane. An unclassified run directory without a result stops both lanes.
There is no automatic replay, failure deduplication, or evidence pruning. A failure artifact is not
a minimized input. In the same credential-free, bounded environment, select the retained executable
from `fuzz.json` and explicitly minimize and replay a copy of the artifact:

```sh
ASAN_OPTIONS=detect_odr_violation=0 "$executable" "$artifact" \
  -minimize_crash=1 -max_total_time=30 -exact_artifact_path="$minimized"
ASAN_OPTIONS=detect_odr_violation=0 "$executable" "$minimized" -runs=1
```

Keep the original, minimized bytes, hashes, both commands and bounded diagnostics. Require the same
property failure on replay. A setup failure or different panic does not show that the failure was
preserved. Minimization may find no smaller input. Retain that result rather than claiming every
crash was already minimal. Do not overwrite an existing artifact path or mutate the baseline
checkout.

For detection-strength checks, apply one negative control at a time in disposable source copies. The
deterministic corpus driver must pass on baseline and fail for the named property on each copy:

- Accept trailing binary records: `trailing receipt record` or `trailing grant record`.
- Ignore the receipt trust interval: `trust time window`.
- Accept a service document one byte above 160 KiB: `service byte limit`.
- Accept an inconsistent signed Git result: `inconsistent signed statement`.

Record each exact mutation diff, source/executable/compiler identity, input and failing command.
Minimize and replay at least one failure with its mutated executable, then replay the same bytes
against baseline. These are isolated test faults, not changes to maintained production semantics. A
surviving required control blocks coverage retirement. No mutation-score threshold replaces owner,
compatibility, transport or receiver checks.

Before resuming a failed lane, reproduce the finding, commit a regression, and run its owning check.
Then explicitly record that reference and passing command:

```sh
python3 tools/dev/run_robustness.py triage --run run-EXAMPLE \
  --regression 'COMMIT:test-name; passing command'
```

Triage changes the result to `TRIAGED` and preserves the previous status and evidence. The reference
is an operator attestation, not an automated proof that a regression exists. For interrupted or
incomplete execution, record the diagnosed cause and recovery check in the same field. Triage never
replays the old run or deletes retained scratch. Archive resolved evidence explicitly when needed.
Never discard the first unresolved replay example to make space.

Infrastructure should alert on nonzero exits, new findings, missing/stuck scheduled jobs, stale
`RUNNING` records, and incomplete evidence. Passing runs need no alert. The infrastructure owner
controls schedules, alert delivery, and activation. This runner neither installs a resident service
nor qualifies native systemd behavior. Public-PR execution remains on hosted CI unless a separately
reviewed isolation design is approved.

Run the small, offline harness regressions with `python3 tools/dev/test_robustness.py`. They cover
exclusion, retained failures, interrupted runs, bounded output, unsafe paths, empty selection,
timeout, and cancellation. They do not qualify isolation or reboot behavior on the deployment host.

## Source privacy and security

The default static gate runs the source privacy check and offline scanner regressions. Run the
privacy check directly with:

```sh
python3 tools/checks/check_source_privacy.py
python3 tools/checks/test_source_checks.py
```

[Privacy](../reference/privacy.md#source-check) describes its scope and limitations. The separate
source security scan requires cargo-audit 0.22.2 and Trivy 0.72.0, network access to refresh their
databases, and a clean committed checkout:

```sh
python3 tools/checks/scan_source_security.py --output /tmp/kapsel-source-security.json
```

It rejects RustSec vulnerabilities or warnings, Trivy HIGH/CRITICAL vulnerabilities and secrets, and
stale or changing Trivy databases. Lower-severity Trivy findings remain in the output for review.
RustSec database identity is captured after a successful refresh and checked again after the scan.
Trivy scans the complete committed Git tree, not ignored build output or uncommitted files. This
source scan does not replace the exact-artifact SBOM scan in the candidate workflow.

## MCP adapter

The fixed service bridge takes no operator document or arguments. The caller identity launches
`/usr/bin/kapsel-service-mcp` against the resident service. See [MCP](../reference/mcp.md) for
framing and ID-only tools. Use the [focused-gate table](build.md#focused-gates) for source checks.

## Release artifact

Requires a clean checkout, Python 3.11+, and Docker with `linux/amd64` support. The sole release
target is `x86_64-unknown-linux-gnu`. The archive contains four executables and operating assets.
Its checksum-bound verifier companion supplies the
[extraction-only route](../reference/release.md#authenticate-and-extract-the-release) without
repository source. Assemble the archive and sidecars under `dist/`:

```sh
python3 tools/release/assemble_artifact.py --output-directory dist
```

For the complete two-assembly proof, keep output outside the worktree:

```sh
a_dir=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-release-a.XXXXXX")
archive_a=$(python3 tools/release/assemble_artifact.py --output-directory "$a_dir")
python3 tools/release/test_artifact.py --archive "$archive_a"
python3 tools/release/test_reproducibility.py --reference-archive "$archive_a"
```

The artifact test first exercises the companion's extraction-only command outside the checkout,
including refusal of an existing/symlink destination and wrong revision. It then includes a fresh
disposable-container service exercise with fixed installed paths, separate numeric identities, cold
publication, selection and read-first restart. It is deliberately not a systemd test. On an ARM
host, `linux/amd64` is emulated and cannot qualify the native target. The
[extracted operator path](../guides/operator.md) must separately run on native x86-64 Linux/systemd
without repository source. Interrupted execution, ambiguity and recovery against the packaged
service belong to the full operator/agent journey and final combined-candidate qualification.
Successful completion followed by graceful restart is not a replacement for those tests. Live
receiver qualification remains separate. Do not dispatch the signing/publication-effect workflow
merely to obtain missing test evidence.

For a quick hostile-layout and dependency-graph regression without building:

```sh
python3 tools/release/test_artifact.py --archive /tmp/unused.tar.gz ReleaseVerifierTests
```

Remove `"$a_dir"` when its evidence is no longer needed.
[Release artifacts](../reference/release.md) defines layout, authentication, publication, and
reproducibility requirements.

### Documented operator example

The artifact test extracts the marked blocks in the [operator guide](../guides/operator.md) and
checks their actual responses. Run against the accepted artifact and its independently recorded
revision:

```sh
python3 tools/release/test_artifact.py --archive "$archive" \
  --example-revision "$revision" \
  ReleaseArtifactTests.test_documented_operator_example
```

The test uses a disposable container and loopback receiver, with separate numeric service/caller
identities. Direct process start/stop replaces systemd/sudo. It withholds the receipt signer,
restores it after graceful retirement, and checks same-ID completion and original receipt retention.
It also exercises missing receiver material, a stopped HTTP listener, withdrawn historical trust,
and an unsupported journal-version fixture. Restoration must preserve original authority and
history. No recovery step edits a database. A version edit is test preparation only.

These adaptations check the executable preparation and response blocks, not the native installation
commands. They do not replace packaged interrupted-execution, live receiver, genuine ENOSPC, native
systemd, or power-loss evidence.

### Native installed-systemd qualification

The checksum-bound verifier also provides the explicit fresh-host `--service-systemd` qualification
mode. Its
[command, prerequisites and retained-host footprint](../reference/release.md#native-installed-systemd-qualification)
ship inside the archive's release guide. It uses the actual unit, identities, socket custody,
journald and cold replacement, but only a loopback receiver fixture. It requires a clean-source
artifact and separate operator authorization. It is not an installer or live/crash qualification.

## Coverage

With cargo-llvm-cov 0.8.7, matching CI:

```sh
cargo llvm-cov --locked --workspace --codecov --output-path codecov.json
```

Coverage is informational and non-blocking, not correctness evidence.

## Toolchain ownership

Cargo manifests and `Cargo.lock` own Rust dependencies. `rust-toolchain.toml` selects the compiler;
`rustfmt.toml`, `rustfmt-nightly.toml`, `clippy.toml`, and `ruff.toml` own style settings.
[`scripts/fmt.sh`](../../scripts/fmt.sh), [`scripts/ci.sh`](../../scripts/ci.sh), and
[CI](../../.github/workflows/ci.yml) own tool invocation. CI consumes the same setup implementation
and pins as local development. Optional qualification tools keep their pins in their owning lanes.

### Tooling ownership

| Owner                   | Responsibility                                                     |
| ----------------------- | ------------------------------------------------------------------ |
| `xtask/` and `scripts/` | Contributor commands and their three shell implementations         |
| `tools/dev/`            | Tool pins, contributor-tool regressions and unattended soak runner |
| `tools/checks/`         | Source checks and their regression tests                           |
| `tools/release/`        | Assembly, standalone verification, SBOM scanning and their tests   |
| `tests/qualification/`  | Environment-specific and long-running evidence lanes               |
| `examples/`             | Maintained fresh-session caller and its tests                      |
| `fuzz/`                 | Fuzz workspace and bounded smoke runner                            |

Rust owns product semantics; Python and shell retain external orchestration and independent checks.
Contributor commands use `cargo xtask <command>` through one Cargo alias. Stock `cargo build`,
`check`, `test` and `fmt` keep their normal meaning; xtask explicitly selects the broader
contributor workflow. A shared command vocabulary does not require a shared tooling library or a
language rewrite. The release verifier remains a standalone distributed file, independent of xtask
and repository imports.

### Tooling names

Rust and Python files use `snake_case`; shell executables use hyphenated names. Contributor shell
entry points mirror their commands: `setup.sh`, `fmt.sh` and `ci.sh`. Name the responsibility rather
than repeating the directory: `tools/release/assemble_artifact.py`, `verify_artifact.py` and
`scan_sbom.py` own distinct release steps.

Use `test` for regression suites, `run` for qualification runners, `probe` for independent
experiments, and `demo` for demonstrations. A `check` enforces source rules; a `scan` produces
security or dependency findings; `verify` authenticates and validates an artifact. A smoke lane is a
bounded exercise, not a substitute for the owning qualification gate. Python regressions import
adjacent modules normally; explicit path loading remains useful across owners and in isolated
subprocesses. These conventions add neither aliases nor a shared tooling library. Source filenames
do not rename distributed companions or paths retained in published tags.
