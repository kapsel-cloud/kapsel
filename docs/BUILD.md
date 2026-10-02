# Build and test Kapsel

This page covers source setup, commands, and validation gates. [Testing](TESTING.md) explains what
each test proves. To run the published release instead, use the
[service operator guide](KAPSEL_SERVICE_OPERATOR.md).

## Everyday commands

Run these from the checkout. Ordinary Cargo builds need only Rust and a C compiler/linker.

| Task                                      | Command                                                                             |
| ----------------------------------------- | ----------------------------------------------------------------------------------- |
| Prepare contributor tools                 | `cargo xtask setup`                                                                 |
| Diagnose prerequisites without installing | `cargo xtask doctor`                                                                |
| Build debug executables                   | `cargo build --locked --workspace`                                                  |
| Fast compile check                        | `cargo check --locked --workspace`                                                  |
| Focused test                              | `cargo test --locked -p kapsel --test service_application_contract cold_validation` |
| Format                                    | `cargo xtask fmt`                                                                   |
| Check formatting                          | `cargo xtask fmt-check`                                                             |
| Full deterministic gate                   | `cargo xtask ci`                                                                    |

The
[one-command disposable service example](KAPSEL_SERVICE_OPERATOR.md#one-command-disposable-example)
uses authenticated release binaries on a fresh native Linux/systemd VM. The older kind crash demo
below is not the resident service. Live, native and artifact gates are separate from the everyday
loop.

## Prerequisites

Use a macOS or Linux development host with Git and a C compiler/linker. Install
[Rust through rustup](https://rust-lang.org/tools/install/), which also supplies Cargo.
`rust-toolchain.toml` selects Rust 1.98.0, Clippy, and rustfmt for this checkout.

Run all commands below from the repository root. The first build downloads the pinned toolchain and
Cargo dependencies. Building the ordinary executable does not require Python, Node.js, or Docker.

## Evaluator CLI

Build and check the local executable:

```sh
cargo build --locked --bin kapsel
target/debug/kapsel --version
```

This builds repository HEAD, not the published v0.2.0 artifact. See [Commands](COMMANDS.md) for the
CLI's fixed forms and operator-owned inputs. For an end-to-end source demonstration, use the
[crash-recovery demo](#public-crash-recovery-demonstration).

## Deterministic gate and formatting

For contributor checks, also install [Python](https://www.python.org/downloads/) 3.11+ with `venv`
and `ensurepip`, and [Node.js](https://nodejs.org/en/download) 24+ with npm. Then run:

```sh
cargo xtask setup
```

Setup installs the selected Rust toolchain and pinned nightly rustfmt. It installs Prettier, Ruff,
Taplo, shfmt, and ShellCheck beneath `$HOME/.local/share/kapsel/dev-tools`. Taplo is built from its
locked crate. Scripts invoke isolated tools directly: no global installation, shell-profile change,
or virtualenv activation is needed. Repeated setup reuses matching tools; missing tools need network
access. Hooks are a separate opt-in.

`cargo xtask doctor` checks prerequisites and installed tools without installing or rewriting
source. Cargo may first build xtask or prepare its compiler. On an unprepared host, use
`./scripts/setup.sh --check` to bypass that bootstrap.

[`tools/dev/dev-tools.sh`](../tools/dev/dev-tools.sh) owns formatter versions for local setup and
CI. [`xtask`](../xtask/src/main.rs) routes contributor commands; it does not define release or
qualification semantics. Commands resolve the checkout root even when invoked from a subdirectory.
The three files in `scripts/` implement setup, formatting and the deterministic gate; setup can also
be invoked directly before the selected Rust toolchain is installed. Python installation ignores
ambient pip configuration and destination overrides. Formatting explicitly selects the pinned
Rustfmt executable rather than an ambient `RUSTFMT` override. Nightly rustfmt enforces
`StdExternalCrate` import grouping and `Crate` import granularity through `rustfmt-nightly.toml`.
Ordinary compilation still uses the stable toolchain.

The everyday loop is:

```sh
cargo xtask fmt
cargo xtask ci
```

Formatting runs **Markdown, Rust, then Python**, including the fuzz workspace and Python fixtures.
It checks tool availability before rewriting files and does not apply lint fixes. To check layout
without changing source, run `cargo xtask fmt-check`.

The local gate checks formatting, Python lint, Markdown links, tooling regressions, Rust line width,
Clippy, rustdoc, deterministic Rust tests, and doctests. It does not start Docker or a cluster. For
a smaller check:

```sh
cargo xtask ci static  # formatting, lint, links, and tooling regressions
cargo xtask ci rust    # Clippy, rustdoc, and deterministic Rust tests
cargo xtask ci doc     # Rust doctests
```

### Git hooks

Inspect any existing custom hook path before enabling the repository hooks:

```sh
git config --get core.hooksPath
git config core.hooksPath .githooks
```

Pre-commit runs only `git diff --cached --check`. It checks staged whitespace errors, not
formatting, lint or tests, and permits partial commits and unrelated unstaged/untracked files.
Pre-push requires a clean checkout matching the pushed tree and runs the complete local gate,
reusing a previous passing result for the same tree. CI independently runs that gate. Neither hook
starts Docker. See [the hooks](../.githooks/) for exact refusal and caching behavior.

## Focused gates

Choose the smallest check that owns the changed behavior. Run the complete local gate before handoff
when practical. Additional environment requirements are listed in the sections below.

| Change                             | Command                                                                           |
| ---------------------------------- | --------------------------------------------------------------------------------- |
| Python tooling                     | `cargo xtask ci static`                                                           |
| Formatting pipeline                | `python3 tools/dev/test_format.py`                                                |
| Effect gateway                     | `cargo test --locked -p kapsel`                                                   |
| Service and private harness        | `cargo test --locked -p kapsel-daemon --features test-harness`                    |
| Shared operator authority          | `cargo test --locked -p kapsel-authority`                                         |
| Service installed assets           | `cargo test --locked -p kapsel-daemon --test install_assets`                      |
| Direct MCP adapter                 | `cargo test --locked --test e2e_mcp_adapter`                                      |
| Service MCP bridge                 | `cargo test --locked -p kapsel-daemon --features test-harness --test service_mcp` |
| Fresh-session caller fixture       | `python3 examples/test_fresh_session_caller.py`                                   |
| Crash-demo harness, without Docker | `./examples/test-demo-harness.sh`                                                 |
| Seeded lifecycle simulation        | `./tests/qualification/run-simulation.sh`                                         |
| Receipt-inspection fuzz smoke      | `./fuzz/smoke.sh`                                                                 |
| Live Kubernetes behavior           | `./tests/qualification/run-kind-effect-gateway.sh`                                |

To run the fresh-session caller fixture against the real MCP bridge and a scripted socket (not
Kubernetes), build the test-harness binary first:

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
[Live Kubernetes and demonstration](TESTING.md#live-kubernetes-and-demonstration) for the gateway,
admission, and frozen JSON Patch comparison cases.

## Packaged-service live workflow

The separate extracted-artifact lane requires Docker, kind 0.32+, kubectl 1.30+ and Python 3.11+.
Use an exact accepted clean release archive and its matching sidecars. This is a privileged
**disposable test environment**, not permission to use an existing cluster:

```sh
python3 tests/qualification/run_kind_agent_action_workflow.py \
  --archive "$archive" --revision "$revision"
```

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
caller before and after cold replacement. Original receipts remain retrievable after catalog
withdrawal. API-server audit independently counts product PATCH requests, excluding explicitly
identified fixture writes used to prepare the faults.

The runner probes private-file and executable custody under the caller identity before submission.
Private fixture credentials and evidence are copied into container-owned directories, not exposed
through host bind mounts whose permission behavior can differ across Docker environments. The
extracted public artifact is the only host bind. These probes are finite process-level evidence, not
a general host-security certification.

To additionally exercise the representative agent integration, supply an independently accepted
Linux x86-64 Codex 0.155.1 executable, its matching `codex-code-mode-host` sibling, and existing
model authentication. The runner does not install or update Codex:

```sh
python3 tests/qualification/run_kind_agent_action_workflow.py \
  --archive "$archive" --revision "$revision" \
  --agent --codex-binary /absolute/path/to/verified/codex
```

The default lane requires no model account or call. The optional lane copies only the model's
`~/.codex/auth.json` into a private caller-owned directory inside the disposable container. An
operator can select another private model-auth file with `--codex-auth`. No host home directory,
agent configuration, Kubernetes authority or Docker socket is exposed to the model. The source auth
file must be private, owned, regular and single-link. It is not modified or synchronized back. The
container copy is removed after the call, and container cleanup removes any remaining local model
state.

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

The printed private workspace retains result summaries, bounded output, and fixture inputs. It also
contains a cluster-admin kubeconfig and an expiring scoped token. **Do not publish that directory.**
The runner removes its container and cluster. If cleanup fails, inspect those named resources; do
not run broad Docker or kind cleanup. The native example separately retains its stopped host state.

## Public crash-recovery demonstration

Requires Docker, kind 0.32+, kubectl 1.30+, and Python 3.11+:

```sh
./examples/demo-kind-crash-recovery.sh
```

The source demo builds its Rust harness, refuses pre-existing kind clusters, and cleans up its owned
cluster and workspace. To run the published artifact without a Rust toolchain, follow the
[v0.2.0 evaluation guide](https://github.com/kapsel-cloud/kapsel/blob/v0.2.0/docs/EVALUATOR.md#fastest-path).

## Independent client experiment

With the pinned kubectl v1.33.9 build and Python 3.11+, run:

```sh
python3 tests/qualification/run_independent_kubectl.py
```

The [kubectl failure corpus](INDEPENDENT_TOOL_CORPUS.md) uses a loopback fixture, not a cluster or
Kapsel runtime. It is separate from the default gate.

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
regressions prove current Kapsel behavior; they do not establish equivalence with another tool.

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
explicit resumptions. The [gateway contract](EFFECT_GATEWAY.md#result-meaning) owns that policy.

## Git transition service

The Git lane requires an explicitly selected Git 2.55.0. Receiver fixtures copy it into private
custody; it is not discovered through ambient PATH. Run the core recovery matrix on macOS or Linux:

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
service-crash windows; no product test hook is used. The cases check exact ref and hook inputs,
observation-only same-ID recovery, original receipt retrieval after catalog/material withdrawal, and
detached inspection. Hook inputs are not packet counts or proof of complete hook delivery.
Containers are removed; the printed private evidence workspace is retained. This is not native
systemd, power-loss, or live-repository qualification.

See the [Git service example](GIT_REF_TRANSITION.md) for material, semantics and evidence limits.
The owning deterministic gate remains `cargo xtask ci`; the Linux process gate below is also
required when service startup or protocol composition changes.

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
receiver waiting and lifecycle contention; process tests preserve original history/receipt bytes
through catalog and key removal. These are deterministic source/process checks, not disk-full,
power-loss, native-host or live-Kubernetes qualification. Never mutate source during a
read-only-mounted container gate, and archive untracked source files alongside its diff.

See [Kapsel service](KAPSEL_SERVICE.md) for the current boundary and
[service testing](TESTING.md#kapsel-service) for evidence coverage.

## Accepted journal layouts

Run the shared writable/read-only physical-layout regressions and retained-charge arithmetic:

```sh
cargo test --locked -p kapsel --lib gateway::tests::capacity_layout
cargo test --locked -p kapsel --lib gateway::journal::capacity
```

These use bundled SQLite records, long retained keys, padded schema SQL and bounded sparse-tree
fixtures to check [completion accounting](EFFECT_GATEWAY.md#completion-accounting). They prove
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
output and controls stay outside the full mount, inside the container; logs and a complete
dirty-source snapshot are saved in the printed host temporary directory. It changes no host
configuration and fills no host filesystem. The fixture verifies the exact tmpfs mount/type/size and
caps actual filler writes at 128 MiB even if its mount precondition is wrong. It explicitly runs the
otherwise ignored test and requires evidence that both cases executed, rather than accepting an
empty test selection.

At 504 retained identities/32 observed pending operations, the first case exhausts space before
receipt SQL can complete. The second fills only after receipt SQL executes, with `dbstat` locating
new destination pages and Linux `SEEK_HOLE` confirming they still require filesystem allocation.
Page 1 is already in the rollback journal at that checkpoint. Commit then reports SQLite disk-full
under actual OS ENOSPC, not the configured page ceiling. Both cases remove only their owned filler,
recover original rows/grants/frozen facts/earlier receipts, and complete without another mutation or
observation. The main journal length observed before commit is finite evidence, not a sampled
universal peak measurement.

Default deterministic gates never start this container. Process-kill tests cover before receipt SQL,
SQL-executed/precommit and after commit; none is an observed kill inside SQLite commit. This lane
uses real tmpfs exhaustion, not disk-backed durability, power loss, a native installation or live
Kubernetes. See [completion accounting](EFFECT_GATEWAY.md#completion-accounting) for the separate
source-backed page and main-rollback arguments.

## Journal version rejection

Repository HEAD uses journal format 6 and rejects older versions, including format 5, without
migration. Run the rejection proof:

```sh
cargo test --locked -p kapsel --lib \
  gateway::tests::v011_upgrade::older_journal_versions_are_rejected_without_touching_rows -- --exact
```

Historical migration and rollback tests are not HEAD qualification or candidate requirements. Use
[the v0.2.0 tagged upgrade guide](https://github.com/kapsel-cloud/kapsel/blob/v0.2.0/docs/UPGRADE.md)
for that separate evidence. Rejection coverage does not replace historical migration coverage.

## Robustness lanes

Fuzzing additionally requires cargo-fuzz 0.13+ and uses nightly for sanitizer instrumentation. The
pinned nightly is already installed by contributor setup. Cargo-fuzz is not needed for formatting or
the deterministic gate. Check the target without starting exploration:

```sh
rustup run nightly-2026-07-03 cargo fuzz check --fuzz-dir fuzz inspect_receipt
```

The shell runners require Python 3.11+, a clean committed checkout, and two existing private (0700),
user-owned directories outside the checkout. Select absolute paths without symlink components. State
and scratch roots must be disjoint. Neither runner updates source. Ordinary contributor Cargo builds
and deterministic tests still accept a dirty checkout.

Supply your owned roots before invoking smoke or simulation:

```sh
export KAPSEL_SOAK_STATE_DIR=/absolute/owned/robustness-state
export KAPSEL_SCRATCH_ROOT=/absolute/owned/robustness-scratch
./fuzz/smoke.sh --fuzz-seconds 30
./tests/qualification/run-simulation.sh --seed 21182435914953528 --cases 1000 --shards 2
```

Smoke defaults to 10,000 fuzz iterations and an ephemeral corpus. It removes scratch only on
success; failed scratch and libFuzzer artifacts remain available. `KAPSEL_FUZZ_RUNS` selects the
smoke iteration maximum. `KAPSEL_FUZZ_MAX_TIME` or `--fuzz-seconds` selects its time maximum. A time
maximum is not a promise to run for that duration.

For persistent exploration, queue this separate lane instead of extending smoke:

```sh
python3 tools/dev/run_robustness.py fuzz --seed 2118243591 --fuzz-seconds 1800 --timeout 3600
```

Exploration uses `-runs=-1` and the retained `state/corpus`. Each invocation preserves its exact
starting corpus, hashes, seed, command, and failure artifacts. It records the selected nightly
compiler and cargo-fuzz versions. Fuzz compilation is a setup step; the runner then launches the
built libFuzzer executable directly, with its digest recorded. This avoids cargo-fuzz's default
artifact-directory creation in the source checkout. Build output stays in the owned scratch root.
The overall timeout includes compilation. Simulation builds once and directly invokes the resulting
libtest executable per shard. A pass requires each shard's expected case-count marker and one passed
test, not merely a zero process exit.

### Background sweep and retained evidence

[The soak runner](../tools/dev/run-nightly-soak.sh) is simulation-only: three recorded random seeds,
1,000 total cases per seed, two concurrent shards, and a 3,600-second overall timeout including
compilation. Repeat `--seed` to select an exact sweep; each shard consumes the same generated case
sequence and runs its assigned cases.

```sh
./tools/dev/run-nightly-soak.sh --timeout 3600 --cases 1000 --shards 2
```

[The Python owner](../tools/dev/run_robustness.py) holds one nonblocking OS advisory lock in the
state root. It never unlinks that lock or uses a PID file as identity. Launched commands inherit the
lock descriptor. Each command owns a process group, which the runner kills on failure, timeout,
cancellation, or command completion to retire leftover descendants. Host isolation must prevent
process-group escape and supervise the entire job on supervisor SIGKILL or reboot. These process
groups are not a hostile-code sandbox. Signal handlers request cancellation; safe checkpoints handle
it after child registration and complete retirement. Cancellation during final scratch cleanup is
classified, but cleanup already in progress can finish. The terminal-decision boundary follows
cleanup; later signals do not change the selected outcome.

The printed `state/run-*/` directory contains:

- `result.json`: full source SHA, toolchain identity, selected workload, scratch path, status,
  timestamps, and runner exit status;
- `commands.json` and `command-*.log`: exact argument vectors, lane environment, process exit
  statuses, and output (at most 8 MiB per command);
- `simulation.json`: seed list, shard and case counts, and executable digest; or
- `fuzz.json`, `corpus-before/`, `corpus-after.json`, and `artifacts/`: fuzz replay evidence.

The runner stops rather than silently truncating and passing. It refuses new runs near its 1 GiB
retained-state budget or below 128 MiB free space, and checks retained storage during command
execution. This is not a filesystem reservation or hard allocation ceiling. Infrastructure must
supply bounded scratch and evidence storage, CPU/memory ceilings, credential-free execution, and
whole-job supervision. Keep source read-only during execution and provide writable Cargo caches and
simulation build output outside source. Use a credential-free home, with no personal home mounts,
SSH agents, signing material, service state, or Docker socket. The provisional sweep budget is two
logical CPUs and approximately 4 GiB host memory; useful throughput and compilation peaks still need
measurement.

| Runner status | Exit | Meaning                                                                 |
| ------------- | ---- | ----------------------------------------------------------------------- |
| `PASSED`      | 0    | Every selected test and expected case completed; owned scratch removed  |
| `FINDING`     | 1    | Test failure or fuzz failure diagnostic; replay evidence retained       |
| `INCOMPLETE`  | 2    | Setup, timeout, missing execution, storage, or evidence failure         |
| `CANCELLED`   | 130  | Handled cancellation; owned command groups retired                      |
| `RUNNING`     | none | No terminal result; treat an abandoned run as interrupted, never passed |

A preflight failure exits 2 and may have no run directory. An interrupted write may leave temporary
JSON files; they are not terminal results. No previous scratch directory is automatically removed.
Failures stop the affected lane. An unclassified run directory without a result stops both lanes.
There is no automatic replay, failure deduplication, or evidence pruning.

Before resuming a failed lane, reproduce the finding, commit a regression, and run its owning check.
Then explicitly record that reference and passing command:

```sh
python3 tools/dev/run_robustness.py triage --run run-EXAMPLE \
  --regression 'COMMIT:test-name; passing command'
```

Triage changes the result to `TRIAGED` and preserves the previous status and evidence. The reference
is an operator attestation, not an automated proof that a regression exists. For interrupted or
incomplete execution, record the diagnosed cause and recovery check in the same field. Triage never
replays the old run or deletes retained scratch. Archive resolved evidence explicitly when needed;
never discard the first unresolved replay example to make space.

Infrastructure should alert on nonzero exits, new findings, missing/stuck scheduled jobs, stale
`RUNNING` records, and incomplete evidence. Passing runs need no alert. The old notification URL
variables are no longer used. The infrastructure owner controls schedules, alert delivery, and
activation; this runner neither installs a resident service nor qualifies native systemd behavior.
Public-PR execution remains on hosted CI unless a separately reviewed isolation design is approved.

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

[Privacy](PRIVACY.md#source-check) owns its scope and limitations. The separate source security scan
requires cargo-audit 0.22.2 and Trivy 0.72.0, network access to refresh their databases, and a clean
committed checkout:

```sh
python3 tools/checks/scan_source_security.py --output /tmp/kapsel-source-security.json
```

It rejects RustSec vulnerabilities or warnings, Trivy HIGH/CRITICAL vulnerabilities and secrets, and
stale or changing Trivy databases. Lower-severity Trivy findings remain in the output for review.
RustSec database identity is captured after a successful refresh and checked again after the scan.
Trivy scans the complete Git archive of HEAD, not ignored build output or uncommitted files. This
source scan does not replace the exact-artifact SBOM scan in the candidate workflow.

## MCP adapter

After building the local executable, start the fixed stdio process with operator-owned
configuration:

```sh
target/debug/kapsel mcp --operator-config /absolute/operator.json
```

See [MCP](MCP.md) for protocol details. The focused-gate table lists its black-box test.

## Release artifact

Requires a clean checkout, Python 3.11+, and Docker with `linux/amd64` support. The sole release
target is `x86_64-unknown-linux-gnu`. HEAD assembles a service artifact containing `kapsel`,
`kapseld`, the fixed service client and existing operating assets. It is not the published v0.2 demo
archive. The checksum-bound verifier companion supplies the
[extraction-only route](RELEASE.md#authenticate-and-extract-the-release) without repository source.
Assemble the archive and sidecars under `dist/`:

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
[extracted operator path](KAPSEL_SERVICE_OPERATOR.md) must separately run on native x86-64
Linux/systemd without repository source. Interrupted execution, ambiguity and recovery against the
packaged service belong to the full operator/agent journey and final combined-candidate
qualification. Successful completion followed by graceful restart is not a replacement for those
tests. Live receiver qualification remains separate. Do not dispatch the signing/publication-effect
workflow merely to obtain missing test evidence.

For a quick hostile-layout and dependency-graph regression without building:

```sh
python3 tools/release/test_artifact.py --archive /tmp/unused.tar.gz ReleaseVerifierTests
```

Remove `"$a_dir"` when its evidence is no longer needed. [Release artifacts](RELEASE.md) owns
layout, authentication, publication, and reproducibility requirements. The
[tagged evaluation guide](https://github.com/kapsel-cloud/kapsel/blob/v0.2.0/docs/EVALUATOR.md) owns
downloading, authenticating, and running the older beta.

### Native installed-systemd qualification

The checksum-bound verifier also owns the explicit fresh-host `--service-systemd` qualification
mode. Its
[command, prerequisites and retained-host footprint](RELEASE.md#native-installed-systemd-qualification)
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
[`scripts/fmt.sh`](../scripts/fmt.sh), [`scripts/ci.sh`](../scripts/ci.sh), and
[CI](../.github/workflows/ci.yml) own tool invocation. CI consumes the same setup implementation and
pins as local development. Optional qualification tools keep their pins in their owning lanes.

### Tooling ownership

| Owner                   | Responsibility                                                     |
| ----------------------- | ------------------------------------------------------------------ |
| `xtask/` and `scripts/` | Contributor commands and their three shell implementations         |
| `tools/dev/`            | Tool pins, contributor-tool regressions and unattended soak runner |
| `tools/checks/`         | Source checks and their regression tests                           |
| `tools/release/`        | Assembly, standalone verification, SBOM scanning and their tests   |
| `tests/qualification/`  | Environment-specific and long-running evidence lanes               |
| `tests/probes/`         | Independent receiver experiments                                   |
| `examples/`             | Maintained caller and crash demonstration, with their tests        |
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
