# Build and test Kapsel

For source development, start below. To try the published resident-service preview, use the
[service operator guide](KAPSEL_SERVICE_OPERATOR.md). [Testing](TESTING.md) explains what each test
proves; this page owns setup and commands.

## Everyday commands

Run these from the checkout. Ordinary Cargo builds need only Rust and a C compiler/linker.

| Task                                      | Command                                                                             |
| ----------------------------------------- | ----------------------------------------------------------------------------------- |
| Prepare contributor tools                 | `./scripts/setup.sh`                                                                |
| Diagnose prerequisites without installing | `./scripts/setup.sh --check`                                                        |
| Build debug executables                   | `cargo build --locked --workspace`                                                  |
| Fast compile check                        | `cargo check --locked --workspace`                                                  |
| Focused test                              | `cargo test --locked -p kapsel --test service_application_contract cold_validation` |
| Format                                    | `./scripts/format.sh`                                                               |
| Full deterministic gate                   | `./scripts/ci-local.sh`                                                             |

The
[one-command disposable service example](KAPSEL_SERVICE_OPERATOR.md#one-command-disposable-example)
uses authenticated preview binaries on a fresh native Linux/systemd VM. The older kind crash demo
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
./scripts/setup.sh
```

Setup installs the Rust toolchain selected by `rust-toolchain.toml`, a pinned nightly rustfmt, and
pinned Prettier/Ruff in versioned directories beneath `$HOME/.local/share/kapsel/dev-tools`. The
scripts invoke those isolated executables directly. Nothing is installed globally, no shell profile
changes, and no virtualenv activation is needed in a new shell. Rerunning setup reuses matching
tools. Network access is needed for missing installations. `./scripts/setup.sh --check` checks
prerequisites and installed tools without installing or rewriting source. Hooks remain a separate
opt-in.

[`scripts/dev-tools.sh`](../scripts/dev-tools.sh) owns formatter versions for local setup and CI.
Nightly rustfmt enforces `StdExternalCrate` import grouping and `Crate` import granularity through
`rustfmt-nightly.toml`. Ordinary compilation still uses the stable toolchain.

The everyday loop is:

```sh
./scripts/format.sh
./scripts/ci-local.sh
```

Formatting runs **Markdown, Rust, then Python**, including the fuzz workspace and Python fixtures.
It checks tool availability before rewriting files and does not apply lint fixes. To check layout
without changing source, run `./scripts/format.sh --check`.

The local gate checks formatting, Python lint, Markdown links, tooling regressions, Rust line width,
Clippy, rustdoc, deterministic Rust tests, and doctests. It does not start Docker or a cluster. For
a smaller check:

```sh
./scripts/ci-local.sh static  # formatting, lint, links, and tooling regressions
./scripts/ci-local.sh rust    # Clippy, rustdoc, and deterministic Rust tests
./scripts/ci-local.sh doc     # Rust doctests
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

| Change                             | Command                                                  |
| ---------------------------------- | -------------------------------------------------------- |
| Python scripts                     | `./scripts/ci-local.sh static`                           |
| Formatting pipeline                | `python3 scripts/test-format.py`                         |
| Effect gateway                     | `cargo test --locked -p kapsel`                          |
| Service and private harness        | `cargo test --locked -p kapseld --features test-harness` |
| Shared operator authority          | `cargo test --locked -p kapsel-authority`                |
| Service installed assets           | `cargo test --locked -p kapseld --test install_assets`   |
| MCP adapter                        | `cargo test --locked --test e2e_mcp_adapter`             |
| Crash-demo harness, without Docker | `./scripts/test-demo-harness.sh`                         |
| Seeded lifecycle simulation        | `./scripts/test-simulation.sh`                           |
| Receipt-inspection fuzz smoke      | `./scripts/test-fuzz.sh`                                 |
| Live Kubernetes behavior           | `./scripts/test-kind-effect-gateway.sh`                  |

## Live Kubernetes gate

Requires Docker, kind 0.32+, kubectl 1.30+, Python 3.11+, and OpenSSL:

```sh
./scripts/test-kind-effect-gateway.sh
```

The script creates and removes its own uniquely named cluster and exports failure logs. It records
the base revision and working-tree diff digest, and refuses untracked files that cannot be included
in that evidence. This lane is separate from deterministic CI. See
[Live Kubernetes and demonstration](TESTING.md#live-kubernetes-and-demonstration) for the gateway,
admission, and frozen JSON Patch comparison cases.

## Packaged-service live workflow

The separate extracted-artifact lane requires Docker, kind 0.32+, kubectl 1.30+ and Python 3.11+.
Use an exact accepted clean preview archive and its matching sidecars. This is a privileged
**disposable test environment**, not permission to use an existing cluster:

```sh
python3 scripts/test-kind-agent-action-workflow.py --archive "$archive" --revision "$revision"
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
python3 scripts/test-kind-agent-action-workflow.py --archive "$archive" --revision "$revision" \
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
lists actual approvals, submits the existing `healthy` ID, reads status and exports its receipt
through the product client. Before starting Codex, the runner must pass the caller's OS custody
probes. Codex's inner approval prompts and sandbox are explicitly bypassed **only inside this
externally isolated disposable caller**. The container's `no-new-privileges`, absent private host
mounts and OS identities are the boundary, not prompt advice or confirmation dialogs. Never copy
that bypass flag into a host or operator invocation.

The agent container has a 4 GiB memory ceiling. The driver waits up to 120 seconds for Codex, then
requires all remaining caller-UID processes to retire before checking evidence or starting scripted
cases. Killing the host `docker exec` process alone is not sufficient. User configuration and
exec-policy rules are not loaded, and session persistence is disabled. This tests specific product
custody boundaries, not comprehensive hostile-code containment. The model can read its own model
authentication and has network access.

The driver checks product state independently of model prose and refuses success if another fixture
action was admitted. Status comes from the installed native client with its fixed socket. Python
supervision and receipt readers use isolated mode to exclude model-writable imports. The driver
snapshots a bounded, regular, non-symlink model receipt **before** creating a canonical export, then
compares the bytes. It records CLI identity, both executable digests and token usage, not raw model
sessions. There is no provider SDK, agent framework or new product command.

This is one model-driven healthy action. The remaining fault and recovery cases are deterministic
caller programs, not model-driven troubleshooting or evidence of useful action selection. Neither
mode qualifies native systemd installation, application quality, publication, or a cumulative
observation deadline across interruptions.

The printed private workspace retains sanitized result summaries, bounded exercise output, and
fixture inputs for inspection. It also contains a cluster-admin kubeconfig and an expiring scoped
fixture token. Do not publish that directory. The owned container and cluster are removed after the
run. A cleanup error requires inspection of those named resources, not broad Docker or kind cleanup.
The native example separately retains its stopped host state.

## Public crash-recovery demonstration

Requires Docker, kind 0.32+, kubectl 1.30+, and Python 3.11+:

```sh
./scripts/demo-kind-crash-recovery.sh
```

The source demo builds its Rust harness, refuses pre-existing kind clusters, and cleans up its owned
cluster and workspace. To run the published artifact without a Rust toolchain, follow the
[v0.2.0 evaluation guide](https://github.com/kapsel-cloud/kapsel/blob/v0.2.0/docs/EVALUATOR.md#fastest-path).

## Independent client experiment

With the pinned kubectl v1.33.9 build and Python 3.11+, run:

```sh
python3 scripts/test-independent-kubectl.py
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

## Kapsel service candidate

The focused package command above includes the service's private harness. On Linux, run the process
tests:

```sh
cargo test --locked -p kapseld --features test-harness --test linux_process
```

With `sg`, Python 3 and an existing `docker` group that the test user may activate through `sg`,
include the ignored distinct-effective-group case. The group must differ from the server's effective
GID. In a disposable root-owned test container, provision that fixture group inside the container,
not on the development host. The test uses only the group identity, not Docker daemon access:

```sh
cargo test --locked -p kapseld --features test-harness --test linux_process \
  distinct_effective_gid_is_denied_before_frame_read -- --ignored --exact
```

Cold publication validation also runs at the shared application owner:

```sh
cargo test --locked -p kapsel --test service_application_contract cold_validation
cargo test --locked -p kapseld --features test-harness
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
concurrent admission at 31 unfinished identities, and the existing full-capacity receipt test
expanded to nine insertion-order/pending-phase combinations. It uses maximal legal fields and valid
fragmented freelists at 16,384 pages, and compares all retained rows without repeatedly verifying
unchanged signatures. Focused commands:

```sh
cargo test --locked -p kapsel --lib gateway::tests::storage -- --nocapture
cargo test --locked -p kapsel --lib full_identity_capacity_completes_all_remaining_receipts
cargo test --locked -p kapsel --lib concurrent_submissions_at_31_unfinished
```

The separate genuine-ENOSPC lane requires Docker and Python 3.11 or later:

```sh
python3 scripts/test-storage-enospc.py
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

Repository HEAD uses journal format 5 and rejects older versions, including format 4, without
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
the deterministic gate. Check the target or run a bounded smoke test:

```sh
rustup run nightly-2026-07-03 cargo fuzz check --manifest-path fuzz/Cargo.toml inspect_receipt
./scripts/test-fuzz.sh
```

For a longer run:

```sh
KAPSEL_FUZZ_RUNS=1000000 KAPSEL_FUZZ_MAX_TIME=3600 ./scripts/test-fuzz.sh
```

Run the seeded lifecycle simulation with defaults, or supply a seed and workload for replay:

```sh
./scripts/test-simulation.sh
KAPSEL_SIMULATION_SEED=21182435914953528 \
KAPSEL_SIMULATION_CASES=10000 KAPSEL_SIMULATION_SHARDS=8 ./scripts/test-simulation.sh
```

Optional `KAPSEL_FUZZ_NOTIFY_URL` and `KAPSEL_SIMULATION_NOTIFY_URL` send completion summaries
through `curl` to a destination you control.

For unattended runs, inspect [the soak runner](../scripts/run-nightly-soak.sh) first. It updates the
checkout by default, so use a dedicated checkout or disable updates explicitly:

```sh
KAPSEL_SOAK_AUTO_UPDATE=0 ./scripts/run-nightly-soak.sh
```

## Source privacy and security

The default static gate runs the source privacy check and offline scanner regressions. Run the
privacy check directly with:

```sh
python3 scripts/check-source-privacy.py
python3 scripts/test-source-checks.py
```

[Privacy](PRIVACY.md#source-check) owns its scope and limitations. The separate source security scan
requires cargo-audit 0.22.2 and Trivy 0.72.0, network access to refresh their databases, and a clean
committed checkout:

```sh
python3 scripts/scan-source-security.py --output /tmp/kapsel-source-security.json
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
target is `x86_64-unknown-linux-gnu`. HEAD assembles a service-preview artifact containing `kapsel`,
`kapseld`, the fixed service client and existing operating assets. It is not the published v0.2 demo
archive. The checksum-bound verifier companion supplies the
[extraction-only route](RELEASE.md#authenticate-and-extract-the-preview) without repository source.
Assemble the archive and sidecars under `dist/`:

```sh
python3 scripts/assemble-release-artifact.py --output-directory dist
```

For the complete two-assembly proof, keep output outside the worktree:

```sh
a_dir=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-release-a.XXXXXX")
archive_a=$(python3 scripts/assemble-release-artifact.py --output-directory "$a_dir")
python3 scripts/test-release-artifact.py --archive "$archive_a"
python3 scripts/test-release-reproducibility.py --reference-archive "$archive_a"
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
python3 scripts/test-release-artifact.py --archive /tmp/unused.tar.gz ReleaseVerifierTests
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
[`scripts/format.sh`](../scripts/format.sh), [`scripts/ci-local.sh`](../scripts/ci-local.sh), and
[CI](../.github/workflows/ci.yml) own tool invocation. CI consumes the same setup command and pins
as local development. Optional qualification tools keep their pins in their owning lanes.
