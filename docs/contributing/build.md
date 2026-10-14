# Build and test

Run commands from the checkout. Ordinary builds need Rust and a C compiler/linker on macOS or Linux.
`rust-toolchain.toml` selects Rust 1.98.0, Clippy, and rustfmt. The first build downloads the
selected toolchain and locked dependencies. Product service execution is Linux-only.

## Everyday commands

```sh
cargo build --locked --workspace
cargo check --locked --workspace
cargo test --locked -p kapsel
```

Builds do not require Python, Node.js, Docker, or receiver credentials. See
[Commands](../reference/commands.md) for the operator and inspection executable. To run the
published service instead of building source, use [Getting started](../getting_started.md).

## Prepare contributor tools

Install [Rust through rustup](https://rust-lang.org/tools/install/), Python 3.11+ with `venv` and
`ensurepip`, and Node.js 24+ with npm. Then:

```sh
cargo xtask setup
cargo xtask doctor
```

Setup installs the selected Rust toolchain, pinned nightly rustfmt, and the formatting/checking
tools beneath `$HOME/.local/share/kapsel/dev-tools`. It reuses matching tools and needs network
access for missing ones. Setup and doctor resolve an absolute Git 2.55.0 executable from
`KAPSEL_TEST_GIT` or PATH. Install that Git version explicitly if missing; checks never download it.
It changes neither shell profiles nor Git hooks. `doctor` checks without installing or rewriting
source; Cargo may first prepare xtask. Use `./scripts/setup.sh --check` on an unprepared host to
bypass that bootstrap.

[`tools/dev/dev-tools.sh`](../../tools/dev/dev-tools.sh) owns contributor-tool versions. CI uses the
same setup and contributor-tool pins. GitHub Action references are specified separately in each
workflow. Stock Cargo commands retain their normal meaning; xtask runs the broader contributor
workflow.

## Before review

```sh
cargo xtask fmt
cargo xtask check
```

Formatting runs Markdown, Rust, and Python, including fuzz sources and Python fixtures. It does not
apply lint fixes. The deterministic gate checks formatting, Python lint/types, Markdown links,
tooling regressions, Rust line width, Clippy, rustdoc, deterministic tests, and doctests. It does
not start Docker or a cluster.

The workspace test profile optimizes `sha2`, `curve25519-dalek`, and `ed25519-dalek`. The Dalek
overrides retain debug assertions and overflow checks. Repeated authenticated reads use real
cryptography without unoptimized curve arithmetic dominating simulation time. These overrides do not
change production profiles or authentication policy.

Use the fixed six-area router:

```sh
cargo xtask test core       # focused deterministic iteration
cargo xtask check core      # completed change within one implementation owner
cargo xtask check docs      # prose-only correction
cargo xtask check           # shared contracts, dependencies, gate wiring, or uncertain scope
```

| Area      | Deterministic owners                                                                 |
| --------- | ------------------------------------------------------------------------------------ |
| authority | Grant grammar, authentication, framing, vectors and shared corpus                    |
| core      | Application, effects, journal, histories, CLI, receipt/document corpus and local Git |
| service   | Daemon, runtime, wire, client, MCP, Linux source processes and fresh-session caller  |
| tools     | xtask, setup, format, robustness, source/security/link checker regressions           |
| release   | Offline artifact, assembly/controller/verifier regressions and installed assets      |
| docs      | Prose format, local links/anchors, source privacy and diff whitespace                |

`tools/dev/run_checks.py` owns selection. Completion scopes include applicable formatting, lints,
types and diff checks. Unscoped check runs default workspace targets once, rustdoc/doctests and
explicit deterministic fuzz replay. Shared corpus selection remains coarse until its local-owner
cutover. Source formatting currently checks all languages for non-docs scopes; Python types cover
the maintained project on both platform targets.

On Linux, service/all also execute the named `test-harness` process and MCP targets and the
feature-only client cases. They build the inspector and run the caller against the real bridge.
These are source-composition witnesses, not installed production-byte proof. Other hosts report
these missing Linux obligations, supplied by Linux PR CI. Core/all explicitly run the ignored
`gateway::git::tests::real_git_` group with the resolved Git executable. Each selected target/group
is listed with identical features and filters and must be nonempty. Runtime executable paths come
from Cargo artifact messages, including configured target directories; the router does not guess
paths beneath `target/debug`. No blanket ignored-test run can start ENOSPC or child fixtures.

A one-owner implementation change with unchanged shared contracts needs that area's check. Shared
contracts, dependencies, gate wiring and uncertain scope need unscoped check. Prose-only changes
need `check docs` and terminology review; changed executable procedures need their owning check. Add
only qualification required by a changed physical premise. Once that set passes on the final inputs,
stop; do not rerun included leaves, pre-push gates, exploration or release builds for reassurance.
Missing prerequisites mean incomplete evidence, not a passing substitute.

Checks print owners, selected prerequisites, elapsed time, command count and outcome. Cargo caches
are compilation reuse, not a pass database. Elapsed command time includes compilation; Cargo's build
output separates preparation from test execution. Existing history, capacity and offline controller
costs remain until their family cutovers. No latency target permits omitted work. Temporary CI phase
aliases select from the same owner mapping; they do not maintain a second list. PR CI explicitly
builds supported Git in its job-local setup before those phases. Release-artifact and coverage
workflow retirement remains a separate cutover.

## Focused gates

| Change                         | Command                                                                                                    |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| Core effect or application     | `cargo test --locked -p kapsel`                                                                            |
| Shared authority               | `cargo test --locked -p kapsel-authority`                                                                  |
| Service or private harness     | `cargo test --locked -p kapsel-daemon --features test-harness`                                             |
| Installed assets               | `cargo test --locked -p kapsel-daemon --test install_assets`                                               |
| MCP bridge                     | `cargo test --locked -p kapsel-daemon --features test-harness --bin kapsel-service-mcp --test service_mcp` |
| Fresh-session caller           | `python3 examples/test_fresh_session_caller.py`                                                            |
| Formatting pipeline            | `python3 tools/dev/test_format.py`                                                                         |
| Python tooling                 | `cargo xtask check tools`                                                                                  |
| Packaged Git controller        | `python3 tests/qualification/test_git_artifact.py`                                                         |
| Packaged Kubernetes controller | `python3 tests/qualification/test_kind_agent_action_exercise.py`                                           |

## Route qualification during iteration

Select additional evidence by the changed guarantee, not the filename or patch size. Use focused
checks while editing. Run the owning broader gate on the finished snapshot, without repeating its
included checks on unchanged inputs.

| Changed guarantee                                            | Additional evidence                                                |
| ------------------------------------------------------------ | ------------------------------------------------------------------ |
| Qualification argument grammar, bookkeeping or report fields | Controller regressions and the Python static gate                  |
| Artifact selection, transfer, custody or caller binding      | One affected selected-byte packaged witness                        |
| Recovery, receiver behavior or observation timing            | Affected physical cases with their prerequisites                   |
| Archive format or sidecars                                   | Offline verifier vectors                                           |
| Assembly or shipped assets                                   | Source correspondence, extracted smoke/guide and A/B proof         |
| Native launch or service unit                                | Fresh-host native profile                                          |
| Final release candidate                                      | Every required [release gate](release_process.md#graduation-gates) |

The packaged [Kubernetes](qualification.md#focused-packaged-cases) and
[Git](qualification.md#git-transition-service) runners accept repeatable `--case` selections.
Focused success is not full-suite or release acceptance. Keep production deadlines, independent
receiver observations and physical loss windows unchanged for each selected case.

A controller-only change can reuse an accepted clean archive when its shipped inputs are unchanged.
Record the archive's original revision and digest separately from current runner and fixture
digests. Do not relabel those bytes as a new release candidate. Rebuild when shipped inputs change;
final release acceptance still requires the actual clean candidate bytes.

[Test strategy](testing.md) explains where tests belong. The [evidence map](evidence.md) connects
guarantees to checks. [Qualification](qualification.md) contains Linux process, real Git, live
Kubernetes, ENOSPC, simulation, fuzz, security-scan, and artifact commands with their prerequisites.
Those lanes are separate from the everyday loop; run the ones required by the changed boundary.

The `fuzz` crate is outside the workspace for cargo-fuzz and does not inherit workspace settings.
The deterministic Rust gate checks its locked dependency graph, Clippy diagnostics, and maintained
corpus through explicit fuzz-manifest commands. Formatting includes its source. Exploratory fuzzing
remains a separate [bounded-job lane](qualification.md#robustness-lanes). Simulation and fuzz jobs
reuse development build output and retain evidence in an explicitly selected new directory. Their
command records separate setup, build and execution time.

## Optional hooks

Inspect any existing custom hook path before enabling repository hooks:

```sh
git config --get core.hooksPath
git config core.hooksPath .githooks
```

Pre-commit checks staged whitespace only. Pre-push prints a non-executing reminder; it neither runs
a gate nor stores tree results. CI owns merge enforcement. See [the hooks](../../.githooks).
