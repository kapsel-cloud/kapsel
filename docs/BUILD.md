# Build

Status: deterministic repository, evaluator commands, thin MCP adapter, reproducible release
assembly, public crash demo, and live-kind gates implemented.

Kind: guide. Authority: commands that exist and their present meaning.

Owns: Runnable repository commands, prerequisites, and CI lanes.

Does not own: Technical scope or planned command design.

## Default gate

Run the deterministic, containerless repository gate:

```sh
./scripts/ci-local.sh
```

It checks Rust and Markdown formatting, local Markdown links and heading anchors, Rust line width,
project tidy rules, Clippy across production and test targets, warning-free rustdoc, workspace unit,
integration, and binary tests, and documentation tests. Missing public rustdoc, unreachable
bare-`pub` items, missing `# Errors`/`# Panics` sections, and broken or private intra-doc links are
denied.

Equivalent cargo-make aliases are:

```sh
cargo make check
cargo make ci
```

Hosted CI invokes the same script as three non-overlapping timed steps: `static`, `rust`, and `doc`.
The ordinary no-argument and `check` forms run all three in that order, so step visibility does not
create a second gate or duplicate compilation.

The managed pre-commit hook skips message-only amendments and rewords whose prospective tree equals
`HEAD`. Every content-changing commit runs the complete default gate rather than formatting alone:

```sh
cargo make hooks-install
```

Format before review:

```sh
cargo make fmt
cargo make fmt-check
```

`cargo make fmt` formats Rust and Markdown. `cargo make fmt-check` checks both without rewriting.

## Hosted informational coverage

Run the same complete deterministic Rust coverage command locally with:

```sh
cargo llvm-cov --locked --workspace --codecov --output-path codecov.json
```

Hosted coverage starts in parallel with the default gate and uses only `target/llvm-cov-target`,
including its separate dependency cache. Report generation has a command-level ten-minute bound;
failure or timeout removes any partial report, emits a workflow warning, and does not change the
default gate result. Codecov upload runs only for a nonempty completed report. An outer non-blocking
15-minute job bound covers setup failures without turning coverage into correctness evidence.

On the clean x86-64 Linux Slice 1 candidate, cargo-llvm-cov 0.8.7 completed a cold compile, the full
suite, and Codecov report in 2m22.791s; compilation took 39.93s and the sandbox library portion took
99.87s. This is a diagnostic measurement on the verification host, not a duration guarantee.

## Tidy and style audit

Run project-local hard hygiene rules with:

```sh
cargo make tidy
```

Hard findings use stable `error[rule-code]` labels, have allowed and denied fixture tests, and block
the canonical gate. Rustdoc tidy checks exact heading vocabulary and order, non-empty sections,
safety-section applicability, Rust doctest fences, and copied-example failure handling.

Run non-blocking review prompts with:

```sh
cargo make style-audit
```

Style-audit findings use `warning[rule-code]` labels and exit successfully. They currently flag
status language in public docs and async public APIs whose cancellation behavior may deserve an
explicit contract. Human review decides whether an advisory requires a change.

## Active experiment library

The narrow deterministic gate for KAP-0038 is:

```sh
cargo test --locked -p kapsel
cargo clippy --locked -p kapsel --all-targets -- -D warnings
```

Signed-grant trust, classifier-complete receipts, inspection, durable publication, migration, and
recovery behavior are exercised through both the library and fixed evaluator commands. The
deterministic suite includes real subprocess kill/restart proofs at the mutation and
receipt-publication seams.

## Upgrade and rollback fixture gate

The [operator upgrade and rollback contract](UPGRADE.md) owns the supported procedure and limits.
Generate exact historical journals through the pinned `v0.1.1` lifecycle behavior, create the
operator-owned offline backups, mark and reopen every durable state with the candidate, and reopen
the marked stores with the exact old source:

```sh
cargo make test-v011-upgrade
```

The direct command is `python3 scripts/test-v011-upgrade-fixtures.py`. It verifies the annotated tag
and peeled source identity, compiles a digest-bound test harness overlay in a detached worktree, and
removes temporary fixtures and worktree state. For every one of the nine historical lifecycle states
it kills the real candidate test process before the exclusive marker transaction, while the marker
is set in that uncommitted transaction, and after commit, then performs two ordinary reopens. The
in-transaction case forces a hot journal with test-only probe pages and uses a controlled
`cfg(test)` direct marker-page write to exercise marker-2 rollback; it does not claim a natural
production page spill. Before kill it requires marker 2 and a nonzero journal header, then marker 0,
exact old schema/row, and no test probe before normal re-mark. It also kills a private test-only
restore process before atomic publication, after synchronized quarantine while the active path
remains, and after atomic replacement. The gate compares complete rows, state, provider-call count,
backup identity, and frozen receipt bytes/path/digest/key, publication, and retained-v2 inspection
across every seam. Malformed migration and restore attempts, including link, mode, and type
substitutions, must remain non-destructive and owner-private; the fixture scan rejects the fixed
signing-seed bytes in every retained file. It uses no Kubernetes cluster or network and does not
prove sudden-power or filesystem/hardware flush behavior. Retain a fixture set only for focused
diagnosis with a new `--output-directory`; receipt-bearing fixture paths are absolute and must not
be copied or relocated.

## Robustness lanes

Compile the offline receipt-inspection fuzz target with:

```sh
cargo make fuzz-check
```

Run its bounded smoke lane with:

```sh
cargo make test-fuzz
```

`cargo-fuzz` 0.13 or newer and an installed Rust nightly toolchain are prerequisites. For an
unbounded session, run `cargo +nightly fuzz run inspect_receipt` from `fuzz/`. Preserve the
generated artifact and exact replay command for every failure. Fuzzing is separate from the default
gate.

Run the ignored seeded lifecycle simulation with:

```sh
cargo make test-simulation
```

The defaults use seed `21182435914953528` and 1,000 cases. Replay or lengthen a run explicitly:

```sh
KAPSEL_SIMULATION_SEED=21182435914953528 \
KAPSEL_SIMULATION_CASES=10000 \
cargo make test-simulation
```

The simulation injects generated mutation and receipt-publication crash windows, reopens the same
journal, and asserts provider-call counts, receiver classification, terminal state, and frozen
receipt location after every case. It uses no live cluster and is separate from the default gate.

## Qualification baseline

The accepted KAP-0061 native-Linux baseline is validated without reading raw journals, provider
bodies, receipt bytes, or key material:

```sh
python3 scripts/validate-kap0061-baseline.py qualification/kap0061-baseline.json
python3 scripts/test-validate-kap0061-baseline.py
cargo make test-kap0061-privacy
```

After every correction and qualification input is committed, rerun all finite lanes and replace the
tracked baseline through the closed orchestrator:

```sh
cargo make qualify-kap0061
```

This command requires a clean tree, Docker, kind, kubectl, cargo-fuzz/nightly, cargo-audit 0.22.2,
Trivy 0.72.0 with current databases, the pinned builder image, and the host Cargo registry. It runs
the default/hostile, simulation, fuzz, historical subprocess, deterministic demo, live-kind,
measurement, security, and privacy lanes. It writes only the closed aggregate manifest after every
lane passes.

The pinned x86-64 measurement harness requires a clean tree, Docker, the already pulled builder
image, and the host Cargo registry. It builds and runs inside the fixed 8-CPU, 8-GiB isolated
container and writes bounded aggregates to a caller-selected temporary path:

```sh
python3 scripts/run-kap0061-measurements.py --output /tmp/kap0061-measurements.json
```

The semantic lanes remain `cargo make test-simulation`, `cargo make test-fuzz`,
`cargo make test-v011-upgrade`, `cargo make test-demo-harness`, and `cargo make test-kind`. The
active candidate-production packet must apply the baseline manifest's invalidation rules before
treating any result as candidate evidence. These commands are qualification evidence, not production
performance or support claims.

## Live Kubernetes gate

The explicit live gate requires a working Docker daemon and `kind` 0.32 or newer:

```sh
cargo make test-kind
```

The direct script equivalent is `./scripts/test-kind-effect-gateway.sh`.

It precompiles the tests, creates a uniquely named disposable cluster from a pinned Kubernetes 1.33
node-image digest, preloads the fixture images, and runs three fault-injected post-patch
journal-reopen paths. The healthy path verifies the exact target image and unchanged untargeted
container. The unhealthy-image path verifies no second patch, observes `ProgressDeadlineExceeded`,
freezes a `FAILED` receipt, and inspects every signed classifier input offline. The bounded-unknown
path deletes the exact Deployment after one returned patch, verifies restart makes no second patch,
exhausts the 30-read production schedule, and inspects an `UNKNOWN` receipt. The script removes only
the cluster it created. On a test failure after cluster creation, it exports kind logs under
`$TMPDIR` before cleanup.

This live gate is not part of hosted deterministic CI. The separate default test suite provides the
real process-kill/restart proof; the live tests use same-process fault injection and journal reopen.

## Public crash-recovery demonstration

Run the complete release-owned demonstration with:

```sh
cargo make demo-kind
```

It requires Docker, `kind` 0.32 or newer, `kubectl` 1.30 or newer, and Python 3.11 or newer. It
refuses pre-existing `kind` clusters before mutation, creates one uniquely named cluster, builds the
same production executable with the private `demo-harness` feature, and uses the supported grant,
operation, restart, and inspection commands. It shows a healthy rollout, kills the failed-rollout
process after one returned mutation, kills it again after frozen receipt publication, restarts under
rotated receipt settings, and inspects the `ProgressDeadlineExceeded` receipt offline. Cleanup
removes only its owned cluster and host directory; bounded failure diagnostics are retained under
`$TMPDIR`.

Run its deterministic process and prerequisite proofs without Docker or `kind`:

```sh
cargo make test-demo-harness
```

The feature-gated binary is demonstration-only. Ordinary builds contain no marker or pause behavior,
and fault control is not part of agent input, operator JSON, or the public Rust interface.

## Evaluator commands

Build the Unix executable from this checkout:

```sh
cargo build --locked --bin kapsel
```

Its three fixed forms provision an exact operator grant, run or reconcile the configured operation,
and inspect a receipt offline:

```sh
target/debug/kapsel provision-grant \
  --authorization /absolute/authorization.json \
  --signing-seed /absolute/owner.seed \
  --signing-key-id owner-key \
  --output /absolute/grant.bin

target/debug/kapsel operate \
  --request /absolute/request.json \
  --operator-config /absolute/operator.json

target/debug/kapsel inspect \
  --receipt /absolute/result.receipt \
  --trust /absolute/receipt.trust \
  --evaluation-time-unix-s 150
```

See the [evaluator command contract](COMMANDS.md) for exact JSON fields, authority separation,
limits, machine output, and exit classes. These forms are the supported v0.2.x beta CLI surface, not
a production or v1-stable interface.

## MCP adapter

Run the focused deterministic black-box MCP proof with:

```sh
cargo test --locked --test e2e_mcp_adapter
```

Start the fixed stdio process with one separately provisioned operator configuration:

```sh
target/debug/kapsel mcp --operator-config /absolute/operator.json
```

The [MCP adapter contract](MCP.md) owns protocol version `2025-11-25`, newline-delimited stdio,
initialization, the sole fixed-schema tool, bounds, shutdown, and response vocabulary. The adapter
uses the same `Application` and operator-file composition as `operate`; it does not use Docker,
`kind`, ambient Kubernetes configuration, or the demonstration feature.

## Release artifact

The sole release target is `x86_64-unknown-linux-gnu`, validated in pinned x86-64 Debian 12 build
and smoke containers. Assemble it only from a clean checkout:

```sh
cargo make assemble-release
```

This emits one normalized `.tar.gz` archive plus deterministic `.sha256`, `.spdx.json`, and
`.SHA256SUMS` sidecars under `dist/`. The archive contains the ordinary executable, a separately
named feature-gated demo executable, the owned demo script and public trust vector, standalone CLI,
MCP, evaluator, release, upgrade, security, and privacy documentation, license, changelog, and fixed
provenance metadata. It contains no evaluator authority, credentials, journals, receipts, or
outputs.

Run the complete artifact-only proof from a clean checkout with Docker while keeping A outside the
worktree:

```sh
a_dir=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-release-a.XXXXXX")
archive_a=$(python3 scripts/assemble-release-artifact.py --output-directory "$a_dir")
python3 scripts/test-release-artifact.py --archive "$archive_a"
python3 scripts/test-release-reproducibility.py --reference-archive "$archive_a"
```

The first verifier preserves the synthetic hostile-archive matrix, validates exact A, and exercises
only extracted A files in the pinned clean container. The second performs exactly one independent
strict assembly B in separate target/output storage and compares archive, checksum, SBOM, and
digest-manifest bytes. Remove `"$a_dir"` after use. See the
[testing strategy](TESTING.md#release-artifact-proof) for the exact proof and
[release artifact contract](RELEASE.md) for the owned format and bounds.

On clean x86-64 Linux revision `0f86e7c`, a cold two-assembly proof took 5m11s: A assembly 2m31s,
exact-A hostile/layout/smoke 11s, and B assembly plus four-file comparison 2m29s. The prior hosted
four-assembly job took 11m55s. These are diagnostic measurements, not duration guarantees.

Scan one exact SPDX sidecar with the KAP-0061-frozen Trivy 0.72.0 policy and a vulnerability
database no older than 24 hours:

```sh
KAPSEL_RELEASE_SBOM=/absolute/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz.spdx.json \
KAPSEL_RELEASE_SBOM_SCAN=/absolute/kap0062-sbom-scan.json \
  cargo make scan-release-sbom
```

The lane refreshes the database immediately before scanning, hashes it before and after the
no-update scan, and writes a bounded summary recording SBOM digest, scanner/database identity,
database digest and time, and every detected finding. It rejects `HIGH` or `CRITICAL` findings. It
is candidate review evidence, not a release sidecar or complete vulnerability-absence claim.

Drive an extracted candidate through one clean finalized exact-v0.1.1 journal, operator backup,
migration-only open/reopen, retained receipt inspection, restore/re-mark, and direct exact-v0.1.1
downgrade with:

```sh
KAPSEL_RELEASE_ARCHIVE=/absolute/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz \
KAPSEL_V011_ARCHIVE=/absolute/kapsel-0.1.1-x86_64-unknown-linux-gnu.tar.gz \
  cargo make test-release-upgrade
```

The historical archive must match the immutable accepted v0.1.1 SHA-256. This artifact-only lane
complements rather than replaces the nine-state, 54-process-seam source fixture matrix.

On every push and pull request, hosted CI runs the same two-assembly proof. A stays outside the
worktree through smoke and A/B comparison. On a push only, the workflow then copies the exact four A
files byte-for-byte to `dist/` and uploads them under the source revision. Pull requests perform no
upload. The GitHub-generated download wrapper is transport only.

The unpublished authenticated candidate is produced only by manually dispatching
`.github/workflows/release-candidate.yml` on `master` at the exact candidate revision. That
least-privilege workflow runs the same two-assembly A-smoke/A-B-comparison proof, copies exact A to
`dist/`, installs Cosign v3.1.2 through a commit-pinned action, keylessly signs the exact
`.SHA256SUMS` bytes, verifies the issuer plus repository/workflow/ref/SHA/trigger certificate
identity, and uploads the resulting bounded `.sigstore.json` bundle with the four deterministic
files. The bundle is intentionally nondeterministic and publication remains KAP-0063-owned. See
[Release artifacts](RELEASE.md) for connected/offline trust, expiry, compromise, withdrawal, and
replacement rules. A dependent clean job downloads that workflow artifact, re-authenticates the
exact bytes, drives operation/restart/MCP/inspection/cleanup/uninstall in the pinned smoke
container, runs the extracted live-kind demo, and crosses the exact v0.1.1 finalized
upgrade/restore/downgrade pair. This is unpublished candidate-download evidence; KAP-0063 still owns
public-release download verification.

On a supported x86-64 GNU/Linux host, run the live disposable-kind demonstration directly from the
safely extracted archive top-level directory:

```sh
./share/kapsel/demo-kind-crash-recovery.sh
```

A repository checkout can drive a named archive through the same live gate with:

```sh
KAPSEL_RELEASE_ARCHIVE=/absolute/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz \
  cargo make demo-release-artifact
```

The source-built `cargo make demo-kind` route remains available. All routes use the same script;
artifact mode refuses missing, relative, symlinked, or non-executable release inputs before Docker
or cluster inspection. See [Release artifacts](RELEASE.md) and the bundled
[evaluator guide](EVALUATOR.md) for exact layout, installation, provenance, expected output, failure
meaning, cleanup, unsupported targets, and non-claims. Public `0.1.1` assets are attached to the
[Kapsel 0.1.1 release](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.1.1); final evidence
is recorded in [KAP-0049](../tasks/KAP-0049.md). Historical `0.1.0` evidence remains in
[KAP-0045](../tasks/KAP-0045.md).

## Sandbox preservation lanes

Validate fixed public bytes without a service or network:

```sh
cargo make test-sandbox-contract
```

Validate the provider-neutral conditional patch and active-route deletion boundary:

```sh
cargo make test-sandbox-preservation
```

Run retained deterministic package lanes with:

```sh
cargo make test-sandbox-serialized-capacity
cargo make test-sandbox-cluster-policy
cargo make test-sandbox-service
cargo make test-sandbox-runner-handoff
cargo make test-sandbox-runner-host
cargo make test-sandbox-package-boundary
```

On the exact supported Linux environments, the existing focused privilege lanes remain:

```sh
cargo make test-sandbox-runner-host-linux
cargo make test-sandbox-fixed-staging-identities-linux
```

These prove only their named offline descriptor, identity, cgroup, authority-staging, conditional
mutation, cleanup, handoff, and package assertions. They use no provider account and do not prove
live runtime, CNI, metadata, network, abuse control, teardown, endpoint, DNS, spend, or traffic.

KAP-0072 removes the reserved `test-sandbox-backup-restore` lane and every planned backup/restore
command. Checkpoint `bde1e3b` is historical evidence, not a runnable deployment gate.

The next implementation must first delete backup-only code while keeping the retained commands
green. Later contract-first work may add a deterministic catastrophe lane only after its Make task
exists; it must prove no manufactured outcome and clean-start stop, not restoration. A separately
selected abuse-control lane must exercise real pre-admission source bounds. Private-live teardown,
zero-inventory, clean recreation twice, and independent traffic cutoff remain separately authorized
KAP-0070 gates and must not appear in this guide before runnable commands exist.

## Toolchain

Authoritative inputs are `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`,
`rustfmt-nightly.toml`, `clippy.toml`, `Makefile.toml`, `.github/workflows/ci.yml`, and
`scripts/ci-local.sh`.

Cargo-make, Prettier 3, and Python 3.11 or newer are repository prerequisites. Hosted CI pins the
Rust toolchain, Prettier version, and Python 3.11. Python, shell, Docker, kind, kubectl, Cosign,
Trivy, and curl are build, qualification, release, or demonstration prerequisites where named; they
are not Kapsel caller interfaces. The ordinary installed executable requires none of them merely to
start, report its version, or expose the adopted local and MCP grammar.
