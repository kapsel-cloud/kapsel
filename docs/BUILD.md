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

The managed pre-commit hook runs this complete default gate rather than formatting alone:

```sh
cargo make hooks-install
```

Format before review:

```sh
cargo make fmt
cargo make fmt-check
```

`cargo make fmt` formats Rust and Markdown. `cargo make fmt-check` checks both without rewriting.

Validate the demonstration-scoped public sandbox fixtures without a service or network:

```sh
cargo make test-sandbox-contract
```

The direct command is `python3 scripts/test-sandbox-contract.py`. It validates the fixed KAP-0051
HTTP transcripts, field bounds, replay ordering, outcome separation, disclosure key set, and raw
receipt digest. It is contract evidence, not a sandbox implementation or live deployment proof.

Run the deterministic KAP-0052 service, fixture, dependency, and deletion-boundary proof with:

```sh
cargo make test-sandbox-service
```

The focused package test crosses strict HTTP translation, durable admission/restart, the real
`Application` against a deterministic Kubernetes transport, exact receipt publication/retrieval,
retention, and cleanup. The boundary script also compiles the ordinary root package from a temporary
copy after deleting `kapsel-sandbox`. This lane uses no Docker, Kubernetes cluster, network,
website, or deployment provider; KAP-0053 owns those live properties.

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

## Live Kubernetes gate

The explicit live gate requires a working Docker daemon and `kind` 0.32 or newer:

```sh
cargo make test-kind
```

The direct script equivalent is `./scripts/test-kind-effect-gateway.sh`.

It precompiles the tests, creates a uniquely named disposable cluster from a pinned Kubernetes 1.33
node-image digest, preloads the fixture images, and runs two fault-injected post-patch
journal-reopen paths. The healthy path verifies the exact target image and unchanged untargeted
container. The unhealthy-image path verifies no second patch, observes `ProgressDeadlineExceeded`,
freezes a `FAILED` receipt, and inspects every signed classifier input offline. The script removes
only the cluster it created. On a test failure after cluster creation, it exports kind logs under
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

Build the prototype Unix executable from this checkout:

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
limits, machine output, and exit classes. These are prototype commands, not a stable installed CLI.

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

This emits one normalized `.tar.gz` archive and adjacent SHA-256 file under `dist/`. The archive
contains the ordinary executable, a separately named feature-gated demo executable, the owned demo
script and public trust vector, standalone evaluator documentation, license, changelog, and fixed
provenance metadata. It contains no evaluator authority, credentials, journals, receipts, or
outputs.

Run the artifact-only deterministic lane with Docker:

```sh
cargo make test-release-artifact
```

It assembles and validates the archive, then exercises only extracted files in the pinned clean
container. See the [testing strategy](TESTING.md#kap-0044-release-artifact-proof) for the exact
proof and [release artifact contract](RELEASE.md) for the owned format and bounds.

Verify two isolated builds produce identical archive and checksum bytes with:

```sh
cargo make test-release-reproducibility
```

After those lanes pass on a push, hosted CI performs one strict clean assembly and uploads the
versioned `.tar.gz` and adjacent checksum as a workflow artifact named with the source revision. The
GitHub-generated download wrapper is transport only; the adjacent checksum still identifies the
inner `.tar.gz` bytes.

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

## Toolchain

Authoritative inputs are `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`,
`rustfmt-nightly.toml`, `clippy.toml`, `Makefile.toml`, `.github/workflows/ci.yml`, and
`scripts/ci-local.sh`.

Cargo-make, Prettier 3, and Python 3.11 or newer are repository prerequisites. Hosted CI pins the
Rust toolchain, Prettier version, and Python 3.11.
