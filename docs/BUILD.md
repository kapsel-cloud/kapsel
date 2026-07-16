# Build

Status: deterministic repository and live-kind gates implemented; public commands planned.

Kind: guide. Authority: commands that exist and their present meaning.

Owns: Runnable repository commands, prerequisites, and CI lanes.

Does not own: Technical scope or planned command design.

## Default gate

Run the deterministic, containerless repository gate:

```sh
./scripts/ci-local.sh
```

It checks Rust and Markdown formatting, local Markdown links and heading anchors, Rust line width,
project tidy rules, Clippy, warning-free rustdoc, workspace unit/binary tests, and documentation
tests. Missing public rustdoc, unreachable bare-`pub` items, missing `# Errors`/`# Panics` sections,
and broken or private intra-doc links are denied.

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
recovery behavior is library-only. The deterministic suite includes real subprocess kill/restart
proofs at the mutation and receipt-publication seams. There is no public operation or inspection
command yet.

## Live Kubernetes gate

The explicit live gate requires a working Docker daemon and `kind` 0.32 or newer:

```sh
./scripts/test-kind-effect-gateway.sh
```

It precompiles the tests, creates a uniquely named disposable cluster from a pinned Kubernetes 1.33
node-image digest, preloads the fixture images, and runs two fault-injected post-patch
journal-reopen paths. The healthy path verifies the exact target image and unchanged untargeted
container. The unhealthy-image path verifies no second patch, observes `ProgressDeadlineExceeded`,
freezes a `FAILED` receipt, and inspects every signed classifier input offline. The script removes
only the cluster it created. On a test failure after cluster creation, it exports kind logs under
`$TMPDIR` before cleanup.

This live gate is not part of hosted deterministic CI. The separate default test suite provides the
real process-kill/restart proof; the live tests use same-process fault injection and journal reopen.

## Missing release commands

No evaluator-facing operation CLI, offline-inspection CLI, MCP entrypoint, or V1 install artifact
exists. The pre-V1 crates.io alpha exposes only the implemented Rust experiment interface; it does
not satisfy the V1 artifact, command, or platform-support contract. Do not publish a quickstart or
command syntax for missing surfaces until implementation and tests exist.

## Toolchain

Authoritative inputs are `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`,
`rustfmt-nightly.toml`, `clippy.toml`, `Makefile.toml`, `.github/workflows/ci.yml`, and
`scripts/ci-local.sh`.

Cargo-make, Prettier 3, and Python 3.11 or newer are repository prerequisites. Hosted CI pins the
Rust toolchain, Prettier version, and Python 3.11.
