# Build and test Kapsel

Use this page to find runnable commands and prerequisites. [Testing](TESTING.md) explains proof
strategy; direct contracts own behavior and evidence limits.

## Prerequisites

The deterministic gate uses Rust 1.98, Python 3.11+, Node.js 24, and Prettier 3.6.2 as pinned by the
repository. Additional lanes require:

- Docker and kind 0.32+ for live Kubernetes;
- kubectl 1.30+ for the public demonstration;
- cargo-fuzz 0.13+ and the pinned Rust nightly for fuzzing;
- Linux and `sg` for the ignored distinct-effective-group service test;
- Docker for installer bundle and release-artifact lanes; and
- Docker, kind, kubectl, cargo-fuzz, Rust nightly, cargo-audit 0.22.2, Trivy 0.72.0 with current
  databases, the pinned builder image, and the host Cargo registry for finite qualification.

## Deterministic gate and formatting

Run the complete local gate:

```sh
./scripts/ci-local.sh
```

Format Rust and Markdown, or check formatting without changing files:

```sh
./scripts/format.sh
./scripts/format.sh --check
```

Use the tracked pre-commit hook:

```sh
git config core.hooksPath .githooks
```

If `git config core.hooksPath` already reports a custom path, inspect it before replacing it.

Use `cargo run --quiet --locked -p kapsel-dev --bin kapsel-tidy -- tidy` for project-specific hard
hygiene checks.

## Focused gates

| Change                           | Smallest useful command                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------------------ |
| Effect-gateway library           | `cargo test --locked -p kapsel`                                                            |
| Effect-gateway Clippy            | `cargo clippy --locked -p kapsel --all-targets -- -D warnings`                             |
| Kapsel service                   | `cargo test --locked -p kapseld --features test-harness`                                   |
| Service operator-input seam      | `cargo test --locked -p kapsel-authority`                                                  |
| Installer skeleton               | `cargo test --locked -p kapsel-installer`                                                  |
| Linux-only installer/bundle code | `python3 scripts/test-kapsel-installer-bundle.py`                                          |
| Service installed assets         | `cargo test --locked -p kapseld --test install_assets`                                     |
| MCP adapter                      | `cargo test --locked --test e2e_mcp_adapter`                                               |
| Upgrade and rollback             | `python3 scripts/test-v011-upgrade-fixtures.py`                                            |
| Crash-demo harness               | `./scripts/test-demo-harness.sh`                                                           |
| Seeded lifecycle simulation      | `./scripts/test-simulation.sh`                                                             |
| Receipt-inspection fuzz smoke    | `./scripts/test-fuzz.sh`                                                                   |
| Live Kubernetes behavior         | `./scripts/test-kind-effect-gateway.sh`                                                    |
| Full local demonstration         | `./scripts/demo-kind-crash-recovery.sh`                                                    |
| Release artifact                 | `python3 scripts/assemble-release-artifact.py --output-directory dist`                     |
| Finite beta qualification        | `python3 scripts/run-beta-qualification.py --output /tmp/beta-qualification-baseline.json` |

## Kapsel service candidate

The service in repository HEAD is unpublished. Run its package, lint, and private-harness gates:

```sh
cargo test --locked -p kapseld
cargo clippy --locked -p kapseld --all-targets -- -D warnings
cargo test --locked -p kapseld --features test-harness
```

Run the Linux-only process test:

```sh
cargo test --locked -p kapseld --features test-harness --test linux_process
```

On Linux with `sg`, run the ignored distinct-effective-group case:

```sh
cargo test --locked -p kapseld --features test-harness --test linux_process \
  distinct_effective_gid_is_denied_before_frame_read -- --ignored --exact
```

See [Kapsel service](KAPSEL_SERVICE.md) for exact service evidence and limits.

## Kapsel installer skeleton

The installer in repository HEAD is partial and unpublished. Run its fixed authority seam and
portable package gates:

```sh
cargo test --locked -p kapsel-authority
```

```sh
cargo test --locked -p kapsel-installer
cargo clippy --locked -p kapsel-installer --all-targets --all-features -- -D warnings
```

Run the Linux/Docker bundle smoke:

```sh
python3 scripts/test-kapsel-installer-bundle.py
```

Default builds stop at `bundle_unavailable`; the Docker smoke uses test-only staged payloads to
cross the implemented recovery seams. [Architecture](ARCHITECTURE.md#partial-installer) summarizes
the current implementation, and [Kapsel service](KAPSEL_SERVICE.md) owns its exact boundary.

## Upgrade and rollback fixture gate

Run the source fixture matrix without Kubernetes or network access:

```sh
python3 scripts/test-v011-upgrade-fixtures.py
```

See [Upgrade and rollback](UPGRADE.md) for supported behavior and limits.

## Robustness lanes

Check the fuzz target with the pinned nightly, or run the bounded smoke script:

```sh
rustup run nightly-2026-07-03 cargo fuzz check --manifest-path fuzz/Cargo.toml inspect_receipt
./scripts/test-fuzz.sh
```

For a longer session, run `cargo +nightly fuzz run inspect_receipt` from `fuzz/`.

Run the seeded lifecycle simulation:

```sh
./scripts/test-simulation.sh
```

Override its defaults for replay or a longer run:

```sh
KAPSEL_SIMULATION_SEED=21182435914953528 \
KAPSEL_SIMULATION_CASES=10000 \
./scripts/test-simulation.sh
```

## Candidate qualification

Run every finite qualification lane against one committed clean candidate:

```sh
python3 scripts/run-beta-qualification.py --output /tmp/beta-qualification-baseline.json
```

Validate the resulting baseline:

```sh
python3 scripts/validate-beta-qualification-baseline.py \
  /absolute/beta-qualification-baseline.json
```

Qualification is finite candidate evidence, not a production or support claim.

## Live Kubernetes gate

With Docker and kind 0.32+:

```sh
./scripts/test-kind-effect-gateway.sh
```

The script owns creation, failure-log export, and cleanup of its uniquely named cluster. This lane
is separate from deterministic CI.

## Public crash-recovery demonstration

With Docker, kind 0.32+, kubectl 1.30+, and Python 3.11+:

```sh
./scripts/demo-kind-crash-recovery.sh
```

Test the demonstration harness without Docker:

```sh
./scripts/test-demo-harness.sh
```

## Evaluator CLI

Build the executable:

```sh
cargo build --locked --bin kapsel
```

Run its fixed forms:

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

See [Evaluator commands](COMMANDS.md) for input, authority, output, and exit contracts.

## MCP adapter

Run the black-box proof and start the fixed stdio process:

```sh
cargo test --locked --test e2e_mcp_adapter
target/debug/kapsel mcp --operator-config /absolute/operator.json
```

See [MCP](MCP.md) for protocol details.

## Release artifact

The sole release target is `x86_64-unknown-linux-gnu`. Assemble files under `dist/`:

```sh
python3 scripts/assemble-release-artifact.py --output-directory dist
```

Run the complete two-assembly proof outside the worktree:

```sh
a_dir=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-release-a.XXXXXX")
archive_a=$(python3 scripts/assemble-release-artifact.py --output-directory "$a_dir")
python3 scripts/test-release-artifact.py --archive "$archive_a"
python3 scripts/test-release-reproducibility.py --reference-archive "$archive_a"
```

Remove `"$a_dir"` afterward. [Release artifacts](RELEASE.md) owns layout, authentication,
publication, evidence, and withdrawal rules.

From an extracted artifact top-level directory, run the live demonstration:

```sh
./share/kapsel/demo-kind-crash-recovery.sh
```

Or run a named archive from a checkout:

```sh
python3 scripts/smoke-release-artifact.py \
  --archive /absolute/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz \
  --live-demo
```

## Coverage

Generate informational source coverage:

```sh
cargo llvm-cov --locked --workspace --codecov --output-path codecov.json
```

Coverage is non-blocking information, not correctness evidence.

## Toolchain ownership

Executable build inputs are `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`,
`rustfmt-nightly.toml`, `clippy.toml`, `.github/workflows/ci.yml`, `scripts/format.sh`, and
`scripts/ci-local.sh`. When prose and an executable command disagree, correct the guide and its
direct contract before relying on the prose.
