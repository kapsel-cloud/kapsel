# Build and test Kapsel

Status: current.

Use this page to find a runnable command. Contracts explain behavior; this page does not repeat
their rationale or evidence.

## Start here

Kapsel uses Rust, Cargo Make, Python 3.11+, and Prettier 3. Run the complete deterministic gate:

```sh
./scripts/ci-local.sh
```

Equivalent aliases are `cargo make check` and `cargo make ci`. The gate formats and checks Rust and
Markdown, validates local documentation links and anchors, runs Clippy and rustdoc with warnings
denied, and executes workspace tests.

Before review:

```sh
cargo make fmt
cargo make fmt-check
```

Install the repository-managed pre-commit hook with `cargo make hooks-install`. It runs the complete
gate for every content-changing commit.

## Choose a focused gate

| Change                           | Smallest useful command                                        |
| -------------------------------- | -------------------------------------------------------------- |
| Effect-gateway library           | `cargo test --locked -p kapsel`                                |
| Effect-gateway Clippy            | `cargo clippy --locked -p kapsel --all-targets -- -D warnings` |
| Kapsel service                   | `cargo test --locked -p kapseld --features test-harness`       |
| Installer skeleton               | `cargo test --locked -p kapsel-installer`                      |
| Linux-only installer/bundle code | `cargo make test-installer-bundle`                             |
| Service installed assets         | `cargo test --locked -p kapseld --test install_assets`         |
| MCP adapter                      | `cargo test --locked --test e2e_mcp_adapter`                   |
| Upgrade and rollback             | `cargo make test-v011-upgrade`                                 |
| Crash-demo harness               | `cargo make test-demo-harness`                                 |
| Seeded lifecycle simulation      | `cargo make test-simulation`                                   |
| Receipt-inspection fuzz smoke    | `cargo make test-fuzz`                                         |
| Live Kubernetes behavior         | `cargo make test-kind`                                         |
| Full local demonstration         | `cargo make demo-kind`                                         |
| Release artifact                 | `cargo make assemble-release`                                  |
| Finite beta qualification        | `cargo make qualify-beta`                                      |

Use `cargo make tidy` for project-specific hard hygiene checks. `cargo make style-audit` emits
non-blocking review prompts.

## Kapsel service candidate

The unpublished service has deterministic package tests:

```sh
cargo test --locked -p kapseld
cargo clippy --locked -p kapseld --all-targets -- -D warnings
cargo test --locked -p kapseld --features test-harness
```

The Linux-only process test proves peer credentials, disconnect-independent execution, reconnect,
and process loss without creating users or touching systemd:

```sh
cargo test --locked -p kapseld --features test-harness --test linux_process
```

The ignored distinct-effective-group case requires Linux and `sg`:

```sh
cargo test --locked -p kapseld --features test-harness --test linux_process \
  distinct_effective_gid_is_denied_before_frame_read -- --ignored --exact
```

The service contract owns what these gates prove and do not prove. See
[Kapsel service](KAPSEL_SERVICE.md).

## Kapsel installer skeleton

The unpublished installer package's portable gate proves its fixed command grammar, fail-closed
development build, strict bootstrap-kubeconfig parser, and canonical prepared-transaction codec:

```sh
cargo test --locked -p kapsel-installer
cargo clippy --locked -p kapsel-installer --all-targets --all-features -- -D warnings
```

The installer produced by default workspace builds deliberately contains no embedded service
payloads. An otherwise valid mutating invocation exits before host access with `bundle_unavailable`;
installation is not yet runnable. The release-only build seam accepts one structurally bounded fixed
stage through `KAPSEL_INSTALLER_STAGE`. The explicit Docker smoke uses test-only ELF fixtures and
root-owned test operator input; it proves bundle generation, descriptor-relative exact input
inventory and metadata checks, grant/key/receipt consistency, valid kubeconfig composition, hostile
filesystem refusal, exact installer-lock handling and named-object modes under a hostile umask,
kill/restart recovery after lock and transaction-directory creation, recovered-parent sync before
crash-safe transaction publication, marked phase-successor update and recovery, and the next
`implementation_incomplete` boundary:

```sh
cargo make test-installer-bundle
```

No host preflight, installation, Kubernetes mutation, credential issuance, activation, refresh, or
uninstall runs yet. No candidate assembly command exists. Exact metadata schema and provenance, real
feature-free payload construction, deterministic assembly, and the final linked installer's 64 MiB
bound remain candidate-assembly work.

## Upgrade and rollback fixture gate

Run the source fixture matrix with:

```sh
cargo make test-v011-upgrade
```

The direct command is `python3 scripts/test-v011-upgrade-fixtures.py`. It checks all nine historical
lifecycle states, migration interruption, restore interruption, repeated reopen, exact rows,
provider-call counts, and frozen receipt bytes. It uses no Kubernetes cluster or network. The
[upgrade contract](UPGRADE.md) owns supported behavior and limits.

## Robustness lanes

Compile or briefly run the receipt-inspection fuzz target:

```sh
cargo make fuzz-check
cargo make test-fuzz
```

These commands require cargo-fuzz 0.13+ and Rust nightly. For a longer session, run
`cargo +nightly fuzz run inspect_receipt` from `fuzz/`.

Run the seeded lifecycle simulation:

```sh
cargo make test-simulation
```

Override its defaults when reproducing or extending a run:

```sh
KAPSEL_SIMULATION_SEED=21182435914953528 \
KAPSEL_SIMULATION_CASES=10000 \
cargo make test-simulation
```

## Candidate qualification

Run every finite qualification lane against one committed clean candidate:

```sh
cargo make qualify-beta
```

This requires Docker, kind, kubectl, cargo-fuzz and Rust nightly, cargo-audit 0.22.2, Trivy 0.72.0
with current databases, the pinned builder image, and the host Cargo registry. A successful run
writes `/tmp/beta-qualification-baseline.json`. Validate it with:

```sh
python3 scripts/validate-beta-qualification-baseline.py \
  /absolute/beta-qualification-baseline.json
```

Qualification is candidate evidence, not a production or support claim.

## Live Kubernetes gate

With Docker and kind 0.32+:

```sh
cargo make test-kind
```

The gate creates and removes one uniquely named cluster. It exercises successful, failed, and
bounded-unknown receiver paths without a blind second patch. On failure it exports kind logs under
`$TMPDIR` before cleanup. It is separate from deterministic CI.

## Public crash-recovery demonstration

With Docker, kind 0.32+, kubectl 1.30+, and Python 3.11+:

```sh
cargo make demo-kind
```

The demonstration creates its own cluster, runs healthy and failed-rollout paths, kills the real
process around mutation and receipt publication, restarts, inspects the frozen receipt, and cleans
up. Test the harness without Docker using `cargo make test-demo-harness`.

## Evaluator CLI

Build the executable:

```sh
cargo build --locked --bin kapsel
```

Its fixed forms are:

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

See [Evaluator commands](COMMANDS.md) for exact inputs, authority separation, output, and exit
classes.

## MCP adapter

Run its black-box proof and start the fixed stdio process with:

```sh
cargo test --locked --test e2e_mcp_adapter
target/debug/kapsel mcp --operator-config /absolute/operator.json
```

See [MCP adapter](MCP.md) for the protocol and fixed tool schema.

## Release artifact proof

The sole release target is `x86_64-unknown-linux-gnu`. Assemble deterministic files under `dist/`:

```sh
cargo make assemble-release
```

Run the complete two-assembly proof outside the worktree:

```sh
a_dir=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-release-a.XXXXXX")
archive_a=$(python3 scripts/assemble-release-artifact.py --output-directory "$a_dir")
python3 scripts/test-release-artifact.py --archive "$archive_a"
python3 scripts/test-release-reproducibility.py --reference-archive "$archive_a"
```

The proof validates and smoke-tests A, independently assembles B, and compares all deterministic
bytes. Remove `"$a_dir"` afterward. See [Release artifacts](RELEASE.md) for layout, authentication,
publication, and withdrawal rules.

Drive an extracted artifact through the live demonstration from its top-level directory:

```sh
./share/kapsel/demo-kind-crash-recovery.sh
```

Or use a named archive from a checkout:

```sh
KAPSEL_RELEASE_ARCHIVE=/absolute/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz \
  cargo make demo-release-artifact
```

## Coverage

Generate informational coverage with:

```sh
cargo llvm-cov --locked --workspace --codecov --output-path codecov.json
```

Coverage is non-blocking information, not correctness evidence.

## Toolchain ownership

The executable build inputs are `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`,
`rustfmt-nightly.toml`, `clippy.toml`, `Makefile.toml`, `.github/workflows/ci.yml`, and
`scripts/ci-local.sh`. When this guide disagrees with an executable command, correct the guide and
its direct contract before relying on the prose.
