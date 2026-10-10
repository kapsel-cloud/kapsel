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
access for missing ones. It changes neither shell profiles nor Git hooks. `doctor` checks without
installing or rewriting source; Cargo may first prepare xtask. Use `./scripts/setup.sh --check` on
an unprepared host to bypass that bootstrap.

[`tools/dev/dev-tools.sh`](../../tools/dev/dev-tools.sh) owns contributor-tool versions. CI uses the
same setup and contributor-tool pins. GitHub Action references are specified separately in each
workflow. Stock Cargo commands retain their normal meaning; xtask runs the broader contributor
workflow.

## Before review

```sh
cargo xtask fmt
cargo xtask ci
```

Formatting runs Markdown, Rust, and Python, including fuzz sources and Python fixtures. It does not
apply lint fixes. The deterministic gate checks formatting, Python lint/types, Markdown links,
tooling regressions, Rust line width, Clippy, rustdoc, deterministic tests, and doctests. It does
not start Docker or a cluster.

For a smaller iteration:

```sh
cargo xtask fmt-check
cargo xtask ci static  # formatting, lint, types, links, and tooling regressions
cargo xtask ci rust    # Clippy, rustdoc, and deterministic Rust tests
cargo xtask ci doc     # Rust doctests
```

Documentation-only changes need formatting, local link and anchor checks, terminology review, and
`git diff --check`. Changed examples also need their owning executable check. Cross-cutting code or
contract changes need the full deterministic gate and any relevant platform, live, or artifact lane.
Missing prerequisites mean missing evidence, not a passing substitute.

## Focused gates

| Change                     | Command                                                                           |
| -------------------------- | --------------------------------------------------------------------------------- |
| Core effect or application | `cargo test --locked -p kapsel`                                                   |
| Shared authority           | `cargo test --locked -p kapsel-authority`                                         |
| Service or private harness | `cargo test --locked -p kapsel-daemon --features test-harness`                    |
| Installed assets           | `cargo test --locked -p kapsel-daemon --test install_assets`                      |
| MCP bridge                 | `cargo test --locked -p kapsel-daemon --features test-harness --test service_mcp` |
| Fresh-session caller       | `python3 examples/test_fresh_session_caller.py`                                   |
| Formatting pipeline        | `python3 tools/dev/test_format.py`                                                |
| Python tooling             | `cargo xtask ci static`                                                           |

[Test strategy](testing.md) explains where tests belong. The [evidence map](evidence.md) connects
guarantees to checks. [Qualification](qualification.md) contains Linux process, real Git, live
Kubernetes, ENOSPC, simulation, fuzz, security-scan, and artifact commands with their prerequisites.
Those lanes are separate from the everyday loop; run the ones required by the changed boundary.

The `fuzz` crate is outside the workspace for cargo-fuzz and does not inherit workspace settings.
The deterministic Rust gate checks its locked dependency graph, Clippy diagnostics, and maintained
corpus through explicit fuzz-manifest commands. Formatting includes its source. Exploratory fuzzing
remains a separate qualification lane.

## Optional hooks

Inspect any existing custom hook path before enabling repository hooks:

```sh
git config --get core.hooksPath
git config core.hooksPath .githooks
```

Pre-commit checks staged whitespace only. Pre-push requires a clean checkout matching the pushed
tree and runs the full local gate, reusing a passing result for the same tree. CI independently runs
the gate. Neither hook starts Docker. See [the hooks](../../.githooks) for refusal and caching
rules.
