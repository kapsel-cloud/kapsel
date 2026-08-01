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

Run the artifact-only deterministic lane with Docker:

```sh
cargo make test-release-artifact
```

It assembles and validates the archive, then exercises only extracted files in the pinned clean
container. See the [testing strategy](TESTING.md#release-artifact-proof) for the exact proof and
[release artifact contract](RELEASE.md) for the owned format and bounds.

Verify two isolated builds produce identical archive, checksum, SBOM, and digest-manifest bytes
with:

```sh
cargo make test-release-reproducibility
```

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

After those lanes pass on a push, hosted CI performs one strict clean assembly and uploads the four
deterministic files as a workflow artifact named with the source revision. The GitHub-generated
download wrapper is transport only.

The unpublished authenticated candidate is produced only by manually dispatching
`.github/workflows/release-candidate.yml` on `master` at the exact candidate revision. That
least-privilege workflow repeats artifact smoke and reproducibility, assembles once more, installs
Cosign v3.1.2 through a commit-pinned action, keylessly signs the exact `.SHA256SUMS` bytes,
verifies the issuer plus repository/workflow/ref/SHA/trigger certificate identity, and uploads the
resulting bounded `.sigstore.json` bundle with the four deterministic files. The bundle is
intentionally nondeterministic and publication remains KAP-0063-owned. See
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

KAP-0070 is active only for the serialized reshape selected by KAP-0069; provider selection,
deployment, credentials, spend, an endpoint, DNS, and public traffic remain separately gated. These
commands preserve the accepted KAP-0070 Gate 0 evidence and Gate 1 Slice 1 serialized-capacity and
local-role evidence. Historical KAP-0053 Gate 1 and Gate 2 tasks and artifacts are removed; Git
history retains their evidence.

Validate the demonstration-scoped public sandbox fixtures without a service or network:

```sh
cargo make test-sandbox-contract
```

The direct command is `python3 scripts/test-sandbox-contract.py`. It validates the fixed KAP-0051
HTTP transcripts, field bounds, replay ordering, outcome separation, disclosure key set, and raw
receipt digest. It is contract evidence, not a sandbox implementation or live deployment proof.

Validate the topology-neutral exact conditional-patch invariant and Gate 0 deletion boundary with:

```sh
cargo make test-sandbox-preservation
```

The direct command is `python3 scripts/test-sandbox-preservation.py`. It uses only
`deploy/sandbox/admission-fixture.json` and `deploy/sandbox/operator-admission-rule.json`, rejects
all mutation beyond the selected image and operation annotation, and asserts that superseded source,
CLI modes, artifacts, and Make tasks are absent. It uses no Docker, provider, credential, resource,
or network.

Run the focused provider-neutral cluster-policy lane with:

```sh
cargo make test-sandbox-cluster-policy
```

It derives the closed baseline, explicit and generated run inventory, conditional Deployment
comparison, and UID-safe cleanup plan from bounded in-process object bodies. It also proves private
plan integrity before any request, one fixed-authority closed cleanup operation, durable cleanup
failure, ten-second request and 30-second attempt deadlines, and the 2 MiB pre-deserialization body
cap for content-length, chunked, and close-delimited responses. In-memory mocks and loopback HTTP
fixtures verify exact delete/observation behavior. It uses no Docker, kind, network, registry,
provider, credential, or live cluster. It does not prove runtime, CNI, RBAC, admission, metadata, or
network enforcement in Kubernetes.

Run the focused deterministic one-active and concrete local-role proof with:

```sh
cargo make test-sandbox-serialized-capacity
```

It proves exactly one durable dispatch/recovery owner, fail-closed reopen and dispatch for corrupt
capacity state, active-first recovery, FIFO dispatch, cleanup-held capacity through restart, retry,
and escalation, and release only after exact UID/owner absence. It uses no runner process, cluster,
provider, credential, or network.

Run the deterministic KAP-0052 service, fixture, dependency, and deletion-boundary proof with:

```sh
cargo make test-sandbox-service
```

The focused package test crosses strict HTTP translation, durable admission/restart, the real
`Application` against a deterministic Kubernetes transport, exact receipt publication/retrieval,
retention, and cleanup. The boundary script also compiles the ordinary root package from a temporary
copy after deleting `kapsel-sandbox`. This lane uses no Docker, Kubernetes cluster, network,
website, or deployment provider; KAP-0070 owns fresh serialized live evidence.

Run the KAP-0055 provider-neutral private runner handoff proof with:

```sh
cargo make test-sandbox-runner-handoff
```

Run the KAP-0070 Slice 2 fixed native-host boundary and retained process-loss proof without a
container with:

```sh
cargo make test-sandbox-runner-host
```

On a Docker-capable host with the already-pulled pinned builder image and Cargo registry cache, run
the separately named network-disabled x86-64 Debian/Linux numeric-identity gate with:

```sh
cargo make test-sandbox-runner-host-linux
```

The Linux lane remains digest-pinned and network-disabled, and uses an explicitly reviewed
privileged container with a private cgroup namespace solely to provide writable cgroup-v2
delegation. It runs as controller UID/GID 0 and requires the fixed helper to establish numeric real,
effective, and saved UID/GID 65532, empty supplementary groups, `no_new_privs`, fixed descriptors,
parent-death fencing, and cgroup process-tree fencing before authority reaches `Application`. The
lane does not yet prove the focused KAP-0070 follow-up's hostile-parent securebit/capability state,
executable file-capability policy, filesystem-concealment boundary, syscall/path restriction
decision, or final bundle binding. No stronger helper command exists yet. The lane never skips a
missing prerequisite. It is separate because the ordinary development host may be macOS; the
containerless deterministic lane remains mandatory. On non-Linux hosts that lane crosses runner loss
before invocation, after the durable invocation acknowledgment, and after `apply_started`, then
separately preserves one terminal report and its exact receipt bytes across a service reopen without
claiming host replacement. The mandatory Linux/root lane alone executes the terminal-report kill,
system restart, and runner replacement against KAP-0038's frozen receipt path.

The retained handoff proof crosses the exact request/grant match check, strict binary codec,
per-lease credential fencing, durable invocation and terminal-report transactions, separate native
runner and system processes, deployment-faithful projected-input symlinks, empty gateway-volume
initialization, receipt-free and finalized deterministic Kubernetes fixtures, exact receipt
publication/replay including public expiry, and the runner CLI state-path boundary. It binds only
loopback fixtures and proves no private-cluster reachability, network isolation, provider identity,
storage fencing, key custody, or public endpoint.

Run the root-package deletion and one-way dependency proof directly when needed:

```sh
cargo make test-sandbox-package-boundary
```

It compiles the ordinary root package after removing `kapsel-sandbox` from a temporary copy and
checks that the sandbox depends one way on `kapsel`. `test-sandbox-service` already includes this
lane.

The superseded KAP-0053 Gate 1/Gate 2, controller/stager, provider-fixture, and image-candidate
tasks and working-tree artifacts are deleted. Gate 1 image or bundle commands become guidance only
after implementation and review.

## Toolchain

Authoritative inputs are `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`,
`rustfmt-nightly.toml`, `clippy.toml`, `Makefile.toml`, `.github/workflows/ci.yml`, and
`scripts/ci-local.sh`.

Cargo-make, Prettier 3, and Python 3.11 or newer are repository prerequisites. Hosted CI pins the
Rust toolchain, Prettier version, and Python 3.11. Python, shell, Docker, kind, kubectl, Cosign,
Trivy, and curl are build, qualification, release, or demonstration prerequisites where named; they
are not Kapsel caller interfaces. The ordinary installed executable requires none of them merely to
start, report its version, or expose the adopted local and MCP grammar.
