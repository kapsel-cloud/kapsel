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

## Active effect-gateway library

The narrow deterministic gate for effect-gateway is:

```sh
cargo test --locked -p kapsel
cargo clippy --locked -p kapsel --all-targets -- -D warnings
```

Signed-grant trust, classifier-complete receipts, inspection, durable publication, migration, and
recovery behavior are exercised through both the library and fixed evaluator commands. The
deterministic suite includes real subprocess kill/restart proofs at the mutation and
receipt-publication seams.

## Kapsel service candidate

Run the focused deterministic package tests for the unpublished Kapsel service with:

```sh
cargo test --locked -p kapseld
cargo clippy --locked -p kapseld --all-targets -- -D warnings
```

The Linux-only real-process peer-credential and execution-ownership gate uses the compile-time test
harness and requires a Linux host. It creates only caller-owned temporary sockets and processes; it
does not create users, change groups, run systemd, or use Kubernetes credentials. A harness-only
status handshake keeps synthetic execution active through the observed `BUSY`, then releases it for
the final status read; timeout bounds detect deadlock rather than define execution lifetime. This
proves disconnect-independent process ownership, immediate `BUSY`, and reconnect status without
claiming provider or receiver behavior:

```sh
cargo test --locked -p kapseld --features test-harness --test linux_process
```

An additional ignored gate launches the client through an existing supplementary group with `sg` and
proves that a distinct effective GID is denied before any frame is sent. It performs no identity or
group mutation:

```sh
cargo test --locked -p kapseld --features test-harness --test linux_process \
  distinct_effective_gid_is_denied_before_frame_read -- --ignored --exact
```

The Kapsel service source gate covers framing, authentication, status, receipt, exact process-local
`ACCEPTED`, immediate non-queued `BUSY`, disconnect-independent execution, startup reconciliation
before bind, real process loss, frozen receipt retrieval, bounded `UNKNOWN`, fixed-root startup,
exact socket identity, stale-socket handling, and static installation records:

```sh
cargo test --locked -p kapseld --features test-harness
```

The process cases use only loopback deterministic Kubernetes fixtures and compile-time-private
controls. The private installation-root prefix and finite connection count exercise ordinary
startup; feature-free production accepts neither. Run the static direct-asset byte gate separately
or through the full package command:

```sh
cargo test --locked -p kapseld --test install_assets
```

The source evidence remains native-kernel process evidence. An exact source snapshot passed the
direct path in a fresh x86-64 Debian 12 KVM VM with systemd 252, kind 0.32.0, and pinned Kubernetes
1.33. It proved separate identities, credential/RBAC bounds, installed process loss and boot
recovery, secret-free diagnostics, ordered uninstall, and retained data. It does not prove the
separate Kapsel service artifact or production safety.

### Source-independent Kapsel service artifact

The unpublished Kapsel service artifact is separate from the immutable v0.2.0 archive. Assemble
strict A only from a clean exact revision:

```sh
service_a=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-service-a.XXXXXX")
archive_a=$(python3 scripts/assemble-kapsel-service-artifact.py \
  --output-directory "$service_a")
python3 scripts/test-kapsel-service-artifact.py --archive "$archive_a"
python3 scripts/test-kapsel-service-reproducibility.py \
  --reference-archive "$archive_a"
```

Assembly uses the pinned x86-64 Debian 12 Rust builder and emits one archive plus deterministic
`.sha256` and `.SHA256SUMS` identity files. The artifact test rejects hostile archives, validates
and exclusively extracts A, then runs the extracted `kapsel`, feature-free `kapseld`, and fixed
`kapsel-service-client` in the pinned clean Debian 12 Python container. The reproducibility gate
performs one independent strict B assembly and compares all deterministic bytes.

The candidate workflow may add one Sigstore bundle over `.SHA256SUMS`; it uploads unpublished
candidate evidence and performs no release action. The exact install/configure/start/call/restart/
uninstall journey is the [Kapsel service operator guide](KAPSEL_SERVICE_OPERATOR.md). The
authenticated artifact-only journey on a fresh native systemd/Kubernetes host remains a separate
required acceptance gate; deterministic container smoke does not imply it passed.

Focused verifier tests that require no Docker are:

```sh
python3 scripts/test-kapsel-service-artifact.py
```

### Direct installation candidate

The following source-based procedure requires root and Kubernetes administration in a disposable
non-production environment. Build on x86-64 Debian 12 from one clean revision, then install the
exact repository inputs:

```sh
! getent passwd kapsel
! getent group kapsel
! getent group kapsel-service-callers
getent passwd kapsel-service-caller
cargo build --release --locked -p kapsel --bin kapsel
cargo build --release --locked -p kapseld --bins
sudo install -D -o root -g root -m 0755 target/release/kapsel /usr/bin/kapsel
sudo install -D -o root -g root -m 0755 target/release/kapsel-service-client \
  /usr/bin/kapsel-service-client
sudo install -D -o root -g root -m 0755 target/release/kapseld \
  /usr/libexec/kapsel/kapseld
sudo install -D -o root -g root -m 0644 crates/kapseld/deploy/kapseld.service \
  /usr/lib/systemd/system/kapseld.service
sudo install -D -o root -g root -m 0644 crates/kapseld/deploy/kapseld.conf \
  /usr/lib/sysusers.d/kapseld.conf
sudo install -D -o root -g root -m 0644 crates/kapseld/deploy/kapseld-rbac.yaml \
  /usr/share/kapsel/kapseld-rbac.yaml
sudo install -D -o root -g root -m 0644 docs/KAPSEL_SERVICE_OPERATOR.md \
  /usr/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md
sudo systemd-sysusers /usr/lib/sysusers.d/kapseld.conf
getent passwd kapsel
getent group kapsel
getent group kapsel-service-callers
sudo passwd --status kapsel
sudo usermod --append --groups kapsel-service-callers kapsel-service-caller
sudo install -d -o kapsel -g kapsel-service-callers -m 0700 \
  /etc/kapsel /var/lib/kapsel /var/lib/kapsel/receipts
```

The operator then installs exact owner-provisioned `operator.json`, `grant.bin`,
`authorization.pub`, `kubeconfig.yaml`, and `receipt.seed` beneath `/etc/kapsel` with owner
`kapsel:kapsel-service-callers` and mode `0600`. The JSON uses only the existing grammar and exact
paths fixed by the [Kapsel service contract](KAPSEL_SERVICE.md). Applying
`/usr/share/kapsel/kapseld-rbac.yaml`, obtaining a short-lived ServiceAccount credential, and
writing the embedded kubeconfig require Kubernetes administrative access. After those inputs exist,
activation is direct:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now kapseld.service
```

The external client's supervisor must set effective `Group=kapsel-service-callers`; supplementary
membership alone does not pass peer authentication. Service state plus successful authenticated
socket use is the health boundary. Direct lifecycle operations are:

```sh
sudo systemctl start kapseld.service
sudo systemctl stop kapseld.service
sudo systemctl restart kapseld.service
```

Uninstall preserves authority/state bytes but revokes use first. Stop the external caller, then run
this exact order. The `kubectl` steps and credential revocation require their own Kubernetes
authorization:

```sh
sudo systemctl disable --now kapseld.service
systemctl is-active kapseld.service
sudo gpasswd --delete kapsel-service-caller kapsel-service-callers
kubectl --namespace demo delete rolebinding kapsel-service-agent-api
kubectl --namespace demo delete serviceaccount kapsel-service
kubectl --namespace demo delete role kapsel-service-agent-api
sudo rm -f /usr/bin/kapsel /usr/bin/kapsel-service-client /usr/libexec/kapsel/kapseld
sudo rm -f /usr/lib/systemd/system/kapseld.service /usr/lib/sysusers.d/kapseld.conf
sudo rm -f /usr/share/kapsel/kapseld-rbac.yaml \
  /usr/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md
sudo systemctl daemon-reload
```

The locked `kapsel` account, its private group, `kapsel-service-callers`, external caller account,
`/etc/kapsel`, `/var/lib/kapsel`, journal, worker lock, and receipts remain. There is no purge
command. The clean-VM gate verified process exit, connection closure, runtime-directory cleanup, and
unchanged retained-data hashes before removing installed static artifacts. It also confirmed that
the daemon refuses a nonexact socket leaf without unlinking it, after which systemd removes the
service-owned runtime directory and leaf as failed-activation cleanup.

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

## Candidate qualification

Run every finite qualification lane against one committed clean candidate:

```sh
cargo make qualify-beta
```

This command requires Docker, kind, kubectl, cargo-fuzz/nightly, cargo-audit 0.22.2, Trivy 0.72.0
with current databases, the pinned builder image, and the host Cargo registry. It runs the
default/hostile, simulation, fuzz, v0.1.1 upgrade, deterministic demo, live-kind, measurement,
security, and privacy lanes. It writes `/tmp/beta-qualification-baseline.json` only after every lane
passes. Validate a retained result with:

```sh
python3 scripts/validate-beta-qualification-baseline.py /absolute/beta-qualification-baseline.json
```

The pinned x86-64 measurement harness builds and runs inside the fixed 8-CPU, 8-GiB isolated
container and writes bounded aggregates to a caller-selected temporary path:

```sh
python3 scripts/run-beta-qualification-measurements.py --output /tmp/beta-qualification-measurements.json
```

The semantic lanes remain `cargo make test-simulation`, `cargo make test-fuzz`,
`cargo make test-v011-upgrade`, `cargo make test-demo-harness`, and `cargo make test-kind`. These
commands produce candidate evidence, not production performance or support claims.

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

Scan one exact SPDX sidecar with the candidate Trivy 0.72.0 policy and a vulnerability database no
older than 24 hours:

```sh
KAPSEL_RELEASE_SBOM=/absolute/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz.spdx.json \
KAPSEL_RELEASE_SBOM_SCAN=/absolute/beta-sbom-scan.json \
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
files. The bundle is intentionally nondeterministic and publication remains independently reviewed.
See [Release artifacts](RELEASE.md) for connected/offline trust, expiry, compromise, withdrawal, and
replacement rules. A dependent clean job downloads that workflow artifact, re-authenticates the
exact bytes, drives operation/restart/MCP/inspection/cleanup/uninstall in the pinned smoke
container, runs the extracted live-kind demo, and crosses the exact v0.1.1 finalized
upgrade/restore/downgrade pair. This is unpublished candidate-download evidence; public release
evidence owns public-release download verification.

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
[Kapsel 0.1.1 release](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.1.1).

## Toolchain

Authoritative inputs are `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`,
`rustfmt-nightly.toml`, `clippy.toml`, `Makefile.toml`, `.github/workflows/ci.yml`, and
`scripts/ci-local.sh`.

Cargo-make, Prettier 3, and Python 3.11 or newer are repository prerequisites. Hosted CI pins the
Rust toolchain, Prettier version, and Python 3.11. Python, shell, Docker, kind, kubectl, Cosign,
Trivy, and curl are build, qualification, release, or demonstration prerequisites where named; they
are not Kapsel caller interfaces. The ordinary installed executable requires none of them merely to
start, report its version, or expose the adopted local and MCP grammar.
