# Testing

This page owns proof strategy, test placement, deterministic inputs, hostile-input coverage, and
crash recovery expectations. [Build and test](BUILD.md) owns runnable commands; direct contracts own
exact behavior and evidence limits.

## Test through the owning interface

Place each test at the lowest layer whose interface states the behavior. Moving a test outward must
not require widening a production seam. A higher layer should add a composition or external-contract
assertion rather than repeat an implementation matrix.

| Location                              | Owns                                                                                             |
| ------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Implementation-local `#[cfg(test)]`   | Pure parsing, classification, SQL and filesystem invariants, and private adapter or fault seams. |
| Root package `tests/application_*.rs` | Exported `Application` behavior with the product compiled without `cfg(test)`.                   |
| Root package `tests/e2e_*.rs`         | Production binaries, machine output, exit classes, restart, and operator workflows.              |
| `crates/<crate>/tests/`               | Exported interfaces of independently meaningful workspace packages.                              |
| `fuzz/`                               | Hostile bytes entering only through production interfaces.                                       |
| Ignored simulation targets            | Seeded lifecycle schedules, repeated recovery, and invariant checks.                             |
| Explicit live-kind scripts and tests  | Disposable-cluster behavior and real process termination.                                        |

The root is both workspace root and product package, so `application_` and `e2e_` prefixes
distinguish package integration from binary end-to-end tests. A test-support crate or public
provider seam requires multiple real consumers; one production Kubernetes adapter does not justify
either.

Assert pure implementation rules exhaustively once at their owner. At higher layers, assert
authority separation, durable outcomes, composition, observable output, and non-disclosure. Prefer
table-driven cases with shared setup, and use separate precise assertions when distinct contract
facts matter.

## Core effect-gateway proof matrix

| Layer                | Required proof                                                                                          |
| -------------------- | ------------------------------------------------------------------------------------------------------- |
| Request validation   | Bounds for identity, namespace, Deployment, container, digest, and authorization.                       |
| Authorization        | Signed grant, configured trust, exact tuple, and rejection before persistence.                          |
| Journal transition   | Deterministic fault injection at every durable state.                                                   |
| Target disposition   | Permanent invalid targets are pre-attempt `NOT_ATTEMPTED`; transient reads defer fairly.                |
| Provider attempt     | Safe GET precedes atomic target identity and `apply_started`; mutation follows that commit.             |
| Recovery             | Every injected window and process kill reopens without a blind second mutation.                         |
| Receiver observation | Request acceptance, timeout, transport completion, and rollout result remain distinct.                  |
| Classification       | Timeout and unresolved evidence are `UNKNOWN`, never false success or failure.                          |
| Receipt/inspection   | Canonical vectors carry all classifier inputs; inspection recomputes under explicit trust and limits.   |
| Publication          | Bytes, path, digest, and key ID freeze before collision-safe publication; kill recovery preserves them. |
| Migration            | Legacy self-asserted authorization fails closed rather than becoming trusted provenance.                |
| Hostile input        | Malformed, oversized, duplicate, reordered, unknown, and trailing records fail closed.                  |
| Disclosure           | Secrets and unbounded provider bodies stay out of SQLite, receipts, reports, errors, and logs.          |

`INSPECTED` means authenticated bytes and classifier consistency under supplied trust. It is not
receiver truth, causation, complete capture, compliance, or `VERIFIED`.

## Determinism and crash proof

Default semantic tests do not depend on wall-clock time, random keys, live services, ambient trust,
locale, or filesystem order. Use fixed keys, explicit evaluation time, private temporary
directories, seeded inputs, and sorted output. A subprocess test may use a bounded monotonic
coordination deadline; result meaning must not depend on polling order or timing.

Fault tests, simulations, process recovery, and compile-time demonstration controls cross the same
private operation-selected provider and publication implementations used by `Application`.
Queue-oriented helpers may select one identity but own no lifecycle transition. Process-kill proof
must cross both the ambiguous mutation seam and the receipt-publication seam, establish one provider
attempt, and prove prepared receipt bytes are neither re-signed nor relocated.

A live `kind` lane is explicit, environment-owning evidence. It complements but never replaces
fault-injection around every journal window.

## Evidence classes

### Deterministic suite

The default suite contains implementation-local tests, package integration tests, binary tests
needing no external service, and documentation tests. It owns repeatable semantic and hostile-input
proof. Source coverage is an informational review aid only; no percentage establishes crash safety,
Kubernetes semantics, release integrity, or production readiness.

The MCP subprocess lane proves bounded newline-delimited framing, one five-field tool, operator
configuration outside caller input, typed `SUCCEEDED`, `FAILED`, `UNKNOWN`, and `NOT_ATTEMPTED`
vocabulary, restart, protocol-only standard output, bounded hostile input, and secret-free failures.
Cancellation, EOF, or transport completion never determines receiver outcome.

The v0.1.1 fixture lane covers every historical lifecycle state, migration and restore interruption,
repeated reopen, provider-call counts, and frozen receipt bytes without Kubernetes or network
access. The [upgrade contract](UPGRADE.md) owns compatibility meaning.

### Robustness

Fuzzing calls production hostile-input interfaces from canonical corpus vectors without network or
ambient authority. Failures retain a minimized artifact and exact replay information.

Long simulations generate bounded lifecycle schedules, crash windows, retry deferrals, and reopen
operations from an explicit seed. Every step checks durable state, provider-call count, terminal
state, and frozen-receipt invariants. The seed is always replayable; wall-clock duration may change
only how many cases run, not their semantics.

### Live Kubernetes and demonstration

The live-kind gate owns real Kubernetes success, defined failed rollout, bounded `UNKNOWN`, and
process loss against a uniquely owned disposable cluster. It must show no blind second patch and
must clean up or export bounded failure evidence.

The public demonstration adds an observable evaluator path through healthy,
`ProgressDeadlineExceeded`, mutation-loss, and receipt-publication-loss cases. Compile-time harness
controls remain outside caller input and the ordinary executable. A visual demonstration is finite
evidence, not exhaustive recovery proof.

### Release artifact

Artifact proof crosses extracted `x86_64-unknown-linux-gnu` bytes rather than a Cargo test binary.
Two isolated assemblies must produce identical archive, checksum, SBOM, and digest-manifest bytes.
Hostile archive validation precedes extraction; smoke uses only extracted files to prove identity,
grant provisioning, operation and restart, offline inspection, MCP equivalence, demonstration-binary
separation, cleanup, and uninstall. It kills the extracted demonstration executable at both owned
seams and preserves one provider attempt and frozen receipt bytes under rotated settings. The
Sigstore bundle receives identity and failure checks rather than a false reproducibility
requirement.

The live artifact demonstration is a separate environment-owning gate. Exact layout, publisher
authentication, provenance, and evidence limits belong to [Release artifacts](RELEASE.md).

### Kapsel service

The unpublished service evidence remains layered around `Application`:

- projection reads status and frozen receipts without Kubernetes access or lifecycle advancement;
- Unix-socket tests cover effective-group peer credentials, framing, allocation, hostile fields,
  disclosure, one in-flight submission, and no queue;
- process tests cover `ACCEPTED` as process ownership only, immediate `BUSY`, caller disconnect,
  concurrent status, one provider attempt, and one journal;
- process-loss tests require startup reconciliation before bind and preserve frozen receipt bytes;
  and
- startup and asset tests freeze fixed roots, no-follow file rules, exact argv, stale-socket
  handling, systemd, sysusers, and namespaced RBAC bytes.

Service-client tests freeze its three-command grammar, bounded framing, receipt digest verification,
exclusive mode-`0600` output, and refusal to replace an existing file. `kapsel-authority` tests
freeze shared grant/trust vectors and consistency without turning that package into a public SDK.
The [Kapsel service contract](KAPSEL_SERVICE.md) owns the complete unpublished boundary.

### Installer

The partial, unpublished installer has four current evidence layers:

- portable package tests cover fixed command grammar, fail-closed payload absence, bounded
  bootstrap-kubeconfig parsing, canonical transaction records, two-group pending/ownership states,
  fixed GID selection, and reverse rollback;
- the explicit Docker fixture crosses bundle generation, exact descriptor-relative operator input,
  authority consistency, hostile filesystem and metadata refusal, durable lock/transaction recovery,
  bounded command execution, group observation, and ownership-safe rollback;
- its embedded ephemeral x86-64 Debian 12 lane crosses Debian `groupadd`, `groupdel`, `getent`, and
  `timeout` for both fixed groups; and
- `./scripts/test-debian12-installer-identities.sh` runs the exact approved groupadd and useradd
  argv against a pinned Debian 12 `linux/amd64` image. It records all changed account files, passwd
  and shadow rows, NSS name and numeric visibility, lock state, home, shell, GECOS, hostile
  defaults, duplicate name and UID, timeout, process loss, injected partial state, and the exact
  sudo effective GID path without supplementary membership.

The direct identity experiment must classify only exactly absent, exactly complete, conflict, or
ambiguous/partial. It must derive no-effect or completion from command status. The container is
always disposable; conflict or ambiguous/partial evidence permits no repair or continuation.

Implemented evidence ends after read-only host and Kubernetes clean-install preflight, durable
`installing`, and recoverable creation or rollback of `kapsel` and `kapsel-service-callers`. The
user argv and recovery rules are contract and experiment evidence only. No test proves user
installation by the installer, assets, Kubernetes mutation, credential issuance, activation,
refresh, uninstall, real payload provenance, final metadata or size bounds, runnable installation,
candidate assembly, or candidate qualification. The default payload-free build stops at
`bundle_unavailable`; staged test builds stop at `implementation_incomplete` after the implemented
group boundary.

The service and installer are absent from v0.2.0 and remain unpublished.
