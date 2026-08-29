# Testing

Status: active experiment strategy.

Kind: design. Authority: proof strategy for the active experiment.

Owns: Test placement, deterministic inputs, hostile-input coverage, and recovery proof expectations.

Does not own: Build commands, technical scope, exact receipt bytes, or public-sandbox wire and
deployment semantics.

## Short answer

The active Kubernetes experiment must be tested through its one deep interface: authorized
`kubernetes.set_deployment_image` request in, durable state and inspected receipt out. Internal
tests may exist for parsers and pure state transitions, but the important proof is crash recovery
across provider-attempt windows.

## Placement and ownership

Tests live at the lowest layer whose interface states the behavior under test. Moving a test outward
must not require widening a production seam, and crossing a deeper interface must add a distinct
contract assertion rather than repeat the same implementation matrix.

| Location                                 | Owns                                                                                             |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Implementation-local `#[cfg(test)]`      | Pure parsing, classification, SQL and filesystem invariants, and private adapter or fault seams. |
| Root package `tests/application_*.rs`    | The exported `Application` interface with the product package compiled without `cfg(test)`.      |
| Root package `tests/e2e_*.rs`            | Black-box production binaries, machine output, exit classes, restart, and operator workflows.    |
| `crates/<crate>/tests/`                  | Exported interfaces of independently meaningful workspace packages.                              |
| `fuzz/`                                  | Hostile-byte entry points reached only through production interfaces.                            |
| Ignored long-simulation targets          | Seeded lifecycle schedules, repeated recovery, and invariant checks.                             |
| Explicit live-kind script and root tests | Disposable-cluster behavior and real process termination required by the release contract.       |

The repository root is also the `kapsel` product package. Its `tests/` directory therefore contains
both package integration tests and true binary end-to-end tests; the `application_` and `e2e_`
prefixes keep those lanes explicit. A test-support crate is justified only after fixtures are shared
by multiple real package interfaces. The private Kubernetes adapter seam remains private while only
one production adapter exists.

Pure implementation rules are asserted exhaustively once at their owner. Higher-layer tests assert
composition, authority separation, durable outcomes, observable output, and non-disclosure; they do
not repeat every parser or classifier mutation. Tests use several precise assertions when different
facts matter, rather than hiding contract failures behind one snapshot or compound predicate.

## Required proof stack for effect-gateway

| Layer                | Required proof                                                                                           |
| -------------------- | -------------------------------------------------------------------------------------------------------- |
| Request validation   | Namespace, deployment, container, digest, authorization, and operation identity bounds.                  |
| Authorization        | Signed grant parsing, application-configured trust, exact tuple, and pre-persistence rejection.          |
| Journal transition   | Every durable state has a deterministic fault-injection test.                                            |
| Target disposition   | Missing/invalid target becomes terminal `not_attempted`; transient reads defer fairly without blocking.  |
| Provider attempt     | Safe target GET precedes atomic target identity plus `apply_started`; mutation follows that commit.      |
| Recovery             | Reopen after every injected window and real process kill reconciles without a blind second apply.        |
| Receiver observation | Request acceptance and rollout outcome remain distinct.                                                  |
| Receipt/inspection   | Canonical vectors carry all classifier inputs; inspection recomputes result under explicit trust/limits. |
| Publication          | Exact bytes/path/digest/key ID freeze before publication; no-follow paths, fsync, kill recovery.         |
| Migration            | Legacy self-asserted authorization fails closed rather than being promoted to trusted provenance.        |
| Hostile input        | Malformed, oversized, duplicate, reordered, unknown, and trailing grant/receipt records fail closed.     |
| Disclosure           | Secrets and unbounded provider bodies do not enter SQLite, receipts, reports, errors, or logs.           |

## Determinism

Default semantic tests do not depend on wall-clock time, random keys, live cloud services, ambient
trust, locale, or filesystem ordering. Use fixed keys, explicit evaluation time, temporary private
directories, seeded inputs, and sorted output. Subprocess kill tests may use a bounded monotonic
coordination deadline and marker-file polling; result semantics must not depend on the polling
schedule. Use deterministic `kind` setup where a test actually crosses Kubernetes.

A live `kind` demonstration is allowed only when its setup and cleanup are explicit. It does not
replace fault-injection tests around the journal. Process-kill tests must cross both the ambiguous
mutation seam and the receipt-publication seam. Deterministic faults, simulations, subprocess
recovery, and the compile-time demo controls cross the same private operation-selected provider and
receipt implementations used by `Application`; queue-oriented helpers may select an identity but own
no lifecycle transition. These tests must prove that recovery does not issue a second mutation and
does not re-sign or relocate already prepared receipt bytes.

## Suite shape and robustness lanes

The default deterministic suite stays small and runs implementation-local unit tests, package
integration tests, binary tests that need no external service, and documentation tests. Every test
names one contract behavior, but may use many assertions to prove all facts owned by that behavior.
Table-driven cases are preferred when the setup and expected invariant are identical.

Fuzz targets are separate from the default gate. They call production hostile-input interfaces,
start from canonical corpus vectors when available, never depend on network or ambient authority,
and retain minimized regressions. A reported failure must include the target, seed or artifact, and
exact replay command.

Long simulations are also separate from the default gate. They use an explicit seed to generate
bounded lifecycle schedules, injected crash windows, retry deferrals, and reopen operations. Each
step checks durable-state, provider-call-count, terminal-state, and frozen-receipt invariants. The
seed is always printed on failure and accepted as input for exact replay. Simulation duration or
case count may vary by lane; semantics and generated schedules may not depend on wall-clock timing.

The live-kind lane remains explicit and environment-owning. It is not called a fuzz test or
simulation and is never used as evidence that a deterministic invariant holds for every crash
window.

## Coverage interpretation

CI publishes source-based coverage for the deterministic Rust suite as an informational review aid.
The hosted lane starts independently of the default gate, keeps its instrumented target and cache
separate, and bounds report generation to ten minutes. It uploads only a nonempty completed report;
generation failure or timeout emits a visible warning and completes without changing the default
gate's correctness result. The outer job remains explicitly non-blocking if setup itself fails or
exceeds its separate safety bound.

Coverage can reveal unexecuted branches or unexpected regressions, but its percentage is not a
correctness, crash-safety, Kubernetes-semantics, release-integrity, or production-readiness claim.
It does not represent the separate live-kind, artifact, shell, Python, fuzz, or long-simulation
lanes. Repository and patch statuses therefore remain informational: no percentage target can
replace the owner-specific assertions and explicit proof stack above.

## MCP adapter proof

The thin MCP adapter is tested as a production subprocess over newline-delimited stdio. Its focused
black-box target proves:

- initialization, version negotiation, and exactly one five-field tool;
- operator configuration outside tool input;
- successful `AgentRequest` and typed-outcome equivalence with the local adapter, repeated calls
  followed by an ordinary local-process restart, and explicit `SUCCEEDED`, `FAILED`, `UNKNOWN`, and
  `NOT_ATTEMPTED` MCP vocabulary;
- lifecycle ordering, string/numeric/null/invalid request IDs, ignored late cancellation without
  disclosure, and clean EOF; and
- incomplete, invalid UTF-8, batch, duplicate, exact-limit, and oversized frame handling, bounded
  response lines, hostile-field rejection, and secret-free errors.

The fixture uses the same explicit owner-private files and deterministic local HTTP Kubernetes
server as the evaluator command tests. It requires no Docker, `kind`, ambient kubeconfig, credential
lookup, trust lookup, clock, external service, public provider seam, or demonstration fault control.
Protocol parser tests stay at this black-box boundary because framing, stdout purity, process exit,
and startup authority separation are transport behavior.

## Release artifact proof

The release artifact lane crosses a fixed `x86_64-unknown-linux-gnu` archive rather than a Cargo
test binary. Assembly runs in a pinned x86-64 Debian 12 Rust container, records exact source, tree,
lockfile, builder, and binary provenance, normalizes archive metadata, and writes deterministic
checksum, SPDX 2.3, and signed-manifest inputs over the final downloadable bytes.

The proof assembles strict isolated A once outside the worktree, runs exact layout and hostile
archive verification plus extracted smoke against A, then assembles B once with a separate target
and output directory. Archive, checksum, SBOM, and digest-manifest bytes must match exactly. No
compiled output or target directory is shared. Only after smoke and comparison pass may the exact A
bytes be copied to `dist/` and uploaded; B is discarded. Pull requests run the same two-build proof
without upload. The separate keyless Sigstore bundle is event-derived and receives semantic
identity/failure tests instead of a false byte-reproducibility requirement.

The clean smoke verifies checksum and digest manifest, SPDX/archive/binary/source bindings, exact
entries, ordering, types, modes, metadata, target, revision, license, binary digests, and traversal,
link, special-file, unsafe-mode, and size rejection before executing only extracted A files in a
pinned x86-64 Debian 12 Python container. A deterministic HTTP Kubernetes fixture proves installed
version identity, grant provisioning, operation and restart, offline inspection, MCP discovery and
call equivalence, bounded output, cleanup, and uninstall. The separately extracted demo executable
is killed at both owned seams; recovery retains one provider attempt, frozen receipt bytes under
rotated settings, and offline classification. This lane never calls Cargo, reads `target/`, or
introduces a public provider seam after extraction.

The live artifact demo remains an explicit environment-owning gate on the supported target. It uses
the same bundled demo script and feature-gated executable, preserves prerequisite-before-mutation
and owned-cleanup behavior, and is separate from deterministic artifact smoke.

## Release demonstration proof

The release demonstration has two complementary lanes. A deterministic black-box test builds the
production `kapsel` executable with the private `demo-harness` feature, drives a local HTTP
Kubernetes fixture, kills the real process at both fixed markers, and verifies one apply, restart,
frozen receipt bytes, rotated settings, and offline inspection. Separate prerequisite tests stub
Docker, `kind`, and `kubectl` to prove failures occur before cluster creation.

The explicit live harness then crosses the same executable and markers against its owned `kind`
cluster. It proves healthy, `ProgressDeadlineExceeded`, and deleted-after-patch bounded `UNKNOWN`
receiver paths, the unchanged untargeted container, one harness-counted apply per operation, frozen
digest and path under rotation, bounded failure logs, no-network inspection, and ownership-safe
cleanup. The compile-time feature and its environment are harness control, not agent input or a
public lifecycle interface. Existing internal fault tests remain the exhaustive transition proof;
the visual demonstration does not replace them.

## Historical public sandbox evidence

The fixed `v1` fixture bytes explain the historical HTTP contract but carry no executable
compatibility or deployment promise. One fixture receipt remains an input to the root offline
inspection test because it is valid classifier-complete effect-gateway evidence. The sandbox is not
an active package, proof lane, or deployable alternative. The root real-process harness and
disposable-`kind` demonstration remain the supported mechanism proof.

## Kapsel service proof categories

The focused runnable gates are documented in
[Kapsel service candidate](BUILD.md#kapsel-service-candidate). They remain layered around the
existing `Application`:

- projected status and frozen-receipt retrieval make no Kubernetes call and advance no lifecycle
  state;
- Unix-socket tests cover peer-credential allow/deny, framing and allocation bounds, hostile fields,
  disclosure, one in-flight submission, and no queue;
- process tests cover `ACCEPTED`, immediate `BUSY`, caller disconnect, concurrent status, one
  provider attempt, and one journal;
- process-loss tests kill `kapseld` after mutation and receipt-publication seams, require startup
  reconciliation before bind, and preserve frozen receipt bytes; and
- startup tests cover fixed-root mode/type/link/component checks, stable consumed bytes, exact argv,
  post-bind socket identity, exact inactive stale-socket removal, and refusal of every other leaf.

Static tests freeze the systemd unit, sysusers file, and ServiceAccount/Role/RoleBinding bytes.
Linux process tests use only compile-time-private root and finite-connection controls; ordinary
startup accepts neither. Service-client tests freeze its three-command grammar, bounded framing,
lowercase receipt decoding, digest verification, exclusive mode-`0600` output, and refusal to
replace an existing receipt.

The `kapsel-installer` package's black-box binary tests freeze its exact three-command grammar,
required-once options, absolute operator-input path, Kubernetes context bounds, secret-free failure
class, and empty stdout. They also prove that a default development build reaches
`bundle_unavailable` without creating anything in its working directory. The explicit Docker bundle
smoke constructs an exact stage with clearly test-only ELF fixtures and root-owned operator input.
It crosses release-stage generation, descriptor-relative exact input validation, cryptographic
consistency, one valid bootstrap kubeconfig, exact installer-lock handling, crash-safe canonical
prepared-transaction publication and recovery, and hostile metadata, inventory, path, special-file,
bounds, authority, lock, and transaction refusal before requiring `implementation_incomplete`.
Portable package unit tests own the strict bounded bootstrap-kubeconfig grammar, canonical prepared
record, and hostile aliases, duplicates, unknowns, external references, credential forms, decoded
bounds, and URL shapes. The Docker smoke explicitly runs the Linux root unit test for unnamed-inode
initial publication, marked phase-successor update, interruption seams, and conflicting-successor
evidence preservation. These gates prove no host preflight, pending-action or resource-evidence
successor, payload provenance, metadata schema, final-size bound, runnable installation, or
candidate qualification.

The Kapsel service is unpublished and absent from v0.2.0. The default CLI/MCP and effect-gateway
suites remain authoritative for v0.2.0.

## Review record

Meaningful changes report:

```text
Contract: <owner document>
Surface: <validation | journal | recovery | receipt | demo | docs>
Gate: <narrowest command run>
Risk: <what remains unproved>
```
