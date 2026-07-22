# Testing

Status: active experiment strategy.

Kind: design. Authority: proof strategy for current work.

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
| Explicit live-kind script and root tests | Disposable-cluster behavior and real process termination where required by the release packet.   |

The repository root is also the `kapsel` product package. Its `tests/` directory therefore contains
both package integration tests and true binary end-to-end tests; the `application_` and `e2e_`
prefixes keep those lanes explicit. A test-support crate is justified only after fixtures are shared
by multiple real package interfaces. The private Kubernetes adapter seam remains private while only
one production adapter exists.

Pure implementation rules are asserted exhaustively once at their owner. Higher-layer tests assert
composition, authority separation, durable outcomes, observable output, and non-disclosure; they do
not repeat every parser or classifier mutation. Tests use several precise assertions when different
facts matter, rather than hiding contract failures behind one snapshot or compound predicate.

## Required proof stack for KAP-0038

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
mutation seam and the receipt-publication seam. They must prove that recovery does not issue a
second mutation and does not re-sign or relocate already prepared receipt bytes.

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
Coverage can reveal unexecuted branches or unexpected regressions, but its percentage is not a
correctness, crash-safety, Kubernetes-semantics, release-integrity, or production-readiness claim.
It does not represent the separate live-kind, artifact, shell, Python, fuzz, or long-simulation
lanes. Repository and patch statuses therefore remain informational: no percentage target can
replace the owner-specific assertions and explicit proof stack above.

## KAP-0043 MCP proof

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

## KAP-0044 release artifact proof

The release artifact lane crosses a fixed `x86_64-unknown-linux-gnu` archive rather than a Cargo
test binary. Assembly runs in a pinned x86-64 Debian 12 Rust container, records exact source and
binary provenance, normalizes archive metadata, and writes a checksum over the final downloadable
bytes. Two isolated builds must produce byte-identical archives and checksum files.

The clean smoke verifies checksum, exact entries, modes, metadata, target, revision, license, binary
digests, and extraction safety before executing only extracted files in a pinned x86-64 Debian 12
Python container. A deterministic HTTP Kubernetes fixture proves installed grant provisioning,
operation and restart, offline inspection, MCP discovery and call equivalence, bounded output, and
cleanup. The separately extracted demo executable is killed at both owned seams; recovery retains
one provider attempt, frozen receipt bytes under rotated settings, and offline classification. This
lane never calls Cargo, reads `target/`, or introduces a public provider seam after extraction.

The live artifact demo remains an explicit environment-owning gate on the supported target. It uses
the same bundled demo script and feature-gated executable, preserves prerequisite-before-mutation
and owned-cleanup behavior, and is separate from deterministic artifact smoke.

## KAP-0042 demonstration proof

The release demonstration has two complementary lanes. A deterministic black-box test builds the
production `kapsel` executable with the private `demo-harness` feature, drives a local HTTP
Kubernetes fixture, kills the real process at both fixed markers, and verifies one apply, restart,
frozen receipt bytes, rotated settings, and offline inspection. Separate prerequisite tests stub
Docker, `kind`, and `kubectl` to prove failures occur before cluster creation.

The explicit live harness then crosses the same executable and markers against its owned `kind`
cluster. It proves healthy and `ProgressDeadlineExceeded` receiver paths, the unchanged untargeted
container, one harness-counted apply, frozen digest and path under rotation, bounded failure logs,
no-network inspection, and ownership-safe cleanup. The compile-time feature and its environment are
harness control, not agent input or a public lifecycle interface. Existing internal fault tests
remain the exhaustive transition proof; the visual demonstration does not replace them.

## KAP-0051 public sandbox contract proof

The sandbox contract lane is distinct from KAP-0038 gateway tests. It must not widen the
`Application`, expose the gateway journal, or treat a service simulation as Kubernetes/isolation
evidence.

Committed fixtures under [`docs/fixtures/sandbox-v1`](fixtures/sandbox-v1/README.md) cover healthy,
unavailable-image, setup failure, saturation, expiry, every bounded error, incompatible version, and
unavailable service behavior. The standard-library gate `python3 scripts/test-sandbox-contract.py`
validates exact field sets and ordering, bounds, enum/null invariants, idempotent replay identity,
event sequence/cursor behavior, error status and retry vocabulary, forbidden disclosure keys, and
the raw KAP-0038 receipt digest. It uses fixed times and identities, no service, network,
dependency, random input, or ambient clock. Fixture validity is contract evidence only; it does not
prove a consumer or deployment.

KAP-0052 defines this deterministic matrix through the implemented `kapsel-sandbox` exported/service
boundary:

- exact JSON/header/query parsing before allocation and no caller-appointed authority;
- one atomic admission/idempotency/capacity/event transaction, including lost-response replay and
  same-key conflict;
- queue and active-run saturation before dispatch, fair bounded scheduling, lease loss, and global
  stop;
- runner restart before `Application` invocation, during uncertain invocation, after report, and
  around receipt-store publication;
- the same operation identity across recovery, no blind second mutation, and unchanged
  `OperationReport`/receipt bytes;
- contiguous append-only projection, pagination from every cursor, concurrent append snapshots,
  rejection above the 64-event request limit without fabricating lifecycle transitions, expiry,
  tombstone, and deletion;
- independent deadline and cleanup transitions that never populate or alter receiver result;
- terminal `service_failed` projection only for setup failure proven before `Application`
  invocation;
- unavailable admission store, receipt store, key custody, cluster, and incompatible revision
  errors; and
- field-level disclosure assertions over responses, durable run state, bounded diagnostics, and
  allowlisted telemetry.

The implemented package tests use explicit times, fixed keys, temporary owner-private storage, and
the existing deterministic Kubernetes transport. They prove atomic admission/replay/conflict,
32-queued and 8-active saturation, global stop, oldest-first dispatch, durable lease exclusion and
recovery, queued age beyond 180 seconds without head blocking, and exact oldest-first dispatch. They
prove an admission-frozen policy revision/inventory digest, cleanup identity, and 180-second
duration plus an exact dispatch-relative absolute deadline. Deterministic target evidence includes
every object identity, immutable UID, owner label, and policy-content digest; missing, stale,
permissive, duplicate-UID, and wrong-owner evidence blocks `Application` before provider traffic.
Cross-run UID reuse is rejected. Cleanup ownership rows are append-only across repeated policy
verification; a mismatched observation with an extra owned object remains required even after later
exact verification. Cleanup completion consumes absence observations for every durable
kind/namespace/name/UID/owner row and rejects missing, mismatched, or still-present objects before
releasing capacity. This does not claim live policy enforcement. The separate confirmed-no-resource
setup path releases capacity without inventing a UID. An explicit periodic sweep deletes expired raw
run data without visitor traffic, and initial-time open removes due tombstones before returning a
service. A direct first restart after both 24-hour windows proves the same transaction deletes the
run and skips its already-due tombstone.

An injected crash with only the sandbox `application_invoked` marker and no gateway journal proves
reconciliation submits the same server-owned request; once gateway state exists, recovery remains
reconcile-only. Cancellation after one returned mutation reopens the same operation after the
ordinary deadline event and observes without a second patch. A deliberately failed receipt-reference
transaction leaves durable pending ownership of the terminal report's exact immutable object;
restart converges to one byte-identical receipt and one contiguous terminal and receipt event. A
concurrent collector test pauses publication after final-object installation, proves open-time
collection preserves the pending-owned exact bytes, completes availability, and safely removes a
pending object whose run no longer exists. Existing database symlinks and permissive entries fail
before SQLite open; a securely created file is rechecked as the same 0600 owned regular inode. Both
fixed scenarios, pre-attempt rejection, strict hostile HTTP including POST queries and forwarding,
tracing, and both hyphenated and `clientcert` client-certificate header families, every retained
event cursor, a concurrent cleanup-event append snapshot, rejection of limits above 64, tombstones,
cleanup identity/UID mismatch, and cleanup failure/retry are covered. Valid prototype transitions do
not generate 64 events, so tests establish the endpoint bound rather than fabricating invalid
lifecycle events. Package-private receipt tests also consume the committed classifier-complete
receipt fixture. No test exposes sandbox state, reuses the KAP-0038 journal as its run database, or
presents deterministic orchestration as live cluster/isolation evidence.

KAP-0053 owns separate live lanes against one exact deployed revision:

| Lane                     | Required evidence                                                                                    |
| ------------------------ | ---------------------------------------------------------------------------------------------------- |
| Isolation adversary      | Cross-run API, DNS, network, metadata, volume, receipt, store, and key access denied                 |
| Policy fail-closed       | Missing namespace, account, quota, limits, network policy, runtime, or ownership proof blocks run    |
| Restart and reconnect    | API/scheduler/runner/store restarts preserve identity, cursor ordering, report, receipt, and cleanup |
| Saturation and stop      | Edge/service/queue/active/cluster exhaustion stays bounded; stop preserves read/recovery/cleanup     |
| Timeout                  | Sandbox deadline remains separate from KAP-0038 observation and receiver result                      |
| Cleanup failure          | Client loss, API outage, stuck finalizer, controller restart, retry, escalation, eventual deletion   |
| Key and storage failure  | Permission denial, rotation, outage, backup restore, expiry, no re-signing or disclosure             |
| Rollback                 | Incompatible service/schema/config/key revision rolls back with retained runs recoverable            |
| Retention and disclosure | Exact public expiry/tombstone/deletion and allowlisted logs/metrics under real requests              |
| Cost/resource ceiling    | Maximum concurrency through deadline and cleanup measures fixed and marginal resource ceilings       |

The live lanes must attempt adversarial access from both the native runner boundary and the most
compromised fixed workload posture the selected runtime permits. A passing namespace test alone is
not called tenant isolation. Provider/runtime/CNI behavior, asynchronous deletion, key custody,
store durability, rollback, and cost remain unproved until those lanes pass.

A fresh website consumer and a fresh Grafik-boundary consumer must each implement fixture parsing,
replay from a nonzero cursor, terminal snapshot rendering, raw receipt retrieval, expiry, and all
retryable/non-retryable errors without reading another checkout or private owner. Consumer
acceptance compares only to the committed fixtures; it cannot infer fields from implementation.

## Review record

Meaningful changes report:

```text
Contract: <owner document>
Surface: <validation | journal | recovery | receipt | demo | docs>
Gate: <narrowest command run>
Risk: <what remains unproved>
```
