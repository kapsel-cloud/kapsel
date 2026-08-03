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

## Release artifact proof

The release artifact lane crosses a fixed `x86_64-unknown-linux-gnu` archive rather than a Cargo
test binary. Assembly runs in a pinned x86-64 Debian 12 Rust container, records exact source, tree,
lockfile, builder, and binary provenance, normalizes archive metadata, and writes deterministic
checksum, SPDX 2.3, and signed-manifest inputs over the final downloadable bytes. Two isolated
builds must produce byte-identical archives, checksums, SBOMs, and digest manifests. The separate
keyless Sigstore bundle is event-derived and receives semantic identity/failure tests instead of a
false byte-reproducibility requirement.

The clean smoke verifies checksum and digest manifest, SPDX/archive/binary/source bindings, exact
entries, ordering, types, modes, metadata, target, revision, license, binary digests, and traversal,
link, special-file, unsafe-mode, and size rejection before executing only extracted files in a
pinned x86-64 Debian 12 Python container. A deterministic HTTP Kubernetes fixture proves installed
version identity, grant provisioning, operation and restart, offline inspection, MCP discovery and
call equivalence, bounded output, cleanup, and uninstall. The separately extracted demo executable
is killed at both owned seams; recovery retains one provider attempt, frozen receipt bytes under
rotated settings, and offline classification. This lane never calls Cargo, reads `target/`, or
introduces a public provider seam after extraction.

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
cluster. It proves healthy, `ProgressDeadlineExceeded`, and deleted-after-patch bounded `UNKNOWN`
receiver paths, the unchanged untargeted container, one harness-counted apply per operation, frozen
digest and path under rotation, bounded failure logs, no-network inspection, and ownership-safe
cleanup. The compile-time feature and its environment are harness control, not agent input or a
public lifecycle interface. Existing internal fault tests remain the exhaustive transition proof;
the visual demonstration does not replace them.

## Serialized public sandbox proof

KAP-0070 retains the fixed API, deterministic service, root-package deletion boundary, and KAP-0055
handoff while replacing the deployment composition. These offline lanes are preservation evidence,
not proof of the planned host, provider, cluster, isolation, backup, or public endpoint. The sandbox
contract lane remains distinct from KAP-0038 gateway tests and must not widen `Application`, expose
the journal, or present simulation as live enforcement.

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

The retained KAP-0052 package tests use explicit times, fixed keys, temporary owner-private storage,
and the existing deterministic Kubernetes transport. They prove atomic admission/replay/conflict,
queue-32 saturation, global stop, oldest-first dispatch, durable lease exclusion and recovery,
queued age beyond 180 seconds without head blocking, and exact oldest-first dispatch. KAP-0070 Gate
1 Slice 1 replaces the historical eight-active cases with exactly one durable active reservation.
Its focused matrix proves fail-closed reopen and dispatch for missing, inconsistent, noncanonical,
or multi-active capacity state, active-first lease recovery, FIFO dispatch, no release after
terminal handoff, cleanup start/failure, retry, restart, public retention, or wrong/present absence
evidence, one durable 15-minute escalation, and release only after exact UID/owner absence. The
retained tests also prove an admission-frozen policy revision/inventory digest, cleanup identity,
and 180-second duration plus an exact dispatch-relative absolute deadline. Deterministic target
evidence includes every object identity, immutable UID, owner label, and policy-content digest;
missing, stale, permissive, duplicate-UID, and wrong-owner evidence blocks `Application` before
provider traffic. Cross-run UID reuse is rejected. Cleanup ownership rows are append-only across
repeated policy verification; a mismatched observation with an extra owned object remains required
even after later exact verification. Cleanup completion consumes absence observations for every
durable kind/namespace/name/UID/owner row and rejects missing, mismatched, or still-present objects
before releasing capacity. This does not claim live policy enforcement. The separate
confirmed-no-resource setup path releases capacity without inventing a UID. An explicit periodic
sweep deletes expired raw run data without visitor traffic, and initial-time open removes due
tombstones before returning a service. A direct first restart after both 24-hour windows proves the
same transaction deletes the run and skips its already-due tombstone.

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

KAP-0055 adds a provider-neutral private runner-handoff lane. Contract tests cross the narrow
non-mutating `Application` request/grant match, exact bounded binary records, generic non-disclosing
rejection, per-generation lease/credential rotation, durable invocation before lifecycle work,
terminal report binding, stale and changed replay denial, replacement-lease recovery, receipt-free
pre-attempt rejection, exact immutable receipt bytes, restart, concurrency, an absolute
trickle-resistant receive deadline, cross-expiry invocation/report denial, and finalized recovery
across public expiry. Direct private-listener tests reject an oversized frame and oversized receipt
field before invocation or report mutation.

Separate production runner and system subprocesses cross deployment-faithful projected-volume
symlinks and a genuinely empty gateway volume against receipt-free and actual KAP-0038
`SUCCEEDED`/`UNKNOWN` deterministic Kubernetes paths. They assert byte-identical outbox/system
receipts and separately trusted inspection/classifier agreement; the actual `FAILED` Application
path crosses the same handoff adapter in the service contract with the same byte and classifier
checks. Production process-kill tests recover one operation from loss before invocation, after the
durable invocation ACK, and after `apply_started` on the containerless host. The mandatory
Linux/root lane additionally kills after the durable terminal report, restarts the system process,
and replaces the runner without changing KAP-0038's frozen receipt bytes. Non-Linux tests instead
assert terminal report and exact receipt-byte preservation across a service reopen without claiming
host replacement. The package-private publication tests own the remaining narrower boundaries:
reopening after a durable pending claim before final-object installation and after installation
before availability commit. The runner owns only its initialized `run/gateway.sqlite3` and receipt
outbox; the system process owns admission SQLite and exact immutable receipt installation.
Escape/substitution layouts and a system-state argument fail before input or lifecycle use, and
credential-bearing debug output is redacted. Loopback TCP and deterministic Kubernetes fixtures
prove only process and state-transition behavior; they do not prove private-cluster reachability,
network/runtime/storage isolation, provider identity, or live custody.

Accepted KAP-0070 Slice 2 replaces copied bootstrap payloads with individually pinned read-only
descriptors transferred through `SCM_RIGHTS`. A fixed C helper and cgroup-v2 generation establish
the pre-runtime identity/FD/parent and descendant boundary while Rust remains
`unsafe_code = "forbid"`. Implementation-local tests cover input-parent replacement, fixed-file mode
changes, lease/credential rotation, durable allocation/fencing/migration crash sides, record/cgroup
ambiguity, and forked-descendant fencing after post-attach failure. Separate generation-root tests
fail closed before processing a fifth entry and remove only obsolete empty directories after the
durable record advances.

Native process tests retain `not_attempted`, `SUCCEEDED`, `UNKNOWN`, the three pre-terminal loss
seams, and deterministic both-sided publication with exact terminal/report bytes. The pinned,
privileged-private-cgroup, network-disabled x86-64 Debian/Linux lane executes rather than skipping
and passes the fixed helper, descriptor, identity, outcome, full retained process-loss matrix, and
real terminal kill/restart/replacement.

The Slice 2 hardening lane compiles the production C normalization logic into a finite
hostile-parent matrix. It tests the exact eight-capability `E=P=B` bootstrap with empty `I/A`,
independently named `CAP_NET_RAW` effective, permitted, inheritable, ambient, and bounding cases,
unlocked and locked `KEEP_CAPS`/`NO_SETUID_FIXUP`, and nonempty helper and runner
`security.capability` values. Linux subset constraints are explicit in the effective and ambient
fixtures. Canonical and unlocked cases must normalize to the exact bootstrap state; locked cases
exit before authority. The composed runner then proves securebits and all five sets zero,
`no_new_privs=1`, UID/GID, empty groups, descriptors, parent-death, cgroup, and recovery. A safe
Rust `/proc/self/status` backstop checks the post-exec state before descriptor receipt.

The lane also rejects C-source or pinned compiler identity drift and hashes the C source, built
helper, and runner bytes as Slice 6 inputs. It does not assemble or prove the final bundle. No
seccomp, Landlock, or equivalent restriction is selected, so tests and review must not imply host
filesystem concealment or syscall/path confinement. The accepted matrix proves the named capability
boundary but not a complete least-privilege native process boundary.

Historical KAP-0053 tests retain only topology-neutral evidence: bounded native HTTP parsing,
durable stop behavior, the exact conditional named-container image and KAP-0038 operation-annotation
rule, strict input non-disclosure, and Ed25519/inspector known answers. Its `ReadWriteOncePod`,
runner Pod, projected Kubernetes input, controller-state, key-stager, multi-volume backup,
concurrent-run, provider fixture, and image-candidate assertions are deleted evidence for KAP-0070
and must not run or pass as current composition proof. Gate 0 retains the exact conditional patch
rule and source/artifact deletion boundary in `test-sandbox-preservation`, which uses only the two
provider-neutral fixtures under `deploy/sandbox`. The current runnable preservation set is
`test-sandbox-contract`, `test-sandbox-preservation`, `test-sandbox-serialized-capacity`,
`test-sandbox-service`, `test-sandbox-package-boundary`, and `test-sandbox-runner-handoff`.

KAP-0070 Slice 3 adds `test-sandbox-cluster-policy`. Its bounded in-process bodies prove the exact
provider-neutral baseline/canary/run composition, generated-child UID inventory, downgrade rejection
before runner/Application, and the only accepted old/new Deployment difference. The focused
correction keeps cleanup observations, plans, and requests private; recomputes the canonical plan
digest before the first request; binds one fixed Kubernetes client at role construction; and exposes
only one closed attempt that owns generated-child refresh, pre-delete observation, exact deletion,
post-plan observation, durable completion, and coalesced failure. Unit and loopback HTTP tests prove
zero requests for a changed private plan, exact UID/propagation deletes, Namespace-presence
branches, frozen-RBAC scans, ten-second request and 30-second attempt deadlines, and a 2 MiB body
cap before kube deserialization for content-length, chunked, and close-delimited framing. Retirement
tests prove one atomic revocation/retiring transition, independent revoked/retiring/retired
recovery-assignment-launch denial, and fresh empty generation state after prior-run retirement. The
ordinary Linux production `ControllerRole::run_once` regression restarts after durable retirement
intent with both an unexpired and expired lease, proves retirement precedes scheduler recovery, and
asserts no epoch, staged authority, invocation/report count, operation identity, receipt, or runner
launch changes. It performs no live action and does not prove Kubernetes runtime, CNI, RBAC,
admission, metadata, or network enforcement.

The Slice 4 offline matrix adds fixed-staging activation/recovery and family-isolation tests; atomic
per-lease publication, canonical debris, inode substitution, and post-retirement deletion tests;
descriptor-bound `RunnerHost` replacement; exact generation-pinned trust and cleanup tests; and a
Service reference matrix for runs, tombstones, receipt ownership, dispatch ownership, malformed
pins, and crash-recovered noncurrent collection. `CleanupController` is exercised through staged TLS
and token authority, and missing old authority must leave lifecycle, cleanup, and event facts
unchanged. `cargo make test-sandbox-fixed-staging-identities-linux` is a separate root-only,
network-namespace lane for the production distinct-UID/GID split; ordinary macOS and unprivileged
runs do not claim that evidence.

The serialized proof matrix is:

| Property                               | Retained Gate 0 evidence                                              | Gate 1 deterministic composition                                        | Gate 3 private-live assertion                                                              | Gate 4 public assertion                                               |
| -------------------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| Identity/replay/receipt                | Exact fixtures and service restart tests                              | Host-volume crash/reopen and immutable publication                      | Replacement-host restore without identity drift                                            | Lost response, reconnect, exact raw receipt                           |
| Server authority/conditional operation | Service authority negatives, real `Application`, exact KAP-0038 tests | Fixed descriptor inputs and exact patch denial matrix                   | Runner/target authority and downgrade denials                                              | Both fixed scenarios only                                             |
| Runner loss/reconcile                  | KAP-0055 subprocess seams and frozen bytes                            | OS identity, no-follow, stale-process/lease fencing                     | Kill at every invocation/apply/report/publication seam                                     | One approved public runner kill                                       |
| Bounds/stop                            | API transport, queue/rate/deadline/retention, durable stop tests      | Active=1 through cleanup, finite host/state/event bounds                | Burst every bound and stop under dependency loss; measure cost                             | Configured rate/spend ceiling and stop                                |
| Temporal isolation                     | Disclosure, stale credential, UID/owner tests                         | Prior-run fixtures and canary model                                     | Runner and target denial against canary, unrelated state, prior journals, metadata/network | Disclosure inspection only; no tenant claim                           |
| Cleanup/backup/recreation              | UID/owner/absence and retention tests                                 | One-unit restore matrix, original-writer fencing, deletion-before-serve | API/finalizer failure, exact absence, teardown/recreation twice                            | Cleanup failure/recovery and endpoint rollback                        |
| Fact separation                        | Exact API fixtures, service transitions, handoff byte identity        | Crash each operation/publication/deadline/transport/cleanup seam        | Independently fail each fact; preserve explicit `UNKNOWN`                                  | Consumer keeps operation, cleanup, receipt and visualization separate |

Gate 1/3 adversarial tests act from both the host runner OS identity and the most compromised fixed
target posture. They deny controller state/receipts/staged inputs/backups, canary/unrelated cluster
objects, prior journals, metadata, API and arbitrary network destinations. A namespace, runtime
label, or policy manifest alone is not enforcement evidence. Provider/runtime/network behavior, key
custody, storage fencing, rollback, teardown, cost, and public safety remain unproved until their
separate gates pass.

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
