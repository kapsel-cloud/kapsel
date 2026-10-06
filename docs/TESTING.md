# Testing

Use this page to choose where a test belongs and what evidence it must establish. It covers
deterministic inputs, hostile-input coverage, and crash recovery. [Build and test](BUILD.md) owns
commands; direct contracts own exact behavior and limits.

## Test through the owning interface

Place each test at the lowest layer whose interface states the behavior. Moving a test outward must
not require widening a production seam. A higher layer should add a composition or external-contract
assertion rather than repeat an implementation matrix.

| Location                              | Owns                                                                                             |
| ------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Implementation-local `#[cfg(test)]`   | Pure parsing, classification, SQL and filesystem invariants, and private adapter or fault seams. |
| Root package `tests/application_*.rs` | Service composition and receiver request counts with production interfaces.                      |
| Root package `tests/e2e_*.rs`         | Production binaries, machine output, exit classes, restart, and operator workflows.              |
| `crates/<crate>/tests/`               | Exported interfaces of independently meaningful workspace packages.                              |
| `fuzz/`                               | Hostile bytes entering only through production interfaces.                                       |
| Ignored simulation targets            | Seeded lifecycle schedules, repeated recovery, and invariant checks.                             |
| Explicit live-kind scripts and tests  | Disposable-cluster behavior and real process termination.                                        |

The root is both workspace root and product package, so `application_` and `e2e_` prefixes
distinguish package integration from binary end-to-end tests. A test-support crate or public
provider seam requires multiple real consumers; one production Kubernetes adapter does not justify
either.

Keep implementation-local unit tests in an inline `#[cfg(test)] mod tests` block beside the code
that owns the behavior. Named inline groups are fine when they clarify distinct rules. Do not split
unit tests into detached `tests.rs` or `*_tests.rs` files just to shorten an implementation file.
Separate modules are appropriate for cross-component, process, simulation and live-receiver
scenarios; name them for the behavior they prove. Use ordinary Rust modules rather than textual
`include!` fragments so imports, scope and formatting remain explicit.

Assert pure implementation rules exhaustively once at their owner. At higher layers, assert
authority separation, durable outcomes, composition, observable output, and non-disclosure. Prefer
table-driven cases with shared setup, and use separate precise assertions when distinct contract
facts matter.

## Receipt-consumer evidence

Receipt tests cross the application/service retrieval path, not just SQL. `gateway::tests::receipt`
covers signing failure, commit-acknowledgement loss, process exit before and after commitment and
frozen observation/signer bytes. The Linux service process lane covers both process-loss seams,
changed signing settings, and original-byte retrieval while the export destination is unavailable.
The application client retry and snapshot regressions retain independent request counts. Process
exits do not prove power loss.

## Git receiver and service checks

The receiver/journal boundary has focused tests, alongside mixed-effect service application tests.
Inline `gateway::git`, `gateway::journal::git` and `gateway::receipt::git` suites cover restricted
inputs, subprocess bounds, receiver-bound dispatch, immutable authority, shared capacity, phase
guards and purpose-separated evidence. The real-Git lane additionally needs an explicitly selected
Git 2.55.0 executable:

```sh
(umask 077; KAPSEL_TEST_GIT=/absolute/path/to/git \
  cargo test --locked -p kapsel --lib gateway::git::tests -- --include-ignored)
```

The private umask matches the service unit and keeps newly created repository contents private.
Disposable fixtures copy the selected executable into private custody and invoke the same receiver
code. They cover a fresh transition, stale competitor, transfer to another receiver, loss before and
after the ref update, dropped dispatch permission with A→B→A, onward movement, and reopening
unchanged signed evidence without receiver or signing material. An explicit unsent-present-B case
drops dispatch permission, lets another sender establish B, then requires `UNKNOWN` with zero
original update packets across recovery. Seeing B does not establish original causation. Receiver
packet traces and hook invocations are counted separately; fixture-owned intervening writes are
explicit. Hook counts establish invocation, not downstream completion. The service-application case
additionally proves selection and signing-only resumption after receiver/material removal. The
process fixture below owns detached inspection and byte-identical receipt retrieval after material
removal.

On Linux, the [runnable Git service fixture](GIT_REF_TRANSITION.md#runnable-source-example)
exercises CLI provisioning, startup material, real service-process loss, the maintained
fresh-session caller, MCP bridge and detached inspection. It covers send/receipt-commit loss and
pre/post-receive loss, then reopens the same history without selectable catalog or execution
material. This is source-level process evidence, not power-loss or installed-systemd qualification.

## Receiver-recovery evidence

`gateway::receiver_recovery_tests` crosses the real Kubernetes adapter, journal and receipt path
against an independent HTTP service fixture. Eight scenarios retain evidence that isolated
fake-adapter or classifier tests do not establish together:

- process exit after attempt commitment but before send, and after a persisted PATCH loses its
  response;
- replacement UID, changed image or a later generation retaining the operation marker before
  recovery;
- a preflight-to-PATCH version race that records an attempt but persists no patch;
- rollout completion after the observation budget, without changing frozen UNKNOWN on reconnect; and
- a defined failed rollout through the complete adapter-to-receipt path.

Expected results, GET/PATCH and persistence counts are independent of the gateway classifier.
`receiver.rs` owns exact PATCH assertions and receiver state without importing the gateway.
`assert_retained_facts` checks receipt inputs against that state. Every case reopens in a fresh
process and proves byte-identical evidence and zero receiver I/O. This is a service fixture, not
live admission or power-loss evidence.

Related behavior is proved at its owning interface rather than repeated in every receiver scenario:

| Behavior                                  | Owner and proof                                                                                                                                                                                                                                                                                                                    |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Healthy execution and identical reconnect | `application_retry::healthy_dispatch_and_restart_preserve_one_http_request_and_original_receipt` checks the actual application, one PATCH/two GETs and original receipt on reopen. Adapter `omitted_zero_replica_counts_can_still_report_success` owns the missing-zero field case.                                                |
| Stale snapshot version or UID             | `gateway::tests::snapshot_approval::stale_snapshot_is_durable_status_only_without_patch_or_receipt` asserts version/UID rejection, no apply/observe, preserved targets and no receipt across reopen. Adapter identification tests own extraction of UID/version. The two churn causes exercise the same opaque-version comparison. |
| Exact request authorization               | `gateway::tests::validation::exact_authorization_is_required_before_persistence` checks every field, both fresh and already requested.                                                                                                                                                                                             |
| Immutable snapshot approval               | `gateway::tests::snapshot_approval` checks original authority across crash seams and rejects changed UID/version before and after receipt completion, preserving original bytes.                                                                                                                                                   |
| Worker exclusion                          | `gateway::tests::recovery::worker_lock_prevents_overlapping_provider_activity` checks zero identify/apply/observe calls; `application_retry` also checks a contender while a real HTTP PATCH is pending.                                                                                                                           |

Image acceptance is not rollout completion. A fresh name or revision lookup can describe an
intervening writer or a recreated Deployment, not the original action. The receiver matrix checks
replacement UID and changed image; owner classifier tables additionally check generation and pending
rollout facts. Current Kapsel regressions do not establish equivalence with an unsigned tool, equal
multi-user isolation, or hostile-input hardening. Use
[Build and test](BUILD.md#receiver-recovery-regressions) for current commands. The deterministic
gate does not qualify live or platform-specific lanes.

## Core effect-gateway proof matrix

| Layer                | Required proof                                                                                            |
| -------------------- | --------------------------------------------------------------------------------------------------------- |
| Request validation   | Bounds for identity, namespace, Deployment, container, digest, and authorization.                         |
| Authorization        | Signed grant, configured trust, exact tuple, and rejection before persistence.                            |
| Journal transition   | Deterministic fault injection at every durable state.                                                     |
| Target disposition   | Permanent invalid targets are pre-attempt `NOT_ATTEMPTED`; transient reads stay authorized without PATCH. |
| Provider attempt     | Safe GET precedes atomic target identity and `apply_started`; mutation follows that commit.               |
| Recovery             | Every injected window and process kill reopens without a blind second mutation.                           |
| Receiver observation | Request acceptance, timeout, transport completion, and rollout result remain distinct.                    |
| Classification       | Timeout and unresolved evidence are `UNKNOWN`, never false success or failure.                            |
| Receipt/inspection   | Canonical vectors carry all classifier inputs; inspection recomputes under explicit trust and limits.     |
| Receipt completion   | Frozen observation precedes signing; bytes, digest, signer and finalized state commit together.           |
| Export               | Collision-safe export uses committed bytes. Failure cannot reopen completion or block later retrieval.    |
| Compatibility        | Format 6 refuses older journals, including format 5, without migration; wire meanings remain explicit.    |
| Hostile input        | Malformed, oversized, duplicate, reordered, unknown, and trailing records fail closed.                    |
| Disclosure           | Secrets and unbounded provider bodies stay out of SQLite, receipts, reports, errors, and logs.            |

`INSPECTED` means authenticated bytes and classifier consistency under supplied trust. It is not
receiver truth, causation, complete capture, compliance, or `VERIFIED`.

## Defensive boundary checks

The maintained parser and I/O owners enforce the following limits. These bound accepted bytes and
work, not measured RSS or operating-system I/O latency. Configuration and private filesystem custody
remain operator responsibilities. The audit found no public receipt-injection path: Kubernetes
completion now checks the private candidate against the current row instead of relying on its
builder's call convention.

| Boundary                     | Exact owner                                                                                                                                                           | Enforced limit and placement                                                                                                                                                                                                                                                                   |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Kubernetes grant             | `crates/kapsel-authority/src/lib.rs::verify_authorization_grant`                                                                                                      | 4 KiB envelope before decoding; 2 KiB statement before parsing; 512-byte ASCII text before copying.                                                                                                                                                                                            |
| Git grant                    | `crates/kapsel-authority/src/git.rs::verify_git_ref_grant`                                                                                                            | 4 KiB envelope, 2 KiB statement; bounded identities, one fixed ref and 40-byte commit IDs.                                                                                                                                                                                                     |
| Ordered binary records       | `crates/kapsel-authority/src/record.rs::Records`, `src/gateway/receipt/mod.rs::Records`                                                                               | Checked header/end/tag arithmetic; exact order and exhaustion; borrowed values before bounded text allocation.                                                                                                                                                                                 |
| Receipt and trust inspection | `src/gateway/receipt/mod.rs::parse_envelope`, `InspectionLimits::validate`, `crates/kapsel-authority/src/lib.rs::parse_receipt_trust`                                 | Both effect receipts: 16 KiB envelope, 8 KiB statement, 1 KiB trust, 512-byte text; supplied limits can only narrow maxima. No ambient trust, clock or I/O.                                                                                                                                    |
| Service operator document    | `src/application/service/document.rs::parse_service_operator_document`, `BoundedVec`                                                                                  | 160 KiB before JSON parsing; 128 keys and 32 approvals; reject an extra array element before decoding it. Hex conversion checks length before output allocation: 32-byte keys, 4 KiB grants.                                                                                                   |
| Receiver configuration       | `src/gateway/git.rs::GitReceiverConfiguration::from_document`, `src/application/mod.rs::load_operator_kubernetes_client`, `ServiceExecution::from_operator_snapshots` | Git JSON 4 KiB; kubeconfig 16 KiB; seeds/public keys exactly 32 bytes. JSON/YAML work is bounded by the input ceiling; service strings also remain within the document ceiling before field validation.                                                                                        |
| Operator file reads          | `src/command/mod.rs::read_bounded`, `crates/kapsel-daemon/src/startup.rs::read_private_file`                                                                          | Metadata size/type checks before allocation/read; capped maximum-plus-one reads catch growth. Nonblocking no-follow opens reject special files without waiting for a FIFO peer. Service inputs additionally enforce owner/group, mode and single-link custody.                                 |
| Production Kubernetes HTTP   | `src/application/mod.rs::load_operator_kubernetes_client`, `src/gateway/kubernetes/adapter.rs`                                                                        | Response body limited to 2 MiB before aggregate collection/JSON decoding; 10-second request deadline, 180 reads/180 seconds per observation pass; one PATCH with transport retries disabled. Custom operator clients retain their own no-retry/body-bound obligations.                         |
| Socket framing               | `crates/kapsel-daemon/src/server/protocol.rs::request_length`, `server/runtime.rs::read_request_frame`                                                                | Nonzero 16 KiB request length before frame allocation; reject trailing bytes. Eight connection permits; two-second whole-frame read/write deadlines. Ordinary/receipt responses are 16/40 KiB; bounded projections precede output validation.                                                  |
| Fixed client replies         | `crates/kapsel-daemon/src/client_transport.rs::exchange`                                                                                                              | 40 KiB checked prefix before allocation; reject trailing bytes; two-second per-socket-operation timeouts, not a cumulative exchange deadline.                                                                                                                                                  |
| Stdio MCP                    | `crates/kapsel-daemon/src/bin/kapsel-service-mcp.rs::main`                                                                                                            | 16 KiB line plus one sentinel byte before JSON parsing; duplicate-key rejection; 96 KiB output ceiling. Stdio waiting has no elapsed deadline.                                                                                                                                                 |
| Receipt files                | `src/command/mod.rs::read_bounded`                                                                                                                                    | 16 KiB metadata ceiling before allocation; maximum-plus-one read; no-follow, nonblocking regular-file reads.                                                                                                                                                                                   |
| Journal opening              | `src/gateway/journal/opening.rs`, `journal/schema.rs`, `journal/capacity.rs`                                                                                          | 64 MiB database and 65 MiB main rollback checks before SQLite recovery; fixed 100-byte header read; 64 KiB SQLite value/row allocation limit; physical encoded payload/depth validation before row loading. No-follow, nonblocking opens then check regular-file/private/single-link identity. |
| Retained journal work        | `src/gateway/journal/capacity.rs::require_retained_bounds`                                                                                                            | 504 retained/32 unfinished identities; 16,384 pages, 20-level accepted trees, 16 KiB individual persisted values and 4 KiB retained grants. Integrity work is physically bounded, not subject to an elapsed deadline.                                                                          |
| Git subprocess               | `src/gateway/git.rs::run`, `run_bounded`, `read_bounded`                                                                                                              | Explicit executable, cleared environment, fixed arguments/protocol restrictions; 15 seconds per command; each stdout/stderr at most 16 KiB before buffer extension. Failure/cancellation retires the owned process group; escaping operator hooks remain outside the boundary.                 |
| Git custody walk             | `src/gateway/git.rs::private_tree`, `trusted_ancestors`                                                                                                               | At most 100,000 entries and depth 32; check pending count before enqueueing; reject links, foreign ownership and writable custody. Paths are operator-owned; filesystem calls have no elapsed deadline.                                                                                        |

The retired direct operator document is not an execution entry point. Journal read-only and
rollback-file opening reject FIFOs without blocking at `open`. The FIFO regression uses real special
files with no peer, not simulated metadata.

The Kubernetes completion regression supplies a correct current snapshot with a same-ID receipt for
different facts, then supplies the foreign snapshot with its matching candidate. Both fail without
changing the phase, frozen statement or retained grant. Correct completion still works. A later
candidate cannot replace prior terminal evidence. Existing signing-failure, acknowledgement-loss,
key-rotation and process-exit traces require original facts and identical retrieval without receiver
I/O. Git already compares the decoded candidate to its transaction-owned statement.

Completion adds transaction-owned reads and takes an immediate write transaction; its UPDATE,
schema, persisted payload bounds and single-write commit shape are unchanged. The owned write-plan,
retained-charge, physical-layout, main-rollback and full-capacity regressions therefore remain the
owning capacity checks. No savepoint, extra tree mutation or new rollback payload is introduced.

The reviewed production owners contain no `unwrap()`, `expect()` or `panic!` exceptions. Always-on
assertions there relate only to compile-time size/schedule constants; schedule assertions and
panic/unwrap permissions are test-only. Other narrow lint exceptions concern module/style or
coherent transition decoding, not operating-error panics. Authority, result classification and
execution-disposition matches keep distinct typed outcomes; parser wildcard branches reject unknown
values. Kubeconfig rejects external credential files, exec and auth providers, and prevents ambient
proxy discovery. Git clears its environment and fixes the executable and configuration sources.
Receipt inspection receives trust, evaluation time and limits explicitly.

`cfg(test)` and explicit `demo-harness`/`test-harness` features own fault controls. Default features
are empty. The release assembler builds the locked production packages without either feature;
test-feature evidence does not qualify installed production artifacts. These checks do not establish
host confinement, power-loss behavior, a hard memory ceiling or a deadline for stalled storage.

## Determinism and crash proof

Default semantic tests do not depend on wall-clock time, random keys, live services, ambient trust,
locale, or filesystem order. Use fixed keys, explicit evaluation time, private temporary
directories, seeded inputs, and sorted output. A subprocess test may use a bounded monotonic
coordination deadline; result meaning must not depend on polling order or timing. Test intentional
SQLite lock conflicts with a zero busy timeout and assert the lock error. Use paused Tokio time for
in-memory deadline tests. Process fixtures should acknowledge admission or handler completion
instead of using fixed sleeps as readiness evidence.

Fault tests, simulations, process recovery, and compile-time demonstration controls cross the same
private operation-selected provider and receipt-completion implementations used by the service.
Tests explicitly select an operation identity and do not claim queue fairness. Process-kill proof
crosses the ambiguous mutation and receipt-commit seams, establishes no second mutation request, and
preserves committed bytes without re-signing. Export may use a new destination without changing the
durable action or signing identity.

The transient-target gateway regression checks no journal update, no PATCH, safe GET repetition on
reopen, and preservation of an existing inert `target_read_failures` value. Format-6 schema
validation still requires that column. `application_retry` service A/B tests preserve another
unfinished row's frozen grant/facts while the selected operation advances. These tests use actual
service selection and independently count receiver requests. Gateway fault tests retain targeted
finalization and `target_read_crash_stays_authorized_and_repeats_only_the_safe_get` evidence.

A live `kind` lane is explicit, environment-owning evidence. It complements but never replaces
fault-injection around every journal window.

## Direct-execution retirement evidence

[ADR 0012](decisions/0012-v04-beta-quality-bar.md#approved-execution-scope-and-compatibility)
approves service-only HEAD execution. HEAD retires the direct adapters and source-only demo after
passing equivalent retained service/process/packaged checks. Shared service checkpoint controls
remain because the Linux process lane consumes them.

| Existing direct-demo assertion                               | Retained service owner                                                                                                  | Required evidence                                                                                                                                  |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Kill after mutation; recover the same ID with one PATCH      | Linux `ordinary_restart_reuses_frozen_snapshot_receipt_under_rotated_configuration`; packaged Kubernetes `service-loss` | Both kill/recovery traces, plus independent HTTP/API-server mutation counts                                                                        |
| Kill after receipt commit but before caller export           | The same Linux test; packaged Kubernetes `service-loss` receipt-commit-loss trace                                       | A terminal status followed by SIGKILL before the first receipt export; this is not graceful restart                                                |
| Changed signing material cannot replace the original receipt | The same Linux test; packaged receipt-commit-loss trace                                                                 | Compare independent format-6 grant/receipt/signer snapshots before loss and after cold key rotation, then compare caller exports to original bytes |
| Repeated selection and reads add no mutation or observation  | Linux HTTP fixture; packaged API-server audit                                                                           | Linux GET/PATCH counts and packaged PATCH counts after same-ID selection and repeated original-byte retrieval                                      |
| Detached inspection needs no receiver authority              | Linux inspection and packaged `kapsel inspect`                                                                          | Original receipt inspected under its original explicit purpose, key and evaluation time                                                            |
| Receipt export failure does not change history               | Linux fixed-client export checks                                                                                        | Missing destination and existing-file refusal, then identical successful exports                                                                   |

The packaged fixture reads format-6 evidence through a separate read-only SQLite connection. It
requires bounded finalized grant/receipt bytes and the original signer, not a reconstructed receipt.
`test_kind_agent_action_exercise.py` checks this reader offline; it does not establish that the
packaged crash journey ran. The fixture retains the original bounded grant/receipt bytes and their
digests in private evidence. It restores only current signing material, never history.

Before removal, run the full Linux process lane and both packaged receiver journeys from
[Build](BUILD.md#packaged-service-live-workflow) on the selected candidate. Keep source/executable
and archive identities with the private evidence. A clean-source artifact is required; a dirty
assembly or an earlier artifact cannot establish candidate acceptance. Missing checks block
candidate acceptance. Historical published releases retain their own commands and bytes.

For retained-history compatibility, pass an exact prior format-6 archive and revision through
`--retained-archive` and `--retained-revision` to both packaged receiver runners. Fixtures first run
the prior producer, then replace only the cold executables with the candidate. Git compares an
independent full-row snapshot across attempted recovery and finalized history reads. Kubernetes
compares full rows across attempted startup and finalized receipt-commit loss. It also compares a
prior producer's original receipt under the rotated candidate key and after catalog withdrawal. Both
preserve the original grant, receipt and signer, inspect original receipts and retain the two
archive identities. This is not a journal migration or downgrade test.

## Evidence classes

### Deterministic suite

The default suite contains implementation-local tests, package integration tests, binary tests
needing no external service, and documentation tests. It owns repeatable semantic and hostile-input
proof. Source coverage is an informational review aid only; no percentage establishes crash safety,
Kubernetes semantics, release integrity, or production readiness.

The service MCP lane proves bounded newline-delimited framing, five ID-only tools, operator
authority outside caller input, protocol-only output and bounded secret-free errors. Socket fixtures
assert exact requests/exchange counts and zero requests for invalid input. Linux process tests
retain `UNKNOWN` and original bytes through real bridge loss and reconnect. Cancellation, EOF or
transport completion never determines receiver outcome. The retired direct CLI/MCP parity check is
not a second classifier oracle; owner tables and service transport projections remain.

The current format-6 version-rejection test proves older journals, including format 5, remain
untouched without migration. [Build and test](BUILD.md#journal-version-rejection) owns the current
command. Historical v0.1.1 migration/restore fixtures describe the published pre-format-4 baseline,
not a current migration path. [Journal retention](UPGRADE.md) owns current operating precautions;
the [v0.2.0 tagged guide](https://github.com/kapsel-cloud/kapsel/blob/v0.2.0/docs/UPGRADE.md) owns
that older release pair.

### Robustness

Five distinct fuzz targets call production Kubernetes/Git receipt inspection, Kubernetes/Git grant
verification and service-document parsing. Canonical valid and deliberately invalid seeds cover
legacy and snapshot purposes, signed inconsistent results, record shapes, UTF-8, lengths, byte
limits and service array counts. The deterministic corpus check asserts seed acceptance
independently of coverage discovery. Existing owner tables, exact vectors, compatibility and unique
composition tests remain required.

Targets receive explicit trust, evaluation times and limits. They never discover credentials or
perform filesystem, network or receiver I/O. The service path is an inert operator-supplied fixture.
Targets check trailing rejection, narrowed limits, external key/purpose/time appointments and
canonical authenticated grants. Bounded fixture re-signing additionally reaches statement
validation; it supplies no production execution authority. Git's independent acknowledgement/result
assertion must reject a signed `SUCCEEDED` statement with `unknown` acknowledgement.

The retained runner records target-specific starting corpus bytes, commands, source and executable
identity, compiler/fuzzer identity and failure artifacts. Artifacts are not automatically minimized.
[Build](BUILD.md#robustness-lanes) owns explicit minimization/replay and isolated negative-control
procedures. Baseline must pass, controls must fail for the intended property, and minimized replay
must preserve that property. Byte coverage, a smoke pass or negative-control detection does not
establish semantic completeness, authority proof or receiver qualification.

Long simulations generate bounded lifecycle schedules, crash windows, transient target-read errors,
and reopen operations from an explicit seed. Each shard uses independent fixture journals with at
most 100 identities per journal. It retains earlier histories until successful fixture cleanup; it
does not prune history or reset an attempted operation to bypass capacity. Separate storage tests
own full-capacity guarantees. Every step checks durable state, provider-call count, terminal state,
and frozen-receipt invariants. The seed is always replayable; wall-clock duration may change only
how many cases run, not their semantics.

### Live Kubernetes and demonstration

The live-kind gate owns real Kubernetes success, defined failed rollout, bounded `UNKNOWN`, and
process loss against a uniquely owned disposable cluster. It must show no blind second patch and
must clean up or export bounded failure evidence. Its recovery-policy case uses an instrumented
mutating webhook to separate PATCH requests and admission effects from persisted Deployment and
controller effects when an identical stale patch is replayed.

The exact-snapshot case separately acquires the operator target through the production adapter. It
proves one matching PATCH, preflight stale rejection for both version drift and same-name recreation
without a PATCH, and a changed receiver version between preflight and the gateway PATCH. That final
conflict remains `apply_started`, not a pre-attempt conclusion; deterministic fault tests own the
exhaustive restart and receipt-projection matrix around it.

The packaged service journey covers mutation-loss and receipt-commit-loss through production
binaries. Live receiver checks retain healthy/failed rollout and untargeted-container assertions.
Published v0.2.0 keeps its historical direct demo. Shared service process checkpoints remain outside
caller input and production executables. Finite traces are not exhaustive recovery proof.

### Release artifact

Artifact checks use extracted `x86_64-unknown-linux-gnu` binaries, not Cargo test binaries. Two
isolated assemblies must produce identical archive, checksum, SBOM, digest-manifest, and verifier
bytes. Hostile-archive validation precedes extraction. Smoke uses extracted files to check binary
identity, grant provisioning, operation, read-first restart, offline inspection, and MCP behavior.
The service-container lane checks fixed paths, separate identities, original receipt retrieval, and
independent mutation counts. It does not qualify native systemd or interrupted-attempt recovery.

The preview archive contains no demonstration binary or pause feature. The older v0.2.0 artifact
retains its tagged demo and crash checks. Current packaged interrupted-execution and live-receiver
checks are separate lanes. The Sigstore bundle receives identity and failure checks, not a
reproducibility requirement. [Release artifacts](RELEASE.md) owns exact layout, authentication,
provenance, and evidence limits.

### Kapsel service

The service evidence is layered around `ServiceApplication`, one bounded catalog over one journal:

- `service_application_contract` proves durable `ADMITTED` before acknowledgement, worker ownership,
  original authority, bounded history and reads without execution material. Admission is not
  receiver success or worker liveness.
- `application_retry::service_selection` exercises independent-target and same-target A/B selection
  through a real loopback HTTP receiver. While A holds a PATCH response and the worker, B is `BUSY`
  with no insertion or receiver I/O. Missing signing material then leaves A `receiver_observed`,
  unfinished rather than terminal `UNKNOWN`. Explicit B selection advances without changing A's
  retained row: an independent target succeeds; the same target's unchanged approval becomes
  `NOT_ATTEMPTED / STALE_APPROVAL` after a real GET. Independent HTTP counts are one PATCH per
  operation for separate targets, and A's one PATCH/B's zero for the shared target. Explicit A
  resumption signs frozen facts without more HTTP; later selection and reopen preserve original
  receipt bytes. A separate paused-clock HTTP mock in that suite retains the retired endpoint's
  transient-preflight and terminal-`UNKNOWN` cases: B completes without changing A's row or receipt;
  only explicit reselection retries A's safe preflight, while terminal A produces no further I/O.
  These are not conflict safety, refreshed approval or live admission evidence.
- `kapseld` protocol/runtime tests cover version-1 framing, hostile fields, disclosure, durable
  admission decisions, one physical execution worker, bounded blocking jobs and no queue.
- Linux `linux_process` tests cover effective-group credentials, caller disconnect, concurrent reads
  and one journal. `ordinary_restart_reads_before_explicit_reselection_without_second_patch` and
  `restart_reads_before_explicit_reselection_without_a_second_patch` prove read-first startup and
  explicit same-ID resumption, not automatic reconciliation before bind. Frozen-receipt restart
  tests preserve original bytes under changed settings.
- Startup, publication and asset tests cover fixed roots, no-follow rules, lifecycle exclusion,
  graceful retirement, exact argv, stale sockets, systemd, sysusers and namespaced RBAC.
  Root-substitution tests prove journal creation and socket bind stay with retained directory
  identities; receipt retrieval has no receipt-root dependency.

Current tests cover authorization, HTTP retry counterexamples, attempt-loss recovery, and original
receipt immutability. Retired prototypes do not define current behavior.

Service-client tests freeze five versioned commands (`list`, `history`, `submit`, `status`,
`receipt`), bounded framing, receipt digest verification, exclusive mode-`0600` output and refusal
to replace an existing file. `kapsel-authority` tests freeze shared grant/trust vectors and
consistency. Its `grammar_tests` own request bounds and spelling; gateway and service tests own
rejection before persistence or application access rather than repeating that matrix. This does not
make the authority package a public SDK.

The [service contract](KAPSEL_SERVICE.md) owns composition and protocol; the
[effect-gateway contract](EFFECT_GATEWAY.md) owns admission, recovery and receipt semantics.
[Build and test](BUILD.md#kapsel-service-candidate) owns source and separate Linux commands. These
checks do not establish installed-native equivalence, disk-backed or power-loss durability, or live
Kubernetes qualification. The service is absent from v0.2.0. The published preview's
[release evidence](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.3.0-preview.1) separately
records native-systemd and live-receiver qualification for its exact bytes; current coverage does
not qualify an installer.
[Experimental-host precautions](KAPSEL_SERVICE.md#experimental-installer-hosts) cover hosts that ran
staged installer builds.
