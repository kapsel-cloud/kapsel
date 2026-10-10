# Evidence map

Use this page to find the check that would catch a broken guarantee. Start with the boundary you are
changing, then follow its maintained tests and qualification lane. A test named here is an
obligation, not a record that a release candidate passed it.

[Testing](testing.md) explains evidence classes. [Qualification](qualification.md) supplies commands
and prerequisites. Contracts define behaviour. This map connects that behaviour to its checks.

## Find a guarantee

| Question                                                           | Start here                                                   |
| ------------------------------------------------------------------ | ------------------------------------------------------------ |
| Can completion or export replace the original receipt?             | [Receipt checks](#receipt-consumer-evidence)                 |
| Can Git recovery resend, or mistake present B for acknowledgement? | [Git checks](#git-receiver-and-service-checks)               |
| Can a lost Kubernetes response lead to another PATCH?              | [Receiver recovery](#receiver-recovery-evidence)             |
| Which checks own each lifecycle boundary?                          | [Core matrix](#core-effect-gateway-proof-matrix)             |
| Is hostile input bounded before use?                               | [Defensive checks](#defensive-boundary-checks)               |
| Does process loss preserve original history and evidence?          | [Crash checks](#service-crash-and-retained-history-evidence) |
| Can a deadline release permits while work survives?                | [Runtime ownership](service_runtime.md)                      |
| Can admitted work exhaust configured completion space?             | [Capacity argument](storage_capacity.md)                     |

## Receipt-consumer evidence

A SQL test alone cannot establish that a caller can retrieve the right receipt after restart.
Receipt checks therefore cross completion, application reads, service retrieval and caller export.

| Guarantee                                                          | Maintained check                                                                                 | Evidence limit                                                 |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------- |
| Signing failure leaves frozen observations unchanged               | [Atomic-record simulator](../../src/kernel_simulation_tests.rs)                                  | Fixture signing, not key-management qualification              |
| Completion rejects another statement for the same ID               | `receipt_commit_rejects_wrong_facts_and_foreign_snapshot_without_changing_history` in that suite | Checks the current row, not only the builder's call convention |
| Lost commit acknowledgement resolves to original bytes             | Atomic receipt-delivery laws; process-exit and application retry/snapshot suites                 | Process exit is not power loss                                 |
| Retrieval survives changed signing settings and unavailable export | [Linux process lane](qualification.md#kapsel-service-candidate)                                  | Source harness, not installed production bytes                 |

A valid signature is not enough for receipt completion: the statement must match the current row's
frozen facts. Both effects check that match under the write transaction. The wrong-facts regression
checks the Kubernetes rejection cases. [`journal::git`](../../src/gateway/journal/git.rs) checks the
Git comparison. Neither a foreign snapshot nor a later candidate may replace original history.

## Git receiver and service checks

Git success depends on the original acknowledgement, not on finding B later. The checks distinguish
receiver packets, ref state and hook invocation so those facts cannot substitute for one another.

| Boundary                      | Maintained check                                                                                   | Key obligation                                                                  |
| ----------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Receiver dispatch             | [`gateway::git`](../../src/gateway/git.rs)                                                         | Restricted inputs, bounded subprocesses and receiver-bound permission           |
| Retained authority and phases | [`journal::git`](../../src/gateway/journal/git.rs)                                                 | Immutable authority, shared capacity and phase guards                           |
| Signed result                 | [`receipt::git`](../../src/gateway/receipt/git.rs)                                                 | Purpose separation and acknowledgement/result consistency                       |
| Real receiver                 | [Git 2.55.0 matrix](qualification.md#git-transition-service)                                       | Fresh transition, stale competitor and ambiguity without resend                 |
| Service composition           | Mixed-effect application suites and [Git process fixture](qualification.md#git-transition-service) | Selection, signing-only resumption, detached inspection and identical retrieval |

The real-Git matrix covers transfer to another receiver, loss before and after the ref update,
dropped permission with A→B→A, onward movement, and reopening without receiver or signing material.
In the unsent-present-B case, another sender establishes B after the original sender's permission is
dropped. Recovery must remain `UNKNOWN` with zero original update packets. Fixture-owned intervening
writes are identified separately. Hook counts establish invocation, not downstream completion.

The Linux fixture adds CLI provisioning, startup material, process loss, the fresh-session caller
and MCP bridge. It covers send/receipt-commit and pre/post-receive loss, then reads the same history
after catalog and material withdrawal. Source process evidence does not qualify native systemd,
power loss or the extracted production artifact. The separate artifact journey is required for
release qualification.

## Receiver-recovery evidence

[`gateway::receiver_recovery_tests`](../../src/gateway/receiver_recovery_tests.rs) runs the real
Kubernetes adapter, journal and receipt path against an independent HTTP fixture. The fixture
supplies expected results, exact PATCH assertions, receiver state and GET/PATCH/persistence counts.
It does not import the gateway classifier. `assert_retained_facts` compares receipt inputs with that
state.

| Failure window or receiver change                                   | Required check                                               |
| ------------------------------------------------------------------- | ------------------------------------------------------------ |
| Process exit after attempt commit, before send                      | Recovery observes; it does not use a new send opportunity    |
| Persisted PATCH loses its response                                  | Recovery adds no PATCH                                       |
| Replacement UID, changed image, or later generation with the marker | Classification uses the original target and generation rules |
| Version changes between preflight and PATCH                         | Attempt is recorded even though no patch persists            |
| Rollout completes after the observation budget                      | Frozen `UNKNOWN` does not improve on reconnect               |
| Defined failed rollout                                              | Failure survives the complete adapter-to-receipt path        |

The eight scenarios reopen in a fresh process and check identical evidence with zero receiver I/O.
They exercise a service fixture, not live admission or power-loss durability. Run the
[full matrix](qualification.md#receiver-recovery-regressions). A reduced replay is not equivalent.

Related checks stay at the interfaces that own them:

| Guarantee                              | Maintained check                                                                                                                                                  |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Healthy execution and reconnect        | `application_retry::healthy_dispatch_and_restart_preserve_one_http_request_and_original_receipt`: one PATCH, two GETs, original receipt                           |
| Missing zero-replica fields            | Adapter `omitted_zero_replica_counts_can_still_report_success`                                                                                                    |
| Stale UID or version                   | `gateway::tests::snapshot_approval::stale_snapshot_is_durable_status_only_without_patch_or_receipt`: no apply/observe or receipt; targets preserved across reopen |
| Exact authority before persistence     | `gateway::tests::validation::exact_authorization_is_required_before_persistence`: every field, fresh and already requested                                        |
| Approval cannot refresh an existing ID | Snapshot-approval crash tests: changed UID/version rejected before and after completion; original bytes preserved                                                 |
| Worker exclusion                       | `gateway::tests::recovery::worker_lock_prevents_overlapping_provider_activity`; application contender during a pending HTTP PATCH                                 |

Adapter identification tests check UID/version extraction. Classifier tables check generation and
pending-rollout predicates. Image acceptance is not rollout completion. A new name/revision lookup
can describe an intervening writer or recreated Deployment.

## Core effect-gateway proof matrix

Use the [gateway contract](../reference/effect_gateway.md) for the definitions in this table. Names
below identify suites, not separate release gates.

| Boundary                         | Maintained checks                                                                                                                 | Obligation                                                                                                                               |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Request and authority            | `kapsel-authority::grammar_tests`; gateway `validation`                                                                           | Bounds and exact signed authority; reject before persistence                                                                             |
| Journal transitions and dispatch | Gateway `lifecycle`, `dispatch`, `recovery`, `snapshot_approval`; [atomic-record simulator](../../src/kernel_simulation_tests.rs) | Enumerate fresh durable windows and deliberate recovery interactions; permission only from a confirmed fresh attempt commit              |
| Target disposition               | Snapshot/target-read tests; adapter/classifier tables                                                                             | Permanent rejection is `NOT_ATTEMPTED`; transient reads remain authorized without PATCH                                                  |
| Observation and classification   | `gateway::kubernetes`; receiver-recovery matrix                                                                                   | Acceptance, timeout, transport and rollout facts stay distinct; unresolved evidence is `UNKNOWN`                                         |
| Receipt and inspection           | Kubernetes/Git receipt suites; authority vectors                                                                                  | Freeze before signing; commit exact bytes/digest/signer with terminal state; inspect under explicit trust                                |
| Export                           | Fixed-client and command-interface tests                                                                                          | Exclusive copy of committed bytes; export failure cannot reopen completion                                                               |
| Original authority after I/O     | [Atomic-record simulator](../../src/kernel_simulation_tests.rs)                                                                   | Suspended preflight, mutation and observation reject changed grant bytes before advancing; both stores and effects                       |
| Stored read projections          | Atomic-record simulator                                                                                                           | Exact status, admitted phase, original targets and receipt bytes/readiness; ordered history entries on SQLite; no writes or receiver I/O |
| Original-key disclosure          | Atomic-record simulator                                                                                                           | Substituted public keys cannot disclose retained targets or receipts; unaffected peers remain readable; history pages use real SQLite    |
| Journal format                   | [Version rejection](qualification.md#journal-version-rejection)                                                                   | Older journals remain untouched, without migration                                                                                       |
| Disclosure and hostile input     | [Defensive checks](#defensive-boundary-checks)                                                                                    | Reject malformed records; keep secrets and unbounded bodies out of retained/output data                                                  |

The same simulator owns fresh interruption enumeration, deliberate joins and suspended service
contention. Its [window mapping](testing.md#consolidated-crash-matrix-obligations) connects safe
pre-attempt retry, unsent and ambiguous attempts, response/observation loss and frozen zero-I/O
continuation. Eligible fresh cuts require exact call counts and durable-write reach. Contenders must
acknowledge only existing responsibility or busy refusal without advancing any peer. The all-peer
oracle checks raw original history even when application trust is unavailable. Exact Git
acknowledgement/ref binding remains independent; an observation-substitution control changes the ref
while leaving acknowledgement/result unchanged. Original receipt bytes remain immutable under later
receiver and signer changes. Legacy-format, HTTP, storage, physical-job, process, live-receiver and
artifact checks retain their existing owners.

`INSPECTED` means the bytes authenticated and the classifier result matched under supplied trust. It
does not prove receiver truth, causation, complete capture or compliance. It is not `VERIFIED`.

## Defensive boundary checks

The useful question is not just “is there a limit?” but “does the check run before the risky work?”
The contracts own exact maxima. This map identifies the parser or I/O suites that must keep checking
placement, rejection and disclosure.

| Boundary                   | Maintained owner/checks                                                                                                              | Must happen before                                                                   |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------ |
| Kubernetes/Git grants      | [`kapsel-authority`](../../crates/kapsel-authority/src/lib.rs), [`git`](../../crates/kapsel-authority/src/git.rs) verification tests | Envelope decoding, statement parsing and text copying                                |
| Ordered binary records     | Authority `record::Records`; receipt parser tests                                                                                    | Arithmetic, allocation and use of ordered fields                                     |
| Receipt/trust inspection   | Kubernetes/Git receipt tests; `InspectionLimits::validate`; trust parser tests                                                       | Parsing beyond supplied limits or accepting key/purpose/time                         |
| Service operator document  | [`document`](../../src/application/service/document.rs) parser and `BoundedVec` tests                                                | JSON decoding of excess bytes or an extra array element; hex output allocation       |
| Receiver material          | Git configuration, kubeconfig loader and service snapshot tests                                                                      | Construction from unsafe or excessive input; ambient fallback                        |
| Operator and receipt files | Command `read_bounded`; daemon startup file tests                                                                                    | Allocation/read, symlink following or waiting for a special-file peer                |
| Kubernetes HTTP            | Adapter/client tests                                                                                                                 | Aggregate body collection and JSON decoding; a retry of mutation                     |
| Socket requests            | Protocol/runtime tests                                                                                                               | Frame allocation, application access or unbounded connection/job creation            |
| Fixed-client responses     | Client-transport tests                                                                                                               | Reply allocation or accepting trailing bytes                                         |
| Stdio MCP                  | [`service_mcp`](../../crates/kapsel-daemon/tests/service_mcp.rs)                                                                     | Parsing an oversized line or exposing authority in tool input/output                 |
| Journal opening            | Opening/schema/capacity tests; `capacity_layout`                                                                                     | SQLite recovery, row loading or accepting unaccounted physical pages                 |
| Retained capacity          | Capacity/storage/validation suites                                                                                                   | Admission beyond aggregate responsibility or completion-space bounds                 |
| Git subprocesses           | `gateway::git` tests                                                                                                                 | Output-buffer extension; unbounded command lifetime or orphaned owned process groups |
| Git custody walk           | `private_tree`/`trusted_ancestors` tests                                                                                             | Enqueueing excessive entries/depth or accepting unsafe custody                       |

Exact limits and exclusions are in [authority/evidence formats](../reference/evidence_formats.md),
[service](../reference/service.md), [MCP](../reference/mcp.md),
[commands](../reference/commands.md), [Git](../reference/git_effect.md) and
[storage](../reference/storage.md). Kubernetes adapter/client bounds are also documented beside
their implementation in `src/application/mod.rs` and `src/gateway/kubernetes/adapter.rs`.

Keep these distinctions when interpreting a pass:

- Journal read-only and rollback opening tests use real FIFOs with no peer. Simulated metadata would
  not show whether `open` blocks.
- Fixed-client timeouts apply per socket operation, not to the whole exchange. Stdio waiting and
  filesystem/integrity work have no elapsed deadline.
- Byte/count/work limits do not establish a measured RSS ceiling or OS I/O latency bound.
- Git process-group retirement does not contain escaping operator hooks. The operator and host must
  enforce custody.
- Kubeconfig tests reject external credential files, exec/auth providers and ambient proxy
  discovery. Git tests check its cleared environment and fixed executable/configuration sources.
- Receipt completion checks candidates against transaction-owned frozen facts. Changes to its
  transaction shape must revalidate the [capacity premises](storage_capacity.md).

[Engineering conventions](../../CONTRIBUTING.md#failures-and-hostile-input) own production panic
restrictions and typed operating failures. Fault controls belong to `cfg(test)` or explicit
`demo-harness`/`test-harness` features. Default features are empty. Release assembly excludes those
features. A test-feature pass cannot qualify installed production bytes.

## Determinism and crash proof

[Test strategy](testing.md#keep-deterministic-tests-deterministic) explains deterministic inputs,
coordination and crash requirements. Fault tests and simulations drive the same private,
operation-selected provider and receipt-completion owners as the service. They select an ID
explicitly. They do not test queue fairness.

The target-read crash regression checks no journal update or PATCH, safe GET repetition on reopen,
and preservation of the inert `target_read_failures` field required by format 6. Application A/B
tests check that selecting B leaves A's original grant, frozen facts and receipt unchanged, with
independent receiver counts. Export may use another destination without changing the action or
signing identity.

Live receiver evidence complements these checks. It cannot replace faults around every journal
window.

## Service crash and retained-history evidence

A successful operation followed by graceful restart does not test interrupted execution. Loss after
mutation and loss after receipt commit but before export need separate traces.

| Guarantee                                               | Maintained check                                                                                                        | Independent evidence                                                  |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Same-ID recovery after mutation loss                    | Linux `ordinary_restart_reuses_frozen_snapshot_receipt_under_rotated_configuration`; packaged Kubernetes `service-loss` | HTTP/API-server mutation counts                                       |
| Original receipt survives commit-to-export loss         | Same Linux test; packaged receipt-commit-loss trace                                                                     | Terminal status, then SIGKILL before first export                     |
| Rotated signing material cannot replace evidence        | Linux/package cold rotation traces                                                                                      | Original grant/receipt/signer snapshots compared with later exports   |
| Repeated selection/reads add no mutation or observation | Linux HTTP fixture; packaged API-server audit                                                                           | GET/PATCH counts and original-byte retrieval                          |
| Inspection needs no receiver authority                  | Linux detached inspection; packaged `kapsel inspect`                                                                    | Original purpose, key and explicit evaluation time                    |
| Failed export leaves history intact                     | Linux fixed-client export tests                                                                                         | Missing destination and existing-file refusal, then identical exports |

The packaged fixture reads bounded finalized grant/receipt/signer data through an independent
read-only SQLite connection, rather than reconstructing a receipt. Its offline reader tests do not
prove the crash journey ran. The fixture retains original bytes/digests in private evidence and
restores only current signing material, never history.

Release qualification requires the full
[Linux process lane](qualification.md#kapsel-service-candidate) and both packaged receiver journeys
on the selected clean candidate. Keep source/executable and archive identities with private
evidence. A dirty assembly, earlier artifact or missing lane cannot establish candidate acceptance.

## Evidence classes

### Deterministic suite

The default suite contains local, package, binary and documentation tests needing no external
service. It checks repeatable semantics and hostile input. Coverage percentages cannot establish
crash safety, receiver semantics, release integrity or production readiness.

MCP fixtures check five ID-only tools, exact socket requests/counts, zero requests for invalid
input, protocol-only output and secret-free errors. Linux bridge-loss tests preserve `UNKNOWN` and
original bytes. Cancellation, EOF and transport completion cannot determine receiver outcome.

### Robustness

Five fuzz targets call production Kubernetes/Git receipt inspection, Kubernetes/Git grant
verification and service-document parsing. The deterministic corpus checks valid and invalid seed
acceptance independently of coverage discovery: legacy/snapshot purposes, inconsistent signed
results, record shape, UTF-8, lengths, limits and array counts. Exact vectors and unique composition
checks remain required.

Targets use explicit trust, evaluation time and limits without discovering credentials or doing
filesystem/network/receiver I/O. The service path is inert. Checks include trailing rejection,
narrowed limits, external key/purpose/time appointments and canonical grants. Bounded fixture
re-signing reaches statement validation without supplying execution authority. Git must reject a
signed `SUCCEEDED` statement with `unknown` acknowledgement.

The runner retains starting corpus bytes, commands, source/executable/compiler/fuzzer identities and
failure artifacts. [Qualification](qualification.md#robustness-lanes) explains how to minimize and
replay failures and run isolated negative controls. Baseline must pass. Each control must fail for
its intended property, and minimized replay must preserve that failure. Coverage, smoke and control
detection do not establish semantic completeness or receiver qualification.

Seeded lifecycle exploration uses two to four identities per real SQLite journal. It explores
interleaved selections, receiver changes, interruption windows, authority/material withdrawal, and
reopening. Each event checks every identity's durable facts, independent receiver counts, and
original evidence. It never prunes or resets attempted work to bypass capacity. Separate storage
tests check full-capacity behaviour. The same explicit trace format supports generated schedules,
deliberate interaction inputs, minimized findings, and direct replay. Wall-clock duration changes
case count, not case semantics.

### Live Kubernetes and demonstration

The live-kind gate checks success, defined failed rollout, bounded `UNKNOWN` and process loss in an
owned disposable cluster. It must count mutations independently and clean up or export bounded
failure evidence. The recovery-policy webhook distinguishes PATCH requests and admission effects
from persisted Deployment/controller effects when an identical stale patch is replayed.

Exact-snapshot cases acquire the target through the production adapter. They check one matching
PATCH, stale-version and same-name-recreation rejection without PATCH, and a preflight-to-PATCH
version conflict. That conflict remains `apply_started`, not pre-attempt rejection. Deterministic
fault tests own the restart/receipt matrix around it.

Packaged journeys add mutation-loss and receipt-commit-loss using production binaries. Live checks
retain healthy/failed rollout and untargeted-container assertions. Private process checkpoints stay
outside caller input and production binaries. Finite traces are not exhaustive recovery proof.

### Release artifact

Artifact checks consume extracted production binaries. Two isolated assemblies must match archive,
checksum, SBOM, digest-manifest and verifier bytes. Hostile validation precedes extraction. Smoke
checks identity, grant provisioning, execution, read-first restart, offline inspection and MCP.
Service-container checks add fixed paths, separate identities, original receipts and mutation
counts, not native systemd or interrupted-attempt qualification.

There is no demonstration binary or pause feature in the archive. Packaged crash/live lanes remain
separate. Sigstore bundles receive identity/failure checks, not a reproducibility requirement.
[Release artifacts](../reference/release.md) defines layout, authentication and provenance.

### Kapsel service

Service tests compose one catalog and journal around `ServiceApplication`:

| Boundary                                            | Maintained checks                                                           | Evidence limit                                                                                      |
| --------------------------------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Admission, original authority and history           | `service_application_contract`                                              | `ADMITTED` does not prove receiver success or worker liveness                                       |
| Independent and shared-target A/B selection         | `application_retry::service_selection`                                      | No inferred conflict safety or refreshed approval                                                   |
| Framing, admission races, jobs and diagnostics      | Daemon protocol/runtime suites                                              | Storage may stall beyond response deadlines                                                         |
| Peer credentials, disconnect and read-first restart | `linux_process`                                                             | Source process lane, not power-loss qualification                                                   |
| Custody, publication and retirement                 | Startup/publication tests                                                   | Stable roots and cooperative launches remain host assumptions                                       |
| Unit, sysusers, RBAC and fixed argv                 | `install_assets`                                                            | Static assets alone do not establish native installation                                            |
| Fixed client and receipt export                     | [Client tests](../../crates/kapsel-daemon/src/bin/kapsel-service-client.rs) | Five versioned commands; bounded framing; receipt digest verification; exclusive mode-`0600` output |

Fixed-client tests freeze `list`, `history`, `submit`, `status` and `receipt` with version 1. They
check receipt hex/digest agreement, refuse existing export files, and keep authority and lifecycle
configuration out of the client interface.

The A/B traces distinguish a free worker from completed evidence or a still-valid approval:

| A's state                                          | Selecting B                      | Required receiver/history check                                               |
| -------------------------------------------------- | -------------------------------- | ----------------------------------------------------------------------------- |
| PATCH response held; worker occupied               | `BUSY`                           | No B insertion or I/O                                                         |
| Frozen at `receiver_observed`; signer missing      | Independent target succeeds      | One PATCH per operation; A's row unchanged                                    |
| Same frozen state; B shares A's target             | `NOT_ATTEMPTED / STALE_APPROVAL` | A has one PATCH, B zero; B performs a real GET                                |
| Transient preflight stopped, or terminal `UNKNOWN` | B can complete                   | A's row/receipt unchanged; only explicit selection repeats A's safe preflight |

Resuming observed A signs frozen facts without more HTTP. Terminal A gains no new I/O. The
paused-clock cases check the transient-preflight and terminal-`UNKNOWN` interleavings.
Root-substitution tests keep journal creation and socket binding with retained directory identities.
Retrieval does not need a receipt root. Authority grammar/vector tests check their own parsers.
Service/gateway tests check rejection before application access or persistence. None makes the
authority crate a public SDK.

Use [service qualification](qualification.md#kapsel-service-candidate) for commands and
[existing-host precautions](../reference/service.md#existing-host-state) for ambiguous state. These
checks do not establish installed-native equivalence, power-loss durability, live receiver results
or an installer.
