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
| Signing failure leaves frozen observations unchanged               | [Atomic-record simulator](../../src/kernel_simulation_tests/mod.rs)                              | Fixture signing, not key-management qualification              |
| Completion rejects another statement for the same ID               | `receipt_commit_rejects_wrong_facts_and_foreign_snapshot_without_changing_history` in that suite | Checks the current row, not only the builder's call convention |
| Lost commit acknowledgement resolves to original bytes             | Atomic receipt-delivery laws; process-exit and snapshot suites                                   | Process exit is not power loss                                 |
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

Compact real-Git witnesses cover transfer to another receiver, loss before and after the ref update,
dropped permission with A→B→A and onward movement. They compare actual update packets, exact hook
inputs and the independently read final ref. One application composition witness freezes the
original acknowledgement without a signer, then signs after receiver withdrawal. Shared simulator
laws own reopen, no-resend, immutable evidence and progress reasoning. In the unsent-present-B case,
another sender establishes B after the original sender's permission is dropped. Recovery must remain
`UNKNOWN` with zero original update packets. Fixture-owned intervening writes are identified
separately. Hook counts establish invocation, not downstream completion.

The Linux fixture adds CLI provisioning, startup material, process loss, the fresh-session caller
and MCP bridge. It covers send/receipt-commit and pre/post-receive loss, then reads the same history
after catalog and material withdrawal. Source process evidence does not qualify native systemd,
power loss or the extracted production artifact. The installed-artifact launch profile uses the same
maintained procedure but retains separate identities, private-material denial, read-only
retained-row checks and cold binary replacement. Its four-case matrix does not replace the source
profile's six-case commitment windows. Both routes are required for Git qualification.

## Receiver-recovery evidence

[`gateway::kubernetes_composition_tests`](../../src/gateway/kubernetes_composition_tests.rs) binds
real Kubernetes adapter HTTP facts to signed receipts. Its independent in-memory receiver asserts
exact PATCH bytes and counts GETs, PATCHes and persisted changes. Receipt comparisons cover original
approval, target, generation, image, marker, replica counts and rollout conditions.

Eight variations cover healthy and failed rollouts, accepted mutation with response loss,
conditional-update conflict and observation-budget exhaustion. After response loss, independent
writer changes cover a replaced UID, a changed image and a later generation retaining the marker.
The fixture does not import the production classifier or observation decoder. These checks establish
adapter composition, not live admission, process death or power-loss durability.

The shared simulator owns interruption, observation-only recovery and frozen no-I/O reconnect laws,
with reached remint and receipt-binding controls. Existing process suites own actual death after
mutation and receipt commitment. Run the
[adapter composition check](qualification.md#receiver-recovery-regressions).

Related checks stay at the interfaces that own them:

| Guarantee                              | Maintained check                                                                                                                                     |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Configured client sends once           | `application_retry::configured_client_sends_once_for_success_and_ambiguous_responses`: success, HTTP errors and response loss                        |
| Missing zero-replica fields            | Adapter `omitted_zero_replica_counts_can_still_report_success`                                                                                       |
| Stale UID or version                   | Shared simulator: single-field drift after authorized reopen; terminal rejection, no mutation or receipt                                             |
| Exact authority before persistence     | `gateway::tests::validation::every_authority_field_is_bound_before_first_or_requested_admission`: independent raw-row preservation                   |
| Approval cannot refresh an existing ID | `each_snapshot_field_and_legacy_downgrade_preserve_original_history`: UID/version conflicts and downgrade before and after completion                |
| Worker exclusion                       | `gateway::tests::recovery::worker_lock_prevents_overlapping_provider_activity`; simulator suspended selection at preflight, mutation and observation |

Adapter identification tests check UID/version extraction. Classifier tables check generation and
pending-rollout predicates. Image acceptance is not rollout completion. A new name/revision lookup
can describe an intervening writer or recreated Deployment.

## Core effect-gateway proof matrix

Use the [gateway contract](../reference/effect_gateway.md) for the definitions in this table. Names
below identify suites, not separate release gates.

| Boundary                         | Maintained checks                                                                                                             | Obligation                                                                                                                               |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Request and authority            | `kapsel-authority::grammar_tests`; gateway `validation`                                                                       | Bounds and exact signed authority; reject before persistence                                                                             |
| Journal transitions and dispatch | [Atomic-record simulator](../../src/kernel_simulation_tests/mod.rs); compact admission, snapshot and physical dispatch checks | Enumerate fresh durable windows and recovery interactions; permission only from a confirmed fresh attempt commit                         |
| Target disposition               | Snapshot/target-read tests; adapter/classifier tables                                                                         | Permanent rejection is `NOT_ATTEMPTED`; transient reads remain authorized without PATCH                                                  |
| Observation and classification   | `gateway::kubernetes`; receiver-recovery matrix                                                                               | Acceptance, timeout, transport and rollout facts stay distinct; unresolved evidence is `UNKNOWN`                                         |
| Receipt and inspection           | Kubernetes/Git receipt suites; authority vectors                                                                              | Freeze before signing; commit exact bytes/digest/signer with terminal state; inspect under explicit trust                                |
| Export                           | Fixed-client and command-interface tests                                                                                      | Exclusive copy of committed bytes; export failure cannot reopen completion                                                               |
| Original authority after I/O     | [Atomic-record simulator](../../src/kernel_simulation_tests/mod.rs)                                                           | Suspended preflight, mutation and observation reject changed grant bytes before advancing; both stores and effects                       |
| Stored read projections          | Atomic-record simulator                                                                                                       | Exact status, admitted phase, original targets and receipt bytes/readiness; ordered history entries on SQLite; no writes or receiver I/O |
| Original-key disclosure          | Atomic-record simulator                                                                                                       | Substituted public keys cannot disclose retained targets or receipts; unaffected peers remain readable; history pages use real SQLite    |
| Journal format                   | [Version rejection](qualification.md#journal-version-rejection)                                                               | Older journals remain untouched, without migration                                                                                       |
| Disclosure and hostile input     | [Defensive checks](#defensive-boundary-checks)                                                                                | Reject malformed records; keep secrets and unbounded bodies out of retained/output data                                                  |

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

| Boundary                   | Maintained owner/checks                                                                                                                         | Must happen before                                                                   |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Kubernetes/Git grants      | [`kapsel-authority`](../../crates/kapsel-authority/src/lib.rs), [`git`](../../crates/kapsel-authority/src/git.rs) verification tests            | Envelope decoding, statement parsing and text copying                                |
| Ordered binary records     | Authority `record::Records`; receipt parser tests                                                                                               | Arithmetic, allocation and use of ordered fields                                     |
| Receipt/trust inspection   | Kubernetes/Git receipt tests; `InspectionLimits::validate`; trust parser tests                                                                  | Parsing beyond supplied limits or accepting key/purpose/time                         |
| Service operator document  | [`document`](../../src/application/service/document.rs) parser and `BoundedVec` tests                                                           | JSON decoding of excess bytes or an extra array element; hex output allocation       |
| Receiver material          | Git configuration, kubeconfig loader and service snapshot tests                                                                                 | Construction from unsafe or excessive input; ambient fallback                        |
| Operator and receipt files | Command `read_bounded`; daemon startup file tests                                                                                               | Allocation/read, symlink following or waiting for a special-file peer                |
| Kubernetes HTTP            | Adapter/client tests                                                                                                                            | Aggregate body collection and JSON decoding; a retry of mutation                     |
| Socket requests            | Protocol/runtime tests                                                                                                                          | Frame allocation, application access or unbounded connection/job creation            |
| Fixed-client responses     | Client-transport tests                                                                                                                          | Reply allocation or accepting trailing bytes                                         |
| Stdio MCP                  | [Bridge decoder](../../crates/kapsel-daemon/src/bin/kapsel-service-mcp.rs) and [`service_mcp`](../../crates/kapsel-daemon/tests/service_mcp.rs) | Parsing an oversized line or exposing authority in tool input/output                 |
| Journal opening            | Opening/schema/capacity tests; `capacity_layout`                                                                                                | SQLite recovery, row loading or accepting unaccounted physical pages                 |
| Retained capacity          | Capacity/storage/validation suites                                                                                                              | Admission beyond aggregate responsibility or completion-space bounds                 |
| Git subprocesses           | `gateway::git` tests                                                                                                                            | Output-buffer extension; unbounded command lifetime or orphaned owned process groups |
| Git custody walk           | `private_tree`/`trusted_ancestors` tests                                                                                                        | Enqueueing excessive entries/depth or accepting unsafe custody                       |

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
input, protocol-only output and secret-free errors. The Linux caller-loss witness checks retained
reference and admission. The public restart journey checks original-byte retrieval through MCP.
Cancellation, EOF and transport completion cannot determine receiver outcome.

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

The [packaged workflow](../../tests/qualification/run_kind_agent_action_workflow.py) owns live
Kubernetes qualification in one disposable, audited cluster. Extracted production binaries acquire
exact snapshots, select approved IDs through the socket and inspect original signed receipts.
Independent API reads check the unchanged sidecar, generation and ReplicaSet increase. Stale
versions and recreated UIDs reject without a product PATCH. A version change after preflight causes
an actual 409 while the journal retains `apply_started`, not pre-attempt rejection.

An operator-owned HTTP barrier forwards requests to the real API server. It parks accepted replies
for failed/deleted-rollout process loss without writing product history. Recovery adds no PATCH;
receipts retain the live failed condition or honest missing-receiver `UNKNOWN`. API-server audit
counts product requests independently of fixture writes. Repeated product sends still reach the
receiver and fail qualification. A reached concurrent-duplicate control checks that the barrier
cannot hide them.

The retained admission webhook distinguishes two requests with distinct admission UIDs from one
persisted Deployment/controller change when the fixture replays the original stale patch. The 60-
and 210-second readiness cases retain interrupted observation, same-ID resumption, in-flight stored
reads and worker exclusion. After late availability, frozen `UNKNOWN` and original bytes remain
unchanged. Audit timestamps bound each pass separately and require no GET after terminal evidence;
compact negative controls reject early/late terminal timing and excessive recovery reads.

Mutation-loss, receipt-commit-loss, cold signer rotation and catalog withdrawal use these same
packaged service journeys. The shared simulator owns lifecycle laws; these finite live traces do not
establish exhaustive recovery or power-loss durability.

### Release artifact

Artifact checks consume extracted production binaries. Two isolated assemblies must match archive,
checksum, SBOM, digest-manifest and verifier bytes. The verifier's independent fixture owns hostile
layouts, source/SBOM binding, sidecar tampering and exclusive extraction. The artifact check adds
source/asset correspondence, ELF identity and checksum-bound companion execution. The bundled
operator-guide trace checks installed fixed paths, separate identities, socket/private-file custody,
grant provisioning, signing repair, read-first restart, original receipts, offline inspection and
MCP, with independent receiver counts. These checks do not qualify native systemd or interrupted
attempts.

There is no demonstration binary or pause feature in the archive. Packaged crash/live lanes remain
separate. Sigstore bundles receive identity/failure checks, not a reproducibility requirement.
[Release artifacts](../reference/release.md) defines layout, authentication and provenance.

### Kapsel service

Service tests compose one catalog and journal around `ServiceApplication`:

| Boundary                                            | Maintained checks                                                                        | Evidence limit                                                                                      |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Admission, original authority and history           | `service_application_contract`                                                           | `ADMITTED` does not prove receiver success or worker liveness                                       |
| Independent and shared-target A/B selection         | Shared simulator; `application_retry::service_selection` for shared-target TCP preflight | Separate peer isolation from actual same-target version conflict                                    |
| Framing, admission races, jobs and diagnostics      | Daemon protocol/runtime suites                                                           | Storage may stall beyond response deadlines                                                         |
| Peer credentials, disconnect and read-first restart | `linux_process`                                                                          | Source process lane, not power-loss qualification                                                   |
| Custody, publication and retirement                 | Startup/publication tests                                                                | Stable roots and cooperative launches remain host assumptions                                       |
| Unit, sysusers, RBAC and fixed argv                 | `install_assets`                                                                         | Static assets alone do not establish native installation                                            |
| Fixed client and receipt export                     | [Client tests](../../crates/kapsel-daemon/src/bin/kapsel-service-client.rs)              | Five versioned commands; bounded framing; receipt digest verification; exclusive mode-`0600` output |

Fixed-client tests freeze `list`, `history`, `submit`, `status` and `receipt` with version 1. They
check receipt hex/digest agreement, refuse existing export files, and keep authority and lifecycle
configuration out of the client interface.

The simulator checks nonselected peers after every selection, including first receipt commitment.
Its suspended selections own same-ID and different-ID contention. The configured-client
`shared_target_preflight_rejects_b_without_changing_frozen_a` checks the distinct TCP fact: after A
changes the object, B's original version is stale. Independent SQL reads preserve A's frozen row.
The exact request sequence is GET, PATCH, GET for A, then one GET for B. Resuming A only signs.
Adapter paused-clock tests own read and elapsed ceilings, including interrupted passes.
Root-substitution tests keep journal creation and socket binding with retained directory identities.
Retrieval does not need a receipt root. Authority grammar/vector tests check their own parsers.
Service/gateway tests check rejection before application access or persistence. None makes the
authority crate a public SDK.

Use [service qualification](qualification.md#kapsel-service-candidate) for commands and
[existing-host precautions](../reference/service.md#existing-host-state) for ambiguous state. These
checks do not establish installed-native equivalence, power-loss durability, live receiver results
or an installer.
