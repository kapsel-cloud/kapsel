# Delegated-action workflow proposal

Status: selected v0.3 direction, with admission, retained authority, completion accounting and cold
replacement implemented in unreleased source. The maintainer approved placement and workflow choices
on 2026-09-13 and the compatibility, trust, capacity and cold-replacement directions on 2026-09-14.
The [service contract](KAPSEL_SERVICE.md#version-1-socket-adoption-contract) owns current behavior.
Independent review, deterministic tests, Linux process checks, bounded storage-failure tests and the
live receiver lane provide implementation evidence. They do not establish installed-service or
combined-artifact qualification. Observation policy and actionable status remain separate work. No
release, supported installation or storage migration is adopted here.

An operator prepares exact image actions. A caller selects one by a stable handle, then reconnects
for status and original evidence. Kapsel retains admitted responsibility, but runs only one action
at a time. Blocked unfinished A need not prevent independently assessed B. The caller retains
unselected intent and explicitly selects unfinished work after restart. There is no waiting queue.

The [scope](SCOPE.md), [effect gateway](EFFECT_GATEWAY.md), [service](KAPSEL_SERVICE.md),
[architecture](ARCHITECTURE.md) and [release](RELEASE.md) remain current-behavior owners. This
proposal owns the selected changes and unresolved adoption questions. Illustrative labels below are
not an additional callable interface; use the canonical service contract for actual HEAD behavior.
Remaining runtime contracts must change before implementation, without presenting the full design as
shipped behavior.

## Decision and evidence

Retain the Linux resident service, local SQLite journal, signed exact-snapshot grants, separate
operator approval and caller activation, and Rust. Do not run a Kubernetes controller prototype as a
v0.3 prerequisite. Hosting and workflow are separate decisions: keeping the service does not keep
its single configured identity or task-only acknowledgement.

The comparison reads committed proposal revision `261fe95ba328e4af2d7541aae74a6703419e4aa7` and
corrected prototype revision `2efcfec83f6d35d71b6a3d79b57b1db9606ae737`. The current-behavior
baseline is the latter revision. The proposal's earlier baseline was
`1fd59f84d2a154111642c40ded8ce5a069ce175e`; it is not a new execution result.

The [two-action prototype](TWO_ACTION_ENDPOINT_PROTOTYPE.md) concluded **refine, do not adopt**. It
demonstrates fixed multi-identity access, explicit reconnect and original receipt retrieval over
mock HTTP and exact child-process loss. It also demonstrates B progressing while A remains
unfinished. Its `ACCEPTED` may precede insertion. Its conflicting-B case relies on a cooperative
caller, not enforced unavailability. The corrected macOS frame reader and regenerated fixture do not
establish authenticated Linux service, durable admission, live Kubernetes or power-loss proof. The
report owns the executable hashes, raw fixture and exact limits. No new runtime experiment was run
for this decision.

The earlier proposal coupled durable acknowledgement to one unfinished row and automatic startup
reconciliation. Neither follows from the acknowledgement itself. Those choices are replaced here,
not retained as parallel alternatives awaiting opportunistic implementation.

### Separate placement choices

| Choice             | Selected direction                                | Alternative and tradeoff                                                                                                                                                                                                                                            |
| ------------------ | ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Process hosting    | Linux resident service                            | A Pod could use cluster scheduling and workload identity, but still needs caller transport/isolation, persistent storage and restart qualification. Pod hosting does not require a CRD or a language change.                                                        |
| Durable state      | One local SQLite journal                          | An action object could use API persistence and conditional status writes. It moves storage operation into the control plane, but introduces deletion/recreation, controller concurrency, API availability and restore obligations.                                  |
| Approval authority | Signed exact-snapshot grants under external trust | Operator identity, RBAC and admission could authorize resource creation. This could remove grant-file/signing operations, but would replace the approval contract and require retaining original approval facts independently of mutable status. Not approved here. |
| Submission         | Operator approves, caller activates               | Operator creation as approval plus submission is coherent for operator-triggered work, but removes caller choice of when an approved action runs. Preserving that choice with a CRD needs another explicit activation surface.                                      |
| Implementation     | Retain Rust and the deep gateway                  | Go has a Kubernetes controller ecosystem, but changing language does not solve one-shot dispatch or custody. Responsibilities do not justify a rewrite.                                                                                                             |

### Operational burden, not just process count

| Responsibility                | Resident service                                                                                        | Kubernetes-hosted action resource/controller                                                                                                                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Packaging and process         | Native binaries, systemd assets and explicit host preparation                                           | Container image, CRD, workload and RBAC assets, cluster-version and admission compatibility                                                                                                                      |
| Identities and caller access  | Separate OS identities and authenticated private socket; caller has no cluster credentials              | Controller workload identity plus caller API read identity, or a separately confined proxy. Direct caller API access changes the literal no-cluster-credentials promise even without Deployment mutation rights. |
| Credentials and trust         | Operator owns receiver credential renewal, grant trust and receipt signing material                     | Platform can supply workload credentials; RBAC, secret access, renewal and signing/trust custody still need owners                                                                                               |
| Persistence and workers       | Private SQLite, one journal-scoped worker lock, conditional transitions                                 | API state and conditional writes; multiple reconciliations/controllers still need safe task ownership and bounds. A leader lease alone cannot mint dispatch permission.                                          |
| Backup, restore and retention | Operator preserves journal, original authority and external trust; no pruning or stale restore as retry | Cluster operator owns etcd backup and object retention. Deletion, garbage collection and restoring pre-attempt state can erase no-resend history. API persistence is not a retention protocol.                   |
| Debugging and reads           | Bounded operator diagnostics and offline stored status/receipts                                         | Events/status/logs are convenient, but mutable status is not immutable evidence. API outage can also remove access to action history.                                                                            |
| Evidence export               | Copy original SQLite-committed receipt bytes                                                            | Preserve exact frozen bytes and approval provenance, then export independently. A status summary cannot substitute for the signed receipt.                                                                       |

The selected model removes the proposed one-unfinished-row restriction and automatic startup
selection, not the underlying safety mechanisms. No new responsibility moves into Kubernetes
configuration. Host identity/process management remain OS responsibilities. Kapsel retains exact
authorization, admission accounting, worker exclusion, fresh dispatch permission, bounded
observation and immutable completion. The operator retains credential/trust custody, safe storage,
confinement, conflict provisioning and desired-state ownership.

This is not a claim that Kubernetes cannot implement the boundary. Its operational facilities are
useful, but the current evidence supports a smaller change to the existing gateway. A controller
would replace storage and recovery contracts without removing the difficult effect boundary. No
bounded controller prototype is justified by the remaining selected-workflow questions, so none is
scoped or implemented here.

### Concrete Kubernetes alternative and failure traces

A comparison-only `ImageChange` resource would have one immutable spec containing a stable action
identity, exact tuple and approved Deployment UID/resourceVersion. The operator creates it. Only the
controller may update `/status`; the caller may only read the authorized resource. Spec validation
must reject mutation and unknown/unbounded fields. An immutable spec could retain signed approval
bytes, or a separately approved RBAC-authority design could retain authenticated creation facts.
These are alternatives, not interchangeable trust models. Do not put credentials or signing seeds in
either spec or status.

Kubernetes provides
[CRD validation and status subresources](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/),
[conditional updates](https://kubernetes.io/docs/reference/using-api/api-concepts/#updates-to-existing-resources)
and [resource/subresource RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/). A
CEL transition rule such as `self == oldSelf` can enforce required spec immutability on updates; it
does not constrain creation or preserve deleted history. `/status` separates writes, not historical
evidence. RBAC cannot constrain top-level create by `resourceNames`; exact approval needs
schema/admission and an authority contract, not a misleading named-create Role.

| Trace                                       | Required behavior and remaining uncertainty                                                                                                                                                                                                                                                                                    |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Create or status acknowledgement lost       | Creation is not Deployment mutation. Re-read the same identity and resolve the conditional operation. Never create another identity as an escape or infer a receiver result.                                                                                                                                                   |
| Two controllers or duplicate reconciliation | Only the confirmed winner of a fresh conditional unattempted-to-attempted update may receive one in-memory dispatch permission. A loser or a reader of stored attempted status receives none. Worker lifetime/exclusion also needs proof; conditional state alone does not prove single active observation or safe completion. |
| Attempt update committed, response lost     | No permission may be reconstructed by reading the claim. Observation-only recovery can yield `UNKNOWN` even if no PATCH was sent.                                                                                                                                                                                              |
| Crash before or after Deployment PATCH      | The action-state write and Deployment PATCH are separate commits. Recovery observes after the marker, never resends, including when the PATCH response was lost. Client retries must not turn one permission into several requests.                                                                                            |
| Later drift                                 | Reconciliation may repeatedly observe unfinished work, but cannot reapply an approved action to restore the image. Terminal history stays frozen. This differs from an ordinary desired-state controller.                                                                                                                      |
| Deletion, recreation or garbage collection  | A name is reusable and the recreated object has a new UID. Immutability does not retain the old action's deduplication record. A retention/identity rule must prevent using recreation to replay approval; a finalizer alone is not immutable history.                                                                         |
| Restore older action state                  | A backup may predate the attempt marker while external effects survive. Neither a new resourceVersion nor restarting a controller restores missing knowledge. Execution must remain stopped pending an explicitly qualified continuity decision. The local journal has the same stale-backup limit.                            |
| Receipt completion                          | Freeze original observation and approval provenance before signing; commit exact receipt bytes as terminal evidence. Repeated status writes, key changes or newer observations cannot rewrite historical bytes.                                                                                                                |

The current primary Kubernetes pages above,
[controller behavior](https://kubernetes.io/docs/concepts/architecture/controller/),
[object names and UIDs](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/)
and
[etcd backup/restore](https://kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/)
were read on 2026-09-13. They support the platform comparison, not an executed Kubernetes design or
a pinned compatibility claim. Ordinary controller convergence is specifically not permission to
repeat this action.

## One operator and one caller trust domain

Only `kubernetes.set_deployment_image` remains available. The operator independently acquires the
Deployment snapshot and signs the exact action. Durable admission retains responsibility but cannot
issue PATCH permission. Only the gateway's fresh conditional attempt commit can do that. Receiver
observations establish the existing bounded result. Application quality stays outside Kapsel.

Retain one operator-controlled journal and one authenticated local caller cohort. Admitted members
share selectable approvals and retained-history access. An operation ID is not authentication. No
per-user, multi-tenant, remote-authentication or online identity-rotation model is added.

Direct image changes require explicit operator ownership of the desired state. If another reconciler
restores a Git-declared image, this workflow is not qualified unchanged. Kapsel neither disables
that reconciler nor claims automatic GitOps compatibility. The operator must choose and test the
ownership arrangement separately from receiver RBAC.

Qualification must attempt caller bypass through private credentials, writable service
configuration/executables, service-identity shell access, privilege escalation and unrestricted
credential-bearing tools. Prompt advice or a confirmation dialog is not confinement. Host root,
kernel and service identity remain trusted. Retaining a local caller preserves the literal
no-cluster-credentials boundary.

## Approvals, handles and retained identity

A selectable approval is operator-provisioned and not yet admitted. The caller retains unselected
intent. Listing it creates no row, target read, scheduling obligation or freshness promise. A handle
shows the stable ID, exact tuple, approved UID/version and an operator-written printable ASCII label
of at most 128 bytes. The full digest remains inspectable; labels are not matching keys.

Selection supplies only the operation ID. The application resolves exact operator authority, never a
caller grant, path or trust lookup. Use the existing fixed socket with mandatory explicit service
protocol versioning; refuse the old unversioned grammar before application access. Keep legacy
CLI/MCP separate. Exact wire fields and vectors must be defined in the service contract before
implementation. A separate versioned socket was rejected because it adds another endpoint and
confinement surface without removing the need to reject old submission semantics.

Selected custody direction:

- First admission atomically freezes original signed grant bytes, tuple, snapshot, signer and grant
  digest in the same journal record. A configured-file-only design loses ordinary history access
  when those files disappear; journal retention removes that separate per-action file dependency.
- Stored bytes never appoint trust. The operator separately retains appointed verification trust for
  historical access and unfinished recovery, receiver credentials and receipt signing material where
  completion requires it. A journal backup alone is still not a full recovery bundle.
- Historical reads use the authenticated cohort and original retained authority, not current catalog
  membership. Maintain bounded, separately appointed external grant-key custody. Missing or
  withdrawn required trust blocks access and advancement for that identity with a bounded authority
  error, not `NOT_FOUND` or replacement authority. Unrelated valid identities remain available.
  History exposes inaccessible IDs without unverified tuple or receipt details. An operation ID is
  not authentication.
- Safe stored reads do not depend on receiver credentials, receipt signing availability or export
  access. Malformed global trust configuration or unsafe storage may still prevent startup. This
  per-identity isolation is preferred over making one missing historical key hide all history.
  Withdrawal does not change durable disposition or cancel responsibility. No new expiry, approval
  refresh or receipt-verification purpose is introduced. Exact key-table bounds and same-snapshot
  authority validation remain implementation obligations.
- Catalog removal makes an unaccepted approval unselectable. It cannot revoke an admitted action,
  erase its responsibility, replace its approval or hide its receipt. Emergency stop is operator
  lifecycle control. A changed grant, tuple or snapshot under an existing ID fails closed.
- Retain admitted records, including rejections and original receipts, for this journal's lifetime
  within finite caps. No pruning, ID reuse or journal rotation to escape an ambiguous action.
- Export copies original receipt bytes and is not completion. Lost storage or an older backup is not
  evidence of no effect and cannot authorize a fresh attempt.

## Durable admission, one worker, no waiting queue

The maintainer selected durable admission with one active worker, not one unfinished action. A
blocked unfinished A releases execution ownership; an independently assessed B can then be selected.
Admitted work is bounded by 32 unfinished identities as well as history/physical caps. Count
`requested`, `authorized`, `apply_started` and `receiver_observed` as unfinished. Terminal `UNKNOWN`
still consumes history/physical capacity; freeing its unfinished slot is not conflict clearance.
There is no detached task per retained identity. Completion-accounting proof remains required.

Kapsel retains admitted responsibility and makes unfinished history available. The caller or
operator owns when to explicitly reselect it. No fairness, FIFO, automatic waiting-work selection,
eventual-completion promise or periodic retry is introduced. Durable responsibility is not a
liveness promise, and the caller must retain unselected intent outside Kapsel.

### Admission and acknowledgement

The new versioned admission boundary must distinguish confirmed retained admission, definite
non-admission and indeterminate commitment. It must not silently strengthen HEAD's unversioned
`ACCEPTED` envelope. A response describing retained admission is separate from execution activity
and receiver result. The service contract must own exact envelopes and old/new refusal vectors.

1. Authenticate, parse bounded input, resolve retained identity or selectable operator authority and
   validate original provenance inside the application/gateway boundary.
2. Resolve existing identity before new-work capacity or execution refusal. A changed duplicate
   fails closed even when terminal. An identical terminal duplicate returns original disposition
   without work. An identical active duplicate joins/reads existing responsibility without another
   task. An identical blocked duplicate preserves its admission and may request one pass if the
   execution slot is free; contention reports retained responsibility plus current unavailability,
   not definite non-admission.
3. For a new identity, acquire journal-scoped exclusion for admission and advancement without
   waiting. If another execution or unsettled admission owns it, refuse new B as `BUSY`, with no B
   row or receiver call. Recheck identity, current operator catalog and capacity under that
   exclusion.
4. Conditionally insert one `requested` row with the complete original authority binding and the
   configured completion-capacity accounting in one transaction. No Kubernetes read, signing or
   rollout wait belongs to admission. Concurrent identical requests resolve to one bound row.
5. Acknowledge only confirmed commitment. Install at most one worker after admission, retaining
   exclusion across that handoff. Failure to install the worker leaves visibly blocked admitted
   work. The acknowledgement proves neither task liveness nor dispatch nor eventual completion.

The exact duplicate/error envelope and cross-process admission/worker-lock composition need tests
before freezing the protocol. Existing admitted identities remain readable at configured capacity
when storage is healthy. A duplicate's attempted advancement can still be blocked by actual storage
failure or a busy worker.

On disconnect or response loss, read and conditionally reselect the same identity. A committed row
is not cancelled by connection loss. If commit completion is unsettled, retain its resource permit
and exclusion until the task actually stops, then reload that identity. A read of absence while the
commit can still finish does not prove rejection. An indeterminate admission response or close is
not the receiver result `UNKNOWN`. No new worker or identity may bypass unsettled admission.

### Active, blocked and terminal

Keep durable lifecycle/disposition separate from current execution activity. `active` needs current
task ownership, not a persisted bit. `blocked` means unfinished without a worker, with a bounded
reason where known. After restart, report recovery required rather than inventing a lost error.
Frozen receiver facts awaiting receipt commitment remain unfinished. Terminal results are read-only.

**Restart is read-first, with explicit same-ID reselection.** Validate private storage and required
authority, compose safe stored reads and bind without selecting any unfinished identity. Multiple
unfinished rows are not an error merely because there are several. Receiver unavailability must not
hide history or trigger observation through a read. Unsafe/unreadable storage or required authority
may still prevent safe composition. Exact failure isolation is a contract/proof obligation, not an
unconditional availability guarantee.

Caller or operator selection of blocked A requests one bounded pass under original authority. Before
the attempt marker it repeats only safe preflight and requires the original snapshot. After the
marker it only observes, or completes already frozen evidence. Terminal selection only reads. No
phase, force flag, refreshed approval, observation budget or restart control enters caller input.

Gateway/application own lifecycle and typed blocked outcomes; runtime owns current task lifetime;
protocol renders them. No second transition ledger or adapter-owned lifecycle interpreter.

## Concrete workflow traces

These are selected contract obligations, not new executed evidence.

| Case                                | Required retained fact and behavior                                                                                                                                                                                                        |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Healthy                             | Durably admit A with original authority and capacity accounting, then GET, freshly commit attempt, consume one PATCH permission, observe and freeze the defined result, commit original receipt.                                           |
| Identical or changed duplicate      | Resolve existing identity before capacity/slot refusal. Identical terminal reads original bytes with zero HTTP; active joins without a task; blocked may explicitly resume. Changed provenance/tuple/snapshot fails closed in every phase. |
| Active A, new B                     | Refuse B without a row, receiver call or future obligation. Caller retains B.                                                                                                                                                              |
| Blocked unfinished A, independent B | Release A's execution ownership, retain its authority/history, admit and advance independently assessed B within caps. A remains blocked until explicitly selected.                                                                        |
| Admission commit/ack loss           | Retain exclusion while a commit can finish. Reload same ID; no false rejection or new-ID escape. Crash after commit before worker installation leaves blocked admitted A.                                                                  |
| Transient or stale preflight        | Transient failure leaves unfinished A with no PATCH/result. Explicit reselection repeats safe GET. Snapshot mismatch freezes `NOT_ATTEMPTED / STALE_APPROVAL`, zero PATCH and no effect receipt. No automatic reapproval.                  |
| Attempt commit/ack loss             | Lost permission is never reconstructed, even if unsent. Recovery only observes and can freeze `UNKNOWN`; it cannot invent `NOT_ATTEMPTED`.                                                                                                 |
| PATCH response loss                 | Read-only recovery may establish the existing result; count no second PATCH. A conflict after the marker remains an attempted path.                                                                                                        |
| Receipt commit/ack loss             | Frozen facts stay unchanged. Reload `receiver_observed` for completion only, or `finalized` for original bytes. No reobservation or re-signing committed evidence.                                                                         |
| Restart with A/B unfinished         | Serve safe stored reads with zero receiver calls. Select neither automatically. Explicitly select original A or independently assessed B under one worker.                                                                                 |
| Catalog or receipt-key replacement  | Removed accepted A remains accessible under retained original authority and separately retained trust. Return original receipt bytes even without Kubernetes/export access. No grant replacement under A.                                  |
| Full configured capacity            | Refuse new identities, preserve existing reads and identical admission lookup. Reserved completion accounting does not guarantee survival of external disk exhaustion or I/O failure.                                                      |
| UNKNOWN and conflicting B           | Released worker is not conflict permission. Conflicting B must remain unavailable to a hostile caller across catalog update and restart. Independent B can proceed without changing A's result.                                            |

## Who holds conflicting B?

The selected boundary is bounded operator provisioning, not a durable dependency engine. The
operator exposes only actions independently assessed against selectable and unresolved actions.
Different Deployment names do not prove independence; containers in one Deployment share a snapshot.
Neither an empty worker slot nor terminal `UNKNOWN` authorizes a conflicting follow-on action.

A cooperative caller withholding B is insufficient. Qualification must prove that B was never
selectable in a conflicting configuration, or that a supported operator-controlled replacement
procedure prevents a stale selection from winning. Withdrawal after B was already admitted cannot
undo that responsibility. If this boundary cannot be enforced, adoption stays blocked pending a
separately approved hold design. Do not implement an inferred conflict policy.

Use enforced cold-only replacement. Stop admission and stop/join all old execution and storage
tasks. Preserve the journal and original authorities. Publish one validated complete private catalog
atomically, then restart read-first. Lifecycle exclusion must precede loading or caching authority,
not merely socket binding or the next worker pass. The replacement acknowledgement must not precede
old-task retirement and confirmed publication. No hot reload is introduced.

A partially replaced configuration must fail closed. An old process or stale cached configuration
must not remain able to accept withdrawn B. A cooperative lock cannot fence an old binary that does
not acquire it, so qualified host launch confinement and retirement of old processes are required.
Arbitrary trusted-operator rollback of configuration or executable is outside this guarantee.
Journal-backed catalog freshness was considered but is not selected; it adds another publication
commit boundary and still cannot constrain binaries that ignore it. Exact lock/publication/startup
mechanics are now implemented and covered by Linux lifecycle/publication tests. The
[service testing owner](TESTING.md#kapsel-service) distinguishes that evidence from installed-host
qualification. Removing A from the catalog never clears its unresolved history.

## Finite resource proposal

The selected limits are now implemented. Current
[journal bounds and completion accounting](EFFECT_GATEWAY.md#durable-facts-and-recovery) and
[service resource bounds](KAPSEL_SERVICE.md#protocol) are canonical. The initial 10,000-identity
candidate was superseded by **504 retained identities**, at most **32 unfinished**, with no pruning.
This is an operating limit of the bounded preview, not a future automatic rotation policy.

Completion accounting depends on the pinned SQLite layout and owned write paths. Schema, statement
or dependency changes must preserve those premises or revise the promise. The main rollback bound is
not a bound on all temporary storage and does not reserve external filesystem space.

Use conservative whole-identity completion reservation rather than a state-dependent remaining-byte
ledger. Charge each new identity for its maximum retained authority, lifecycle facts, original
receipt and SQLite overhead before acknowledgement. Do not reclaim the charge as the row grows. This
trades history utilization for simpler crash accounting. The implemented 504-identity ceiling
replaces the original 10,000-identity candidate; no pruning is provided to recover its charges.

Do not choose a byte charge from payload sizes alone. SQLite stores table/index pages, overflow
pages and rollback records with their own overhead. Its
[maximum page count](https://sqlite.org/pragma.html#pragma_max_page_count) can constrain database
growth, but does not reserve future completion. Its
[journal size limit](https://sqlite.org/pragma.html#pragma_journal_size_limit) limits files left
after transactions, not peak rollback growth. The
[file format](https://sqlite.org/fileformat.html#the_rollback_journal) permits sector-padded headers
between rollback segments. These primary references were read on 2026-09-14; they are design input,
not a proof for this schema or platform.

Prove configured completion reservation separately from physical disk-full/commit failure. Freeze
schema only after row/decoder/index bounds, maximum transient allocation and any observation fields
agree. A reservation is not a guarantee against external filesystem exhaustion. Completion failure
leaves frozen facts and admitted responsibility intact. Stable task/memory counts under delayed
storage, repeated timeouts, connection churn and oversized output are required.

## Observation budget and restart clocks

This placement decision did not approve an observation policy change. The separately approved
[observation policy](EFFECT_GATEWAY.md#result-meaning) now selects bounded per-pass observation and
classifier-aligned stopping. It owns the exact limits and restart semantics; the historical
reconnect report remains evidence for its original revision, not current behavior.

The candidate comparison was:

- Per-pass time/read bounds, including early-stop versus sufficient-classifier evidence. Explicit
  reselection of an unfinished attempt can grant another bounded pass after process loss. This has
  no lifetime ceiling across repeated interruptions and requires no durable clock fields.
- A durable lifetime time/read budget. Reserve reads before GET so a crash cannot mint
  opportunities. Define downtime, monotonic versus wall clocks, backward/forward jumps, reboot,
  expiry and overflow before promising a bound. Clock uncertainty cannot invent receiver facts or
  extend permission.

The smallest evidence is deterministic early-stop, cancellation and repeated-restart cases plus a
pinned live rollout exceeding 30 seconds and one exceeding the candidate bound. Measure time and
reads independently. Status/reconnect reads never reset budgets. Longer observation occupies the
single worker longer, but read-first startup does not wait for it. Receipt v2/v3 has no timestamp or
budget claim; new evidence fields need an explicitly approved format. Supplementary observation and
relaxed approval remain separate decisions, not prerequisites.

## Compare two implementation owners

Prefer application-owned bounded catalog resolution with gateway-owned admission. `Application` was
the original single-action owner; `ServiceApplication` now resolves selectable or retained original
authority. The gateway hides admission, reconciliation and blocked outcomes; the sole journal owns
conditional rows, capacity and receipt commitment. Runtime owns peer/framing limits and task
lifetime. This keeps lifecycle out of the transport.

The alternative is a service-owned collection of configured `Application` handles, as in the
prototype. It reuses more existing construction but spreads custody, history and startup knowledge
between application and service. It is not the default production architecture. Neither candidate
justifies a generic registry, a second store, public phase helpers or a scheduler.

Direct proof seams remain `src/application/mod.rs`, `src/gateway/mod.rs`,
`src/gateway/journal/{mod,schema,opening}.rs`, `crates/kapseld/src/server/{protocol,runtime}.rs`,
[application contract tests](../tests/application_contract.rs),
[gateway lifecycle tests](../src/gateway/tests/lifecycle.rs),
[dispatch tests](../src/gateway/tests/dispatch.rs), [receipt tests](../src/gateway/tests/receipt.rs)
and [Linux service tests](../crates/kapseld/src/server/linux_tests.rs). The implemented
[service application tests](../tests/service_application_contract.rs),
[HTTP-backed A/B tests](../tests/application_retry/service_selection.rs) and
[cold-publication process tests](../crates/kapseld/tests/linux_process/cold_publication.rs) now
exercise the new admission, retained-authority and provisioning rules. Receiver HTTP counts remain
independent of shim calls or result labels. See [testing](TESTING.md#kapsel-service) for the
evidence boundary.

## Compatibility decisions before implementation

The published v0.2.0 beta keeps its named CLI/MCP, grant v1, receipt/trust v2 and bounded historical
continuity. The proposal baseline used journal format 4, snapshot grant v2 and receipt v3. Current
source implements format-5 retained grants and the version-1 service admission workflow. Actionable
status, observation policy and the installed operator journey still require their own work. Keeping
the resident service does not make those surfaces published or silently change old clients.

The implemented journal format refuses format 4 unchanged, without migration or reinterpretation.
Preserve old journals, their sidecars and original access materials under the matching binary. Do
not delete or rotate history, or recreate old operations in a fresh journal. A fresh-format
installation is not continuity for a populated experimental host. Format 4 retains grant digests,
not the original signed bytes. Offline migration would require every original grant plus all-phase
preservation and interruption proof; that additional compatibility path is not selected.

| Surface               | Selected direction or named adoption blocker                                                  | Smallest decision/evidence needed                                                                                                                                                             |
| --------------------- | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Protocol              | Version-1 ID-only selection and durable admission/refusal/indeterminate outcomes implemented  | Reviewed protocol, contention and acknowledgement tests; legacy CLI/MCP remain separate.                                                                                                      |
| Storage               | Format 5 retains signed grants and refuses format 4 unchanged                                 | Reviewed physical-layout and opening checks; no migration, history deletion or stale restoration as retry.                                                                                    |
| Grant/trust           | Snapshot v2 service execution and externally appointed historical trust implemented           | Original-key validation and per-identity read isolation tested; historical v1 reads do not permit service execution.                                                                          |
| Receipt               | Original v2/v3 bytes and purposes preserved                                                   | Retrieval tested across restart/catalog/key changes. New observation claims still require an explicit version decision.                                                                       |
| Completion capacity   | 504 retained, 32 unfinished; whole-identity accounting implemented and independently reviewed | Full-capacity completion, bounded tmpfs ENOSPC and commit/acknowledgement failures tested. Process kills bracket commit, not death inside commit; no disk-backed or power-loss qualification. |
| Conflict provisioning | Cold replacement, lifecycle exclusion and physical retirement implemented and reviewed        | Linux race/process checks passed. Installed-host confinement remains a qualification requirement, not established deployment support.                                                         |
| Observation           | Policy unresolved, no speculative schema fields                                               | Measured stopping/read/time comparison and explicit approval at the observation owner before implementation.                                                                                  |
| Hosting/release       | Linux resident service selected, no supported artifact yet                                    | Native service, artifact-only journey and exact combined-candidate qualification. Separate publication approval remains mandatory.                                                            |

## Adoption gate

The selected direction is approved, not production adoption. Keep affected implementation unpromoted
until its exact contract decisions and prerequisite committed evidence are concrete. Retained
authority/storage, execution-status projection and observation policy stay in their feature owners.
Storage is not automatically a separate project or a broad refactoring round. Artifact construction
owns native packaging/assets, the journey consumes that artifact, and final qualification checks the
exact combined bytes rather than certifying a list of independently passing tickets.

Independent read-only authority/recovery/hostile-input/compatibility review must challenge admission
traces, conflict enforcement, original authority custody and no-resend behavior. Resolve findings in
this proposal or leave explicit blockers. Deterministic, Linux process, live receiver and artifact
proof remain distinct; none follows from this discussion or the prototype's mock HTTP results. No
controller rewrite, queue, policy language, new capability, signature removal, production promise,
deployment or publication follows from this decision.
