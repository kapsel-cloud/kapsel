# Delegated-action workflow proposal

Status: selected v0.3 design direction, not implemented or approved for production adoption. The
maintainer approved the placement and workflow choices below on 2026-09-13. Exact compatibility,
resource accounting and qualification blockers remain explicit. No release, supported installation,
protocol version or storage migration is adopted here.

An operator prepares exact image actions. A caller selects one by a stable handle, then reconnects
for status and original evidence. Kapsel retains admitted responsibility, but runs only one action
at a time. Blocked unfinished A need not prevent independently assessed B. The caller retains
unselected intent and explicitly selects unfinished work after restart. There is no waiting queue.

The [scope](SCOPE.md), [effect gateway](EFFECT_GATEWAY.md), [service](KAPSEL_SERVICE.md),
[architecture](ARCHITECTURE.md) and [release](RELEASE.md) remain current-behavior owners. This
proposal owns the selected changes and unresolved adoption questions. New behavior and illustrative
labels below are not callable interfaces. Canonical runtime contracts must change before their
implementation, without presenting the design as shipped behavior.

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

Selection supplies the operation ID, or an exact tuple plus ID if the final compatibility decision
requires it. The application resolves authority, never a caller grant, path or trust lookup. Any
supplied tuple must match. The protocol spelling remains an explicit blocker, not a new command.

Selected custody direction:

- First admission atomically freezes original signed grant bytes, tuple, snapshot, signer and grant
  digest in the same journal record. A configured-file-only design loses ordinary history access
  when those files disappear; journal retention removes that separate per-action file dependency.
- Stored bytes never appoint trust. The operator separately retains appointed verification trust for
  historical access and unfinished recovery, receiver credentials and receipt signing material where
  completion requires it. A journal backup alone is still not a full recovery bundle.
- Historical reads use the authenticated cohort and original retained authority, not current catalog
  membership. Missing or withdrawn required trust fails closed with a bounded access error, not
  `NOT_FOUND` or replacement authority. Exact trust-withdrawal and safe read-composition rules
  remain an adoption blocker. No new expiry, revocation or rotation semantics are inferred.
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
Admitted work is bounded by an explicit unfinished-identity cap as well as history/physical caps.
The exact unfinished cap and accounting proof remain an adoption blocker. It cannot be an unbounded
collection of detached tasks.

Kapsel retains admitted responsibility and makes unfinished history available. The caller or
operator owns when to explicitly reselect it. No fairness, FIFO, automatic waiting-work selection,
eventual-completion promise or periodic retry is introduced. Durable responsibility is not a
liveness promise, and the caller must retain unselected intent outside Kapsel.

### Admission and acknowledgement

The new admission boundary must use a distinct, explicitly chosen protocol compatibility rule. It
must not silently strengthen HEAD's `ACCEPTED` envelope.

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

The smallest candidate procedure to prove is stop admission, stop/join all old execution and storage
tasks, preserve the journal and original authorities, install one validated private catalog, then
restart read-first. No hot reload is required. A partially replaced configuration must fail closed;
an old process or stale configuration must not remain able to accept withdrawn B. Exact atomic
publication, operator acknowledgement and startup validation remain unresolved. Merely documenting
stop/start is not the race proof. Removing A from the catalog never clears its unresolved history.

## Finite resource proposal

These limits are candidates retained for implementation proof, not measured guarantees. Current
[journal bounds](EFFECT_GATEWAY.md#durable-facts-and-recovery) and
[frame bounds](KAPSEL_SERVICE.md#protocol) remain unchanged until their owners are amended.

| Resource              | Candidate bound and required behavior                                                                                                                                                                                                                   |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Catalog               | 32 approvals, 4 KiB per grant and 160 KiB aggregate encoded configuration including labels. Reject count/byte overflow before allocation or traversal. No dynamic caller path lookup.                                                                   |
| Accepted work         | One active reconciliation and one admission transaction under exclusion. Multiple unfinished identities with an explicitly selected finite cap; cap and completion accounting are adoption blockers. No pending task per stored row.                    |
| History               | 10,000 identities, 64 MiB main database, 65 MiB rollback artifact and existing per-value/row caps. First cap wins. Reserve room for frozen facts/receipt completion at admission, or refuse new work. Do not promise 10,000 maximum-sized receipts fit. |
| Caller frames         | Retain 16 KiB requests/ordinary responses, 40 KiB receipt responses. Candidate catalog pages contain at most eight handles with bounded cursor and byte ceiling. No whole-history load per read.                                                        |
| Tasks and connections | Eight admitted connections, immediate saturation close, no detached accumulation. A storage task keeps its permit until it actually stops, even after a response deadline.                                                                              |
| Admission             | Candidate two-second decision deadline after frame read, with existing two-second read/write deadlines. Immediate lock refusal. Unsettled commit is indeterminate. No hard deadline on stalled fsync is claimed.                                        |
| Advancement           | One bounded pass per explicit same-ID selection. Restart and reads do not advance work. No retry loop or caller-supplied budget.                                                                                                                        |

Prove configured completion reservation separately from physical disk-full/commit failure. Freeze
schema only after row/decoder/index bounds, unfinished capacity and any observation fields agree. A
reservation is not a guarantee against external filesystem exhaustion. Completion failure leaves
frozen facts and admitted responsibility intact. Stable task/memory counts under delayed storage,
repeated timeouts, connection churn and oversized output are required.

## Observation budget and restart clocks

No observation policy change is approved by this placement decision. The existing 30-second/30-read
per-invocation behavior and early stopping predicate remain current behavior. The reconnect report's
longer workflow is motivation to measure, not permission to lengthen a timeout optimistically.

The observation owner must compare two bounded candidates before implementation:

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

Prefer application-owned bounded catalog resolution with gateway-owned admission. `Application`
resolves selectable or retained original authority. The gateway hides admission, reconciliation and
blocked outcomes; the sole journal owns conditional rows, capacity and receipt commitment. Runtime
owns peer/framing limits and task lifetime. This keeps lifecycle out of the transport.

The alternative is a service-owned collection of configured `Application` handles, as in the
prototype. It reuses more existing construction but spreads custody, history and startup knowledge
between application and service. It is not the default production architecture. Neither candidate
justifies a generic registry, a second store, public phase helpers or a scheduler.

Direct proof seams remain `src/application/mod.rs`, `src/gateway/mod.rs`,
`src/gateway/journal/{mod,schema,opening}.rs`, `crates/kapseld/src/server/{protocol,runtime}.rs`,
[application contract tests](../tests/application_contract.rs),
[gateway lifecycle tests](../src/gateway/tests/lifecycle.rs),
[dispatch tests](../src/gateway/tests/dispatch.rs), [receipt tests](../src/gateway/tests/receipt.rs)
and [Linux service tests](../crates/kapseld/src/server/linux_tests.rs). Tests must independently
count receiver HTTP, not just shim calls or result labels. Existing tests are not evidence for the
new admission, retained-grant or provisioning rules.

## Compatibility decisions before implementation

The published v0.2.0 beta keeps its named CLI/MCP, grant v1, receipt/trust v2 and bounded historical
continuity. Unpublished HEAD uses journal format 4, snapshot grant v2 and receipt v3. Keeping the
resident service does not make those surfaces published or silently change old clients.

| Surface               | Selected direction or named adoption blocker                                                                                                    | Smallest decision/evidence needed                                                                                                                                                                      |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Protocol              | Durable acknowledgement, duplicate precedence, handle/history access and separate activity are selected; exact version/envelopes remain blocked | Choose explicit new-version/endpoint or old-client refusal policy, then bounded protocol vectors covering duplicates, BUSY and admission ambiguity. Keep legacy CLI/MCP separate.                      |
| Storage               | Journal-retained signed grants and completion accounting are selected; new schema/opening policy remains blocked                                | Specify decoder/index/capacity changes and choose tested migration or unchanged refusal of format 4. Preserve multiple unfinished identities, original bytes and history. Never delete state to retry. |
| Grant/trust           | Keep signed snapshot v2 authority and externally appointed trust; historical trust retention/withdrawal details remain blocked                  | Define bounded original-key resolution, missing-trust read/recovery behavior and operator custody tests. No signature removal, expiry or approval refresh.                                             |
| Receipt               | Preserve exact v2/v3 bytes and purposes; no new receipt claim selected                                                                          | Retained vectors and original-byte retrieval across restart/catalog/key changes. A new observation claim must get a separate explicit version decision.                                                |
| Completion capacity   | New admission must account for later completion; exact reservation and unfinished cap remain blocked                                            | Prove logical/physical accounting and full-capacity duplicates, external disk-full, interrupted commit and acknowledgement loss separately.                                                            |
| Conflict provisioning | Operator-only independent catalog selected; replacement/race mechanism remains blocked                                                          | Hostile B selection through stop/update/restart and stale-process/configuration cases under actual Linux confinement.                                                                                  |
| Observation           | Policy unresolved, no speculative schema fields                                                                                                 | Measured stopping/read/time comparison and explicit approval at the observation owner before implementation.                                                                                           |
| Hosting/release       | Linux resident service selected, no supported artifact yet                                                                                      | Native service, artifact-only journey and exact combined-candidate qualification. Separate publication approval remains mandatory.                                                                     |

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
