# Delegated-action workflow proposal

Status: proposed v0.3 preview design, not implemented or approved for production adoption. No
release, hosting model, installation path, protocol version or storage migration is adopted by this
document.

An operator prepares exact image actions. A caller selects one by a stable, understandable handle,
then reconnects to that same action for status and original evidence. Kapsel retains one unfinished
selection, not a queue of future work.

The [scope](SCOPE.md), [effect gateway](EFFECT_GATEWAY.md), [service](KAPSEL_SERVICE.md),
[architecture](ARCHITECTURE.md) and [release](RELEASE.md) remain the current owners. This document
owns only the proposed changes and the questions that must be tested before those owners change. All
new behavior below is a proposal; illustrative labels are not a callable wire grammar.

## Why change the caller workflow?

At inspected revision `1fd59f84d2a154111642c40ded8ce5a069ce175e`, the unpublished service has one
configured grant and request. Its `ACCEPTED` response means background-task ownership, not durable
admission. A transient preflight failure can release that task while status remains `IN_PROGRESS`.
Switching configuration to another action also removes the first action's ordinary read visibility.
Those are current boundaries, not bugs silently repaired by this proposal.

The proposed improvement is a small selectable set of exact approvals, durable acknowledgement of
one selected action, and status that distinguishes work running now from work awaiting help. It
keeps the existing deep recovery mechanism and immutable receipts.

The committed reports [Reconnectable agent action](RECONNECTABLE_AGENT_ACTION.md),
[Two pending operations](MULTIPLE_PENDING_OPERATIONS.md) and
[Protected typed-tool comparison](PROTECTED_TOOL_COMPARISON.md) were read at that revision. Their
own evidence revisions and limitations still apply: one live reconnect experiment, a source design
exercise, and a historical controlled comparison respectively. None proves this proposed workflow.
No new runtime probe or live experiment accompanies this design.

## One operator and one caller trust domain

Only `kubernetes.set_deployment_image` remains available. Permission, dispatch, receiver observation
and application quality stay separate:

1. The operator independently acquires the Deployment UID and resourceVersion and signs the exact
   operation identity, namespace, Deployment, container and immutable digest-bound image.
2. Durable admission records responsibility for that action. It permits neither a PATCH nor a
   receiver conclusion by itself.
3. The gateway's fresh conditional attempt commit may issue one private dispatch permission. Loaded
   attempted history cannot issue another permission.
4. Bounded receiver observations determine the existing result. Application tests and operational
   judgment determine whether the change was useful. An available rollout is not application health.

The preview assumes one operator-controlled journal and one authenticated local caller cohort, not
per-user or multi-tenant isolation. Every admitted member may see and select the same approvals and
read the same retained action history. Knowing an operation ID is not authentication. Reconnecting
means using the same operation identity through this same authorized cohort, not proving continuity
of an individual agent process. Peer admission and private filesystem checks remain service-owned;
remote authentication and identity rotation require the separate placement decision.

### Desired-state ownership and caller confinement

Direct image changes require the operator's explicit approval of desired-state ownership. If a
reconciler restores a Git-declared image, this workflow is not qualified unchanged. The operator
must choose a compatible ownership arrangement outside caller input; Kapsel neither disables
reconcilers nor claims automatic GitOps compatibility. RBAC and admission remain adjacent controls,
not proof that a direct change is appropriate. See Kubernetes
[RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) and Argo CD
[automatic sync and self-heal](https://argo-cd.readthedocs.io/en/stable/user-guide/auto_sync/).
These documentation links are background, not version-pinned integration evidence.

The caller must not possess another route to mutation: writable kubeconfig or token files, shell
access under the service identity, privilege escalation, writable service executables/configuration,
or an unrestricted tool holding cluster credentials would bypass this boundary. A wrapper or an
agent's conversational confirmation is not enforcement. Qualification must exercise a hostile caller
under the intended OS isolation and prove those routes denied. Kapsel cannot confine a caller that
also controls host root, the kernel or the service identity.

## Approvals, handles and retained identity

A **selectable approval** is operator-provisioned permission that has not been accepted for
execution. The caller retains responsibility for unselected intent. Merely listing or reading an
approval creates no action row, target read, scheduling obligation or promise that its snapshot
stays fresh.

Proposed handle presentation contains the stable operation ID, exact tuple, approved UID/version and
an operator-written printable ASCII display label of at most 128 bytes. For example, `release-api-1`
can be labelled `Update demo/agent-api api image`. The full immutable digest must remain
inspectable; a label or truncated image is never the matching key. Handles disclose no grants, keys,
credentials, private paths or lifecycle controls. The operator supplies the bounded handle view
through the service; an untrusted pasted description does not authorize an action.

Selection supplies only the operation ID, or the existing exact tuple plus ID if compatibility
requires it. The application resolves operator-owned authority; supplied tuple fields must match.
The final request spelling is a protocol decision, not a new command in this document.

Proposed retention rules:

- At most 32 approvals are selectable in one operator configuration. Loading replacements is
  operator-only; no caller upload, path lookup, wildcard or approval refresh is introduced.
- First admission freezes the tuple, approval, signer, grant digest and original signed grant bytes
  in the same journal row. Keeping original bytes is a proposed schema change: HEAD freezes
  provenance but relies on the configured grant bytes. Stored bytes never appoint their own trust.
- Original grants and separately appointed verification trust remain available for unfinished
  recovery. Catalog removal cannot replace accepted authority or act as revocation of an accepted
  action. Emergency stop and trust withdrawal are operator lifecycle decisions, not caller actions.
- Accepted identities, including rejections and original receipts, remain readable by the cohort
  independently of the current selectable catalog. Unaccepted removed approvals are no longer
  selectable. An absent or nonvisible ID reveals no unrelated authority facts.
- Retain accepted records for the lifetime of this journal, up to its finite logical and physical
  caps. Do not prune, reuse IDs, silently forget deduplication history or rotate journals to retry
  an ambiguous action. At capacity refuse new identities; existing reads and exact duplicates remain
  available when storage is healthy. This is a bounded preview retention policy, not unlimited
  history or host-loss continuity.
- Receipt export is a copy, not completion. Consistent operator backups must retain history,
  original evidence and the external authority needed for recovery. No automated backup, trust
  rotation, pruning or restore protocol is added. Lost storage is not evidence of no effect.

## One durable selection, no waiting queue

Proposed admission accepts at most one nonterminal action in this journal. Its existing lifecycle
row identifies the selected unfinished action; do not add a second service state machine or a
separate pending store. This is stricter than HEAD's operation-selected gateway, which can retain
multiple unfinished rows. The compatibility decision must handle that difference explicitly.

Selectable B is not accepted behind A. If A is unfinished, different B receives `BUSY`, even when A
has no live worker. The caller keeps B. There is no FIFO, fairness, skip-over, periodic retry or
promise to progress without the caller/operator. This deliberately sacrifices independent B's
progress while A is blocked; the workflow experiment must test whether that tradeoff is usable.

### Admission and acknowledgement

The proposed durable acknowledgement uses a new protocol contract; it must not silently strengthen
HEAD's `ACCEPTED` spelling. The bounded application admission entry point would:

1. Authenticate at the adapter, parse bounded input, then resolve the exact operator approval and
   validate provenance inside the application/gateway boundary.
2. In a conditional journal transaction, either return an identical existing action, reject changed
   identity facts, refuse a different unfinished selection, or insert the new `requested` row with
   its complete authority binding. The single unfinished-row invariant is checked atomically across
   processes, not inferred from a runtime semaphore.
3. Return a durable acknowledgement only after confirmed commitment. No Kubernetes read, attempt,
   signing or rollout wait belongs to admission. The worker is installed after durable admission;
   inability to start it leaves a visible blocked selection, not an unaccepted request.

An acknowledgement establishes retained responsibility under the stated storage assumptions. It is
not proof of authorization advancement, dispatch, receiver success, eventual completion or
power-loss durability. Status can already be terminal by the time the caller receives the
acknowledgement.

A disconnect never cancels a committed selection. On response loss the caller reads and, if needed,
selects the **same** identity with the same original authority. An identical existing action returns
its admission/disposition without creating an overlapping worker. A changed tuple, grant or approval
under that ID fails closed, including for terminal records. No caller retry mints a fresh ID.

If a commit or its acknowledgement is ambiguous, the service must not report definite rejection or
absence. It retains exclusion while the commit task may still finish, then reloads the same
identity. If it cannot establish durable state, it returns a bounded admission-indeterminate error
or closes; this is not the receiver result `UNKNOWN`. A read of absence while that task is
unresolved is not proof that insertion cannot still occur. After restart, journal recovery and the
conditional same-identity admission resolve this ambiguity without selecting a second action.

### Active, blocked and terminal

Proposed status has two separate dimensions: existing durable lifecycle/disposition and current
execution activity. Illustrative activity values are `active`, `blocked` and `idle`; these do not
replace `SUCCEEDED`, `FAILED`, `UNKNOWN` or `NOT_ATTEMPTED`.

- `active` requires a currently owned reconciliation task. A durable nonterminal phase alone never
  proves a worker is running. Activity can change immediately after a status snapshot.
- `blocked` means the accepted action is unfinished without a running worker. A bounded reason can
  distinguish transient preflight failure, recovery required, receipt completion failure or operator
  authority/storage intervention. It contains no raw provider/SQLite error or private path. If a
  crash erased the reason, say recovery required, not an invented failure cause.
- Terminal disposition is durable and read-only; no worker is required. A frozen receiver statement
  awaiting receipt commitment remains unfinished, not falsely complete.

The gateway reports the blocked boundary to `Application`; the runtime supplies only current task
ownership. Error projection must not become an adapter-owned lifecycle interpreter. Persist only
facts needed for correct recovery, not a stale `active` bit or a second transition ledger.

At restart, validate private storage and authority before serving. Recover the sole unfinished row,
not the first catalog entry or a sorted list of approvals. More than one unfinished row or missing
original authority blocks execution and needs an explicit compatibility/operator decision. Once safe
read-only composition is possible, make stored status/receipts available while one bounded startup
reconciliation runs. Provider unavailability must not masquerade as missing history. Unsafe or
unreadable storage may still prevent service startup; availability is not promised in that case.

Before the attempt marker, explicit re-selection of the same blocked action is permitted to request
one reconciliation pass: recheck original authority and repeat the safe GET. It neither refreshes
approval nor forces dispatch. A duplicate while active only reads/joins existing responsibility.
After the marker, the same request may resume observation or frozen receipt completion, never PATCH.
Terminal duplicates only return history. There is no caller-supplied phase, force/retry switch,
observation budget or service restart control. Startup and explicit re-selection are the only
proposed advancement triggers; neither runs an indefinite retry loop.

## Concrete failure traces

A denotes one exact approved action; B denotes another identity. These are proposed contract traces,
not executed test results. Each should become an independently asserted workflow case.

| Case                           | Retained fact and next action                                                                                                                                                                                                                                                                              |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Healthy                        | Admit A durably, acknowledge, then authorize and GET the approved target. Matching snapshot permits the conditional attempt commit and one PATCH opportunity. Observe the defined rollout predicate, freeze `SUCCEEDED`, commit original signed receipt. Caller evaluates application behavior separately. |
| Identical duplicate            | Before admission, two concurrent identical requests resolve to one row. While active, return existing responsibility with no extra task. When blocked, one explicit same-ID reconciliation may acquire exclusion. At terminal, return the same disposition and bytes without receiver I/O.                 |
| Changed duplicate              | Change any tuple field, original grant provenance, UID or resourceVersion under A. Reject before advancement, including after restart or catalog replacement; A's row and receipt remain unchanged.                                                                                                        |
| BUSY                           | A owns the unfinished selection; B is still only selectable. Reject B without a B row or Kubernetes call. This also holds when A is blocked and its worker lock is free. Caller retains B; no eventual admission is implied.                                                                               |
| Admission loss before commit   | No confirmed acceptance. A may remain absent; same-ID conditional re-selection resolves it. Do not infer absence from one read while a commit task is live. No Kubernetes call is allowed before durable admission.                                                                                        |
| Admission commit/ack loss      | A's bound row survives but the caller receives no acknowledgement. Reopen/read A under the same authority; do not insert B as an escape. Loss after commit but before worker installation produces recoverable blocked A, not forgotten intent.                                                            |
| Transient preflight failure    | Safe GET fails; A stays `authorized`, with no attempt, receiver result or receipt. Task ends with blocked preflight status. Explicit same-ID selection or one startup pass repeats GET; a still-matching snapshot is required before a fresh attempt. B remains unaccepted.                                |
| Stale approval                 | A's preflight observes a different UID/version. Freeze `NOT_ATTEMPTED / STALE_APPROVAL` and observed target; zero PATCHes and no effect receipt. Only an independent operator decision may create a new grant and new handle. A remains unchanged.                                                         |
| Loss at attempt commit         | Even if no PATCH was sent or commit acknowledgement was lost, durable `apply_started` makes restart observation-only. Lost dispatch permission is not recreated. Missing result facts can freeze `UNKNOWN`, never `NOT_ATTEMPTED`.                                                                         |
| Loss after PATCH               | Whether Kubernetes persisted the image or the response disappeared, recover from stored attempt facts with no second PATCH. A matching observation may establish success/failure; ambiguity remains `UNKNOWN`. A conflict between GET and PATCH is likewise attempted, not stale preflight rejection.      |
| Receipt commit/ack loss        | Freeze receiver facts before signing. Reopen `receiver_observed` to finish only those facts, or `finalized` to retrieve committed bytes. Do not reobserve to improve a result or re-sign already committed evidence.                                                                                       |
| Original receipt after restart | Change selectable catalog and receipt signing key without replacing original action authority. Read A's identical original receipt and digest, even with Kubernetes/export unavailable. Missing database/trust is a bounded access failure, not permission to reconstruct evidence.                        |
| Conflict after UNKNOWN         | A is terminal and exclusion is released. Conflicting B is held outside selectable authority pending operator investigation and independent evidence. A new approval is not an automatic retry and does not resolve A. An independently assessed B may proceed without changing A's result.                 |

### Who holds conflicting B?

The operator/surrounding workflow owns dependencies and conflicting follow-on actions after
`UNKNOWN`. Different Deployment names do not prove application independence; different containers in
one Deployment still share the object snapshot. The worker lock is mechanical exclusion, not an
enduring conflict reservation.

For this preview's minimal workflow, the operator exposes only actions assessed as independent of
other selectable or unresolved actions. It withholds conflicting B's selectable approval until an
explicit decision. Caller advice alone is insufficient when B is already selectable: a hostile
caller could select it immediately after A terminalizes. The proposed service does not infer
cross-action conflict or enforce an application dependency graph. Qualification must either prove
operator provisioning/confinement keeps conflicting B unavailable, or reject this workflow and
require a separately approved durable conflict-hold design. Do not silently add such a policy
engine.

Removing accepted A's catalog entry never erases its history or makes it safe to issue conflicting
B. Withdrawing an already exposed but unaccepted B also needs operator-controlled update ordering; a
restart race must not let stale selection win. The exact update mechanism and that race proof remain
production adoption blockers.

## Finite resource proposal

These are candidate limits to falsify in the workflow experiment, not measured service guarantees.
Existing [journal and receiver bounds](EFFECT_GATEWAY.md#durable-facts-and-recovery) and
[frame bounds](KAPSEL_SERVICE.md#protocol) continue to apply unless explicitly revised.

| Resource              | Proposed bound and refusal behavior                                                                                                                                                                                                                                                                                                           |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Selectable approvals  | 32 entries; at most 4 KiB per signed grant and 160 KiB total encoded catalog including labels/metadata. Validate aggregate size/count before allocation or file traversal. No dynamic caller-controlled lookup.                                                                                                                               |
| Accepted work         | One nonterminal row, including blocked work; no backlog of accepted B. At most one reconciliation task and one outstanding admission transaction. No detached task accumulation after timeouts.                                                                                                                                               |
| History               | At most 10,000 identities, 64 MiB main database, 65 MiB rollback artifact and existing per-value/row caps. First reached cap wins; 10,000 maximum-size receipts are not promised to fit. Reserve/check completion capacity at admission or reject new work; exact reservation accounting requires schema proof.                               |
| Caller input/output   | Retain 16 KiB requests/ordinary responses and 40 KiB receipt responses. Proposed catalog view returns at most eight handles per page, with a bounded validated cursor and byte ceiling; never load/serialize all history to answer one read. Changed catalogs may invalidate a cursor rather than imply a stable snapshot.                    |
| Connections and tasks | Retain eight admitted connections and immediate saturation close. Timed-out blocking storage jobs retain their resource permit until they actually stop; a dropped future is not cancellation of SQLite or fsync.                                                                                                                             |
| Admission work        | One exact approval lookup, one identity lookup, one conditional insert transaction or existing-row response; no Kubernetes, signing, full-history traversal or polling. Maintain the unique unfinished selection in the journal's constraints/indexes. Startup integrity checks remain separately bounded by store caps.                      |
| Admission latency     | Proposed two-second admission decision deadline after the bounded frame is read, in addition to existing two-second read and write deadlines. Lock contention refuses without waiting. Deadline exhaustion with unsettled commit is indeterminate, not definite rejection. No hard wall-clock bound on a stalled filesystem/fsync is claimed. |
| Advancement           | One reconciliation pass per startup or explicit same-ID request, with existing target/PATCH deadlines and the selected bounded observation policy. No automatic backoff loop or caller-controlled budget.                                                                                                                                     |

A production implementation must demonstrate stable task/memory counts under repeated timeout,
connection churn, locked/delayed SQLite and oversized output, including completion-space exhaustion.
Finite connections alone do not prove bounded detached work or admission latency.

## Observation budget and restart clocks

Current source observes within 30 seconds and at most 30 reads per reconciliation invocation. It can
also stop on the current generation's available/progress-deadline signal before the final classifier
has enough facts for success. Extending only the timeout may therefore not avoid early `UNKNOWN`.
The reconnect experiment's 45–180 second workflow span motivates testing, not an automatic change.

Compare two concrete initial-observation policies before adoption:

- **Per-pass budget:** retain 30 seconds/30 reads, or test an operator-fixed 180 seconds/180 reads
  at one-second intervals. Use a monotonic in-process deadline. Restart grants another bounded pass
  to an unfinished attempt, so repeated restarts have no lifetime time/read ceiling. State that
  limit honestly and test early-stop predicates separately. No durable clock fields are needed.
- **One durable lifetime budget:** test 180 seconds/180 reserved read opportunities from the first
  post-attempt observation. Store remaining read budget and deadline facts in the same journal;
  reserve each opportunity before GET so a crash can consume budget but cannot create extra reads.
  Include downtime in a persisted wall-clock deadline, with monotonic time inside each process. This
  requires explicit clock validity, backward/forward jump, reboot and overflow rules. An
  untrusted/backward clock must not extend observation; clock uncertainty needs a fail-closed
  bounded disposition rather than guessing elapsed time. Define and test the exact behavior before
  choosing this option.

Neither policy is selected here. A durable budget changes schema and observation semantics; a longer
per-pass budget changes work and latency but does not solve lifetime bounds. Both must state when
facts freeze, how cancellation consumes budget, and what a restart after expiry can conclude without
inventing receiver facts. Receipt v2/v3 currently carries no observation timestamps or budget; any
new evidence claim needs an explicit receipt-format decision rather than reinterpretation.

Later supplementary observation is a separate disposition decision. It is not adopted, an implicit
status-read effect or a mandatory prerequisite here. If separately approved, it must bind the
original receipt digest and leave the historical result and bytes unchanged. Exact-snapshot approval
relaxation likewise belongs to its own evaluation; this proposal retains strict UID/resourceVersion
approval and does not depend on relaxing it.

## Compare two implementation owners

Both candidates retain one store and the gateway's complete reconciliation. Neither permits service
code to switch on durable phases, issue PATCHes or commit receipts.

| Candidate                                                     | Boundary, failure behavior and change cost                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A: application-owned bounded catalog, gateway-owned admission | `Application` resolves the operator catalog and retained identity to exact authority, then calls gateway admission/reconciliation/read methods. Gateway owns the one-unfinished rule and blocked outcome projection; journal owns atomic admission, conditional attempt and receipt commitment. Protocol renders; runtime owns peers, frames, deadlines and task lifetime. Catalog and trust changes stay in application composition, while all lifecycle rules stay inside the gateway. This adds a small complete admission interface rather than public phase helpers. |
| B: service-owned catalog of configured applications           | `server.rs` holds up to 32 configured application handles and a read-history resolver, all sharing one journal. Each application delegates admission/reconciliation to the gateway. The service must retain original authority beyond catalog replacement and select unfinished A at restart through a new application query. It cannot use only its semaphore for durable exclusion. Catalog, startup and authority-retention knowledge spreads between server and application, and every new consumer must reproduce that composition.                                  |

**Prefer A for the next experiment, not as a frozen architecture.** It contains authority resolution
and hides durable admission from protocol/runtime. B initially reuses more of the single-grant
application but makes restart/history access a service-specific policy and increases change
amplification. If A requires a generic catalog service, second state machine, separate database or
scheduler, reconsider the boundary rather than accepting that machinery by default.

### Obligation and proof map

The files below are current implementation/test seams to extend, not claims that new behavior is
already tested. Public owner changes must precede production code changes.

| Obligation                                                       | Canonical contract; implementation owner                                                                                                                                  | Consumer and focused proof seam                                                                                                                                                                                                                                 |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Exact approvals, handles, retention and access                   | [Effect gateway](EFFECT_GATEWAY.md#exact-snapshot-approval-in-unpublished-head) and [service](KAPSEL_SERVICE.md); `src/application/mod.rs`, `crates/kapsel-authority/src` | Caller handle/status view; extend [application contract tests](../tests/application_contract.rs) for cohort scope, catalog removal, original-grant retention and changed duplicates; retain [snapshot tests](../src/gateway/tests/snapshot.rs).                 |
| Durable admission, one unfinished action and lost ack            | Effect-gateway lifecycle; `src/gateway/mod.rs`, `src/gateway/journal/mod.rs` and `schema.rs`                                                                              | Application admission, then service response; extend [validation tests](../src/gateway/tests/validation.rs) and [lifecycle tests](../src/gateway/tests/lifecycle.rs) with concurrent identity/capacity races and pre/post-admission commit cuts.                |
| Active/blocked status, restart selection and explicit resumption | [Architecture](ARCHITECTURE.md#complete-reconciliation) and service lifecycle; gateway reconciliation, application projection, `server.rs`, `server/runtime.rs`           | Caller reconnect; extend application isolation tests and [Linux service tests](../crates/kapseld/src/server/linux_tests.rs) for blocked A, unaccepted B, restart before worker creation and offline reads during recovery.                                      |
| Dispatch, attempt loss and stale approval                        | Effect-gateway fresh dispatch; journal `begin_attempt`, gateway, concrete Kubernetes adapter                                                                              | Reconciler only; preserve [dispatch tests](../src/gateway/tests/dispatch.rs), snapshot tests and [receiver-recovery matrix](../src/gateway/receiver_recovery_tests.rs), asserting HTTP PATCH counts rather than only result labels.                             |
| Immutable completion and original retrieval                      | Effect-gateway receipt completion; journal `commit_receipt`, receipt codec and application reads                                                                          | Status, receipt client, offline inspector; extend [receipt tests](../src/gateway/tests/receipt.rs) and application tests for catalog/key changes, completion capacity and commit-ack loss.                                                                      |
| Hostile input and operating bounds                               | Service protocol and effect-gateway bounds; `server/protocol.rs`, `server/runtime.rs`, journal `opening.rs`/`schema.rs`                                                   | Authenticated socket and operator loader; extend protocol/Linux framing tests, [migration validation tests](../src/gateway/tests/migration.rs), and source-owned private-path tests for aggregate catalog, stalled storage, malformed cursor and output limits. |
| Conflict hold, confinement and desired-state ownership           | [Scope](SCOPE.md), [threat model](THREAT_MODEL.md), service/operator contract                                                                                             | Operator and surrounding workflow; pinned disposable-environment workflow must attempt forbidden B, credential/tool bypass, stale catalog/restart races and reconciler overwrite. No current test proves the proposed hold.                                     |
| Observation clocks and compatibility                             | Effect-gateway result/receipt contract, [release](RELEASE.md) and [v0.2.0](V0.2.md)                                                                                       | Receiver classifier and offline inspector; deterministic clock/restart cases plus retained grant/receipt vectors and explicit journal refusal/migration tests before any new format is accepted.                                                                |

## Compatibility decisions before implementation

The published v0.2.0 beta promises its named CLI/MCP, v1 grant, v2 receipt/trust and bounded
historical journal continuity. Unpublished HEAD uses format 4, snapshot grant v2 and receipt v3,
rejects older journals without migration, and has a service that is not in that release. None is
silently upgraded by calling this a v0.3 proposal.

Production adoption must explicitly resolve:

- **Protocol:** new durable admission meaning, handle selection/listing, duplicate precedence,
  activity/error vocabulary and history visibility. Choose a version/endpoint or deliberate
  rejection/replacement policy for old clients; do not return an old success envelope with stronger
  unannounced semantics. Keep CLI/MCP old contracts separate unless explicitly revised.
- **Journal/schema:** retained grant bytes, atomic single-unfinished admission, completion-space
  reservation, indexes and any budget fields need a new format decision. Existing format-4 journals
  may contain several unfinished rows; never choose one silently. Choose tested migration with
  preservation/rollback rules or explicit unchanged refusal. No reinterpretation of the inert
  `target_read_failures` column as scheduling, elapsed time or activity.
- **Grant/trust:** retain strict signed snapshot authority and existing wire by default. Catalog
  membership is selection availability, not replacement authority. Define external trust retention
  and withdrawal across restart before supporting rotation; stored grants cannot appoint trust. No
  expiry, signature removal or relaxed approval is inferred from the historical comparison.
- **Receipt:** retain exact v2/v3 bytes and original purposes under explicitly supplied trust.
  Frozen receipt retrieval never re-signs or upgrades. If changed observation claims require new
  fields, version the format and inspection policy explicitly; do not repurpose old fields.
- **Hosting and persistence:** choose the caller isolation, authority provisioning, persistence
  placement, restart/health and backup responsibility only after testing this workflow. The existing
  local service is the reference composition, not a selected deployment product.
- **Release:** update the release owner with exact supported artifact, compatibility, qualification
  and support boundaries only after adoption. Passing design review is not release certification.

## Adoption gate

The next workflow experiment must try to falsify the concrete traces and candidate limits,
especially blocked A preventing independent B, durable-ack loss, catalog/history visibility,
conflicting B after `UNKNOWN`, hostile caller confinement and realistic rollout observation.
Preserve exact source and fixture revisions and separate model behavior, HTTP fixtures, process
exits and live Kubernetes results. Anecdotal success cannot substitute for the missing crash/race
cases.

Independent read-only authority, recovery and hostile-input review must challenge the traces,
acknowledgement semantics, access and compatibility. Resolve findings in this proposal or retain
explicit adoption-blocking decisions. Current blockers are experimental validation, conflict-hold
provisioning/update ordering, completion-capacity accounting, exact protocol/schema/trust decisions,
observation policy/clock semantics and hosting/authority/persistence placement. These are not
runtime features to implement opportunistically.

Production implementation must consume both the final workflow-experiment outcome and the subsequent
approved placement/authority/persistence decision, not merely completion or review of this proposal.
Approval-relaxation evaluation and supplementary-observation disposition remain separate optional
work, not mandatory implementation prerequisites. No queue, policy language, SDK, second capability,
distributed guarantee or production-readiness claim follows from this design.
