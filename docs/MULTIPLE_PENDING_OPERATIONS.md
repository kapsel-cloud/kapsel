# Two pending operations, one execution boundary

Status: bounded design exercise against source revision `bbe35548c978ea4bead92bf04840e17c320732ba`.
Recommendation, not an adopted API or scheduling contract. The resident service is unpublished. No
production behavior changes in this exercise.

Two approved actions do not require two concurrent mutations. They first require someone to retain
both intentions, select one, and handle the other while authority or execution is uncertain.

**Recommendation: keep selection and waiting with the surrounding caller/operator workflow.** Keep
Kapsel's existing sequential, configured-operation execution. Defer a Kapsel-owned pending queue and
parallel execution until a concrete workflow cannot tolerate caller-owned waiting. The current
service cannot transparently serve two approved identities. That usability gap remains explicit, not
solved by relabeling `BUSY` as acceptance.

The [gateway contract](EFFECT_GATEWAY.md) owns authority, lifecycle and recovery. The
[service contract](KAPSEL_SERVICE.md) owns admission and reconnect behavior. This report applies
those rules rather than extending them.

## Concrete workflow

A maintainer's release automation has two proposed image updates in a disposable namespace:

- A: `release-api-1`, Deployment `demo/agent-api`, container `api`, immutable digest X.
- B: `release-worker-1`, Deployment `demo/agent-worker`, container `worker`, immutable digest Y.

X and Y denote full digest-bound images accepted by the existing grammar. The operator independently
reads each target and provisions a separate exact-snapshot grant for each complete tuple and stable
identity. The automation retains the two proposals and the association with those identities, not
credentials or signing material. The operator retains the grants and private configuration.

The workflow selects A, obtains its frozen result, and selects B when its own release policy allows.
For this exercise, independence is an operator assertion about the application, not something
inferred from different Deployment names. Receiver `SUCCEEDED` does not establish application
quality.

This can be reasoned about using two operator-configured application handles and one local journal.
It is not a two-operation service configuration or a supported public Rust SDK. The shipped static
service RBAC names only `demo/agent-api`, so the independent-target case is not runnable unchanged
with those assets. This report authorizes no RBAC, provisioning or hosting change.

### Where the current service gets in the way

With the service configured for A:

1. Submit A while idle: `ACCEPTED` means the process owns a background task and execution slot. The
   durable row may not yet exist. A following status read can still return `NOT_FOUND`.
2. Submit well-formed B while A owns the slot: `BUSY`, before any application access. No B row,
   target read or pending-service obligation is created.
3. Submit B after the slot is released: `operation_failure`, because B does not match A's configured
   grant. Waiting longer does not fix this.
4. Read B through A's configured application: `NOT_FOUND`, even if B exists in the same journal.
   This is authority-scoped visibility, not a global absence claim.

Selecting B requires operator-owned composition, not a caller-supplied grant, path or lifecycle
command. Starting the existing service under B's configuration reconciles only B before binding. It
does not drain unfinished A. It also ceases to expose A through that configured projection.
Preserving A's original authority for later recovery and retrieval is therefore an operator duty.
Repeatedly replacing the service configuration is friction, not a recommended automation interface.

## Three separate choices

| Choice               | Current behavior                                                                             | What it would buy                                                                                       |
| -------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Pending acceptance   | The caller retains unsubmitted B. Service `ACCEPTED` is not a durable queue acknowledgement. | Durable service acceptance would let the caller stop retaining responsibility after a defined commit.   |
| Sequential execution | The selected configured operation advances under one journal worker lock.                    | Explicit selection can skip an independent blocked action without introducing concurrency.              |
| Parallel execution   | One service execution slot and journal worker exclusion prevent it in this composition.      | Overlapping observation could reduce latency, but needs new conflict, authority and recovery semantics. |

Multiple journal rows are not a scheduler. They do not make all rows selectable by one application,
provide a durable admission API, or promise fair progress. A caller retry after `BUSY` retains the
same identity and exact tuple. It is not a new approval or permission to replay a mutation.

## Short traces

These are contract/source traces, not measurements or executable probe output. No new probe is
retained. State names refer to the journal. A and B are separately approved before selection.

### Independent targets

Select A with its own configuration. Its matching preflight GET allows a fresh conditional attempt
commit, then one PATCH opportunity and bounded observation. Completion freezes A's result and
receipt. B's caller-held proposal is unchanged. Select B with B's original grant. Its own matching
preflight can proceed in the same way, provided the target has not drifted while waiting.

If both rows already exist, selecting B still leaves A unchanged. Selection does not scan, finish
receipts for, or recover other identities. There is no promise that approval survives the wait.

### Same target, two approvals from the same snapshot

Use B as `release-api-2`, also for `demo/agent-api`, with digest Y. Both grants bind UID U and
resourceVersion R. A's conditional PATCH changes the target from R to R2. B's later preflight sees
R2 and freezes `not_attempted / stale_approval`, with no PATCH, receiver result or effect receipt.
This also applies to different containers in the same Deployment: approval binds the object version.

If another write intervenes after B's matching GET but before its PATCH, the attempt marker already
exists. A conditional conflict is an attempted path, not stale preflight rejection or rollout
failure. Recovery cannot resend it. Neither a queue nor sequential execution keeps a snapshot fresh.
Status/controller updates can also invalidate an approval without A changing the image.

A desired follow-on change requires a new operator decision, independently acquired snapshot, new
grant and new operation handle. Never update B's existing approval or automatically reapprove it.

### Transient preflight failure while B could proceed

A's preflight GET fails transiently. A remains `authorized`, with no new journal write, marker,
PATCH, receiver result or receipt from that failure. Application execution returns an operation
failure. In the service, the earlier response remains `ACCEPTED`; the background error releases the
slot, while status projects `IN_PROGRESS`. There is no automatic retry loop or error detail in
status that tells the caller this was specifically a transient preflight failure.

A surrounding workflow with operator-owned A/B configurations may select independent B rather than
retry A immediately. B can complete without advancing A. Later selecting A repeats a safe preflight
GET and must obtain fresh conditional attempt permission before any PATCH. It does not reuse a
failed dispatch permission.

Timed backoff answers _when to try again_. Ordering answers _which eligible action to select_. The
inert historical `target_read_failures` column provides neither a current selection rule nor a
clock. Restoring failure-count/operation-ID ordering would not implement backoff.

### Process loss or UNKNOWN with B still pending

- Loss after service `ACCEPTED` but before durable insertion can leave A absent. Reconnect using the
  same configured authority and identity. `NOT_FOUND` alone during an active task is not proof that
  no insertion will occur. An identical resubmission may be `BUSY` or join existing durable history
  through idempotent submission when the slot is available. Do not mint a new ID to escape
  ambiguity.
- Loss before A's attempt marker leaves pre-attempt recovery eligible for safe GET and a fresh
  conditional attempt. After `apply_started`, recovery only observes, even if no PATCH was sent.
- With A selected at service restart, reconciliation happens before bind. A recovery error can keep
  the service unavailable. B is not silently selected as a fallback.
- A finalized `UNKNOWN` releases execution resources but remains immutable. It is not permission for
  B to affect the same target. The surrounding workflow holds conflicting B for an operator decision
  and independent evidence. Different names alone do not prove non-conflict.
- For an independently assessed B, the workflow may select B without resolving A's receiver result.
  It must retain responsibility for A's recovery/evidence. Selecting B neither repairs nor changes
  A.

The worker lock is mechanical exclusion while advancing one journal. It is not a persistent
same-target conflict reservation after a crash or `UNKNOWN`. Kapsel does not enforce the workflow's
hold on B across distinct operation identities.

### Duplicate submission and reconnect

An identical submission uses the original identity, request and exact grant provenance. Existing
history is resumed or returned, never refreshed. Changed request or approval under the same identity
fails closed. A duplicate while the service slot is occupied gets `BUSY`, not a second task or a
promise of eventual execution. When idle, even a terminal duplicate can return `ACCEPTED` for a task
that reads existing history without another mutation.

Status and receipt reads are read-only. Reconnect under A's original configuration returns A's
frozen result and exact original receipt bytes when finalized. A configuration selecting B cannot
serve as a global reconnect index for A. The caller must keep the stable identity and the operator
must keep the corresponding original authority available.

## Ownership and bounds

For this bounded workflow, the surrounding automation retains at most these two intentions and runs
one selected operation at a time. It owns release ordering, retry timing, and preserving its own
pending work across caller loss. If the automation cannot persist that intent, it has not obtained
durable waiting merely by submitting to Kapsel.

The operator owns exact approvals, target independence/conflict decisions and any decision after
`UNKNOWN`. Caller selection cannot supply or enlarge authority. Kapsel owns its existing service
connection bounds, immediate slot admission, journal capacity, conditional execution, recovery and
immutable results. The service has eight admitted connections, one execution slot and no waiting
queue. Journal bounds remain 10,000 identities and 64 MiB, not 10,000 pending service admissions.

All described exclusion is local to one journal and its worker lock. Separate journals, hosts,
service instances and external Kubernetes writers are not coordinated. No fleet ordering,
distributed lock, transaction or exactly-once effect follows from these traces. No hidden PATCH
retry is introduced, and loading attempted history cannot recreate fresh dispatch permission.

## Compare the owners

**Caller-owned selection** keeps release dependencies and operator conflict judgment where they
already exist. It can choose independent B after A stalls. Its cost is retaining pending intent,
retry/reconnect bookkeeping and today's awkward per-operation configuration boundary. It promises no
fairness if the caller stops selecting A. For this two-action exercise, explicit A/B selection is
sufficient. No generic caller scheduler is proposed.

**Bounded Kapsel scheduling** could accept both actions durably and continue without the caller. But
ordering alone is insufficient. It needs an operator-owned way to retain multiple exact grants, a
durable acknowledgement, bounded admission, multi-identity retrieval, eligibility after failure,
conflict holds and recovery selection. Even FIFO would need an explicit choice between blocking B
behind A and skipping A. Failure-count ordering adds policy without answering those questions. No
Kapsel queue or fairness rule is recommended here, so none is adopted implicitly.

Revisit when a maintainer workflow requires two approved identities to remain independently
retrievable through one resident endpoint across caller loss, or requires B to progress while A
waits without an operator configuration switch. Measure whether the actual missing behavior is
multi-identity access, durable acceptance, or overlapping execution before selecting a solution.
Hosting should consume this distinction rather than assuming Kubernetes implies a controller/queue.

Unresolved user decisions are whether Kapsel should own durable waiting at all, whether automatic
skip-over is desirable, and who may resolve a conflicting action after ambiguity. This exercise
recommends no production change and does not require those decisions to be made now.

Any later production proposal needs a separately approved implementation issue. It must name changes
to `EFFECT_GATEWAY.md`, `KAPSEL_SERVICE.md`, application/configuration APIs and journal storage (or
explicitly no storage change), handle legacy single-operation behavior and frozen identities, bound
pending work and retry timing, and require independent authority/recovery review. Parallel execution
would require its own justification, not ride along with pending acceptance.

## Evidence and limits

The source revision above supplies the following direct checks:

- [Application isolation](../tests/application_contract.rs),
  `configured_reconciliation_neither_advances_nor_signs_another_operation`: explicit selection
  leaves another authorized or receiver-observed row unchanged, including retry after a transient
  GET.
- [Gateway lifecycle tests](../src/gateway/tests/lifecycle.rs): selected-operation execution and
  finalization, transient GET with unchanged journal data version and inert counter.
- [Snapshot tests](../src/gateway/tests/snapshot.rs): stale approval produces no apply or receipt,
  and replacement approval cannot change existing history.
- [Service runtime](../crates/kapseld/src/server/runtime.rs), `admit_submission`, and its
  [Linux tests](../crates/kapseld/src/server/linux_tests.rs): slot-first `BUSY` without another
  application call, grant matching, background ownership and concurrent read projection.
- [Application owner](../src/application/mod.rs) and [gateway owner](../src/gateway/mod.rs):
  configured identity visibility, disabled automatic server-response retries, exact reconciliation,
  fresh dispatch permission and observation-only recovery.

These checks have different evidence strength. Gateway test adapters count method calls, not HTTP
requests. Application tests use a mock HTTP service, not a Kubernetes control plane. Linux socket
tests require Linux. Existing legacy-grant isolation fixtures do not by themselves prove the full
two-snapshot workflow. The same-target and process-loss traces above compose existing contracts, not
a new end-to-end experiment. No live Kubernetes, throughput, fairness, distributed coordination or
power-loss result is claimed. Validation performed for this documentation change is recorded in the
owning review, separately from the source traces.
