# Effect-gateway contract

The gateway authorizes approved operations, records attempts before external mutation, and retains
original signed evidence. This contract defines the shared admission, dispatch, recovery, and
completion rules. The [Kubernetes](kubernetes_effect.md) and [Git](git_effect.md) contracts define
effect-specific inputs, states, and results.

For an explanation, read [How Kapsel works](../tour.md). For execution commands, use the
[caller](../guides/caller.md) or [operator](../guides/operator.md) guide.

## Authority and identity

Both effects execute through the resident service. The caller selects an operator-approved ID.
Caller input cannot supply credentials, grants, trust, signing material, private paths, or lifecycle
controls. Each application-configured grant trust appointment contains one exact signing-key
identity and Ed25519 verifying key. The service accepts at most 128 appointments with unique key
IDs. An empty set permits opening safe storage but cannot authenticate retained actions.

Permission to act, evidence of execution, and decision quality are separate. A signature
authenticates bytes under separately appointed trust. It does not prove receiver truth, causation,
complete capture, or compliance. The [threat model](threat_model.md) states security assumptions and
limits.

## Service admission and historical authority

### Resolve the original operation first

Suppose an operation stops halfway through execution and the operator replaces the catalog before it
resumes. The caller still selects the same ID. That selection must continue the original operation,
not pick up a new approval from the replacement catalog.

The service application therefore looks for retained history first. It consults the operator catalog
only if no record exists. A changed catalog cannot refresh an existing operation's authority.

The gateway authenticates retained bytes under externally appointed keys. Within one SQLite read
snapshot, it compares authorization provenance and lifecycle facts. The retained bytes cannot
appoint their own key. Resumption keeps the original authorization binding through every reload.
After receiver I/O, the gateway rechecks custody before recording returned facts. Holding the worker
lease does not authorize direct SQLite edits.

If required trust is missing, access fails for that ID without returning its tuple or receipt. Other
history remains accessible under its own original trust.

### Commit responsibility before acknowledging it

Admission records responsibility for an operation. It does not establish that the receiver did
anything. For a new identity, the gateway acquires a nonwaiting journal worker lease, checks the
identity again, and commits the original grant after checking capacity.

The acknowledgement callback runs only after a confirmed commit or definite busy/capacity refusal.
It reports the durable phase, not worker liveness or receiver result. A storage error before that
callback leaves admission unconfirmed. The gateway holds the lease through acknowledgement and the
bounded advancement pass. The same journal handle cannot reacquire it while it remains outstanding.

Identical existing identities resolve before slot/capacity refusal. Terminal selection is read-only.
An unfinished identical selection with a busy worker acknowledges its existing responsibility and
starts no new work. Missing execution material leaves admitted work unfinished. Receipt completion
needs signing material, but stored reads and original receipt retrieval do not. Requested-phase
authorization still uses original retained grant bytes, not refreshed catalog authority.

### Keep ownership after the caller stops waiting

A commit may still finish after a response deadline or caller disconnect. The socket runtime must
retain the task and its resources until blocking storage actually stops. Otherwise it could free the
worker or report refusal while the original admission was still committing. The application callback
alone does not establish this runtime guarantee.

[Runtime ownership](../contributing/service_runtime.md) explains the competing-submission race.
These rules introduce no queue, startup selection, or new observation policy.

## Operation lifecycle

Kubernetes first records `requested`. Git first records `authorized`. Both retain original authority
before receiver mutation and keep attempt, observation, and receipt completion distinct. Their exact
transitions are defined by the [Kubernetes lifecycle](kubernetes_effect.md#operation-lifecycle) and
[Git dispatch/result rules](git_effect.md#preflight-and-dispatch).

Pre-attempt rejection is `NOT_ATTEMPTED`, not a receiver outcome, and has no effect receipt. After
an attempt marker, recovery never resends the mutation. Once receiver facts are frozen, completion
uses those facts only. Terminal retrieval neither observes nor re-signs.

### Durable facts and recovery

| Boundary                  | Safe continuation                                                                 |
| ------------------------- | --------------------------------------------------------------------------------- |
| Before attempt            | Reauthenticate original authority and repeat safe preflight reads when permitted. |
| Attempt recorded          | Observe only. Never reconstruct permission to send.                               |
| Receiver statement frozen | Sign and commit that statement without new observations.                          |
| Receipt finalized         | Read the original bytes. Export separately.                                       |

Execution and completion select only the configured operation identity, with no queue or fairness
guarantee. Journal format 6 requires schema validation of the inert `target_read_failures` column.
Execution neither increments nor uses it, including for retry timing. Existing values remain
untouched, with no migration or reinterpretation of persisted rows.

The implementation holds one crash-released exclusive worker lock around provider and receiver I/O
so two processes cannot advance the same journal concurrently. A contender performs no provider or
receiver call and changes no public fact. Internal lease or scheduling fields must not change result
meaning.

## Fresh dispatch permission

The attempt marker answers “might this operation have been sent?” Recovery must treat the answer as
yes. It cannot read the marker as permission to send.

Permission comes from a different event: confirmation that this execution just committed a fresh
attempt. The journal returns a private, one-use value that the adapter consumes. The transaction
checks the complete authorized snapshot against its durable row, including request, approval, and
authorization provenance. A snapshot from another journal cannot substitute different facts under
the same operation identity.

The permission binds the frozen request and attempted target. It is neither `Clone` nor `Copy`, and
the Kubernetes adapter consumes it instead of accepting separately supplied request and target
arguments. Loading attempted history, losing the conditional transition, or an ambiguous commit
acknowledgement cannot produce permission. Cancellation or loss after commitment may discard an
unsent permission. The action remains attempted, and recovery observes without resending or
inventing `NOT_ATTEMPTED`, success, or failure.

The gateway still holds the crash-released worker lock through provider and receiver I/O. Permission
is not lifetime-bound to that lock and does not replace process exclusion, conditional database
writes, or the driver's obligation to keep the lock. This is an internal sequential boundary, not a
public API or a shared approval/recovery kernel. The
[design decision](../decisions/0011-retain-observation-only-recovery.md#fresh-dispatch-permission)
records its adoption and finite evidence.

One consumed permission must not become multiple mutation requests through client retries. The
shared application client disables kube-client's automatic server-response retries, including PATCH
retries on 429, 503, and 504. Explicit target-read retries and bounded receiver observation remain.
Operator-supplied custom clients must uphold the same no-mutation-retry obligation. A local HTTP
fixture verifies request counts across response loss, cancellation, and restart. It does not prove
arbitrary proxy or HTTP/2 behaviour, prevent admission reinvocation within one Kubernetes request,
or establish power-loss durability or exactly-once effects.

## Execution guidance, not historical evidence

An admitted action can be unfinished without a running worker. Service status therefore keeps
execution disposition separate from the existing receiver result and immutable target/receipt facts.
The application builds the typed status projection. The runtime supplies current-process physical
job ownership and bounded stop conditions. Protocol code only renders that projection.

A current physical job means `active`, including time blocked on storage. It does not promise
progress or receiver availability. Another locally owned job means `waiting_for_worker`. Without
current ownership or a surviving stop explanation, unfinished history means `resume_required` with
an unknown cause. Restart, cancellation and diagnostic eviction never invent a historical cause.
Terminal history takes precedence over process diagnostics. Stored status and process observations
are separate snapshots, so they cannot give one atomic view of all activity. The service reports
external worker contention only after a failed lock acquisition. Retained history alone cannot tell
it whether an external worker is alive.

Safe preflight read failure supports explicit same-ID selection. Missing receiver material, missing
signing material and failed receipt completion require operator remediation before selection.
Receiver errors do not hide authenticated history or force a terminal disposition. Receipt
completion failure preserves frozen facts. The application classifies typed failures without
retaining raw errors. The [service contract](service.md#actionable-execution-status) defines wire
tokens, process-local retention and operator diagnostics.

Any authenticated service caller may explicitly select a retained v2 Kubernetes identity through the
existing ID-only submit command, even after catalog removal, provided original external authority
remains available. This grants no new lifecycle authority: the gateway alone decides the safe
continuation. Before attempt, resumption repeats safe reads before a fresh conditional attempt.
After attempt it only observes, or completes frozen facts. Reads never resume, reset an observation
budget or change receipt bytes. No automatic retry or reapproval is introduced. Git uses its
separate v1 grant and the same retained-ID admission interface.

## SQLite-owned receipt completion

`receiver_observed` durably freezes the historical receiver statement before signing. One
conditional SQLite transaction commits the exact signed receipt bytes, their SHA-256 digest, signer
identity, and terminal `finalized` state together. Under that write transaction, the journal binds
completion to the current frozen facts and rejects a same-ID receipt with a different statement. A
stale or foreign snapshot cannot substitute those facts. `finalized` means durable terminal
evidence, not an installed filesystem copy. Recovery before that commit signs only frozen facts. A
signing failure leaves the observation unchanged, and commit acknowledgement loss is resolved by
reading durable state rather than dispatching or observing again.

Filesystem export is separate from execution. The fixed service client exports original bytes to a
caller-selected new file. Export failure cannot reopen the finalized action or prevent later service
retrieval. The service does not require an installed receipt copy. Supplementary observations, if
separately implemented, must bind the operation identity and original receipt SHA-256 without
modifying the original receipt or result.

Receipt retrieval depends on database availability. Consistent operator-owned backups must preserve
receipt bytes and action history together. Exported copies may survive database loss, but execution
does not guarantee creating them. No automatic backup or replication protocol is provided.
Process-exit tests do not prove power-loss behaviour or the filesystem and hardware assumptions of
[SQLite atomic commit](https://sqlite.org/atomiccommit.html).

## Storage and retained history

Journal format 6 retains original signed grants at first insertion and original receipts at
completion. Fresh and existing format-6 journals are accepted. Format 5 and older versions are
rejected unchanged before processing, without migration. Preserve refused journals, sidecars and
original access materials unchanged. A matching binary may be needed for inspection. This is not an
upgrade policy. A fresh journal is not continuity or permission to recreate old actions. Signed
formats retain their original meanings.

The logical ceiling is 10,000 distinct identities, but format-6 completion accounting limits
admission to **504 retained identities and 32 unfinished identities**, shared across both effects.
An identical existing ID remains readable and idempotent at either limit. Terminal work releases an
unfinished slot, never retained history. [Storage](storage.md) defines physical bounds, completion
accounting, and interrupted-commit alternatives. [Journal retention](../guides/journal_retention.md)
defines binary-replacement precautions.

## Related reference

- [Kubernetes](kubernetes_effect.md): snapshot authority and bounded rollout classification.
- [Git](git_effect.md): exact-lease dispatch, acknowledgement, and ref observations.
- [Evidence formats](evidence_formats.md): canonical bytes, trust, and inspection.
- [Service](service.md): protocol, custody, and physical process ownership.
- [Evidence map](../contributing/evidence.md): maintained boundary checks.
- [Release process](../contributing/release_process.md): required qualification before publication.

Implement another receiver's concrete authority, attempt, recovery, and evidence rules together.
Extract common machinery only where implementations enforce the same rule. This contract does not
define a provider framework or public Rust SDK.
