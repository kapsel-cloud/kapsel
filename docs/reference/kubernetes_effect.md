# Kubernetes image-change contract

This reference defines `kubernetes.set_deployment_image`: its input grammar, snapshot approval,
mutation, recovery, and rollout result. The [effect gateway](effect_gateway.md) defines shared
admission, dispatch permission, and receipt completion. Use the
[operator guide](../guides/operator.md#provision-authority-and-an-exact-approval) for preparation.

## Authorized input

The Kubernetes approval authorizes only `kubernetes.set_deployment_image` with:

- Kubernetes namespace;
- deployment name;
- container name; and
- immutable OCI image digest.

Authorization binds all four values and one stable local operation identity. The current
implementation uses this deliberately narrow input grammar:

- operation and authorization identities are 1–128 ASCII bytes containing only letters, digits, `.`,
  `_`, `:`, or `-`;
- namespaces are 1–63 byte lowercase Kubernetes DNS labels;
- deployments are 1–253 byte lowercase Kubernetes DNS subdomains whose labels are each at most 63
  bytes;
- containers are 1–63 byte lowercase Kubernetes DNS labels; and
- the image is at most 512 ASCII bytes and has the exact form
  `<named-image>@sha256:<64-lowercase-hex>`. The named image is slash-separated lowercase components
  that begin and end with an ASCII letter or digit and contain only letters, digits, `.`, `_`, or
  `-`. This bounded grammar excludes tags, registry ports, tag-plus-digest forms, digest-only
  values, empty components, and uppercase spelling even where a wider ecosystem grammar may allow
  them.

No wildcard namespace, deployment, container, tag, shell command, manifest, arbitrary patch, or
second Kubernetes operation is in scope. The owner-signed grant carries one bounded authorization
identity and an exact copy of the operation identity, namespace, deployment, container, and image.
It has no wildcards, policy rules, ambient lookup, or expiry semantics. The gateway accepts only the
fixed effect-gateway grant purpose, persists the signer identity and SHA-256 digest of the exact
signed grant bytes, and does not accept trust from the request or grant.

## Exact-snapshot approval

An operator approves a change to a particular Deployment snapshot. If the Deployment is deleted and
recreated under the same name, that approval must not follow the name to the new object. If another
writer changes the existing object, Kapsel must not quietly refresh the approval either.

Grant v2 therefore binds `approved_target`: the independently acquired Deployment UID and opaque
resourceVersion, alongside the exact operation tuple. Kubernetes assigns
[UIDs](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids) to distinguish
recreated objects. Its
[conditional updates](https://v1-33.docs.kubernetes.io/docs/reference/using-api/api-concepts/#patch-and-apply)
use resourceVersion to reject intervening writes. Both approved values are 1–128 ASCII bytes.
Equality is byte-for-byte, with no numeric interpretation, normalization, or refresh.

### Acquire approval from the receiver

`kapsel provision-snapshot-grant` takes operator authorization JSON, a signing seed, key ID, output
arguments, and an explicit private `--kubeconfig`. The JSON contains the intent, not UID or version
fields. The command validates the tuple, reads the named Deployment through the bounded production
adapter, validates the named container, and signs the UID/version it read. It accepts no
caller-supplied snapshot bytes. The operator controls the proposal file, credentials, invocation,
and output. Acquisition has a ten-second deadline and 2 MiB response cap. There is no separate
snapshot document or second authority store.

### Compare before attempting

Before `apply_started`, a successful target read supplies `observed_target`. Kapsel compares that
read with the signed approval rather than treating it as replacement authority.

A mismatch durably freezes `NOT_ATTEMPTED / STALE_APPROVAL`, including the observed target. There is
no attempt, receiver result, effect receipt, or signed denial artifact. Other permanent read
rejections retain their meanings and have no observed target.

A matching read freezes `attempt_target` using the approved values. The strategic merge PATCH
includes both approved UID and resourceVersion. A writer can still intervene between this read and
the PATCH. A conflict after the attempt marker remains an attempted path, never `NOT_ATTEMPTED`. The
marker does not establish network transmission. Recovery after it only observes and never resends.

### Read the three target fields

Status is read-only and reports these distinct facts alongside the disposition:

| Field             | Meaning                                                                                                                                                   |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `approved_target` | The signed UID/version approval, or null for legacy authority.                                                                                            |
| `attempt_target`  | The frozen PATCH precondition pair, or null before the marker.                                                                                            |
| `observed_target` | The successful preflight read before the marker, then the frozen receiver UID/version once observation is complete. Either observed member may be absent. |

The fields disclose bounded public identity/version facts, not grant bytes, trust, credentials, or
paths. A rejection without a successful read has no invented observation.

### Preserve original authority

Resident service execution requires v2. Read-first startup may authenticate retained v1 history, but
cannot select or advance it. Legacy history keeps its original late-bound meaning for inspection,
not fresh execution permission. Every v2 execution enforces the snapshot. Neither existing grant
bytes nor existing operation handles can acquire snapshot authority. Reapproval needs an
operator-created grant and a new handle. It is not an automatic retry after `UNKNOWN`.

Journal format 6 retains nullable approved UID/version and preflight observed UID/version columns.
Legacy-grant actions have null approval and retain their original meaning. Older journal versions
are rejected without migration before processing. New requests atomically retain the exact signed
grant bytes with original grant identity, signer, digest and snapshot at their first durable
insertion, including the requested window. Stored bytes never appoint trust. Authorized reads and
identical submission compare original bytes and provenance in the same SQLite snapshot. Snapshot
authority never replaces authority on an existing row.

### Snapshot grant and receipt encoding

Grant v2 uses `KAPSEL-KAP0038-K8S-GRANT-STATEMENT-V2\0` and `KAPSEL-KAP0038-K8S-GRANT-V2\0`, with
purpose `kapsel.kap0038.kubernetes-set-deployment-image-grant.v2`. Statement fields 1–6 retain their
v1 order. Fields 7 and 8 are approved UID and resourceVersion. Envelope order and signature
construction are unchanged. The 2 KiB statement, 4 KiB grant, 512-byte individual text, strict
record ordering, and existing identity/trust bounds remain. Mixed envelope/statement versions fail
closed.

Snapshot attempts emit receipt/statement v3 with magic prefixes ending `RECEIPT-V3\0` and
`STATEMENT-V3\0`, and purpose `kapsel.kap0038.kubernetes-effect-receipt.v3`. Fields 1–27 retain
their v2 meaning. Fields 28–29 contain approved UID/version. Fields 10–11 are `attempt_target`,
which must exactly equal approval. Fields 12 and 18 are `observed_target`, not approval. Receipt and
statement bounds do not change. Trust v2 remains the trust encoding but must explicitly appoint the
v3 purpose for snapshot receipts. Old receipt v2 remains inspectable under its original purpose,
with null approval, never invented snapshot evidence. Frozen bytes are never re-signed or upgraded.
[Evidence formats](evidence_formats.md) describes the legacy v1 grant/v2 receipt wire extended here.

## Operation lifecycle

The journal has explicit local states:

```text
requested
  -> authorized
       -> not_attempted
       -> apply_started
            -> receiver_observed
            -> finalized
```

- `requested` records the bounded input and stable operation identity.
- `authorized` records that the exact request matched an authentic fixed-purpose grant under the
  application-configured owner trust. The signer identity and digest of the exact signed grant bytes
  are frozen.
- From `authorized`, the adapter safely reads and validates the target Deployment and named
  container. A transient API error leaves the selected operation `authorized` without a journal
  update or PATCH. A retry or crash before the next transition repeats only this safe GET before a
  fresh attempt.
- `not_attempted` is terminal and records exactly one bounded pre-attempt rejection:
  `deployment_not_found`, `container_not_found`, `invalid_target`, or `stale_approval`. No mutation
  marker, provider write, receiver observation, receiver result, or effect receipt exists for this
  disposition. It is never reported as receiver `FAILED` or `UNKNOWN`.
- `apply_started` atomically records the target Deployment UID, target resource version,
  write-strategy identity, and attempt marker before Kubernetes mutation. The strategic merge patch
  carries both target preconditions, changes the exact name-keyed container image, and writes the
  operation identity in the `kapsel.dev/kap0038-operation-id` Deployment annotation. Target
  precondition conflicts fail before mutating a different target. A successful patch response must
  return the same Deployment UID and a resource version; missing or replacement identity facts fail
  closed. Recovery from `apply_started` never issues a blind second patch.
- `receiver_observed` records every bounded classifier input and the resulting classification,
  including target and receiver identity, observed image and operation marker, current, requested,
  and observed generations, replica counts, and rollout condition, or explicit missing facts.
- `finalized` atomically commits the exact signed receipt bytes, SHA-256 digest, signing key
  identity, and terminal state in SQLite. It is terminal and read-only. Filesystem export happens
  separately from this transition.

Observation-only recovery determines what can be concluded without sending the mutation again. After
`apply_started`, it uses the stored Deployment UID, operation annotation, and requested image digest
to observe and classify the operation. It does not replay even the frozen conditional patch:
Kubernetes UID and resource-version preconditions bound persisted updates, but do not prevent a
stale replay from invoking mutating admission and its allowed out-of-band effects again. Decision
[0011](../decisions/0011-retain-observation-only-recovery.md) records the comparison and evidence.

When the patch response was lost, an exact matching UID, operation annotation, and image binds the
observed current generation to the request; without all three facts the requested generation remains
unknown. If a later template writer retains those three facts, that generation may satisfy the
classifier, but the result does not attribute that later rollout to the original patch. If the
available receiver facts cannot establish the result, the result is `UNKNOWN`; it is never guessed
from request success or a timeout.

## Result meaning

For operations that reached `apply_started`, classification first requires all of these facts:

- The receiver UID equals the stored nonmissing target UID.
- The operation marker and image match the request.
- The requested generation is known and equals the current generation.
- The observed generation is at least the requested generation.

Success also requires a known desired replica count, updated and available counts equal to it, zero
unavailable replicas, and `Available=True`. Failure requires `Progressing=False` with reason
`ProgressDeadlineExceeded`; that failure takes precedence over availability. Missing facts yield
`UNKNOWN`.

The receiver result is exactly one of:

| Result      | Establishes                                                                                                                                                              | Does not establish                                                              |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `SUCCEEDED` | The observed deployment reached the requested generation and reports an available rollout for the requested image digest.                                                | Causation, workload correctness, complete cluster health, or universal capture. |
| `FAILED`    | The same deployment UID and requested image are observed at the requested generation, and Kubernetes reports `Progressing=False` with reason `ProgressDeadlineExceeded`. | Permanence, why Kubernetes failed, or whether another actor later changed it.   |
| `UNKNOWN`   | Kapsel could not establish either defined observed outcome within its bounded reconciliation procedure.                                                                  | That the request failed, was not received, or was later harmless.               |

`not_attempted` is a local pre-attempt disposition, not a receiver result. An accepted Kubernetes
request is not a rollout result. A fresh lookup by Deployment name or revision number is not an
original-action handle: it can describe a replacement UID or an intervening writer's rollout.
Original UID, image, operation marker and generation checks remain necessary, and they do not prove
causation. A healthy rollout does not prove that no other change occurred. A conditional patch
conflict is never forced or blindly retried and does not by itself establish a failed rollout.
`ReplicaFailure=True` may be retained as an observed condition but does not by itself classify
`FAILED`. A local observation timeout always classifies `UNKNOWN`. Deployment UIDs, resource
versions, operation markers, and condition reasons retained from Kubernetes are ASCII and at most
128 bytes each. Generations and replica counts must be nonnegative. The requested and observed image
remains subject to the 512-byte immutable-image grammar above. Target observation and the
conditional strategic merge patch each have a ten-second request deadline. The shared explicit
operator Kubernetes client rejects any HTTP response body above 2 MiB while it is streamed, before
kube-client can collect or deserialize it; this applies with content-length, chunked, or
close-delimited framing. An oversized target read is transient and cannot create a mutation marker.
An oversized patch response may leave the already marked provider attempt ambiguous, so restart
observes without another patch. An oversized receiver response contributes no facts and therefore
cannot strengthen `UNKNOWN` into another result.

Receiver observation uses a fixed **per-pass** policy: a 180-second monotonic deadline, at most 180
Deployment reads, and a ten-second deadline for each read within the remaining pass time. The first
read starts immediately; subsequent reads wait one second after the preceding read completes or
times out. Reads and sleeps consume the same pass budget. No new read starts at or after the pass
deadline, and a response completing at or after it contributes no facts. This is an observation
bound, not a total execution or storage-latency guarantee.

Observation stops early only when the unchanged receiver classifier can establish `SUCCEEDED` or
`FAILED`, including target UID, requested image, operation marker, generation and rollout facts. An
available condition alone, incomplete replica counts or a terminal signal from another generation is
provisional, not sufficient evidence. Exhausting the read budget returns the last observation;
exhausting elapsed time returns no receiver facts. Neither can strengthen incomplete evidence beyond
`UNKNOWN`. Read failure, deletion, identity mismatch and oversized responses never establish
failure.

A pass starts when initial observation or explicit observation-only recovery starts. Startup remains
read-first. Explicit resumption after an interrupted, unfinished pass starts a fresh budget;
repeated interruptions therefore have no cumulative operation-wide time or read bound. Reconnect,
status, receipt retrieval and selection while the worker is busy do not reset a surviving pass.
Frozen results and receipts never reopen. Wall-clock corrections do not change a pass's monotonic
budget. Suspend accounting follows the host monotonic clock, not a durable wall-clock deadline.
Timer expiry requires runtime scheduling and is not a hard real-time guarantee.

The [live observation-policy tests](../contributing/qualification.md#initial-observation-policy)
exercise 60- and 210-second readiness periods. The fixed policy accommodates bounded waiting without
promising all rollouts complete within it. A durable operation-wide deadline would instead need
persisted timing facts and a clock-discontinuity and compatibility policy. The per-pass choice adds
no timing columns, journal version, migration, caller configuration or later-observation path.
Format 6 and all finalized history remain unchanged.

Kubernetes credentials and signing seeds are operator-controlled private inputs; they never enter
caller requests, SQLite, receipts, reports, or errors. The grant does not itself grant Kubernetes
authority, prove a human made a decision, or replace Kubernetes RBAC. Operator paths must be safe,
and diagnostics must not print secrets or unbounded provider response bodies.
