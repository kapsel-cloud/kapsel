# Retain observation-only recovery after an ambiguous patch

Status: accepted. Date: 2026-09-05.

This decision owns the choice between observing an attempted operation, replaying its frozen patch,
and delegating retry scheduling to a workflow runtime. The
[effect-gateway contract](../reference/effect_gateway.md) owns lifecycle, classification, and
receipt bytes.

## Context

A process can die after committing `apply_started` but before sending anything. Observation-only
recovery can abandon that authorized action. Replaying the original patch could complete it while
the Deployment UID and resourceVersion remain current.

The same journal state also covers a request accepted by Kubernetes whose response was lost.
Recovery cannot distinguish these windows. UID and resource-version preconditions constrain
persistence, but not all earlier request processing.

## Decision

Retain observation-only recovery after `apply_started`. A reconnecting caller resumes the same ID;
it cannot refresh authority or preconditions, resend the mutation, or invent another operation ID to
resolve ambiguity. `UNKNOWN` stops dependent automation and hands the frozen evidence to an
operator.

Do not adopt Temporal for this operation. Durable workflow history and retry scheduling do not make
an external Kubernetes effect atomic with activity completion. The integration would still need
Kapsel's exact authority, receiver-aware recovery, classification, and receipt semantics.

## Why a frozen replay is insufficient

A comparison at revision `93552ccf220d605c02671f0e66259191d730efec` used the same operation ID,
Deployment UID, opaque resourceVersion, immutable image, and strategic merge patch on every replay.
The independent receiver model compared observation-only recovery, one frozen replay, and a Temporal
Activity projection with `MaximumAttempts: 2`. It did not execute Temporal.

The key tradeoffs were:

| Scenario                              | Observation only                             | One frozen replay or Activity retry                          |
| ------------------------------------- | -------------------------------------------- | ------------------------------------------------------------ |
| Death before send                     | Can leave an authorized action unsent        | Can complete the unsent action                               |
| Accepted mutation, response lost      | Adds no mutation request                     | Adds a request even when only one Deployment update persists |
| Admission has an out-of-band effect   | Does not repeat that effect through recovery | Can invoke admission and its effect again                    |
| Later writer retains image and marker | Classification may describe later state      | Replay does not establish original causation either          |

The maintained live gate supplies a concrete counterexample on Kubernetes v1.33.12. The first
strategic patch persists and creates one ReplicaSet. An identical stale replay invokes an
instrumented mutating webhook again, then returns `409 Conflict`. Deployment spec, annotation,
images, generation, resourceVersion, and ReplicaSet count remain equal to their post-first-patch
values. No second persisted update does not mean no second admission effect.

This ordering follows the pinned Kubernetes sources:

- [PATCH handler admission and update](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/patch.go#L628-L704)
- [Registry storage version checks](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go#L649-L733)

Kubernetes'
[webhook good practices](https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/)
recommend idempotence and avoiding out-of-band side effects, but permit real-request effects with
`sideEffects: NoneOnDryRun`. Kapsel's operation annotation is not a receiver-enforced idempotency
key.

### JSON Patch does not remove the ambiguity

The comparison at `430e7f20aed71ef8daec81b681625a641d98ee18` tested original UID, resourceVersion,
and container name before changing the image. It did not adopt JSON Patch.

Stale JSON tests can fail before mutating admission. However, two overlapping requests can both
reach admission before either persists. An admitted candidate can also fail validation without
persisting; replay then causes another admission effect. Earlier rejection reduces exposure in some
races but does not make recovery replay safe.

[RFC 6902](https://www.rfc-editor.org/rfc/rfc6902#section-4.6) defines ordered tests. The pinned
[PATCH transformer](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/patch.go#L388-L425)
and
[GuaranteedUpdate](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/storage/etcd3/store.go#L436-L520)
explain early rejection, cached-object evaluation, and transformer retries. These observations are
bounded to the experiment's receiver, not universal admission cardinalities.

### Workflow retries have the same receiver boundary

Temporal [Activity execution](https://docs.temporal.io/activity-execution) is at least once.
Explicitly bounded [retry policies](https://docs.temporal.io/encyclopedia/retry-policies) can limit
attempts, but the second execution still faces the same receiver ambiguity. A workflow runtime also
adds service, persistence, worker, upgrade, and backup operations without removing the
capability-specific logic.

## Fresh dispatch permission

The implementation keeps commitment, dispatch, observation, and receipt completion distinct:

- The attempt transaction checks the complete authorized snapshot against the durable row.
- Only a confirmed fresh commit issues a private, one-use `DispatchPermission`.
- The adapter consumes that permission into the bound request and target.
- Loading attempted history never reconstructs permission.
- Receipt completion preserves original signed bytes independently of export.

This prevents ordinary callers from repeating an apply or substituting a snapshot from another
journal under the same ID. No transaction spans network I/O or an await. The type does not replace
worker exclusion or the client's obligation to disable hidden mutation retries.

[Fresh dispatch](../reference/effect_gateway.md#fresh-dispatch-permission) defines the exact
contract. [Receiver-recovery evidence](../contributing/evidence.md#receiver-recovery-evidence) and
the [focused gates](../contributing/build.md#focused-gates) identify maintained checks. Permission
tests establish commitment and payload binding; real HTTP counts separately establish client
behavior across response loss, cancellation, restart, and repeated selection.

## Consequences and limits

- Death before send can leave an authorized operation unsent. `UNKNOWN` is the honest outcome when
  observation cannot establish a result.
- Dispatch permission is not lifetime-bound to the worker lease. The driver must retain exclusion
  through I/O. Hostile code already holding raw credentials can bypass that discipline.
- Custom clients, proxies, HTTP/2 behavior, and admission reinvocation remain separate obligations.
  One permitted request can have multiple internal admission invocations.
- Later observations can describe another writer's state. Neither signatures nor replay establish
  causation.
- Commit-acknowledgement fault injection, dropped futures, process kills, and live receiver checks
  establish different finite facts. None certifies power-loss durability or arbitrary schedules.
- Reconsider replay only with receiver-enforced idempotence covering the whole admission and
  persistence pipeline, or an enforced admission profile that excludes side effects.
