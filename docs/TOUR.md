# One operation through Kapsel

Kapsel can record an attempt without knowing whether the receiver reached the intended state. This
tour follows one Kubernetes image change through authorization, execution, recovery, and receipt
inspection.

The [effect-gateway contract](EFFECT_GATEWAY.md) owns exact rules. This page explains the current
service path. The older v0.2.0 beta has different approval and receipt-storage behavior. See
[Technical scope](SCOPE.md#what-is-published) for release distinctions.

## Separate the request from authority

An automated workflow asks for one operation:

```text
kubernetes.set_deployment_image(
  namespace,
  deployment,
  container,
  immutable_image_digest
)
```

The direct CLI/MCP caller supplies these fields and a stable operation identity. The service caller
selects an operator-prepared action ID instead. Neither can supply credentials, a kubeconfig, trust,
a signing key, a manifest, a patch, a tag, a shell command, or retry and recovery instructions.

The operator supplies authority and private material separately:

```text
caller
  -> operation identity + exact bounded target

operator
  -> exact signed grant + trusted grant key
  -> Kubernetes credentials
  -> private journal and optional export destination
  -> receipt signing key
```

The signed grant binds operation identity, namespace, Deployment, container, and immutable image.
Kapsel checks the grant against configured trust before accessing Kubernetes. The request cannot
appoint its own authority.

The service requires snapshot grants. These also bind the Deployment UID and opaque resourceVersion
acquired by the operator. A changed version, including a status or annotation update, produces
`NOT_ATTEMPTED / STALE_APPROVAL` before a PATCH. Reapproval needs an operator decision and a new
action ID. It cannot replace authority on the existing action. Legacy CLI/MCP grants retain their
late-bound target meaning.

## First, make the intent durable

A new operation begins as `requested`. After the exact grant and request match, it becomes
`authorized`.

Kapsel can safely repeat the next step after a crash because it only reads the target Deployment. If
the Deployment or container is permanently missing or invalid, the operation becomes
`not_attempted`.

That distinction matters:

```text
not_attempted
  = Kapsel stopped before recording a mutation attempt
  != Kubernetes rollout failure
  != UNKNOWN receiver state
```

There is no effect receipt for `NOT_ATTEMPTED`, because there was no recorded provider attempt to
explain.

## Record the attempt before sending the patch

Once Kapsel has safely identified the target, it commits `apply_started` to SQLite. That durable
record includes the Deployment UID, resource version, write strategy, and attempt marker.

The adapter receives private permission to send the patch only after the fresh conditional commit is
confirmed successful. It can use that permission once. The adapter consumes it to send the
conditional strategic merge patch. Loading an attempted row cannot restore permission. The
application disables automatic PATCH retries.

```text
SQLite commit: apply_started
  -> conditional patch guarded by Deployment UID + resource version
```

The patch changes one named container image and writes the operation identity as a Deployment
annotation. UID and resource-version preconditions reject updates to a replaced or concurrently
changed target. They do not prevent mutating admission from causing effects before Kubernetes
returns a conflict.

This is not exactly-once mutation. Before `apply_started`, no attempt was recorded. After it, Kapsel
must assume the request may have reached Kubernetes.

## A lost response does not become a retry

Imagine Kubernetes applies the patch, but Kapsel dies before recording the response. On restart the
journal says `apply_started`. It does not say whether Kubernetes received, rejected, or applied the
request.

Kapsel does not send the patch again. The same stored state could also mean it died before sending
anything. In that case, an authorized action can remain unsent. This is the cost of preventing a
second mutation opportunity after an uncertain attempt.

Recovery loads the stored target identity and observes the Deployment. It issues no blind second
patch. When the original response is missing, Kapsel can associate an observed generation with the
request only when the Deployment UID, operation annotation, and requested image all match.

This is the heart of the design:

> Durable state before the effect; observation, not mutation, after ambiguity.

## Classification starts with identity

Kapsel does not classify a rollout from a convenient condition alone. It first checks that the
observation belongs to the attempted operation:

- the Deployment UID still matches the target;
- the operation annotation matches the operation identity;
- the observed image matches the requested immutable digest;
- the requested generation is known;
- the current generation equals that requested generation; and
- the observed generation has reached it.

Only then can the rollout facts support a terminal receiver result.

| Result      | Bounded conclusion                                                                                                                                                        |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SUCCEEDED` | The requested generation is observed with the requested image, desired replicas are updated and available, none are unavailable, and Kubernetes reports `Available=True`. |
| `FAILED`    | The requested generation is observed with the requested image and Kubernetes reports `Progressing=False` with reason `ProgressDeadlineExceeded`.                          |
| `UNKNOWN`   | The identity, generation, or rollout facts establish neither defined result within bounded reconciliation.                                                                |

A successful HTTP response to the patch is not `SUCCEEDED`. `ReplicaFailure=True` by itself is not
`FAILED`. A timeout is `UNKNOWN`, not failure. `UNKNOWN` also does not mean the effect did not
happen or that retrying is safe.

These results describe retained, bounded observations. They do not establish universal receiver
truth.

## Freeze the evidence before exporting it

The `receiver_observed` state freezes receiver facts and the classified result. Kapsel signs those
facts. SQLite then commits the exact bytes, digest, signing-key identity, and `finalized` state
together. A signing failure cannot trigger new observations to improve the result.

Retrieval returns the committed bytes without re-signing. Filesystem export is optional and separate
from completion. A failed export cannot reopen the action, and the service can retrieve the original
receipt without an output directory. The database must remain available for retrieval. An exported
copy may survive its loss, but execution does not guarantee creating that copy.

The receipt contains enough classifier input for offline inspection to recompute the result. The
inspector receives trust, evaluation time, and resource limits explicitly and performs no Kubernetes
or network lookup.

An `INSPECTED` receipt establishes that:

- the receipt structure parsed within its bounds;
- its signature authenticated;
- the separately supplied trust accepted the key, purpose, and evaluation time; and
- the signed classifier inputs reproduce the signed result.

It does not establish that Kubernetes told the truth, that Kapsel caused the observed state, that no
other actor changed the Deployment, or that every relevant event was captured. The report says
`INSPECTED`, never `VERIFIED`.

## What an automated workflow gains

The workflow can request one approved operation without receiving Kubernetes credentials. It can
also retrieve durable evidence that distinguishes:

```text
receiver success
receiver failure under one exact classifier
unresolved receiver state
pre-attempt local rejection
operation or configuration error
```

These distinctions survive process loss and remain inspectable later.

### When the result is unknown

Suppose an agent requests the approved image change and loses its connection. That disconnect is not
a rollout result. Recovery belongs to Kapsel under operator control, using the same durable
operation, not to an agent guessing whether it should send another mutation.

If bounded reconciliation finishes as `UNKNOWN`, the surrounding workflow should stop dependent
mutations and present the operation identity and available receipt for operator inspection. Creating
a fresh operation identity or automatically rolling back is not a way to resolve the uncertainty.
Any corrective action needs its own authorization and reasoning about current state.

The surrounding workflow owns this handoff. A signed receipt preserves evidence; it does not replace
operational judgment or prove application health.

A rollout may become available after the original `UNKNOWN`. Ordinary status and receipt reads still
return historical evidence without contacting Kubernetes. An operator's later observation does not
rewrite that receipt or establish that the original action caused the later state.

## Where to go next

- Run the mechanism with the
  [service example](KAPSEL_SERVICE_OPERATOR.md#one-command-disposable-example).
- Read the exact lifecycle and receipt rules in the [effect-gateway contract](EFFECT_GATEWAY.md).
- See the implementation boundaries in [Architecture](ARCHITECTURE.md).
- Review the exact CLI and MCP surfaces in [Evaluator commands](COMMANDS.md) and
  [MCP adapter](MCP.md).
- Check the complete current boundary in [Technical scope](SCOPE.md).
