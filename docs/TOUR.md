# One operation through Kapsel

Kapsel is built around an awkward gap: a system can know that it attempted an external effect
without knowing whether the receiver reached the intended state.

This tour follows one Kubernetes image change across that gap. The exact rules live in the
[effect-gateway contract](EFFECT_GATEWAY.md); this page explains why the pieces are arranged this
way.

## The request is intentionally boring

An automated workflow asks for one operation:

```text
kubernetes.set_deployment_image(
  namespace,
  deployment,
  container,
  immutable_image_digest
)
```

It also supplies a stable operation identity so a restart can find the same durable operation. It
cannot provide credentials, a kubeconfig, trust, a signing key, a manifest, a patch, a tag, a shell
command, or instructions about retry and recovery.

The operator supplies those powerful inputs separately:

```text
caller
  -> operation identity + exact bounded target

operator
  -> exact signed grant + trusted grant key
  -> Kubernetes credentials
  -> journal and receipt paths
  -> receipt signing key
```

The signed grant binds the operation identity, namespace, Deployment, container, and immutable image
digest. Kapsel checks it against application-configured trust before Kubernetes access. The request
cannot appoint its own authority.

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

## The important write happens before Kubernetes

Once Kapsel has safely identified the target, it commits `apply_started` to SQLite. That durable
record includes the Deployment UID, resource version, write strategy, and attempt marker.

Only after that commit may Kapsel send the conditional strategic merge patch.

```text
SQLite commit: apply_started
  -> conditional patch guarded by Deployment UID + resource version
```

The patch changes one named container image and writes the operation identity as a Deployment
annotation. The UID and resource-version preconditions make replacement or concurrent desired-state
changes fail closed instead of forcing the patch through.

This does not provide exactly-once mutation. It creates a trustworthy boundary: before
`apply_started`, no attempt was recorded; after it, Kapsel must assume the request may have crossed
the provider boundary.

## A lost response does not become a retry

Imagine Kubernetes applies the patch, but Kapsel dies before recording the response. On restart the
journal says `apply_started`. It does not say whether Kubernetes received, rejected, or applied the
request.

The tempting recovery strategy is to send the patch again. Kapsel deliberately refuses.

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

The useful promise is not universal truth. It is the strongest honest conclusion Kapsel can support
from the bounded observations it retained.

## Freeze the story before publishing it

After classification, Kapsel records the receiver facts and result. It then prepares the exact
signed receipt bytes and durably freezes their digest, path, signing-key identity, and write
strategy before publishing the file.

If the process dies during publication, restart installs or verifies those same bytes. Changed
process configuration cannot move the receipt or cause it to be re-signed.

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

The workflow receives two bounded things:

1. authority to request one exact operation without receiving Kubernetes credentials; and
2. a durable outcome vocabulary that preserves uncertainty instead of inventing certainty.

That lets downstream automation distinguish:

```text
receiver success
receiver failure under one exact classifier
unresolved receiver state
pre-attempt local rejection
operation or configuration error
```

Those distinctions survive process loss and remain inspectable later. They are narrow on purpose.

## Where to go next

- Run the mechanism with the [evaluation guide](EVALUATOR.md).
- Read the exact lifecycle and receipt rules in the [effect-gateway contract](EFFECT_GATEWAY.md).
- See the implementation boundaries in [Architecture](ARCHITECTURE.md).
- Review the exact CLI and MCP surfaces in [Evaluator commands](COMMANDS.md) and
  [MCP adapter](MCP.md).
- Check the complete current boundary in [Technical scope](SCOPE.md).
