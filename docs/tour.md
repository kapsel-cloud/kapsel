# How Kapsel works

Consider an automated workflow changing the `api` container in `demo/agent-api` to a reviewed image.
It sounds like a small job: approve it, send a patch, wait for the rollout. The awkward part arrives
when Kubernetes accepts the patch and Kapsel dies before recording the response.

On restart, should Kapsel try again? Say it failed? Check whether the Deployment looks healthy? Each
answer can be wrong for a different reason. Follow this operation through approval, dispatch,
recovery, and receipt creation to see how Kapsel keeps those questions separate.

## Approve the change, then select its ID

The operator approves the `api` container's exact immutable image, not “deploy whatever the caller
asks for.” The provisioning command reads the Deployment and includes its UID and resourceVersion in
the signed approval. The UID distinguishes this Deployment from a later object with the same name.
The resourceVersion binds the approval to this snapshot.

The caller selects only the approved ID. Credentials, grants, trust, signing keys, and private
storage come from the operator, not caller input.

```text
operator: exact signed approval + external trust + credentials
                              |
caller: approved ID ----------+----> Kapsel ----> receiver
                                      |
                                      +----> retained history and receipt
```

Suppose someone updates the Deployment before the caller selects the ID. Kapsel's preflight read now
finds a different resourceVersion. It records `NOT_ATTEMPTED / STALE_APPROVAL` without a PATCH. Even
an annotation or status update can cause this refusal. That is deliberately conservative: approval
for the earlier snapshot is not approval for the new one. The operator decides whether to approve
another operation.

## Record the attempt before sending

With a matching snapshot, Kapsel can proceed. It commits `apply_started` to SQLite before sending
the conditional patch. This marker records the operation and target identity while Kapsel still
knows that no mutation has been sent.

Only a freshly confirmed attempt commit gives the adapter permission to send. It can consume that
permission once. Loading the stored attempt cannot recreate it, and the HTTP client disables
automatic mutation retries.

```text
validate approval -> read target -> commit attempt -> send conditional patch
```

The patch changes the named container's image and writes an operation annotation. Its UID and
resourceVersion preconditions guard against changing a replaced or concurrently updated target. They
do not make replay harmless: mutating admission can cause effects before a conflict is returned.

## After ambiguity, observe instead of resending

Return to the crash. The journal contains `apply_started`, but no response. Two histories now look
identical to Kapsel:

- It recorded the attempt, then died before sending.
- It recorded the attempt, Kubernetes accepted the patch, then it died before recording the
  response.

A second send helps the first history and risks another effect in the second. No amount of rereading
the marker tells Kapsel which happened. It therefore observes the stored target rather than sending
again. An approved change can remain unsent. This is the tradeoff, not a window a retry loop can
close.

This is not exactly-once execution. The
[recovery contract](reference/effect_gateway.md#fresh-dispatch-permission) defines the exact
boundary.

## Results describe bounded evidence

For Kubernetes, Kapsel checks target identity, image, operation marker, generation, and rollout
facts before classifying a result.

| Result      | Interpretation                                                              |
| ----------- | --------------------------------------------------------------------------- |
| `SUCCEEDED` | The matching generation satisfies the defined available-rollout conditions. |
| `FAILED`    | The matching generation reports the defined progress-deadline failure.      |
| `UNKNOWN`   | Bounded observations establish neither result.                              |

An accepted PATCH is not rollout success. A timeout is not rollout failure. `NOT_ATTEMPTED` is
separate: execution stopped before recording a mutation attempt, so there is no effect receipt. The
[Kubernetes reference](reference/kubernetes_effect.md#result-meaning) contains the exact predicates
and observation limits.

Git makes the distinction especially visible. Suppose Kapsel is approved to move a branch from
commit A to B. A fresh per-ref acknowledgement establishes ref acceptance. If that acknowledgement
is lost, finding B later is not a substitute: another sender could have put it there, even if Kapsel
never sent its own update. Recovery keeps `UNKNOWN`. Git success says nothing about hook, CI, or
deployment completion. The [Git reference](reference/git_effect.md) defines those rules.

## Freeze the statement, then sign it

Suppose the observation pass ends without enough facts to classify the rollout. Kapsel freezes
`UNKNOWN` and its receiver facts before signing. If the signing key is unavailable and the rollout
becomes healthy while the operator restores it, completion still signs the frozen statement. Key
repair is not another chance to observe.

SQLite commits the original signed receipt bytes, digest, signer identity, and terminal state
together. The statement cannot improve during signing, and the committed receipt cannot be replaced
afterward.

Retrieval returns those original bytes without contacting the receiver or signing again. Export to a
caller-owned file is separate from completion. Database availability is still required for service
retrieval, and no automatic backup is provided.

Offline inspection checks the signature against separately supplied trust and evaluation time, then
recomputes the classifier result. `INSPECTED` means those checks passed. It does not establish that
the receiver told the truth or that Kapsel caused its state.

## Reconnect to the operation, not the current receiver

Caller disconnect does not cancel surviving service work. After a service restart, reads return
stored history without advancing it. The caller follows execution guidance before explicitly
selecting the same unfinished ID.

A terminal `UNKNOWN` stays unknown even if the rollout later becomes healthy. That can be
frustrating, but “healthy now” and “what this operation established” are different questions. Stop
dependent mutations and give the operator the original identity and evidence. A replacement ID or
automatic rollback would be a new action, not a resolution of the old uncertainty.

## Next steps

- [Run an operation](getting_started.md) using a disposable fixture.
- [Use the caller interface](guides/caller.md) on a provisioned service.
- [Prepare authority and recover blocked work](guides/operator.md) as an operator.
- Read the [lifecycle contract](reference/effect_gateway.md) or
  [architecture](contributing/architecture.md) for deeper detail.
