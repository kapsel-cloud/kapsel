# Threat model

> A durable operation record narrows crash ambiguity. It does not make a provider action exactly
> once, prove the receiver is truthful, or prove no action bypassed Kapsel.

Status: active experiment design.

Kind: design. Authority: adversaries, surviving claims, and explicit non-claims for the Kubernetes
effect-gateway experiment.

Owns: Experiment threat analysis, result limits, and security assumptions.

Does not own: Kubernetes authorization policy, credential operations, or production assurance.

## Assets and seams

The experiment protects the integrity of disclosed experiment receipt bytes, the distinction between
a durable Kubernetes attempt and an observed outcome, bounded offline inspection, and the ability to
identify an unresolved crash window.

The relevant seams are:

- request-only agent intent and the application composition boundary;
- separately provisioned owner-signed exact grant and out-of-band application-configured grant
  trust;
- effect-gateway journal and signing key;
- Kubernetes credentials and API;
- Kubernetes deployment controller and observed rollout state;
- receipt transport and offline inspector; and
- externally supplied inspection trust.

Collusion, compromised credentials, or a bypassed gateway remove independence. The receipt must not
imply otherwise.

## Surviving claims

| Event                | What Kapsel can establish                                                       | What remains unproven                                                             |
| -------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Authorized request   | An owner-trusted key signed the exact fixed-purpose operation grant.            | That Kubernetes RBAC permits it or a human made the decision.                     |
| `not_attempted`      | A permanent target rejection occurred before any mutation attempt was recorded. | A receiver failure, unknown receiver state, or Kubernetes write outcome.          |
| `apply_started`      | Target identity and the attempt marker committed before the Kubernetes attempt. | That Kubernetes received, applied, or rejected the request.                       |
| Receiver observation | Kubernetes reported the disclosed classifier inputs at the observation point.   | Causation, complete cluster state, or that no other actor changed the deployment. |
| Signed receipt       | The signing key authenticated classifier-complete bytes and recomputed result.  | Truth, authority beyond the grant, or completeness.                               |
| `UNKNOWN`            | Defined bounded reconciliation could not establish a result.                    | Failure, success, safety, or harmlessness.                                        |

## Principal threats

### Ambiguous provider attempt

Permanent missing or invalid targets become terminal `not_attempted` dispositions before the
mutation marker; transient reads are deferred fairly so one operation cannot block all later work.
Neither path becomes a receiver result.

The process can fail after Kubernetes receives a request but before Kapsel records the response.
Kapsel first safely validates the target, atomically records target identity with `apply_started`,
and then reconciles by observation after ambiguity. It must not blindly apply again or promote a
timeout into `SUCCEEDED` or `FAILED`.

### Authorization mismatch or excessive authority

An agent can request destructive or broader operations or construct self-asserted authorization. The
experiment accepts only one exact namespace, deployment, container, and immutable image digest in a
fixed-purpose grant signed by the configured owner key. The application receives that grant, trust,
Kubernetes client, signing material, and paths through operator configuration; its request-only
caller cannot select them. Trust is never taken from agent or grant contents. This reduces the
gateway input surface; it does not replace Kubernetes RBAC or prevent credential misuse outside
Kapsel.

### Gateway bypass

Another actor holding Kubernetes credentials can change the deployment without Kapsel. The
experiment cannot detect universal capture. Receipts name one Kapsel operation, not all operations.

### False or changing receiver state

Kubernetes reports may be stale, incomplete, or overwritten by another change after observation.
Kapsel records bounded facts, including deployment identity and generation, and states result
meaning narrowly. It does not claim Kubernetes truth or causal attribution.

### Secret, response, and receipt disclosure

Agent input, SQLite, reports, and receipts must not contain Kubernetes credentials, signing keys, or
unbounded provider response bodies. Private paths are validated before use. Receipt fields can still
disclose deployment identifiers, image digests, timing, and operational relationships.

### Malicious receipt input

Offline inspection input may be malformed, oversized, self-trusting, or substituted. Parsing and
reports are bounded, inspection uses explicit external trust, and no inspection step performs
network access.

## Non-claims

The experiment does not establish:

- exactly-once real-world Kubernetes mutation;
- Kubernetes truth, workload correctness, or complete cluster health;
- authorization legality, policy compliance, or complete capture;
- causation between a Kapsel request and a receiver state;
- complete history, non-omission, or no gateway bypass;
- independent witnessing, trusted existence time, or `VERIFIED`; or
- production readiness or tenant isolation.

## Security assumptions

- The owner protects Kubernetes credentials, SQLite storage, and signing keys.
- Kubernetes RBAC limits the configured credential to the experiment's intended scope.
- The `kind` cluster is disposable and controlled by the demonstrator.
- The deployment controller exposes the documented receiver facts needed for the experiment's result
  classification.
- External trust supplied to offline inspection is reviewed separately from receipt bytes.
