# Threat model

> A durable operation record narrows crash ambiguity. It does not make a provider action exactly
> once, prove the receiver is truthful, or prove no action bypassed Kapsel.

Status: active experiment design.

Kind: design. Authority: adversaries, surviving claims, and explicit non-claims for the Kubernetes
effect-gateway experiment.

Owns: Experiment threat analysis, result limits, and security assumptions.

Does not own: Kubernetes authorization policy, credential operations, public-sandbox HTTP grammar or
deployment configuration, or production assurance.

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
- externally supplied inspection trust; and
- for the fixed public sandbox only, anonymous admission, durable idempotency/projection state,
  scheduler and runner authority, dedicated cluster isolation, receipt storage, key custody, and
  forced cleanup.

Collusion, compromised credentials, or a bypassed gateway remove independence. The receipt must not
imply otherwise. [Public sandbox API](SANDBOX_API.md) and [deployment](SANDBOX_DEPLOYMENT.md) own
the concrete hosted controls; this document owns the threats and surviving claims.

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

### Demonstration fault-control misuse

The release harness must stop processes at two exact crash windows without adding lifecycle control
to agent input. Ordinary builds contain no demonstration pause behavior. The separately built
`demo-harness` executable accepts only two fixed environment-selected seams and one owner-private
control directory; malformed, partial, symlinked, or repeated controls fail closed. This feature is
an evaluator mechanism, not an authorization boundary or a production-safe binary. Anyone able to
replace the executable or its process environment already controls that local demonstration process.
Markers and the harness-owned apply counter make no claim about Kubernetes truth or exactly-once
real-world effects.

### MCP transport confusion and hostile input

The local MCP client can send malformed, duplicated, oversized, out-of-order, or unknown protocol
messages, attempt another tool, or place operator authority in tool arguments. The fixed stdio
adapter bounds each frame before JSON allocation, rejects duplicate and extra fields, exposes one
five-field tool, loads operator configuration separately at process startup, and returns only
bounded protocol or typed application vocabulary. Standard output is protocol-only. Cancellation,
disconnect, or transport completion cannot establish that an application operation was unattempted,
failed, rolled back, or safe; restart uses the same application reconciliation semantics.

### Release substitution or provenance overclaim

An archive or checksum can be replaced, built from a dirty tree, mislabeled for another target, or
presented as authenticated because its SHA-256 matches. Release assembly records the exact source
revision, dirty state, target, pinned builder, and binary digests; normalizes archive bytes; and
checks the final archive digest before extraction. Clean smoke rejects unsafe entries and executes
only extracted bytes. These controls detect mismatches and make assembly repeatable; they do not
sign the archive, authenticate a publisher, witness build inputs, prove source review, support other
targets, or establish production safety.

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

## Public sandbox threats

The sandbox is anonymous and intentionally discloses fixed synthetic demonstration evidence. A
high-entropy run locator limits opportunistic enumeration but is a bearer locator, not
authentication or confidentiality. Anyone who obtains it before expiry can read that run's public
projection and unchanged receipt.

### Abuse, enumeration, and denial of service

An attacker can flood admission, vary idempotency keys, replay requests, guess run identifiers, hold
capacity, or exhaust cluster, subnet, store, signer, receipt, telemetry, and cleanup resources. The
optional edge provides only additive coarse rejection. The native admission transaction enforces the
global stop, per-source bound, queue bound, active reservation, idempotency, and body bounds before
committing a run. Saturation creates no run and retry hints disclose no capacity count. Malformed
and absent run identities receive the same `run_not_found`; expired tombstones reveal no scenario or
outcome. These controls bound owned work but do not guarantee availability or fair use under a
distributed attack.

Idempotency keys are caller-generated 128-bit correlation and bearer replay locators, not browser or
authority identities. The service stores only their required private mapping and a keyed digest in
bounded diagnostics, never echoes them, and reserves them through the expiry tombstone. During live
retention, a repeated key and changed scenario fails before dispatch; during tombstone retention,
any matching key returns only `run_expired` regardless of scenario.

### Admission, scheduling, and outcome confusion

HTTP success establishes durable sandbox admission only. It does not establish Kapsel submission,
Kubernetes request acceptance, mutation, rollout, receipt publication, or cleanup. Scheduler lease
expiry, runner crash, edge timeout, disconnect, replay failure, sandbox deadline, store failure, and
cleanup failure remain sandbox facts. Only an unchanged KAP-0038 `OperationReport` can populate a
receiver result or pre-attempt rejection, and recovery uses the same operation identity without a
blind second mutation.

### Correlation and disclosure

Run locators, whole-second admission/event times, scenario, synthetic operation identity, result,
and classifier-complete receipt can be correlated across requests or copied outside the service. The
fixed scenarios use no visitor, customer, or production data. Public receipt identifiers are
server-chosen synthetic evidence. Private runner Pod/node/lease/store/control-plane identifiers,
credentials, internal paths, raw journal rows, uncontrolled logs, and fault controls are excluded.
Bounds and retention reduce exposure but do not establish anonymity or unlinkability.

### Compromised workload and namespace escape

A fixed image or its dependency can be compromised and attempt Kubernetes API access,
cross-namespace discovery, metadata/identity access, network egress, volume reads, resource
exhaustion, or a container/runtime escape. Every run receives a policy-complete namespace, unique
service account, quota, limits, default-deny network policy, restricted security context, and
server-owned deadline in a dedicated non-consequential cluster. Run workloads cannot access
admission/receipt state or signing authority.

Kubernetes namespaces, RBAC, quotas, and NetworkPolicy are not by themselves hard tenant isolation.
The selected runtime and CNI must pass live adversarial proof; a container or kernel escape can
still compromise the dedicated cluster. No production or customer workload may share that cluster.

### Compromised native runner and gateway journal

A compromised native runner can use its per-run Kubernetes controller authority, read or corrupt
that run's gateway journal, misuse loaded grant/signing material, forge public projection handoff,
or attack stores and control-plane services reachable from its identity. This is more powerful than
a compromised synthetic target workload. The deployment gives each run a separate runner identity
and owner-private durable journal, scopes Kubernetes access to the exact run namespace, denies other
run journals/stores/keys where the existing `Application` permits, and keeps the global stop and
cleanup controller under separate operator authority.

The existing `Application` requires authorization and receipt signing material during composition,
so runner compromise while that material is available can forge grants or receipts under the loaded
key. Process, workload-identity, key-access, egress, journal-volume, and signer isolation require
live proof; contract separation cannot eliminate that blast radius. Detection activates the global
stop, preserves journals and immutable receipts, rotates affected keys through the separately owned
trust route, and reconciles/cleans already admitted runs without rewriting their receiver results.
No public receipt claims independence from its runner or signing authority.

Journal loss, rollback, cloning, or concurrent mounting can omit durable facts or create unsafe
recovery. The per-run journal survives runner replacement, is never cloned as runnable state, and
uses KAP-0038 locking/settings. Receiver-result journals remain through final report and verified
receipt handoff; `not_attempted` journals remain through durable rejection projection and cleanup
handoff without awaiting a nonexistent receipt; pre-Application `service_failed` runs need no Kapsel
journal. Cleanup then proceeds from its separate durable ownership record and does not extend
journal retention. Admission-store state cannot substitute for missing gateway facts.

### Key, storage, and receipt failure

Compromise of authorization-signing or receipt-signing material permits forged grants or receipts;
compromise of the durable store can alter admission/projection; loss or rollback can omit runs or
resurrect state. Keys are separated from run namespaces and public storage, access is restricted to
the native signer/runner identity, and rotation/restore/deletion protection require live proof.
Receipt storage accepts only exact frozen bytes and refuses replacement. A store, signer, or key
outage fails admission or receipt publication without changing receiver classification.

A receipt signature authenticates bytes under separately supplied trust; receipt retrieval does not
publish or appoint trust. Backups and restore narrow loss but are not an external witness or proof
of complete history.

### Cleanup failure and unsafe deletion

Namespace deletion is asynchronous and can stall on finalizers or API/controller failure. Cleanup
uses recorded UIDs and ownership labels, retries durably, scans only owned orphans, escalates, and
never deletes by a reusable name alone. Public expiry and client disconnect do not release cleanup
ownership. A compromised controller credential can still exceed these software checks within its
RBAC, and a stuck cleanup can consume resources indefinitely until operator remediation.

### Dependency and image compromise

The HTTP, database, Kubernetes client, base image, scenario image, CNI, runtime, cluster, receipt
store, and key service are supply-chain inputs. Exact versions, provenance, vulnerability response,
rollback, and image immutability are KAP-0053 deployment evidence. Pinning and scanning reduce but
do not eliminate malicious dependencies or registry/control-plane compromise.

### Global stop misuse or failure

An attacker or operator mistake can activate the global stop, prevent activation, or scale away the
components needed for recovery. Stop state is durable and fail-closed for new admission while
retained reads, recovery, receipt retrieval, and cleanup remain available. Its control path is
separately authenticated and not public. The stop limits new work; it cannot undo an admitted run,
revoke already held cluster authority, or prove cleanup.

## Non-claims

The experiment does not establish:

- exactly-once real-world Kubernetes mutation;
- Kubernetes truth, workload correctness, or complete cluster health;
- authorization legality, policy compliance, or complete capture;
- causation between a Kapsel request and a receiver state;
- complete history, non-omission, or no gateway bypass;
- independent witnessing, trusted existence time, or `VERIFIED`; or
- production readiness, authenticated confidentiality, anonymous fairness, or hard tenant isolation.

## Security assumptions

- The owner protects Kubernetes credentials, SQLite storage, and signing keys.
- Kubernetes RBAC limits the configured credential to the experiment's intended scope.
- The `kind` cluster is disposable and controlled by the demonstrator.
- The deployment controller exposes the documented receiver facts needed for the experiment's result
  classification.
- External trust supplied to offline inspection is reviewed separately from receipt bytes.
- The public sandbox cluster contains only synthetic non-consequential workloads, and the operator
  protects admission/receipt storage, controller credentials, and key custody.
- The selected CNI, runtime, key service, store, and cleanup controller enforce the exact deployment
  configuration proved by KAP-0053; contract text alone cannot establish that enforcement.
