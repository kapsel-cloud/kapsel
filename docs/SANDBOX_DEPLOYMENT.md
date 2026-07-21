# Public sandbox deployment contract

Status: accepted deployment contract; provider and implementation selection deferred.

Kind: design. Authority: ownership, isolation, capacity, durability, key custody, rollback, global
stop, and cleanup for the fixed public sandbox.

Owns: The required deployment composition and fail-closed controls for KAP-0052 and KAP-0053.

Does not own: A hosting provider, HTTP framework, database product, Kubernetes runtime, production
cluster, general multi-tenancy, or KAP-0038 lifecycle/result/receipt meaning.

## Required composition

```text
optional stateless edge admission
  -> native Rust sandbox API and scheduler
       -> transactional admission and public-projection store
       -> durable runner work and KAP-0038 Application
            -> dedicated non-consequential Kubernetes cluster
                 -> one policy-complete namespace per run
       -> immutable receipt storage
       -> forced-cleanup reconciler
```

The website, optional edge, native service, durable state, runner, cluster, receipt storage, and key
custody are separately owned deployment concerns. Provider choice remains open until KAP-0053 proves
one exact revision, region, cluster/runtime version, network implementation, store, key setup, and
rollback route.

The sandbox reuses the existing Kapsel `Application`, `AgentRequest`, `OperationReport`, lifecycle,
receiver classification, and unchanged receipt bytes. Sandbox scheduling, process health, timeout,
storage, projection, and cleanup cannot become Kapsel receiver facts.

## Ownership matrix

| Component                 | Must own                                                                                         | Must not own or expose                                                          |
| ------------------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| Optional edge             | Coarse anonymous rate limits, body-size rejection, TLS termination, forwarding                   | Durable admission, idempotency truth, run state, receipt truth, result, cleanup |
| Native Rust API           | Exact HTTP contract, bounded parsing, durable admission transaction, read projection             | KAP-0038 classification, provider truth, arbitrary Kubernetes input             |
| Durable admission store   | Run/idempotency identity, capacity reservation, immutable run specification, events, leases      | Gateway journal reuse, raw provider bodies, private keys                        |
| Bounded scheduler         | Fair queue, global active-run limit, leases, restart recovery, fail-closed dispatch              | Unbounded retry, receiver classification, lifecycle input from callers          |
| Native runner             | Server-owned `Application` composition, execute/reconcile, frozen report and receipt handoff     | Public fault controls, caller authority, new lifecycle/result vocabulary        |
| Dedicated sandbox cluster | Only synthetic non-consequential targets and sandbox system workloads                            | Customer workloads, production credentials, unrelated tenants                   |
| Per-run namespace         | One run's target, service account, quota, limits, network policy, deadline, ownership metadata   | Shared mutable run resources, signing/store access, another run's resources     |
| Receipt storage           | Exact frozen bytes, digest, immutable retrieval, retention, restore                              | Re-signing, redaction, trust appointment, mutable replacement                   |
| Key custody               | Authorization and receipt private-key availability, access policy, rotation, audit, recovery     | Browser access, run-workload access, logs, exports to public projection         |
| Cleanup reconciler        | Deadline enforcement, UID-safe deletion, retry, orphan scan, escalation, terminal cleanup record | Receiver result changes, blind cross-run deletion                               |
| Operator global stop      | Durable fail-closed block on new admission with reason kept private                              | Blocking retained reads, recovery, receipt retrieval, or cleanup                |

## Durable run identity and state

Before admission returns success, one transaction must durably establish:

1. one unpredictable public `run_id` and its idempotency mapping;
2. one immutable server-owned scenario specification and KAP-0038 `operation_id`;
3. admission/expiry times and event sequence 1;
4. one queue-capacity reservation;
5. the deployment policy revision that must be satisfied before dispatch; and
6. cleanup ownership and the maximum run deadline.

The admission store is not the KAP-0038 SQLite journal. It may identify the runner work item and
public receipt digest, but it cannot reconstruct, overwrite, or reinterpret gateway durable states.
KAP-0038 keeps its own journal and recovery semantics.

Each run receives one owner-private durable gateway-journal volume outside the target workload
namespace. It is mounted by only the exact runner identity for that run, uses the KAP-0038
owner/private-path and SQLite settings, survives runner Pod/process replacement, and is never shared
as an admission database or public projection source. Storage unavailability fails runner work
closed. Backup/restore preserves exact bytes and operation identity without cloning a runnable
journal. Retention has three explicit terminal paths:

- a receiver-result journal is deleted within one hour after Kapsel finalization, durable public
  report projection, and receipt storage verification of the frozen bytes;
- a `not_attempted` journal is deleted within one hour after its terminal rejection is durably
  projected and cleanup ownership is handed off; no receipt is awaited; and
- a pre-`Application` `service_failed` run has no Kapsel journal requirement; any allocated empty
  journal volume is deleted within one hour after that terminal projection and cleanup handoff.

Cleanup completion does not extend journal retention on any path. An unresolved Kapsel recovery may
require the operator-only journal to outlive public expiry; it remains active-run state and follows
the appropriate one-hour deletion rule after eventual terminal projection. Its path, storage
identity, rows, lock, and backups are never public.

Runner restart uses the same operation identity, journal, and configured `Application::reconcile`;
it never translates an uncertain service call into a second operation.

A scheduler lease is an internal revocable coordination fact, not admission, Kapsel submission,
provider acceptance, or a public identifier. Lease expiry permits another scheduler to resume owned
work; it does not authorize another provider mutation outside Kapsel recovery.

## Capacity and deadlines

One deployment has these hard maxima:

- 32 durably admitted runs waiting for dispatch;
- 8 active runs whose owned namespace setup, Kapsel execution/recovery, or cleanup has started and
  whose owned resources are not yet confirmed deleted;
- 64 public events and 64 KiB public JSON per run;
- 180 seconds from dispatch through the sandbox execution deadline; and
- 24 hours of public projection and receipt retention, followed by the API's 24-hour non-disclosing
  tombstone.

The scheduler reserves queue and active capacity transactionally. An active reservation remains held
through confirmed cleanup, including failed cleanup retries, so orphaned resources cannot make total
owned work unbounded. It dispatches admitted runs in ascending durable admission order, with bounded
implementation-owned fairness for recovery and cleanup. It never starts work without an active
reservation. Capacity exhaustion, loss of the durable store, inability to read the global stop, or
an incompatible deployment policy fails closed before dispatch or admission as applicable.

The 180-second sandbox deadline stops ordinary new runner work and gives reconciliation priority. It
is not the KAP-0038 30-second receiver-observation deadline. Reaching it appends only
`execution.deadline_reached`; it cannot classify the receiver, imply rollback, or prove whether a
provider attempt occurred. The namespace and receiver resources remain intact while Kapsel could
still observe them. Recovery with the same journal and operation identity remains required until
Kapsel returns a terminal receiver report or pre-attempt disposition. Deadline alone never starts
resource deletion. The active reservation remains held, so unresolved recovery can saturate and stop
new admission rather than create unbounded work or a manufactured `UNKNOWN`.

Per-source edge or service rate limits are deployment configuration, not identity or fairness proof.
They must be finite, reject before admission, and never weaken the 32/8 durable bounds. The exact
anonymous source signal and threshold require privacy and abuse review in KAP-0053; raw source
addresses are not run fields or idempotency identities.

## Policy-complete per-run isolation

Every run receives a unique namespace before dispatch. The service verifies the complete policy set
against exact ownership UIDs and the admitted deployment-policy revision before invoking Kapsel. A
missing, stale, permissive, or unverifiable control fails closed; it cannot fall back to a shared or
ordinary target.

The required set is:

- a namespace used by exactly one admitted run and labeled with an internal ownership digest;
- a unique service account with no automounted token for the synthetic target workload;
- separate controller credentials scoped to the minimum API verbs and exact namespace needed by
  Kapsel and cleanup;
- namespaced Role/RoleBinding that cannot read secrets, receipts, admission state, other namespaces,
  nodes, persistent volumes, token requests, or privilege-escalating resources;
- ResourceQuota and LimitRange bounding Pods, CPU, memory, ephemeral storage, and object counts;
- explicit CPU, memory, and ephemeral-storage requests and limits for every Pod;
- a default-deny ingress and egress NetworkPolicy plus only the exact DNS, registry, and synthetic
  traffic required by the fixed scenario;
- denial of cloud metadata, node-local services, cluster control surfaces not required by the
  controller, other run namespaces, admission/receipt stores, and key services;
- restricted security context: non-root, read-only root filesystem where compatible, no privilege,
  host namespaces, host paths, added Linux capabilities, or arbitrary volume mounts;
- one immutable scenario specification containing only server-owned target names and image digests;
- an absolute wall deadline and cleanup identity fixed before any target mutation; and
- ownership labels plus recorded Kubernetes UIDs for every object that cleanup may delete.

The admitted policy revision enforces these per-run hard ceilings; an infrastructure product may
round billing upward but cannot admit a larger Kubernetes specification:

| Resource                                      | Hard ceiling per run    |
| --------------------------------------------- | ----------------------- |
| Deployment replicas                           | 1                       |
| Containers in the synthetic target Pod        | 2                       |
| Pods                                          | 4                       |
| Deployments / ReplicaSets                     | 1 / 4                   |
| Services / EndpointSlices                     | 1 / 2                   |
| ConfigMaps / NetworkPolicies                  | 2 / 4                   |
| Secrets / persistent volume claims / Jobs     | 0 / 0 / 0               |
| Sum of CPU requests / limits                  | 2 / 4 cores             |
| Sum of memory requests / limits               | 2 / 4 GiB               |
| Sum of ephemeral-storage requests / limits    | 4 / 8 GiB               |
| One container CPU / memory / ephemeral limits | 2 cores / 2 GiB / 4 GiB |

The fixed Pod templates state nonzero requests and limits within both the per-container and
aggregate ceilings. No autoscaler, LoadBalancer/NodePort Service, persistent volume, dynamic token
request, or additional workload object is permitted. Namespace-policy objects needed for ownership
and RBAC are also schema-count bounded by the admitted policy revision; KAP-0052 must freeze their
exact list before the scheduler accepts that revision.

The dedicated cluster contains no production or customer workload and no customer credential. A
namespace, RBAC, quota, or NetworkPolicy is not by itself a hard tenant boundary. KAP-0053 must
prove the selected CNI enforcement, runtime boundary, metadata denial, cross-namespace denial, and
fixed images under adversarial tests. If ordinary containers cannot satisfy that proof, deployment
must use a documented per-Pod sandbox or VM boundary rather than weakening this contract.

## Authority and key custody

Browser authority is zero. The caller cannot select a namespace, object, image, digest, grant, trust
root, Kubernetes credential, key, path, deadline, callback, lifecycle action, result, or cleanup
action.

Controller authority and synthetic workload authority are separate. Only the native runner may
receive the exact operator inputs needed to compose `Application`; the target workload service
account receives none. Authorization-grant and receipt-signing private material must survive runner
Pod replacement through an independently protected custody system, be encrypted at rest and in
transit, and be available only to the minimal signer/runner workload identity. It is never stored in
the admission database, gateway journal, receipt store, run namespace, environment dump, log,
metric, event, error, or public fixture.

KAP-0053 must select and prove the concrete custody mechanism, Ed25519 compatibility, non-export or
narrow export boundary required by the existing `Application`, access audit, backup/deletion
protection, outage behavior, and rotation. If the selected system cannot meet the existing signing
interface without broad export, implementation must stop for a contract/interface review rather than
inventing another receipt or ambient trust source.

Rotation creates new server-owned grants and receipts with explicit key identities. Every key and
public trust version needed to inspect an unexpired receipt remains available through an
independently published trust channel; receipt transport never appoints trust. Revocation or key
outage cannot rewrite a frozen receipt or receiver result.

## Receipt durability

Receipt storage is outside ephemeral runner and run-workload Pods. It installs only the exact bytes
frozen by KAP-0038, verifies their recorded SHA-256 digest, refuses replacement by different bytes,
and supports restoration within the public retention window. The public API reads only an installed
immutable object whose digest matches the durable run reference.

A database row or object-storage write alone does not prove both are committed. The implementation
must own a restart-safe publication protocol: after either side of every durable write, recovery
converges to the same bytes and digest without re-signing. Loss, ambiguity, or temporary
unavailability yields a sandbox service/projection error; it does not alter KAP-0038 result.

## Global admission stop

A durable global stop is read in the same fail-closed admission seam as capacity. Missing,
unreadable, stale, or incompatible stop state rejects new admissions with `service_unavailable`.
Activation is auditable to operators, but its reason and operator identity are not public fields.

The stop does not scale all components to zero or block retained snapshots, event replay, receipt
retrieval, Kapsel recovery, cleanup retry, orphan scans, or expiry. Runs committed before activation
remain durably owned. Operators have a separately authenticated path to activate and clear the stop;
that path is not part of the public sandbox API or an operator console.

## Forced cleanup

Cleanup begins only after a terminal report and receipt handoff, a pre-attempt rejection, or an
unrecoverable setup failure that is durably known to precede `Application` invocation. It never
deletes the namespace or receiver resources while Kapsel may still need them for observation.
Sandbox deadline, process loss, service unavailability, or ambiguous invocation starts recovery, not
deletion. Cleanup is durable, reconnectable after controller restart, and independent from browser
connection and receiver result.

The reconciler:

1. loads the run's recorded namespace and object UIDs;
2. refuses a name match with a different UID or ownership label;
3. requests deletion only for the owned namespace and explicitly owned external objects;
4. observes asynchronous deletion rather than treating request acceptance as completion;
5. retries with bounded backoff while keeping `cleanup_state` observable;
6. scans for orphaned ownership labels without broad name-prefix deletion;
7. escalates after 15 minutes and keeps retrying; and
8. records `succeeded` only when the namespace and every owned external object are absent.

A stuck finalizer, API outage, deleted controller, or partial cleanup becomes `cleanup.failed`; it
never becomes receiver `FAILED` or `UNKNOWN`, and it never changes a frozen receipt. Manual
escalation must preserve UID checks and a record of what was removed. Public expiry does not cancel
cleanup ownership.

## Availability, rollback, and recovery

Deployment health distinguishes public read availability, new admission, scheduling, execution,
receipt publication, and cleanup. A healthy edge or HTTP process does not imply durable-store,
cluster, signer, or cleanup health. New admission is allowed only when the owned dependencies needed
to establish and eventually clean a run are compatible and available.

Rollback plans separately own:

- native service and runner revision;
- admission/event schema and reversible migration;
- deployment-policy revision and fixed scenario images;
- cluster/runtime and network-policy configuration;
- key and trust version;
- receipt-store format and reference protocol; and
- in-flight runs admitted by both old and new revisions.

A Kubernetes Deployment rollback changes only a Pod template; it does not roll back schema,
configuration, keys, external state, or in-flight work. No migration may make retained `v1` runs
unreadable or reinterpret their fields. An incompatible release must activate the global stop,
preserve reads/recovery/cleanup, and roll back or migrate through a rehearsed path.

Backups include the admission/event store, immutable receipt objects, required public trust
versions, and deployment metadata needed for ownership-safe recovery. Restores must not resurrect
expired public data, duplicate a run, reuse capacity incorrectly, re-sign a receipt, or delete by
name without UID proof.

## Deployment acceptance for KAP-0053

One exact deployed revision must prove:

1. both fixed images and native runner work with the selected runtime and key/store configuration;
2. cross-run Kubernetes API, DNS, network, metadata, volume, receipt, store, and key access is
   denied;
3. omission or corruption of each required policy fails before dispatch;
4. process/store/runner restart after admission, dispatch, provider ambiguity, and receipt
   publication preserves one run identity, ordered replay, no blind second mutation, and frozen
   receipt bytes;
5. bursts exceed edge, queue, active, subnet/IP, and cluster capacity without unbounded admission;
6. global stop rejects new runs while reads, recovery, receipt retrieval, and cleanup remain live;
7. timeout, stuck finalizer, API outage, and controller loss preserve receiver meaning and converge
   through retry/escalation;
8. key denial, rotation, storage interruption, backup restore, and expiry fail closed without
   disclosure or receipt replacement;
9. rollback across a deliberately incompatible release preserves retained runs; and
10. measured worst-case timeout plus cleanup produces a reproducible resource and cost ceiling.

Passing this contract cannot prove production multi-tenancy, kernel safety, provider truth,
commercial viability, or absence of future dependency compromise. The selected infrastructure
remains a dedicated non-consequential demonstration.
