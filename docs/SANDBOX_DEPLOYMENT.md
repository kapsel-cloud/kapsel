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

## KAP-0053 finite deployment experiment

This section is the public planning baseline for KAP-0053. It does not select a provider or
authorize an account, credential, secret, resource, endpoint, deployment, spend, or traffic. The
experiment starts from accepted source revision `1726915942a95e63aca97d49d843b8d0728514da`. A later
execution revision must retain that base in its evidence lock and identify every subsequent
implementation commit.

The smallest acceptable experiment is one temporary dedicated cluster, one native service
composition, the two fixed scenarios, and one reusable adversarial harness. Candidate environments
are evaluated sequentially, not provisioned in parallel. A candidate that fails a mandatory gate is
cleaned up and rejected before another candidate is authorized. The first candidate to pass is not
automatically selected: its measured total cost and operating burden must also satisfy the
pre-authorized ceilings and residual-risk review below.

### Reproduction lock and evidence bundle

Before any provision or deployment command, the later implementation must commit one reviewable
experiment fixture containing:

- the clean Kapsel source revision, dirty-state check, OCI image digest, fixed scenario image
  digests, build command, builder identity, target architecture, and dependency lock;
- the infrastructure tool and provider-plugin versions and lock files, rendered configuration
  digest, exact provider candidate, region, Kubernetes version, runtime class, CNI and policy mode,
  node or serverless compute shape, storage class, and enabled control-plane features;
- the admission-store, per-run journal, receipt-store, crash-consistent backup/restore, static
  volume, workload-identity, exact operator admission rule, network, quota, retention, global-stop,
  cleanup, and observability configuration digests, with no credential or private key bytes;
- separate authorization-grant, receipt-signing, and tombstone-digest key inventory entries. Each
  entry records purpose, algorithm and interface, key/version identity, allowed workload identity
  and IAM actions, audit source, backup or continuity rule, rotation state, and deletion guard;
- an inventory of every expected resource, its owner, deletion order, fixed or metered cost class,
  and a command that proves absence after teardown;
- an owner-private, access-controlled raw-evidence location outside the repository for bounded HTTP
  transcripts, Kubernetes/store/key audit decisions, object UIDs, provider-generated identifiers,
  fault output, and billing records. It has a named reviewer, fixed deletion time no later than 24
  hours after capture, no secret or private-key permission, and a deletion receipt; and
- a separate committed evidence bundle containing only machine-readable test IDs, exact revisions
  and configuration digests, receipt SHA-256 values, mutation counts, aggregate timings/resources/
  costs, synthetic identifiers, approved receipt fields, source-document URLs, and a sanitization
  check. Raw evidence, raw locators, provider billing IDs, credentials, and private infrastructure
  identifiers are never committed.

Generated provider IDs, timestamps, UIDs, and billing record IDs are declared variable evidence; the
source, inputs, digests, bounds, commands, and assertions are fixed. A clean checkout must render
the same owned configuration and image digests before the first run. After full teardown, one clean
recreation must pass the compatibility, healthy-scenario, policy-denial, receipt-digest, and absence
smoke cases. Reproduction means equivalent owned inputs and assertions, not identical
provider-generated identifiers.

### Decision criteria and surviving options

Every candidate must pass the same contract assertions. Mandatory criteria, in order, are:

1. exact native Rust, fixed-image, Kubernetes API, journal, receipt, and Ed25519 compatibility;
2. fail-closed runtime and policy selection plus denial of all cross-run, metadata, store, receipt,
   journal, volume, and key access attempted by the adversarial harness;
3. restart-safe admission, gateway recovery, immutable receipt publication, backup/restore, cleanup,
   rollback, and global stop;
4. enforcement of the 32 queued, 8 active, 180-second ordinary-work deadline, resource, retention,
   and event/response ceilings already owned here; and
5. a reproducible worst-case run and monthly cost ceiling that includes every fixed and marginal
   line item, cleanup escalation, failed work, backup, telemetry, and retained data.

Any successful forbidden access, fallback from the required runtime or policy, receipt replacement
or re-signing, blind second mutation, unsafe name-only cleanup, admission beyond a hard bound,
unrecoverable retained run, unaccounted cost class, or private-data disclosure rejects the
candidate. Among candidates that pass all mandatory criteria and their pre-authorized cost ceiling,
prefer the least operator-managed runtime, networking, storage, key, patching, and rollback surface.
No provider claim or preference substitutes for measurements.

The document screen leaves these candidates; it does not rank or select them:

| Candidate                                       | Officially documented boundary used only to justify a test                                                                                                                                                                                         | Evidence still missing before selection                                                                                               |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Dedicated managed Kubernetes, ordinary runtime  | Kubernetes documents namespace-based soft multi-tenancy and recommends additional isolation where stronger separation is needed in its [multi-tenancy guidance](https://kubernetes.io/docs/concepts/security/multi-tenancy/).                      | Whether the exact runtime and CNI deny every owned adversarial case; kernel/runtime exposure, durable-volume fit, cleanup, and cost.  |
| GKE Sandbox in one dedicated GKE cluster        | Google documents GKE Sandbox as gVisor-based isolation that intercepts workload system calls, with configuration differing between Standard and Autopilot in [GKE Sandbox](https://cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods). | Exact mode/region/version, fixed-image and volume compatibility, policy and metadata denial, startup, cleanup, key/storage, and cost. |
| AKS Pod Sandboxing in one dedicated AKS cluster | Microsoft documents Kata Containers selected through `runtimeClassName: kata-vm-isolation` and a supported node pool in [AKS Pod Sandboxing](https://learn.microsoft.com/en-us/azure/aks/use-pod-sandboxing).                                      | Exact region/version/node support, fixed-image and storage compatibility, network denial, cleanup, key/storage, and cost.             |

EKS Pods on AWS Fargate is rejected at the document screen. AWS states that Amazon VPC CNI
[NetworkPolicy support](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html) is
limited to EC2 Linux nodes and does not apply to Fargate nodes, while
[AWS Fargate for EKS](https://docs.aws.amazon.com/eks/latest/userguide/fargate.html) does not
support alternate CNIs. It therefore cannot satisfy this contract's mandatory enforced default-deny
NetworkPolicy and must not consume an Infrastructure Enforcement Proof (Gate 2) experiment.

Self-operated Kata Containers or a Firecracker-class runtime is held out of this finite experiment:
it adds node image, runtime, kernel, CNI/CSI, patch, and recovery ownership before a managed
candidate has failed. It may re-enter only through a new reviewed KAP-0053 planning revision with a
narrow measured need. A non-Kubernetes VM service or edge isolate is not a complete candidate
because this contract requires a dedicated Kubernetes target and native Rust runner; an optional
edge remains stateless admission only.

Kubernetes also documents that NetworkPolicy enforcement depends on a supporting network plugin and
that Pods are otherwise non-isolated by default in
[Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/). The
harness therefore records the selected CNI and proves traffic denial; manifest presence is not
accepted as enforcement evidence. Kubernetes documents that object deletion can remain blocked by
finalizers in
[Finalizers](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/) and that
Deployment rollback applies to the Pod template in
[Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#rolling-back-a-deployment).
The cleanup and rollback experiments below test the wider owned state rather than inferring it from
a delete request or Deployment revision.

### Proof stages and authorization gates

Each stage has a semantic proof name and retains its `Gate 0` through `Gate 4` ordinal as a stable
compatibility alias for existing evidence, commands, and task history. Existing machine identifiers
such as `gate1`, `test-sandbox-gate1`, and `GATE2_*` remain unchanged compatibility names. The proof
name states what uncertainty the stage removes; the gate records what risk may be authorized next.
Clearing one stage never authorizes its successor.

The stages are fail-closed and separately approved:

- **Contract Lock (Gate 0):** source and official-document review only. No external authority or
  resource is needed. KAP-0053 completed this planning baseline before offline implementation.
- **Authority Composition Proof (Gate 1):** a reviewed execution revision may add only the native
  listener/operator control, deployment fixture, local image build, evidence harness, durable
  store/static-volume and crash-consistent backup/restore composition, the operator-owned admission
  rule, retention/cleanup/stop configuration, and raw-seed key fixture needed by this contract. The
  admission rule permits the per-run runner identity to patch only its UID- and owner-matched
  Deployment, only when its current image and resource version equal the verified preconditions, and
  only by replacing the selected named container's image with the already validated digest while
  writing the required `kapsel.dev/kap0038-operation-id` Deployment annotation. Namespace, name,
  UID, owner, resource version, every other annotation, every other container and image, and every
  other Pod-template or Deployment field must remain byte-identical. This operation-marker exception
  is required by the higher-authority KAP-0038 recovery contract; it authorizes no other metadata
  mutation. This stage proves the exact rule and the existing KAP-0038 known-answer path from an
  exact 32-byte exported seed through derived public key and pure Ed25519 signing input to the
  production inspector. It proves no managed key custody. It still creates no provider resource and
  uses no provider credential.
- **Infrastructure Enforcement Proof (Gate 2):** requires explicit approval of one disposable
  provider candidate, account and region, named cleanup owner, experiment expiration, maximum
  experiment spend, allowed billing classes, key/data classification, and teardown command. Before
  candidate selection it must prove the candidate's concrete grant, receipt, and tombstone key
  algorithms/interfaces, export format where applicable, exact workload IAM, independent trust
  distribution, audit trail, and allowed and denied access. Any exported Ed25519 material must be
  exactly the 32-byte seed, derive the locked public key, sign the pure Ed25519 input, and verify
  with the production inspector. Credentials are supplied only through the approved operator channel
  and are never committed. The cluster has no public application endpoint and tests use an
  operator-controlled private access path.
- **Failure Recovery Proof (Gate 3):** requires confirmation that every target is synthetic and
  disposable, backups are experiment-only, the global stop works, and the remaining approved cost
  and cleanup window cover the fenced restore, key-outage, denial, restart, and rotation matrix.
- **Bounded Public Exposure (Gate 4):** is outside planning and remains blocked until the exact
  deployment passes all lanes, committed evidence passes disclosure review, teardown/recreation
  succeeds, and an explicit residual-risk review approves one bounded endpoint revision.

Once provider resources exist, a failed or expired authorization activates the global stop,
preserves reads/recovery/cleanup, and runs the owned teardown. Before resources exist, failure or
expiry blocks fixture finalization and provisioning; it does not claim a deployed stop or teardown.
Clearing a gate never implies the next gate.

### Experiments and measurements

Run the cases below in order. Later cases are skipped after a rejection condition.

| Case                        | Exact experiment                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Required measurement and pass evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Compatibility and cold path | Build the locked OCI bytes; start the native service and both fixed images on cold and warm capacity; create only server-owned targets.                                                                                                                                                                                                                                                                                                                                                                                                                          | Image digests, runtime/CNI observation, pull/ready/terminal/receipt/namespace-gone times, exact receipt inspection, and no unsupported or fallback execution.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Isolation adversary         | Run A and run B concurrently. From the runner boundary and the most compromised fixed-workload posture allowed, attempt API discovery/read/write/delete, DNS and network discovery, metadata/identity, other volumes/journals, admission/receipt stores, and signing services. After policy verification, use the real runner identity to attempt arbitrary image replacement and changes to its target's `runtimeClassName`, service account, pod security context, labels, volumes, containers, owner/UID, operation annotation, and every non-KAP-0038 field. | Every attempted capability, destination, and post-verification patch is enumerated. The admission rule accepts only the exact selected named-container image plus required KAP-0038 operation-annotation patch and independently rejects every downgrade; all other forbidden attempts are denied in workload output plus network, Kubernetes admission/audit, store, and key-access evidence. No broad credential is used merely to observe denial.                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Policy fail-closed          | Omit, stale, mislabel, or relax the namespace, service account, Role/RoleBinding, quota, limits, NetworkPolicy, runtime class, ownership UID/label, operator admission rule, and policy revision one at a time.                                                                                                                                                                                                                                                                                                                                                  | No `Application` invocation or provider mutation; one bounded setup failure or admission refusal; no fallback to an ordinary runtime or permissive policy.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Restart, storage, and keys  | Stop the API/scheduler/runner after durable admission, after dispatch, in the ambiguous provider window, and on both sides of receipt publication; interrupt each store; deny each key role independently; execute the fenced backup/restore matrix; rotate authorization-grant and receipt-signing keys independently; restart across each change; and attempt tombstone-digest rotation during a retained tombstone.                                                                                                                                           | One run/operation identity, contiguous replay, one mutation maximum after `apply_started`, and restored capacity. Old admitted grants recover while new grants use the new authorization key. Old and new receipts inspect at explicit times against trust from the separate trust channel; frozen receipt bytes and digests never change or re-sign. Restored tombstones still match, so digest-key rotation is either proved compatible or prohibited until every protected tombstone expires. Each allowed/denied key call is attributed to least-identity IAM and no expired data is resurrected.                                                                                                                                                                                                                                                                        |
| Saturation and global stop  | Burst past transport, source, 32-queued, 8-active, subnet/IP, scheduler, and cluster capacity; hold eight runs through timeout/recovery/cleanup; activate stop mid-burst.                                                                                                                                                                                                                                                                                                                                                                                        | Exact admitted/rejected counts and retry headers, no dispatch without an active reservation, bounded CPU/memory/storage/connections/events, and successful existing reads, receipt retrieval, recovery, expiry, and cleanup while stopped.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Cleanup and abandonment     | Disconnect every client, reach the sandbox deadline, stop the cleanup controller, deny the Kubernetes API, inject a stuck finalizer, and present wrong-name/UID/owner objects before recovery.                                                                                                                                                                                                                                                                                                                                                                   | Deadline never classifies the receiver; cleanup retries and escalates after 15 minutes; wrong ownership is never deleted; removal of the injected fault leads to observed absence of every owned UID and releases capacity.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Rollback and unavailability | Admit retained and in-flight runs on N; deploy a deliberately incompatible or failing N+1 service/config/policy/key reference; activate stop; roll back each owned layer separately.                                                                                                                                                                                                                                                                                                                                                                             | Retained `v1` reads and exact receipts survive, in-flight work reconciles without blind mutation, schema/config/key state is not inferred from Deployment rollback, and no transport failure becomes a receiver result.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Retention and disclosure    | Send real bounded requests through the private test path; clock-step every terminal journal path, public/idempotency state, tombstone, diagnostic/security/access-log store, raw evidence, audit/key record, and backup/snapshot expiry; restore stale backups; and inspect all allowed logs, metrics, audit records, traces, events, receipts, volumes, and evidence.                                                                                                                                                                                           | Every normal-terminal, pre-mutation setup-failure, and ambiguous/`UNKNOWN` recovery journal and volume is deleted within one hour of reaching its owned terminal path. Public and idempotency state expires at exactly 24 hours, its tombstone after the further 24 hours, and security telemetry, operator diagnostics, access logs, raw evidence, and private key/audit diagnostics no later than 24 hours. Admission/receipt backups and snapshots expire or are cryptographically erased no later than 24 hours after capture and never after the corresponding source record's deletion deadline. A stale restore reapplies deletion before readiness and cannot resurrect expired state. The committed bundle contains only approved aggregate/synthetic fields and no secrets, raw visitor locators, raw transcripts, provider IDs, or private infrastructure fields. |
| Cost and exact recreation   | Hold the configured maximum through the worst operation, recovery, 15-minute cleanup escalation, retained-data window, backup, and telemetry; create one owned orphan; then tear down and recreate from a clean checkout.                                                                                                                                                                                                                                                                                                                                        | Provider invoice/export quantities and current official regional rates for control plane, compute rounding, load balancing/private access, addresses, network/NAT/egress, storage/snapshots, key calls, logs/metrics, registry, and tax/credits treatment; measured per-run maximum and monthly ceiling; zero inventory after both teardowns; required recreation smoke passes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

The crash-consistent restore lane is this fixed matrix:

| Backup seam                                                    | Required restore proof                                                                                                                                                                                                                                                               |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Durable admission, before dispatch                             | Capture admission state, the one per-run journal, receipt/reference state, and UID/owner metadata atomically. Fence and destroy the original writer, prove the restored volume has one writer and cannot be concurrently mounted, then resume the same run identity and reservation. |
| After dispatch, before `apply_started`                         | Repeat the full capture and fencing proof; recovery may dispatch only under the same identity and active reservation.                                                                                                                                                                |
| After `apply_started`, including the ambiguous provider window | Repeat the full capture and fencing proof; recovery performs no blind mutation, preserves `UNKNOWN` where receiver outcome is unavailable, and proves at most one mutation.                                                                                                          |
| Receiver terminal, before immutable receipt publication        | Repeat the full capture and fencing proof; recovery publishes once from the retained terminal result and restores capacity exactly once.                                                                                                                                             |
| On both sides of receipt/reference publication                 | Repeat the full capture and fencing proof; recovery returns the byte-identical receipt and digest without replacement or re-signing.                                                                                                                                                 |
| During UID-safe cleanup                                        | Repeat the full capture and fencing proof; recovery deletes only the recorded UID/owner set and proves final absence without cloning runnable journal state.                                                                                                                         |

Every row restores the admission record, exactly one journal, receipt bytes or publication
reference, ownership metadata, and capacity accounting as one crash-consistent set. A backup that
permits the primary writer to survive, concurrent mounting, a second runnable journal, identity
drift, a second mutation, receipt drift, capacity duplication, or name-only cleanup fails the
candidate.

The cost result states assumptions and raw quantities separately from rates. Budget alerts are
observations, not synchronous admission bounds. Current rates must be captured from the selected
provider's official pricing pages or machine-readable billing catalog during Infrastructure
Enforcement Proof (Gate 2); no planning-time price is treated as evidence.

At the Contract Lock baseline, the existing package accepted local SQLite and receipt-directory
paths, held a private digest key in process memory, and composed `Application` with a raw Ed25519
receipt-signing seed. Authority Composition Proof later added the native listener, operator-only
stop path, exact provider-neutral durable volume/store composition, backup route, and operator-owned
patch admission. It proved only the raw-seed known-answer fixture and stop condition, without
creating a generic storage or provider interface or claiming managed custody. Infrastructure
Enforcement and Failure Recovery Proofs must prove the candidate's concrete custody compatibility,
access denials, outage, audit, independent trust, rotation, restart, and continuity before
selection. If no candidate can give the existing interface a narrow export boundary, or if
non-export signing requires changing receipt construction, work stops for contract and interface
review rather than silently weakening custody.

### Selection record and missing evidence

A provider may be selected only after one candidate's evidence bundle contains every passing case,
current official configuration and pricing sources, a complete teardown, the clean recreation smoke,
and an approved residual-risk review. The selection record states why each other surviving candidate
was not needed or which mandatory criterion it failed; it publishes no private commercial or
organizational rationale.

After accepted Authority Composition, there is still no live evidence for runtime/CNI isolation,
metadata denial, Kubernetes authority scope, durable volume or backup behavior, key compatibility or
non-export, restore, deletion under finalizers, rollback, global stop under dependency loss,
saturation, costs, or exact recreation. No provider is selected, no isolation is claimed, and no
public traffic is unblocked.

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
