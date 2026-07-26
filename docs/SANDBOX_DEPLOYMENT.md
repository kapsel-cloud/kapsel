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

The first 2026-07-23 document screen found that Google, Azure, and AWS retain provider-managed
records beyond the sandbox's 24-hour application lifecycle. The privacy owner now treats the sandbox
as a synthetic, non-consequential prototype: Kapsel-owned records retain their explicit lifecycle,
while the minimum provider records needed for management and enforcement follow documented provider
storage semantics under the field, access, export, and non-disclosure rules in
[Privacy](PRIVACY.md#collection-and-disclosure-rules). The experiment must prove exclusion from
Kapsel-controlled stores and no Kapsel query or replay after 24 hours; it does not claim
provider-wide inaccessibility or physical erasure of provider replicas. This change reopens managed
candidates; it does not accept one.

GKE Sandbox is the first reopened candidate because its runtime, account, regional version, quota,
image, storage, key, and price surfaces have already received the narrowest screen. Google documents
that Admin Activity and System Event audit logs are always written to the `_Required` bucket and
cannot be disabled, excluded, or rerouted away from that bucket in
[Cloud Audit Logs](https://cloud.google.com/logging/docs/audit). The
[retention table](https://cloud.google.com/logging/quotas#logs_retention_periods) fixes `_Required`
retention at 400 days and marks it non-configurable. Infrastructure Enforcement must inspect the
actual record set and prove that it contains only the allowed administrative metadata. Secret
Manager Data Access, Kubernetes audit, and Policy Denied evidence must use only the minimum fields
needed for the Gate 2 assertions. Exclude them from long-lived default buckets, route at most one
bounded copy through the shortest practical logical retention, and prove that Kapsel cannot query or
replay the records after 24 hours.

AKS Pod Sandboxing and ordinary EKS remain document-screen alternatives but are not active parallel
work. Microsoft documents an unchangeable 90-day
[Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log); AWS
documents an immutable
[90-day CloudTrail event history](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html).
Each would require the same field-level exception proof before account use. EKS Pods on AWS Fargate
remains independently rejected because AWS states that Amazon VPC CNI
[NetworkPolicy support](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html) is
limited to EC2 Linux nodes and does not apply to Fargate nodes, while
[AWS Fargate for EKS](https://docs.aws.amazon.com/eks/latest/userguide/fargate.html) does not
support alternate CNIs.

Self-operated Kata Containers or a Firecracker-class runtime remains held out. It adds node image,
runtime, kernel, CNI/CSI, patch, physical access, and recovery ownership before the reopened managed
candidate has failed for a runtime-specific reason. A non-Kubernetes VM service or edge isolate is
not a complete candidate because this contract requires a dedicated Kubernetes target and native
Rust runner; an optional edge remains stateless admission only.

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

| Case                        | Exact experiment                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Required measurement and pass evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Compatibility and cold path | Build the locked OCI bytes; start the native service and both fixed images on cold and warm capacity; create only server-owned targets.                                                                                                                                                                                                                                                                                                                                                                                                                          | Image digests, runtime/CNI observation, pull/ready/terminal/receipt/namespace-gone times, exact receipt inspection, and no unsupported or fallback execution.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Isolation adversary         | Run A and run B concurrently. From the runner boundary and the most compromised fixed-workload posture allowed, attempt API discovery/read/write/delete, DNS and network discovery, metadata/identity, other volumes/journals, admission/receipt stores, and signing services. After policy verification, use the real runner identity to attempt arbitrary image replacement and changes to its target's `runtimeClassName`, service account, pod security context, labels, volumes, containers, owner/UID, operation annotation, and every non-KAP-0038 field. | Every attempted capability, destination, and post-verification patch is enumerated. The admission rule accepts only the exact selected named-container image plus required KAP-0038 operation-annotation patch and independently rejects every downgrade; all other forbidden attempts are denied in workload output plus network, Kubernetes admission/audit, store, and key-access evidence. No broad credential is used merely to observe denial.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Policy fail-closed          | Omit, stale, mislabel, or relax the namespace, service account, Role/RoleBinding, quota, limits, NetworkPolicy, runtime class, ownership UID/label, operator admission rule, and policy revision one at a time.                                                                                                                                                                                                                                                                                                                                                  | No `Application` invocation or provider mutation; one bounded setup failure or admission refusal; no fallback to an ordinary runtime or permissive policy.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Restart, storage, and keys  | Stop the API/scheduler/runner after durable admission, after dispatch, in the ambiguous provider window, and on both sides of receipt publication; interrupt each store; deny each key role independently; execute the fenced backup/restore matrix; rotate authorization-grant and receipt-signing keys independently; restart across each change; and attempt tombstone-digest rotation during a retained tombstone.                                                                                                                                           | One run/operation identity, contiguous replay, one mutation maximum after `apply_started`, and restored capacity. Old admitted grants recover while new grants use the new authorization key. Old and new receipts inspect at explicit times against trust from the separate trust channel; frozen receipt bytes and digests never change or re-sign. Restored tombstones still match, so digest-key rotation is either proved compatible or prohibited until every protected tombstone expires. Each allowed/denied key call is attributed to least-identity IAM and no expired data is resurrected.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Saturation and global stop  | Burst past transport, source, 32-queued, 8-active, subnet/IP, scheduler, and cluster capacity; hold eight runs through timeout/recovery/cleanup; activate stop mid-burst.                                                                                                                                                                                                                                                                                                                                                                                        | Exact admitted/rejected counts and retry headers, no dispatch without an active reservation, bounded CPU/memory/storage/connections/events, and successful existing reads, receipt retrieval, recovery, expiry, and cleanup while stopped.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Cleanup and abandonment     | Disconnect every client, reach the sandbox deadline, stop the cleanup controller, deny the Kubernetes API, inject a stuck finalizer, and present wrong-name/UID/owner objects before recovery.                                                                                                                                                                                                                                                                                                                                                                   | Deadline never classifies the receiver; cleanup retries and escalates after 15 minutes; wrong ownership is never deleted; removal of the injected fault leads to observed absence of every owned UID and releases capacity.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Rollback and unavailability | Admit retained and in-flight runs on N; deploy a deliberately incompatible or failing N+1 service/config/policy/key reference; activate stop; roll back each owned layer separately.                                                                                                                                                                                                                                                                                                                                                                             | Retained `v1` reads and exact receipts survive, in-flight work reconciles without blind mutation, schema/config/key state is not inferred from Deployment rollback, and no transport failure becomes a receiver result.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Retention and disclosure    | Send real bounded requests through the private test path; clock-step every terminal journal path, public/idempotency state, tombstone, diagnostic/security/access-log store, raw evidence, audit/key record, and backup/snapshot expiry; restore stale backups; and inspect all allowed logs, metrics, audit records, traces, events, receipts, volumes, and evidence.                                                                                                                                                                                           | Every normal-terminal, pre-mutation setup-failure, and ambiguous/`UNKNOWN` recovery journal and volume is deleted within one hour of reaching its owned terminal path. Public and idempotency state expires at exactly 24 hours, its tombstone after the further 24 hours, and security telemetry, operator diagnostics, access logs, and raw evidence no later than 24 hours. Minimum provider management and audit records may follow documented provider storage semantics only under the privacy owner's field and routing restrictions; the proof establishes exclusion from long-lived configurable buckets and no Kapsel query or replay after 24 hours, not physical erasure of provider replicas. Workload, application, visitor, key-payload, and request records remain ineligible. Admission/receipt backups and snapshots expire or are cryptographically erased no later than 24 hours after capture and never after the corresponding source record's deletion deadline. A stale restore reapplies deletion before readiness and cannot resurrect expired state. The committed bundle contains only approved aggregate/synthetic fields and no secrets, raw visitor locators, raw transcripts, provider IDs, or private infrastructure fields. |
| Cost and exact recreation   | Hold the configured maximum through the worst operation, recovery, 15-minute cleanup escalation, retained-data window, backup, and telemetry; create one owned orphan; then tear down and recreate from a clean checkout.                                                                                                                                                                                                                                                                                                                                        | Provider invoice/export quantities and current official regional rates for control plane, compute rounding, load balancing/private access, addresses, network/NAT/egress, storage/snapshots, key calls, logs/metrics, registry, and tax/credits treatment; measured per-run maximum and monthly ceiling; zero inventory after both teardowns; required recreation smoke passes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |

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

| Component                 | Must own                                                                                           | Must not own or expose                                                          |
| ------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Optional edge             | Coarse anonymous rate limits, body-size rejection, TLS termination, forwarding                     | Durable admission, idempotency truth, run state, receipt truth, result, cleanup |
| Native Rust API           | Exact HTTP contract, bounded parsing, durable admission transaction, read projection               | KAP-0038 classification, provider truth, arbitrary Kubernetes input             |
| Durable admission store   | Run/idempotency identity, capacity reservation, immutable run specification, events, leases        | Gateway journal reuse, raw provider bodies, private keys                        |
| Bounded scheduler         | Fair queue, global active-run limit, leases, restart recovery, fail-closed dispatch                | Unbounded retry, receiver classification, lifecycle input from callers          |
| Native runner             | Server-owned `Application` composition, execute/reconcile, authenticated invocation/report handoff | Public fault controls, caller authority, new lifecycle/result vocabulary        |
| Dedicated sandbox cluster | Only synthetic non-consequential targets and sandbox system workloads                              | Customer workloads, production credentials, unrelated tenants                   |
| Per-run namespace         | One run's target, service account, quota, limits, network policy, deadline, ownership metadata     | Shared mutable run resources, signing/store access, another run's resources     |
| Receipt storage           | Exact frozen bytes, digest, immutable retrieval, retention, restore                                | Re-signing, redaction, trust appointment, mutable replacement                   |
| Key custody               | Authorization and receipt private-key availability, access policy, rotation, audit, recovery       | Browser access, run-workload access, logs, exports to public projection         |
| Cleanup reconciler        | Deadline enforcement, UID-safe deletion, retry, orphan scan, escalation, terminal cleanup record   | Receiver result changes, blind cross-run deletion                               |
| Operator global stop      | Durable fail-closed block on new admission with reason kept private                                | Blocking retained reads, recovery, receipt retrieval, or cleanup                |

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
it never translates an uncertain service call into a second operation. The runner never mounts or
writes the system-state volume. Its read-only operator composition includes the immutable
server-owned `AgentRequest` derived from the admitted fixed scenario. One narrow non-mutating
`Application` validation method may expose only whether that request matches the grant already
verified by `Application::open`; the runner must call it before the invocation handoff. Grant
parsing, trust, and tuple comparison remain in KAP-0038 and are not duplicated in the sandbox
package.

The private system-service handoff is one configured provider-neutral TCP endpoint. The system binds
it only on the owner-private interface selected by deployment; deterministic tests bind loopback. It
has no discovery, public route, publicly reachable Service, forwarding, or ambient configuration.
One connection carries exactly one request and one response and then closes. The request is a
four-byte unsigned big-endian body length followed by one canonical binary body. The body is at most
20 KiB. The listener reads the length into fixed storage and rejects zero or a value above that
limit before allocating the body. A truncated body, bytes after the framed body, or a request side
that does not reach EOF fails before state mutation.

A body begins with its exact ASCII magic, including the final zero byte, followed by records encoded
as one-byte field number, four-byte unsigned big-endian length, and the exact field bytes. Fields
appear exactly once in strictly increasing field-number order. Unknown, duplicate, missing,
reordered, truncated, trailing, non-ASCII, or out-of-grammar records fail closed. Common fields are:

1. `run_id`: exactly 32 lowercase hexadecimal ASCII bytes;
2. `operation_id`: exactly the eight ASCII bytes `sandbox-` plus that `run_id`;
3. `lease_id`: exactly 32 lowercase hexadecimal ASCII bytes; and
4. `credential`: exactly 32 raw random bytes.

The two request families are:

- `application_invoked`, with magic `KAPSEL-SANDBOX-APPLICATION-INVOKED-V1\0`, contains only common
  fields 1 through 4.
- `application_report`, with magic `KAPSEL-SANDBOX-APPLICATION-REPORT-V1\0`, contains common fields
  1 through 4 and field 5. Field 5 is exactly `not_attempted` or `finalized`. For `not_attempted`,
  field 6 is exactly `DEPLOYMENT_NOT_FOUND`, `CONTAINER_NOT_FOUND`, or `INVALID_TARGET`, and no
  receiver-result, digest, or receipt record exists. For `finalized`, field 6 is exactly
  `SUCCEEDED`, `FAILED`, or `UNKNOWN`; field 7 is the 64-byte lowercase hexadecimal SHA-256 digest
  of field 8; and field 8 is 1 through 16 KiB of exact frozen receipt bytes. The system recomputes
  the digest before mutation. No request carries a path, filename, timestamp, lifecycle state,
  cleanup state, destination, provider fact, or public field.

Success uses a distinct `KAPSEL-SANDBOX-APPLICATION-INVOKED-ACK-V1\0` or
`KAPSEL-SANDBOX-APPLICATION-REPORT-ACK-V1\0` body containing fields 1 through 3 and field 4 equal to
`committed`; it never echoes a credential, result, rejection, digest, or receipt. Every fully parsed
semantic or authentication failure returns the one fixed `KAPSEL-SANDBOX-HANDOFF-REJECTED-V1\0` body
without records or diagnostic detail. Oversize, truncated, trailing, timeout, and framing failures
may close silently. A missing, malformed, rejected, or lost acknowledgment is ambiguous: the runner
exits before its next `Application` lifecycle call. The listener permits at most 16 open connections
and eight handlers, receives the complete request plus EOF within one monotonic absolute five-second
deadline, and returns its response within 30 seconds. Every read uses only the deadline's remaining
time, so trickled bytes cannot restart the receive window. These transport bounds do not reserve
capacity, revoke already loaded Kubernetes authority, or classify an outcome.

Every dispatch and recovery generation creates a new random lease identity and independent 32-byte
credential. Admission state stores only
`SHA-256("KAPSEL-SANDBOX-HANDOFF-CREDENTIAL-V1\0" || run_id || operation_id || lease_id || credential)`.
The system recomputes and compares that verifier without early exit or diagnostic disclosure. Lease
identity and verifier rotate atomically on every generation, including renewal by the current owner,
and the verifier is cleared when the run becomes inactive. The raw credential is sent only through
the owner-private read-only runner channel; it has no read-back endpoint and is never derived from
public identity.

Invocation and report handlers parse completely, obtain the lease-evaluation time after complete
frame plus EOF parsing and immediately before the transaction, then use one immediate admission
transaction to validate the exact run and operation, active current unexpired lease, bound
credential verifier, policy readiness, and allowed durable state together with their mutation.
`application_invoked` sets the pre-lifecycle marker before acknowledgment. Exact replay under the
same current lease is a no-op. A replacement recovery lease may acknowledge the same durable marker,
but an old lease or credential cannot commit invocation, report, or receipt state.

The first terminal report transaction binds the semantic variant, result or rejection, receipt
digest when present, and a domain-separated SHA-256 digest of the canonical semantic payload,
including exact receipt bytes but excluding current lease and credential. This binding permits an
authorized replacement lease to deliver the same report while rejecting any changed variant, result,
rejection, digest, bytes, run, or operation across restart and concurrency. A `not_attempted`
binding atomically commits the receipt-free projection and cleanup eligibility. A `finalized`
binding atomically commits the receiver-result projection and pending immutable receipt reference.
The system acknowledges a finalized report only after the existing restart-safe publication protocol
has installed or verified the exact object and committed receipt availability; it never treats a
digest-only pending row as ownership of missing bytes. If unresolved finalized recovery crosses
public expiry, the private pending reference remains restart-safe without becoming publicly
available. Exact replacement-lease replay verifies the same bytes, removes the now-expired object,
and makes cleanup eligible so capacity can converge. Exact replay is idempotent.

On an empty gateway volume the runner descriptor-relatively creates exactly one `run` directory and
its `receipt-outbox`, both owned by the runner at mode `0700`; the journal is then created by
`Application` at `run/gateway.sqlite3`. Existing entries, symlinks, wrong ownership, or wrong modes
fail closed. Read-only ConfigMap, Secret, and projected inputs accept only Kubernetes' exact atomic
writer layout: a key link to `..data/<key>`, a single-component `..data` generation link, a
no-follow generation directory, and a no-follow regular key. Escape targets, nested targets, or
substituted key symlinks fail before composition.

The runner opens `Application`, verifies only that the immutable server-owned `AgentRequest` matches
the grant already verified by `Application::open`, and obtains the durable invocation acknowledgment
before the first lifecycle call. It calls `Application::reconcile` first on the same journal. A
terminal report is handed off directly; only `reconcile` returning no gateway operation permits
`Application::execute` with the same validated request. Thus marker-only recovery can submit once,
while any gateway state or ambiguous invocation is reconciled without a blind mutation.

The runner's receipt outbox is temporary per-run state on the same owner-private gateway volume as
its journal; it is not the system receipt store or a public source. The system service alone commits
handoff facts to admission SQLite and installs immutable receipt storage. Runner timeout,
disconnect, transport status, scheduler state, lease loss, storage error, cleanup, or receipt
publication failure cannot create or alter a receiver result or target rejection.

A scheduler lease is an internal revocable coordination fact, not admission, Kapsel submission,
provider acceptance, or a public identifier. Lease expiry permits another scheduler to resume owned
work; it does not authorize another provider mutation outside Kapsel recovery.

### Offline GKE control-topology lock

The direct local-`Service` scheduler and cleanup implementations expose the intended transitions but
cannot be deployed as extra containers in the current system Pod. SQLite and its `ReadWriteOncePod`
system-state claim permit one Pod owner, while one Pod has one Kubernetes service account. Giving
that Pod the union of API, scheduler, cleanup, and cloud-key authority would contradict the separate
controller credentials and cleanup key denials above. Separate controller Pods cannot mount or write
the system claim. A shared filesystem, multi-attach claim, copied database, or generic storage
backend is not an allowed repair.

The GKE candidate therefore locks this control topology before complete rendering:

- the singleton system-state Pod remains the only admission SQLite and receipt-store owner and runs
  only the native API, runner handoff, periodic retention, and durable-layout initialization;
- scheduler and cleanup run in separate Pods under distinct Kubernetes service accounts, with no
  system-state, receipt-store, tombstone-key, grant-key, or receipt-key mount;
- the system process owns two fixed, private, bounded state protocols: scheduler operations may only
  list recoverable work and its policy status, transactionally reserve the next FIFO run and initial
  lease, recover or renew that exact lease, read the server-owned provisioning/runner assignment,
  commit exact provisioning or setup facts, and append the existing deadline fact; cleanup
  operations may only read eligible recorded ownership and commit the existing
  start/failure/escalation/exact-absence transitions;
- those protocols remain transport adapters over the existing `Service` methods. They accept no
  caller-selected lifecycle, receiver result, Kubernetes manifest, path, key, receipt destination,
  or generic database operation and do not become public APIs or provider interfaces;
- each controller presents a short-lived bound service-account token for a fixed application
  audience over authenticated encryption with pinned system trust. The system validates it through
  Kubernetes `TokenReview` and requires the exact role identity; NetworkPolicy permits only that
  role to reach its named state port. Each controller separately receives its own projected
  Kubernetes-API token and exact RBAC. The system Pod receives a separate projected Kubernetes-API
  token whose only cluster authorization is `create` on `tokenreviews.authentication.k8s.io`; it has
  no controller-resource verbs. The application audience, GKE Kubernetes-API audience, server
  certificate/trust delivery, and fail-closed rotation must be locked from current provider evidence
  before any object is rendered deployable; and
- Secret Manager access belongs only to separate staging identities. The system and controller
  service accounts receive no Secret Manager IAM. Tombstone staging produces only the owner-private
  Kubernetes Secret mounted by the system-state Pod. Per-run grant and receipt staging produces only
  the exact read-only runner channels. Before any per-run external object is created, the system
  durably fixes its complete server-derived resource-slot inventory. The scheduler then creates or
  exactly observes one fixed slot and immediately appends its observed UID and cleanup-owner label;
  exact recovery replay is idempotent, while changed evidence is rejected. After policy verification
  and registration of the journal, composition, Kubernetes, trust, grant, and receipt-signing slots,
  handoff assignment may prepare only the fixed lease, endpoint, and credential bytes needed to
  stage the two handoff channels; that preparation is not Application invocation eligibility. All
  eight prerequisite channels are registered before runner Pod creation. The runner Pod is created
  with the exact `kapsel.dev/ownership-registration` scheduling gate, and its UID and owner are
  registered before the scheduler may remove the gate or Application invocation may be accepted.
  Cleanup consumes only registered UID/owner evidence. A fixed slot without a registered UID remains
  setup/recovery work and cannot be ignored, treated as absent, or deleted by name.

The protocols, authenticated transport, stagers, append-only runner-resource registration, projected
tokens, RBAC, and NetworkPolicies must be implemented and tested before the incomplete
system-workload wrapper can be called complete. This correction preserves one system-state writer
and least authority; it does not select GKE, authorize provisioning, or prove live identity,
storage, policy, or custody.

### Authenticated controller-state transport contract

Both role-specific payload codecs use one private TLS transport implementation; this repeated
transport is not a generic protocol, controller, provider, or storage interface. The deployment owns
one application audience, `https://kapsel.dev/sandbox/controller-state/v1`, and these exact
controller identities in namespace `kapsel-sandbox-system`:

- scheduler: ServiceAccount `sandbox-scheduler`, username
  `system:serviceaccount:kapsel-sandbox-system:sandbox-scheduler`, and its render-time observed
  ServiceAccount UID; and
- cleanup: ServiceAccount `sandbox-cleanup`, username
  `system:serviceaccount:kapsel-sandbox-system:sandbox-cleanup`, and its render-time observed
  ServiceAccount UID.

The system remains unready until both UIDs are observed and installed in its immutable role binding.
A recreated ServiceAccount has a different UID and is denied until a reviewed rerender installs that
new identity. Groups and `extra` returned by authentication appoint no role and are never logged.
The exact username form and UID binding follow Kubernetes
[ServiceAccount authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens)
and the
[bound service-account token mechanism](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-token-volume-mechanism).

Each controller disables ambient token mounting and receives two distinct read-only projected token
files. The state-authentication projection requests only the fixed application audience above with
`expirationSeconds: 600`; the client reopens the projected file for every connection and never
copies or caches its bytes in an environment variable, ConfigMap, Secret, durable store, diagnostic,
or evidence record. The separate Kubernetes-client projection also requests 600 seconds but
intentionally omits `audience`, which Kubernetes defines as requesting the API server's configured
default audience. Its token and cluster CA are used only by that role's concrete `kube::Client` and
are never presented to the state service. There is no documented universal GKE Kubernetes-API
audience literal: accepted API audiences are cluster configuration, so the renderer locks the
intentional absence of that field and the offline fixture plus later live gate must fail closed
unless the projected token authenticates and receives exactly the role's RBAC. It must not derive an
audience from a GKE issuer or Workload Identity Federation value. These rules follow Kubernetes
[projected service-account token](https://kubernetes.io/docs/concepts/storage/projected-volumes/#serviceaccounttoken)
and
[API audience](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
semantics.

For every state connection, the system submits a `TokenReview` containing only the presented token
and the singleton application audience. It accepts authentication only when the Kubernetes call
completes within three seconds, `status.authenticated` is exactly `true`, `status.audiences` is
exactly the singleton application audience, and `status.user.username` plus `status.user.uid` equal
the selected port's complete render-time role binding. Empty, missing, duplicate, or additional
audiences; missing user fields; a missing UID; any other namespace, ServiceAccount, username, or
UID; `status.error`; malformed status; timeout; and Kubernetes transport or API error all fail
closed. The request and accepted response fields follow the Kubernetes
[`TokenReview` v1 API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/).
The system ServiceAccount `kapsel-gate2-sandbox-api` receives only `create` on
`tokenreviews.authentication.k8s.io`; it receives no controller-resource verb, and TokenReview
success never substitutes for scheduler or cleanup RBAC.

The state service has the exact TLS DNS identity
`kapsel-sandbox-controller-state.kapsel-sandbox-system.svc`, with scheduler on TCP port 8082 and
cleanup on TCP port 8083. TLS 1.3, SNI, that exact DNS SAN, certificate validity, and one pinned
owner bundle are mandatory; clients use no system roots, Kubernetes API CA, DNS-only trust, leaf
pin, plaintext fallback, or alternate server name. The system mounts the owner-private leaf and key;
controllers mount only the read-only CA bundle. A separate controller-TLS staging identity owns both
projections, while the system and controller identities have no read or write API authority over
their source objects and no Secret Manager IAM. Core Kubernetes supplies no general Service serving
certificate, as recorded by its
[CSR signer contract](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#kubernetes-signers).

The CA bundle contains exactly one current root or, only during rotation, the current and next
roots, and its canonical bytes and SHA-256 digest are render-locked. Rotation first stages the
two-root bundle, rolls and proves both controller clients, stages a new valid leaf and key under the
same DNS SAN, rolls and proves the system, then removes the old root and rolls the clients again.
Missing, extra, reordered, expired, or not-yet-valid trust; a leaf outside either root; a changed
SAN; an incomplete overlap; or rollback to a removed root fails readiness and connection
establishment. GKE cluster-credential rotation is a separate Kubernetes-API trust lane and cannot
rotate or appoint this service identity.

After TLS succeeds, one connection carries exactly one request and one response and then closes. The
client writes the exact ASCII magic `KAPSEL-SANDBOX-CONTROLLER-STATE-V1\0`, a two-byte unsigned
big-endian token length, 1 through 16 KiB of token bytes, and exactly one already-defined role
payload frame, then sends TLS `close_notify` for its write direction while retaining its read
direction. The selected port appoints the only allowed role; no role or method is caller-selected
outside that role's payload. The transport reuses each payload codec's literal 64 KiB JSON maximum
and its four-byte length without introducing another payload limit. The server requires
`close_notify` immediately after the complete request before TokenReview or payload dispatch; raw
TCP EOF without it is truncation. On success it writes
`KAPSEL-SANDBOX-CONTROLLER-STATE-ACCEPTED-V1\0`, the exact role response frame, then sends its own
TLS `close_notify`; the client rejects raw EOF or any trailing byte between that exact frame and the
authenticated closure. A fully read, correctly framed TLS request whose authentication fails
receives only `KAPSEL-SANDBOX-CONTROLLER-AUTHENTICATION-REJECTED-V1\0` followed immediately by the
server's TLS `close_notify`. The client returns `authentication_rejected` only for that exact marker
and authenticated closure. Plaintext, TLS, magic, length, oversize, truncation, trailing-byte, and
pre-authentication timeout failures close silently. The client exposes only that fixed local class
or `transport_rejected` for every other TLS, framing, timeout, closure, or malformed-response
failure; neither class includes diagnostic detail. No authentication or transport rejection response
or local error distinguishes token absence, staleness, audience, identity, TokenReview outage, role
mismatch, or framing cause. Authenticated payload dispatch separately retains only its role-specific
fixed response vocabulary, including its bounded payload and state errors.

The client TCP connect deadline is two seconds. TLS handshake is three seconds. Complete request
write/read plus `close_notify` and complete response write/read plus `close_notify` are each five
seconds, with no-progress idle capped at one second. TokenReview is capped at three seconds.
Authenticated payload dispatch and response production are capped at five seconds. One monotonic
absolute deadline of 20 seconds starts when TCP connects; every phase uses the smaller of its phase
remainder and absolute remainder, so a trickled frame or repeated partial I/O cannot restart a
window. One process-wide semaphore permits at most 16 total open connections across both listeners;
a second process-wide semaphore permits at most eight concurrent authenticated dispatches across
both ports. Excess connections close without dispatch. There is no keepalive, retry within a
connection, second request, or protocol negotiation.

TLS acceptance, TokenReview acceptance, connection acceptance, and response transmission are private
orchestration facts only. Rejection, timeout, loss, retry, or outage appends no public event and
changes no KAP-0038 lifecycle, receiver result, frozen receipt, cleanup transition, capacity, or
provider fact. Only an authenticated, fully parsed role payload may call its existing `Service`
transition, and transport failure after that call remains ambiguous rather than undoing or
reclassifying the committed transition.

### Fixed scheduler-state payload contract

The scheduler-state payload is one private adapter over the existing scheduler-owned `Service`
transitions. A payload is a four-byte unsigned big-endian JSON length followed by exactly that many
UTF-8 bytes and no trailing byte. The JSON payload is at most 64 KiB, uses protocol token
`scheduler-state-v1`, and is encoded without insignificant whitespace by the owned codec. Zero,
oversize, truncated, trailing, malformed UTF-8/JSON, duplicate or unknown fields, unknown
operations, and invalid identities, enum values, inventory counts, or lengths fail before dispatch.

Because no scheduler-state endpoint has been deployed or authorized, `scheduler-state-v1` permits
this additive, owner-reviewed operation expansion before its Gate 2 evidence lock. The protocol
token remains `scheduler-state-v1`; the exact codec vectors and both peers change atomically. After
that lock, any incompatible grammar change requires a new token.

The only requests are:

- list active recoverable run identities with their server-owned policy status in durable admission
  order;
- reserve the next FIFO run, active capacity, absolute deadline, initial lease, and handoff verifier
  in one existing transaction;
- recover or renew one exact lease handle;
- read the immutable server-owned provisioning specification for one exact current lease;
- commit one complete policy-verification inventory for that lease;
- read the complete server-derived external resource-slot inventory and immutable registration
  status for one exact current lease;
- append one exact observed UID and cleanup-owner label for one allowed external slot;
- prepare its server-owned private handoff assignment after policy verification and registration of
  the six non-handoff prerequisite slots so the exact handoff channels can be staged, without making
  Application invocation eligible;
- record setup failure either for recorded resources or for the exact no-resource path; and
- append the existing deadline fact for one exact current lease.

The external slot inventory is distinct from the eleven admitted `sandbox-policy-v2` objects. It is
fixed from the run identity and contains exactly these runner-namespace objects, in this order:

1. `PersistentVolumeClaim/kapsel-sandbox-runners/journal-${RUN_ID}`;
2. `ConfigMap/kapsel-sandbox-runners/runner-composition-${RUN_ID}`;
3. `ConfigMap/kapsel-sandbox-runners/runner-kubernetes-${RUN_ID}`;
4. `ConfigMap/kapsel-sandbox-runners/runner-trust-${RUN_ID}`;
5. `ConfigMap/kapsel-sandbox-runners/runner-handoff-${RUN_ID}`;
6. `Secret/kapsel-sandbox-runners/runner-grant-${RUN_ID}`;
7. `Secret/kapsel-sandbox-runners/runner-receipt-signing-${RUN_ID}`;
8. `Secret/kapsel-sandbox-runners/runner-handoff-${RUN_ID}`; and
9. `Pod/kapsel-sandbox-runners/runner-${RUN_ID}`.

The first eight are prerequisite slots. Slots 1 through 4, 6, and 7 must be registered before
handoff assignment is prepared so slots 5 and 8 can be staged, but neither assignment preparation
nor a mounted credential authorizes Application invocation. All eight immutable UID/owner
registrations must exist before the Pod may be created. The accepted Gate 1 Pod fixture remains a
historical lock and is superseded for future runner creation; the later execution renderer must add
exactly `spec.schedulingGates: [{name: "kapsel.dev/ownership-registration"}]`, and gate removal must
be its only allowed scheduling-gate mutation. A Pod with that gate is non-runnable. The Pod
UID/owner registration must exist before gate removal or Application invocation eligibility. The
system-side invocation transaction independently requires all nine registrations, so an early or
compromised credential still fails closed. The per-run runner ServiceAccount remains one of the
eleven policy objects and is not duplicated here. The cluster-owned `kube-root-ca.crt` ConfigMap and
system-wide controller TLS or tombstone staging objects are not per-run cleanup slots.

Wire DTOs are distinct from domain types. A lease handle carries only run identity, lease identity,
epoch, and expiry; it never carries the raw handoff credential. After exact policy verification and
six non-handoff prerequisite registrations, the successful handoff-assignment preparation appoints a
fresh credential and atomically replaces the current lease's stored verifier, but the invocation
handler still requires all nine registrations. The raw credential appears only in that response,
remains redacted from `Debug` and errors, and is never persisted by this adapter.

The external-slot response is bounded to the exact nine entries above. Each entry returns only its
kind, namespace, name, prerequisite classification, and either no observation or its immutable UID
and owner label. Registration accepts no manifest, object body, content, path, timestamp, lifecycle
choice, or cleanup action. Only the current unexpired lease after complete policy-v2 verification
may append. Invocation, terminal projection, or cleanup start forbids new registration. An exact
already-committed replay under the still-current unexpired lease remains idempotent across those
lifecycle advances; changed slot identity, UID, owner, namespace, kind, run, cross-slot UID reuse,
or cross-run UID reuse is denied. Durable expected-but-unregistered slots survive restart and
prevent the no-resource setup path from claiming absence if any registration exists or any fixed
slot might have been created. Idempotent migration backfills pending slots only for active legacy
runs that have not invoked Application. A pre-schema active run whose invocation marker already
exists retains no external slots, because that implementation could not create them, and may only
finish same-operation reconciliation and cleanup; every run dispatched by the migrated schema must
use the nine-slot contract.

The fixed response error vocabulary is `invalid_request`, `not_found`, `busy`, `saturated`,
`deadline`, `denied`, and `unavailable`; it discloses no storage, provider, SQL, Kubernetes,
credential, or receipt diagnostic. Recoverable inventories are bounded by the existing eight-active
limit, policy inventories by a literal maximum of 16 objects, and external slots by exactly nine.
The normal combined cleanup ownership inventory is exactly 20 objects: eleven verified policy
objects plus nine external slots. Failed policy observation may retain immutable ownership evidence
without redefining the eleven-object policy contract; cumulative policy ownership is bounded to 16,
so cleanup ownership and absence inventories are bounded to 25.

This payload contract adds no listener, network endpoint, TLS, bearer-token processing,
`TokenReview`, retry loop, or generic request executor. A later authenticated-encryption transport
with pinned system trust will carry it and obtain operation time outside caller-controlled payload
bytes. Payload parse or authorization failure is private transport state only: it appends no public
event and changes no lifecycle, receiver result, receipt, cleanup state, or provider fact.

### Fixed cleanup-state payload contract

The cleanup-state payload is a separate private adapter over only the existing cleanup-owned
`Service` transitions. It does not share the scheduler-state operation or error vocabulary. A
payload is a four-byte unsigned big-endian JSON length followed by exactly that many UTF-8 bytes and
no trailing byte. The JSON payload is at most 64 KiB, uses protocol token `cleanup-state-v1`, and is
encoded without insignificant whitespace by the owned codec. Zero, oversize, truncated, trailing,
malformed UTF-8/JSON, duplicate or unknown fields, unknown operations, and invalid identities,
states, object counts, or lengths fail before dispatch.

The only requests are:

- list active, eligible, policy-owned cleanup candidates in durable admission order, including each
  exact recorded run identity, cleanup owner, namespace UID, cleanup state, durable start and
  escalation facts, and the kind, namespace, name, UID, and owner label of every recorded object;
- start cleanup for one exact candidate;
- record its one coalesced cleanup failure;
- commit its durable idempotent escalation only when the system-supplied operation time is at least
  15 minutes after the durable cleanup start; and
- complete cleanup only from one exact absent observation for every recorded object, with no
  duplicate, missing, extra, present, or identity-changed evidence.

Wire DTOs are distinct from domain types. Candidate inventories are bounded by the existing literal
eight-active limit and each ownership/evidence inventory by a literal maximum of 25 objects. The
fixed response error vocabulary is `invalid_payload`, `cleanup_missing`, `cleanup_forbidden`,
`cleanup_conflict`, and `state_unavailable`; it discloses no storage, SQL, Kubernetes, receipt,
receiver, or provider diagnostic. Deletion request acceptance is not an operation or evidence value
and can never complete cleanup. Public expiry does not remove an active private candidate, and
capacity remains held until the exact completion transaction succeeds.

This payload contract obtains time outside caller-controlled payload bytes and adds no listener,
network endpoint, authentication, TLS, bearer-token processing, `TokenReview`, retry loop,
Kubernetes behavior, or generic request executor. Payload rejection is private transport state only:
it appends no event and changes no lifecycle, receiver result, frozen receipt, cleanup state, or
provider fact.

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

Transactional scheduler dispatch first reserves active capacity, establishes the absolute deadline,
and appoints one private lease. The scheduler then creates the run's unique namespace and verifies
the complete policy set against exact ownership UIDs and the admitted deployment-policy revision
before creating runner work or invoking Kapsel. A missing, stale, permissive, or unverifiable
control fails closed; it cannot fall back to a shared or ordinary target. This reservation-first
order bounds partially provisioned work; it does not make scheduler dispatch, setup, or lease state
a Kapsel lifecycle or receiver fact.

The admitted `sandbox-policy-v2` revision binds SHA-256 digests of eleven complete, fixed,
server-rendered objects in this order: the run Namespace; the target ServiceAccount; the external
per-run runner ServiceAccount; namespaced runner Role and RoleBinding; ResourceQuota; LimitRange;
default-deny and fixed-DNS-egress NetworkPolicies; the two-container target Deployment; and its
ClusterIP Service. The renderer pins the candidate `gvisor` runtime, Kubernetes `v1.35` Pod Security
baseline, distinct immutable baseline and requested images, exact resources and security context,
and every count below. Its live observer may remove only enumerated Kubernetes-assigned identity,
status, and fixed default fields before requiring normalized equality and recomputing each digest.
Unknown defaults, extra fields, changed ownership, permissive mutations, missing objects, or another
UID fail closed. This revision remains an offline candidate until KAP-0053 binds and proves the
scheduler, RBAC, token audience, key staging, policy enforcement, and complete rendered composition.

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
and supports restoration within the public retention window. A runner may submit those bytes only
through the per-run-authenticated private handoff after `Application` returns the matching frozen
reference; it cannot name a destination path or request re-signing. The public API reads only an
installed immutable object whose digest matches the durable run reference.

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

The offline implementation first proves this as one native `cleanup` reconciler over the private
system database and a concrete in-cluster Kubernetes client. The deployable GKE composition must
preserve the same calls through the fixed cleanup-state protocol above rather than mounting that
database in the controller Pod. It selects only active, eligible, policy-owned records; scans the
fixed runner namespace for the exact cleanup-owner label without name-prefix deletion; rejects every
labeled UID not already recorded; deletes recorded external objects before the exact namespace; and
puts each immutable UID in the API deletion precondition. Delete acceptance never releases capacity.
Every recorded object must subsequently be absent under an exact name/UID/owner observation before
the existing atomic completion transition runs. One `cleanup.failed` event coalesces request,
identity, finalizer, and observation failures while retries continue. Private `started_at` and one
idempotent escalation bit survive restart and become eligible only after 15 minutes. Migration
recovers the start from the durable `cleanup.started` event; a malformed legacy row without that
required event receives epoch zero and is conservatively escalation-eligible rather than retrying
forever. Neither field is public or a receiver fact. The role remains omitted from the incomplete
Gate 2 wrapper until its fixed state adapter, projected tokens, exact RBAC, NetworkPolicy, and
runner-resource UID recording are complete.

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
3. omission or corruption of each required policy fails before runner dispatch or Kapsel invocation;
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
