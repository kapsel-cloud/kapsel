# Public sandbox deployment contract

Status: active KAP-0070 serialized-deployment contract; Contract Correction (Gate 0) is accepted.
Serialized Composition (Gate 1) remains unstarted. No provider, credential, resource, spend, image
push, endpoint, DNS, private live command, or public traffic is authorized.

Kind: design. Authority: ownership, isolation, capacity, durability, key custody, rollback, global
stop, and cleanup for the fixed public sandbox.

Owns: The one permitted native-controller-host composition and the controls that later KAP-0070
gates must prove.

Does not own: A hosting provider, HTTP framework, generic storage/provider/queue interface,
Kubernetes product or version, production deployment, general multi-tenancy, or KAP-0038
lifecycle/result/receipt meaning.

## One active route

The only active deployment route is:

```text
same-origin edge or reverse proxy
  -> one native controller host
       -> one owner-private durable controller volume and one writer
            -> admission SQLite and immutable receipt directory
            -> serial scheduler, durable global stop, retention, and cleanup roles
       -> one separate per-run native runner process
            -> distinct least-privilege OS identity
            -> fresh owner-private gateway journal and receipt outbox
            -> fixed descriptor-relative read-only composition inputs
            -> authenticated KAP-0055 report handoff
            -> real kapsel Application
                 -> one dedicated synthetic Kubernetes cluster
                      -> one policy-complete namespace and target at a time
```

The edge is optional and holds no durable truth. The controller host is one bounded deployment unit,
not a resident product service or generic control plane. The cluster contains no admission database,
receipt store, signing store, controller workload, customer workload, or production credential.

KAP-0069 superseded the Kubernetes-hosted remote controller, split controller-state protocols,
controller-state TLS authority, projected controller credentials, `TokenReview`, Kubernetes key
stagers, runner Pod/PVC composition, concurrent visitor runs, and multi-volume backup generation.
They are history in Git and the task records, not deployable alternatives or KAP-0070 inputs.

The fixed [public `v1` API](SANDBOX_API.md), KAP-0052 admission/projection behavior, and KAP-0055
handoff implementation are retained evidence. Host composition, one-active enforcement, host key
staging, cluster policy, complete backup/restore, fencing, and live isolation are planned KAP-0070
work and are not established merely by this contract.

## Authorization gates

KAP-0070 uses four separately accepted evidence stages after this contract correction:

1. **Gate 1, serialized composition:** deterministic, topology-neutral offline implementation and
   package/image evidence only. It selects no provider and uses no external authority.
2. **Gate 2, reviewed live authorization:** one zero-resource fixture may research and name exact
   provider/runtime/version/region/cost facts. Only separate maintainer approval of that fixture may
   authorize the bounded private experiment.
3. **Gate 3, private live acceptance:** no public application endpoint; prove the exact host,
   cluster, recovery, isolation, cost, teardown, and recreation assertions.
4. **Gate 4, bounded public exposure:** separately approve one accepted revision, endpoint, DNS,
   exposure interval, spend ceiling, stop, rollback, and cleanup owner before traffic.

Passing a gate never authorizes its successor. Gate 0 performs no provider research or command.

## Ownership and authority

| Component or authority        | Must own                                                                                               | Must not own or expose                                                              |
| ----------------------------- | ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| Optional same-origin edge     | TLS termination and additive coarse rate/body rejection                                                | Admission identity, idempotency, result, receipt, capacity, or cleanup truth        |
| Native controller/API         | Exact HTTP translation, durable admission and projection, local role dispatch                          | KAP-0038 classification, arbitrary Kubernetes input, public fault control           |
| Controller volume/writer      | Admission SQLite, immutable receipts, capacity, stop, leases, ownership inventory, deployment metadata | A generic state API, shared runner write access, key payloads in SQLite or receipts |
| Serial scheduler role         | FIFO bounded queue, one-active reservation, fresh lease, fail-closed dispatch and restart recovery     | Receiver meaning, unbounded retry, caller lifecycle input                           |
| Per-run runner identity       | Fixed `Application` execute/reconcile, its journal/outbox, authenticated handoff                       | Controller volume, other/prior journals, cleanup authority, caller-selected inputs  |
| Runner Kubernetes credential  | Read the fixed target facts and submit only the exact conditional mutation                             | Cleanup, namespace creation, arbitrary patch, another object or namespace           |
| Cleanup Kubernetes credential | Observe/delete only the complete recorded UID/owner inventory and prove absence                        | Mutation, name-only deletion, receiver-result changes                               |
| Target identity               | Run the fixed synthetic image under the policy-complete boundary                                       | Kubernetes API, host, key, controller, runner, receipt, or cleanup authority        |
| Backup identity               | Read the fixed crash-consistent unit and restore only while fenced                                     | Serving, mutation, admission, key export, a second runnable copy                    |
| Key-staging identity          | Install fixed authorization, receipt, tombstone, and public-trust inputs                               | Operation, scheduling, cleanup, public disclosure, generic secret access            |
| Operator identity             | Canary ownership, stop/rollback/teardown approval and bounded evidence access                          | Visitor operation input or implicit day-to-day runner authority                     |
| Dedicated cluster             | One synthetic target namespace plus operator canary and required policy                                | Customer/production work, controller state, signing/store workloads                 |

Controller, runner, cleanup, target, backup, key-staging, and operator authorities are fixed and
separate. Scheduler, retention, and cleanup call concrete local `Service` transitions; they do not
open a remote state endpoint. Exactly one process is the controller-state and immutable-receipt
writer. A compromised controller host remains a concentrated security and availability risk.

## Durable identity and serial capacity

Before admission succeeds, one controller-state transaction establishes the unpredictable `run_id`
and idempotency mapping, fixed scenario and operation identity, admission/expiry times, initial
event, queue reservation, frozen policy identity, cleanup ownership, and maximum deadline. The
admission database is never the KAP-0038 journal and cannot reconstruct or reinterpret gateway
facts.

The public queue maximum remains 32. The active maximum is exactly one. Admission also retains the
public API's per-source rate, 512-byte body, 64-event, 64-KiB response, 128-connection, and
64-in-flight transport bounds. The KAP-0055 handoff separately retains 16 connections, eight
handlers, a five-second absolute receive deadline, and a 30-second response deadline. These bounds
are independent: transport availability neither reserves nor releases execution capacity.

One active reservation is held from dispatch until all applicable facts are durable:

- `Application` is terminal or the exact `not_attempted` report is committed;
- the terminal report and, when finalized, frozen receipt bytes completed authenticated handoff;
- operation, deadline, transport, and receipt-availability facts were projected separately;
- cleanup has observed absence of every exact recorded UID/owner object; and
- runner authority is revoked, the process is absent, and the journal/outbox reached its owned
  retention handoff.

No subsequent run dispatches before that release transaction. A cleanup failure or stuck finalizer
therefore holds capacity; it never changes the receiver result. Saturation and durable global stop
fail before admission and preserve exact existing `v1` error bytes.

Ordinary dispatched work retains the admission-frozen 180-second absolute deadline. Public state and
idempotency mapping retain the exact 24-hour lifetime and the minimal tombstone a further 24 hours.
A gateway journal is deleted within one hour after finalized report plus verified receipt handoff,
or after durable `not_attempted` projection and cleanup handoff; pre-Application `service_failed`
has no gateway-journal requirement. Cleanup escalates once its bounded retry window reaches 15
minutes. Recovery work may outlive public expiry without restoring public visibility.

Gate 1 must lock finite CPU, memory, controller-volume bytes, journal/outbox bytes, receipt bytes,
connections, event count, retry count, cleanup duration, retained aggregate bytes, and object-count
ceilings for one host and one cluster. Gate 2 must lock every fixed and metered cost class, maximum
experiment spend, and teardown reserve. Missing or exceeded resource/cost configuration fails
closed; budget alerts are observations, not admission controls.

## Runner boundary and retained handoff

Every dispatch generation creates a fresh run directory owned by a distinct least-privilege OS
identity. The directory contains only one KAP-0038 gateway journal, its lock/rollback files, and the
private receipt outbox. The runner has no path, descriptor, mount, group access, or environment
reference to controller SQLite, system receipts, backup snapshots, other or prior run directories,
or unrestricted key sources.

The controller opens each fixed request, grant, authorization trust, receipt-signing input,
Kubernetes input, handoff credential, and public-trust input descriptor-relatively beneath its
expected owner-private directory. Every component is a fixed name and regular file, with exact owner
and mode, no symlink traversal, no parent replacement, no writable runner source, and a same-inode
check across open. The runner receives read-only descriptors; it does not discover paths, accept
composition through arguments/environment, or choose a destination. A stale descriptor, process,
lease, credential, owner, generation, or replaced input fails before `Application` lifecycle work.

The exact KAP-0055 private TCP framing, message grammar, connection/deadline bounds, credential
verifier, lease rotation, durable `application_invoked` marker, report binding, and acknowledgments
remain authoritative and unchanged. The endpoint is bound to one owner-private host interface, has
no discovery or public route, and carries one four-byte big-endian body length plus one canonical
body of at most 20 KiB. A body has its exact ASCII magic (including final zero), then strictly
increasing one-byte field numbers, four-byte big-endian lengths, and exact field bytes. Unknown,
duplicate, missing, reordered, truncated, trailing, non-ASCII, zero-length, or oversized framing
fails before mutation. Common fields are the 32-lowercase-hex `run_id`, `sandbox-` plus that ID,
32-lowercase-hex lease ID, and 32 raw credential bytes. It carries only:

- magic `KAPSEL-SANDBOX-APPLICATION-INVOKED-V1\0` and common fields for `application_invoked`;
- magic `KAPSEL-SANDBOX-APPLICATION-REPORT-V1\0`, common fields, variant `not_attempted`, and
  exactly `DEPLOYMENT_NOT_FOUND`, `CONTAINER_NOT_FOUND`, or `INVALID_TARGET`, with no receipt or
  receiver result; or
- that report magic, common fields, variant `finalized`, exactly `SUCCEEDED`, `FAILED`, or
  `UNKNOWN`, the 64-lowercase-hex SHA-256 digest, and 1 through 16 KiB of exact frozen receipt
  bytes. The controller recomputes the digest before mutation.

Success uses the corresponding exact `KAPSEL-SANDBOX-APPLICATION-INVOKED-ACK-V1\0` or
`KAPSEL-SANDBOX-APPLICATION-REPORT-ACK-V1\0` magic with run, operation, lease, and `committed`; it
never echoes the credential or result. Semantic/authentication rejection is exactly
`KAPSEL-SANDBOX-HANDOFF-REJECTED-V1\0`; framing/deadline failure may close silently. The raw
credential is never stored: controller state stores only the domain-separated SHA-256 verifier.
Every generation rotates lease and credential atomically, clears the verifier when inactive, and
binds the first terminal semantic payload and exact receipt bytes idempotently. The listener retains
16 connections, eight handlers, a five-second absolute trickle-resistant receive deadline, and a
30-second response deadline. Missing or lost acknowledgment remains ambiguous and cannot classify an
outcome.

The runner calls `Application::execute` only when the durable invocation/journal state proves first
execution. Ambiguous acknowledgment or any gateway state requires `Application::reconcile` for the
same operation. Loss before invocation, after its durable acknowledgment, after `apply_started`,
after terminal report, or on either side of receipt publication must converge without a blind second
mutation. An old process is killed and its OS identity, lease, descriptors, and credential are
revoked before replacement can run. At most one runnable journal and runner generation exists.

## Cluster and conditional operation

Exactly one policy-complete run namespace may exist in the dedicated synthetic cluster. Before
`Application` invocation the controller verifies the complete admission-frozen inventory and exact
content for namespace ownership, runtime boundary, target and service accounts, runner/cleanup RBAC,
quota, limits, default-deny and explicitly allowed network policy, metadata denial, immutable image,
deadline, canary separation, and object-count ceiling. Missing, stale, permissive, substituted,
extra, or fallback policy fails closed. A sandboxed runtime or independently equivalent boundary and
actual network enforcement require Gate 3 evidence; namespace manifests alone are insufficient.

The runner credential may submit one conditional strategic merge patch only when namespace,
Deployment name, Deployment UID, owner, resource version, named container, and current image match
verified preconditions. The patch may replace only that container image with the server-selected
immutable digest and add or preserve the required `kapsel.dev/kap0038-operation-id` Deployment
annotation. The annotation is the sole metadata exception required for KAP-0038 recovery. Every
other annotation, field, container, image, owner, security setting, volume, account, and object
remains unchanged. Conflicts fail without forcing or blind retry.

The target carries no Kubernetes or host authority. The runner and the most compromised target
posture must be denied metadata, other namespaces, the operator canary, unrelated objects, cleanup
actions, controller host/state/receipts, key sources, volumes, backup state, prior journals, and
arbitrary network destinations. Serialization replaces simultaneous visitor-run evidence with these
canary and prior-run temporal checks. It does not claim hard tenant isolation.

## Host-owned key and trust staging

Authorization-grant signing input, receipt-signing input, tombstone-digest input, and public receipt
trust are four distinct fixed authorities. Kubernetes runner and cleanup credentials are also
separate fixed inputs. The target receives none of them. Receipt retrieval never appoints trust;
inspection uses the separately staged public trust, explicit time, and explicit limits.

Gate 1 must define for each staged input one exact source identity and schema, destination directory
and filename, installing identity, consuming identity, owner, group prohibition, mode, maximum byte
size, no-follow/same-inode checks, refresh trigger, outage behavior, rotation overlap, restart
behavior, and deletion rule. Installation is atomic and fail-closed. A missing, stale, malformed,
permissive, linked, replaced, or wrong-owner input blocks the dependent transition without changing
an existing receiver result.

Private key, credential, request, locator, receipt, journal, and trust-decision payloads never enter
arguments, environment, public fields, controller SQLite, generic diagnostics, access/provider logs,
committed evidence, or a backup outside the exact crash-consistent unit. Rotation never re-signs or
rewrites frozen receipts. An outage preserves stopped admission, retained reads, recovery from
already durable facts, receipt retrieval, expiry, and cleanup to the extent their distinct fixed
authorities remain available. Gate 3 must prove each denial, outage, rotation, and non-disclosure
rule; this contract does not claim managed or non-export key custody.

## Receipt, result, and public projection

Only the unchanged real KAP-0038 `OperationReport` may populate `not_attempted` or a receiver
result. `SUCCEEDED`, `FAILED`, and explicit `UNKNOWN` retain the KAP-0038 classifier meaning. HTTP
success, queue/lease state, request acceptance, runner exit, handoff timeout, sandbox deadline,
cleanup, receipt availability, inspection, and visualization cannot manufacture or alter those
values.

The controller installs exact frozen receipt bytes once in its immutable receipt directory, checks
the digest, and then commits availability. It never decodes, redacts, relocates, replaces, or
re-signs them. Report binding survives restart. `not_attempted` and pre-Application `service_failed`
remain receipt-free. Public operation transition, report/receipt publication, deadline event,
handoff transport, cleanup state, retention, and capacity release are separate durable facts even
though runs are serialized.

## Global stop and local roles

One owner-private controller-state row is the durable global stop. Its authenticated operator path
is fixed and non-public. Activation atomically blocks new admission; restart or ambiguity fails
closed. Stop does not revoke admitted authority or block existing projection reads, operation
recovery, exact receipt retrieval, retention deletion, or UID-safe cleanup. Host-process or host
replacement failure must preserve this behavior through fenced restore; a stopped or absent process
is not itself durable stop evidence.

Scheduler, retention, receipt publication, and cleanup are explicit local roles over concrete
bounded `Service` transitions. They cannot execute arbitrary SQL or widen lifecycle/result
vocabulary. Restart-before-serve runs fencing, restore validation, expiry/tombstone deletion,
pending receipt convergence, active journal reconciliation, stale-process denial, ownership scan,
and cleanup before admission readiness.

## UID- and owner-safe cleanup

The controller keeps an append-only inventory of every owned cluster object with kind, namespace,
name, immutable UID, and owner marker. The cleanup credential observes and deletes external objects
before their namespace, only when UID and owner both match. A reused name, wrong UID/owner,
unrecorded object, unavailable API, or stuck finalizer fails closed and retries durably. The
operator-owned canary and unrelated resources are never cleanup candidates.

Cleanup success requires a fresh absence observation for every inventory row, no remaining owned
orphan, namespace absence, revoked runner credential, terminated runner process, and the journal
retention handoff. A confirmed pre-creation failure may use the existing explicit
confirmed-no-resource path; it cannot invent absence evidence. Public expiry and client abandonment
never release cleanup ownership or capacity. The 15-minute escalation is an operator fact, not a
receiver outcome or permission for unsafe deletion.

## Crash-consistent backup, restore, and rollback

There is exactly one backup unit for the controller host. One generation captures, as one
crash-consistent identity:

- admission/idempotency/projection/tombstone state and durable global stop;
- immutable receipt objects and pending publication ownership;
- the one active gateway journal, lock-relevant generation, and receipt outbox when present;
- queue and exactly-one active capacity accounting, lease generation and revocation state;
- the complete append-only UID/owner inventory and cleanup/escalation state;
- host bundle/configuration and deployment metadata needed to identify compatible bytes; and
- the required public receipt trust and its version identity.

Private signing seeds and Kubernetes credentials are not copied into this unit; their separately
owned continuity source is referenced by fixed identity only. No diagnostics or secondary backup may
copy the unit's request, locator, receipt, or journal payload.

Backup creation records one generation while the sole writer is quiesced or uses an equivalently
proved atomic capture. Restore requires the original writer and runner fenced and destroyed, the
controller volume unavailable to them, one replacement writer identity, compatible bundle and trust,
and exactly one runnable active journal. A backup is never mounted or served in parallel. Before
readiness, restore verifies every component/digest/owner/mode, reapplies public expiry and tombstone
deletion, removes stale diagnostics and due journals, reconciles pending receipts and the one active
operation, resumes cleanup from the exact inventory, and refuses duplicated identity, capacity,
receipt, or runnable journal state.

Deterministic Gate 1 and private Gate 3 restore matrices cross durable admission before dispatch,
after dispatch before `apply_started`, the ambiguous provider window, receiver terminal before
receipt publication, both sides of receipt publication, and UID-safe cleanup. After `apply_started`,
restore observes and preserves `UNKNOWN` when evidence is insufficient; it never blindly mutates.
Rollback uses the last compatible exact host bundle and state, keeps global stop active, preserves
retained reads and frozen receipts, and reconciles the one active operation. Endpoint/visualization
rollback remains separate from operation, host/state/cluster rollback, and cleanup.

Teardown activates stop, drains or recovers the admitted run, completes UID-safe cleanup, deletes
the cluster and host resources in owned dependency order, proves complete inventory absence, and
removes private evidence under its retention rule. Gate 3 must perform clean creation, teardown to
zero, recreation and smoke, second teardown to zero. Failure to fence, restore-before-serve, delete,
or recreate activates KAP-0070's retirement rule rather than another topology.

## Gate 0 preservation and live proof map

“Retained now” below means accepted implementation evidence that must continue passing while the
serialized composition is built. “Planned” means this contract selects the production path but no
host/provider/live enforcement claim exists yet.

| KAP-0069 essential property                                                       | Owner                                       | Selected production path and present classification                                                                      | Gate 0 deterministic preservation                                                                                             | Later assertion                                                                                 |
| --------------------------------------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Durable opaque identity, idempotency, reconnect/replay, receipt retrieval         | API; this deployment; Privacy               | Retained KAP-0052 admission SQLite and immutable receipt logic; planned owner-private host volume                        | `test-sandbox-contract`, `test-sandbox-service`, package-boundary deletion proof                                              | Gate 1 crash/reopen; Gate 3 host loss/restore; Gate 4 lost response and reconnect               |
| Fixed scenarios and server-owned authority                                        | API; this deployment                        | Retained request-only composition; planned fixed host staging and separate role credentials                              | Contract fixtures, service authority negatives, runner handoff negatives                                                      | Gate 1 descriptor/policy matrix; Gate 3 runner/target denials; Gate 4 fixed scenarios           |
| One conditional real `Application` mutation and exact result vocabulary           | KAP-0038; this deployment                   | Retained real `Application`, classifier, receipt and exact patch harness; planned cluster admission enforcement          | Contract bytes, service path, runner handoff, root package after sandbox deletion                                             | Gate 1 normalized patch denial; Gate 3 exact patch and `UNKNOWN`; Gate 4 both scenarios         |
| Runner loss and same-operation reconcile                                          | KAP-0038; KAP-0055; this deployment         | Retained KAP-0055 protocol/process proofs; planned OS identity, stale-process fencing                                    | `test-sandbox-runner-handoff` at all accepted seams                                                                           | Gate 1 host kill/no-follow; Gate 3 seam kills; Gate 4 approved runner kill                      |
| Admission/rate/queue/active/resource/deadline/retention/cost bounds               | API; this deployment                        | Retained 32-queue/rate/transport/event/deadline/retention mechanisms; planned active=1 and finite host/cluster/cost lock | Fixtures and service saturation/deadline/retention tests, plus topology-neutral one-active preservation lane when implemented | Gate 1 exact resource bounds; Gate 3 burst/cost measurement; Gate 4 configured ceiling          |
| Durable global stop                                                               | This deployment; Threat model               | Retained native durable stop semantics; planned local-role and replacement-host continuity                               | Service stop/read/recovery/cleanup tests in topology-neutral preservation lane                                                | Gate 1 restart/role tests; Gate 3 dependency-loss stop; Gate 4 public-boundary stop             |
| Minimal disclosure and temporal isolation                                         | API; Privacy; Threat model; this deployment | Retained public field/log negatives; planned OS/path, prior-run, canary, runtime/network denials                         | Fixture/service/handoff disclosure and stale credential tests                                                                 | Gate 1 path/canary model; Gate 3 adversarial runner/target denial; Gate 4 disclosure inspection |
| UID-safe cleanup, retention, backup/restore, restart/rollback/teardown/recreation | This deployment; Privacy                    | Retained inventory/absence/retention transitions; planned one-unit backup, fencing and exact recreation                  | Service UID/owner/absence and retention tests; topology-neutral backup model tests when implemented                           | Gate 1 restore matrix; Gate 3 teardown/recreation twice; Gate 4 rollback/cleanup recovery       |
| Operation, receipt, deadline, transport, cleanup, visualization remain separate   | KAP-0038; API; this deployment              | Retained exact projection/report/handoff semantics; planned serialized transition composition                            | Exact fixtures, service transitions, runner receipt byte identity                                                             | Gate 1 crash matrix; Gate 3 independent failures; Gate 4 consumer rendering/retrieval           |

Gate 0 accepted this map after the exact public fixtures, topology-neutral preservation, retained
service and handoff lanes, root package deletion boundary, formatting, links, the full repository
gate, and independent architecture/security review passed. No row treats historical provider
configuration or Kubernetes-hosted controller composition as preservation evidence.

## Acceptance and non-claims

A KAP-0070 deployment is acceptable only when one exact revision proves all selected controls at its
separately authorized gate, complete teardown and recreation pass twice, and no duplicate route is
runnable. If a mandatory property requires concurrent runs, remote controller state, a generic
provider/storage/queue seam, broader caller authority, customer data, production credentials,
unbounded key export, unproved runtime/network enforcement, an unowned cost, or a larger unapproved
cleanup/spend window, stop and retire the hosted proof.

The sandbox proves at most one bounded synthetic demonstration. It does not prove exactly-once
mutation, Kubernetes truth, causation, complete capture/history, independent witnessing, anonymity,
hard tenant isolation, production safety, production availability, commercial viability, or a future
resident interface.
