# Public sandbox deployment contract

Status: active KAP-0070 serialized-deployment contract; Contract Correction (Gate 0) and Gate 1
Slices 1–3 and the focused Slice 2 runner-hardening follow-up are accepted. Gate 1 Slice 4 offline
fixed input/key staging is explicitly authorized. No provider, credential, resource, spend, image
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
handoff implementation are retained evidence. Gate 1 Slice 1 implements one-active enforcement and
concrete process-local scheduler, retention, and cleanup role sequencing. Accepted Slice 2 uses one
fixed reviewed C pre-exec helper, individual `SCM_RIGHTS` input descriptors, fresh crash-convergent
generations, and a private cgroup-v2 process-tree boundary. Its durable allocation/restart record,
production controller composition, denial matrix, exact Linux gate, both-sided publication seams,
and fresh reviews passed. Accepted Slice 3 compiles the deterministic provider-neutral cluster-
policy, conditional-mutation, fixed-authority bounded cleanup, atomic runner retirement, and fail-
closed static policy composition. Host key staging, complete backup/restore, and live isolation
remain planned KAP-0070 work; deterministic records do not establish live Kubernetes enforcement.

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
- runner authority is revoked, the process/cgroup is absent, the journal/outbox reached its owned
  retention handoff, and the fenced generation is explicitly retired before capacity release.

No subsequent run dispatches before that release transaction. The implemented serial scheduler
recovers the sole active reservation before considering the oldest queued run; reopen and dispatch
refuse multiple, noncanonical, inconsistent, or missing capacity ownership rows, and restart waits
for an unexpired foreign lease. A cleanup failure or stuck finalizer therefore holds capacity; it
never changes the receiver result. Saturation and durable global stop fail before admission and
preserve exact existing `v1` error bytes.

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
Kubernetes input, and handoff input descriptor-relatively beneath its expected owner-private
directory. Public receipt trust remains controller inspection/publication authority and is not a
runner input. Every runner component is a fixed name and regular file, with exact owner and mode, no
symlink traversal, no parent replacement, no writable runner source, and a same-inode check across
open. The runner receives each individually pinned read-only descriptor through one fixed Unix
`SCM_RIGHTS` message; bootstrap metadata contains identities and bounds, never copied input payloads
or composition paths. It accepts no composition through arguments/environment and chooses no
destination. A stale descriptor, process, lease, credential, owner, generation, or replaced input
fails before `Application` lifecycle work.

On Linux, one fixed non-Rust pre-exec helper is part of the bound host executable set. Before the
Rust runner runtime, it clears supplementary groups, installs exact real/effective/saved UID and
GID, closes every descriptor except bootstrap, state, and the pinned executable, closes the
parent-death race, and enables `no_new_privs`. The controller places the still-authority-blocked
child in one fresh deployment-owned cgroup-v2 generation before sending descriptors. Replacement
writes `cgroup.kill`, waits for `populated 0`, verifies the recorded PID/start identity is absent,
and only then releases a successor. Missing writable cgroup-v2 delegation fails closed;
process-group or direct-child kill is not a fallback.

The runner-hardening follow-up freezes the controller/helper bootstrap as exact
`effective=permitted=bounding={CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_KILL,CAP_SETGID,CAP_SETUID,CAP_SETPCAP,CAP_SYS_ADMIN}`
and `inheritable=ambient={}`; `CAP_NET_RAW` is the hostile representative. One fixed first helper
stage rejects file capabilities and normalizes unlocked parent authority to that state. The second
stage rechecks both pinned executables, verifies the bootstrap state before mount/identity work,
drops the entire bounding set, installs the runner UID/GID, clears all other capability sets, sets
`no_new_privs`, and verifies securebits and all five sets are exactly zero before a final runner
file-capability check and exec. The Rust runner independently checks `/proc/self/status` before
receiving descriptors. Linux's capability subset rules require the effective case also to carry the
representative in permitted and the ambient case also in permitted/inheritable; the finite matrix
names each target set separately and covers unlocked and locked `KEEP_CAPS`/`NO_SETUID_FIXUP`. A
file capability present at any check fails closed. A privileged parent can still race an xattr
change between a check and exec; zero bounding/permitted/effective sets, `no_new_privs`, and the
Rust backstop contain that race rather than establishing independence from that parent.

The private mount namespace prevents propagation and gives the runner a fixed `/run/kapsel-sandbox`
state alias; it does not hide the rest of the host filesystem or provide hard filesystem isolation.
This follow-up selects no seccomp, Landlock, or equivalent restriction. The remaining native
syscall/path surface is an explicit non-claim and Gate 3 adversary. The pinned Linux lane binds the
exact C-source digest, compiler/toolchain identity, helper digest, and runner digest as Slice 6
inputs without assembling the final bundle. The accepted Slice 2 evidence proves its named
descriptor, identity, parent-death, capability, cgroup, and recovery assertions, but not hard
filesystem isolation, syscall/path confinement, or a complete least-privilege process boundary.

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
revoked before replacement can run. Retained recovery state is accepted only for the same run and
operation before any launch side effect. After terminal or `not_attempted` handoff, the controller
atomically commits revocation, process absence, journal handoff, verifier clearing, and durable
retirement intent, then removes that run's fenced journal/outbox and durable generation record, and
finally commits runner-state retirement before cleanup may release capacity. On restart, the
controller converges the sole active retiring or retired run before scheduler lease recovery, grants
no authority during that preflight, and fails closed if active capacity is not singular. It
therefore completes an interrupted intent without launching the terminal run again under either an
unexpired or expired prior lease. A different run fails closed while any retained state exists. At
most one runnable journal and runner generation exists.

Recovery and retirement permit at most four generation-root entries: the canonical durable record,
its atomic-write temporary record, the recorded generation, and one adjacent generation used only
while moving the same run directory. Enumeration fails closed before processing a fifth entry. Once
the durable record advances, every older generation directory must be empty and is removed
descriptor-relatively; any older journal, outbox, or other content fails closed rather than being
deleted as obsolete state. This bound covers allocation, preparation, fencing, retirement, and their
atomic-record crash sides without treating the generation root as a generic store.

## Cluster and conditional operation

### Slice 3 scope and compatibility profile

Slice 3 freezes one deterministic provider-neutral model. It performs no provider, registry, image,
credential, cluster, endpoint, DNS, or network action. The later Gate 2 fixture must select a
cluster that implements the stable `v1`, `apps/v1`, `rbac.authorization.k8s.io/v1`,
`networking.k8s.io/v1`, and `node.k8s.io/v1` resources used by the model, the exact ResourceQuota
count keys below, Pod Security `restricted` version `v1.35`, UID-preconditioned deletion, immutable
UID/resource-version facts and one admission implementation for the three closed rules below. This
is a required behavior profile, not a provider or Kubernetes-version selection.

The dedicated cluster contains no customer or production workload and permits one run namespace at a
time. Its exact runtime-class name and handler are `kapsel-sandbox-runtime-v1` and
`kapsel.dev/sandbox-runtime-v1`; its fixed network-enforcement evidence identity is
`kapsel-sandbox-network-v1`. The three exact admission rules are `composition-v1`,
`conditional-operation-v1`, and `cleanup-v1`. Their checked-in canonical provider-neutral behavior
records are respectively `deploy/sandbox/composition-admission-rule.json`,
`operator-admission-rule.json`, and `cleanup-admission-rule.json`; `network-boundary-record.json`
closes the separate network evidence identity. They are not Kubernetes objects. Their exact bytes
and SHA-256 digests are deployment inputs, and Gate 2 must map each record and the network identity
to one enforced implementation without fallback. The controller verifies one bounded
`ClusterBoundaryEvidence` containing the runtime object UID and canonical digest, network
identity/readiness digest, all three admission-rule digests, baseline digest, and canary UIDs before
each run. Missing, renamed, unready, stale, or multiply mapped runtime, CNI, admission, account, or
policy evidence blocks provisioning. These records and rendered objects are not live enforcement
evidence; Gate 3 must prove the selected implementations.

### Closed cluster inventory and bootstrap

Policy revision `sandbox-policy-v3` owns three disjoint inventories. Every Kapsel-created object
carries exact labels `kapsel.dev/policy-revision=sandbox-policy-v3` and
`kapsel.dev/sandbox-owner=<owner>`. Server-created `default` ServiceAccounts are verified to have no
binding and are never used by a Pod, but are system-owned rather than relabelled or inventoried.

A separately gated `kapsel-sandbox-bootstrap` operator creates the immutable baseline in this order:
the RuntimeClass; the three authority Namespaces; ServiceAccounts `kapsel-sandbox-provisioner`,
`kapsel-sandbox-runner`, and `kapsel-sandbox-cleanup` in their corresponding Namespaces; the two
ClusterRoles; then their two bindings. It then creates and verifies the canary Namespace and
ConfigMap before recording readiness. Bootstrap verifies exact content and is absent during service
operation. The runtime provisioner cannot create, update, patch, bind, escalate, or delete a
RuntimeClass, ClusterRole, ClusterRoleBinding, baseline Namespace, baseline ServiceAccount, canary,
or admission-rule record.

| Inventory                  | Exact Kapsel-owned objects and canonical content                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Count and owner                                                                                                             |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Immutable cluster baseline | `RuntimeClass/kapsel-sandbox-runtime-v1` with handler `kapsel.dev/sandbox-runtime-v1` and no overhead or scheduling; Namespaces `kapsel-sandbox-provisioner`, `kapsel-sandbox-runners`, and `kapsel-sandbox-cleanup`; ServiceAccounts `kapsel-sandbox-provisioner`, `kapsel-sandbox-runner`, and `kapsel-sandbox-cleanup` in their corresponding Namespaces with `automountServiceAccountToken=false`; ClusterRoles and ClusterRoleBindings `kapsel-sandbox-provisioner-v1` and `kapsel-sandbox-cleanup-v1` with the exact rules and subjects below | Exactly 11. Owner `kapsel-cluster-baseline`. Never visitor cleanup candidates. Any drift blocks readiness.                  |
| Operator canary            | `Namespace/kapsel-sandbox-canary`; `ConfigMap/kapsel-sandbox-canary/isolation-canary` with exact data `sentinel=kapsel-sandbox-canary-v1`                                                                                                                                                                                                                                                                                                                                                                                                           | Exactly 2. Owner `kapsel-operator-canary`. Never a provisioning, mutation, or cleanup candidate.                            |
| One run                    | The ten explicit objects below plus at most two live Deployment-owned ReplicaSets and one live Pod                                                                                                                                                                                                                                                                                                                                                                                                                                                  | At most 13 live Kapsel-owned objects. Owner `cleanup-<run_id>`. Every observed run UID is an append-only cleanup candidate. |

The peak modeled composition is 31 live objects: 26 Kapsel-owned objects plus the five
server-created `default` ServiceAccounts for the baseline, canary, and run Namespaces. At most ten
are cluster-scoped: one RuntimeClass, two ClusterRoles, two ClusterRoleBindings, and five
Namespaces. The append-only per-run cleanup inventory is independently bounded to 64 unique UIDs
over the 180-second run and cleanup lifetime. Exceeding it fails closed, holds capacity, and
escalates; it never authorizes name-only deletion. Gate 2 must inventory unavoidable
provider-managed objects separately; they cannot carry a Kapsel owner label or become visitor
cleanup candidates.

The provisioner ClusterRole has exactly these rules: `get/list` RuntimeClasses, ClusterRoles,
ClusterRoleBindings, baseline/canary Namespaces and their fixed ServiceAccounts, and the canary
ConfigMap; `get/list/create` Namespaces; `get/list/create` ServiceAccounts, ResourceQuotas,
LimitRanges, Roles, RoleBindings, NetworkPolicies, and Deployments; `get/list` ReplicaSets and Pods;
and the minimum `bind/escalate` authority for Roles named `sandbox-runner` and `sandbox-cleanup`.
The composition admission rule reduces that temporary union authority to one canonical run inventory
and rejects every baseline/canary change. After the final full observation, the controller durably
closes the provisioning generation, revokes its raw credential, and admission rejects every further
run create/update before runner authority or cleanup can proceed.

The fixed runtime accounts are
`system:serviceaccount:kapsel-sandbox-provisioner:kapsel-sandbox-provisioner`,
`system:serviceaccount:kapsel-sandbox-runners:kapsel-sandbox-runner`, and
`system:serviceaccount:kapsel-sandbox-cleanup:kapsel-sandbox-cleanup`. The run Role `sandbox-runner`
permits exactly `get/patch` on `deployments.apps` with `resourceNames=["sandbox-target"]`. The run
Role `sandbox-cleanup` permits `get/list/delete` only for the explicit run inventory and
Deployment-generated children. It has no Secret, ConfigMap, Service, EndpointSlice, PVC, or Job read
authority. Exact ResourceQuota counts and fail-closed admission establish the forbidden-kind zero
facts without granting either runtime role payload read authority. Admission denies later creation
throughout cleanup, so payload-bearing kinds are never exposed to the cleanup role. The fixed
cleanup ClusterRole permits `get/delete` Namespaces and `get/delete` Roles and RoleBindings with
`resourceNames=["sandbox-cleanup"]`; `cleanup-v1` rejects any delete without the exact closed
cleanup epoch, namespace, owner, revision, and UID precondition. It grants no list of cluster-scoped
objects. The cleanup subject is the fixed cleanup account. The target ServiceAccount has no Role or
binding and receives no API token.

The three admission rules fail closed and have no audit-only action. `composition-v1` permits only
the bootstrap baseline, operator canary, one canonical provisioner generation, exact Deployment-
controller children derived from its owner references and Pod template, and cleanup deletes; it
rejects runtime fallback, default-account Pod use, token automount, extra fields/objects, and any
baseline/canary mutation by a runtime identity. `conditional-operation-v1` accepts only the exact
old/new Deployment comparison below from the fixed runner account. `cleanup-v1` accepts only exact
UID-preconditioned deletion of a recorded object after provisioning and runner generations are
closed. The focused rule fixtures are the normative canonical behavior records; Gate 2 owns their
mapping to one concrete admission implementation.

### Exact run namespace inventory

For run `<run_id>`, the namespace is `sandbox-<run_id>`, the cleanup owner is `cleanup-<run_id>`,
and every explicit object is canonical JSON rendered by the compile-time policy module in this exact
semantic order:

1. Namespace with the run, cleanup-owner, policy-revision, and Pod Security
   `enforce=restricted`/`enforce-version=v1.35` labels;
2. `ServiceAccount/sandbox-target` with `automountServiceAccountToken=false`;
3. `Role/sandbox-runner` and `RoleBinding/sandbox-runner` for the fixed runner account and exact
   Deployment `get`/`patch` authority;
4. `Role/sandbox-cleanup` and `RoleBinding/sandbox-cleanup` for the fixed cleanup account and the
   exact metadata scan and recorded-object deletion rules above;
5. `ResourceQuota/sandbox-quota` with exact hard keys and values: `count/deployments.apps=1`,
   `count/replicasets.apps=2`, `pods=1`, `count/serviceaccounts=2`,
   `count/roles.rbac.authorization.k8s.io=2`, `count/rolebindings.rbac.authorization.k8s.io=2`,
   `count/resourcequotas=1`, `count/limitranges=1`, `count/networkpolicies.networking.k8s.io=1`,
   `count/configmaps=0`, `count/secrets=0`, `count/services=0`,
   `count/endpointslices.discovery.k8s.io=0`, `count/jobs.batch=0`, and
   `count/persistentvolumeclaims=0`; aggregate requests are CPU `200m`, memory `64Mi`, ephemeral
   storage `32Mi`, and limits are CPU `500m`, memory `128Mi`, ephemeral storage `128Mi`;
6. `LimitRange/sandbox-limits`, requiring each container to request at least CPU `10m`, memory
   `16Mi`, and ephemeral storage `1Mi`, and limiting each to CPU `250m`, memory `64Mi`, and
   ephemeral storage `64Mi`;
7. one `NetworkPolicy/default-deny` selecting every Pod with both `Ingress` and `Egress` policy
   types and no allow rules; and
8. `Deployment/sandbox-target` as frozen below.

There is no Service, DNS allowance, ConfigMap, Secret, volume, init container, ephemeral container,
or other run object. The system-owned `default` ServiceAccount may exist only without a RoleBinding;
admission rejects every Pod that names it or enables token automount. ResourceQuota limits live
Deployment children to two ReplicaSets and one Pod, but does not claim a lifetime UID ceiling. Every
child seen during provisioning, mutation observation, cleanup selection, or the fixed owner-marker
scan is appended by exact UID; a final scan appends every then-live child before deletion.
Historical rows already absent are valid absence facts. More than 64 unique rows fails closed and
holds capacity.

Cleanup uses exact UID-preconditioned `DeleteOptions`. It first stops the Deployment controller with
`propagationPolicy=Orphan`, then processes ReplicaSets in ascending `(name, UID)` order with
`propagationPolicy=Orphan`, then deletes Pods child-first, followed by the NetworkPolicy, target
ServiceAccount, ResourceQuota, LimitRange, runner RoleBinding/Role, and cleanup RoleBinding/Role.
The fixed cleanup ClusterRole permits the final cleanup Role/Binding deletions after their
namespaced binding disappears. It deletes the Namespace last with its recorded UID and
`propagationPolicy=Foreground`; the system-owned `default` ServiceAccount is removed only by that
Namespace deletion. Every other delete uses `propagationPolicy=Background`. A replacement between
observation and deletion conflicts on the API-server UID precondition and is never retried by name.

### Fixed workload and normalization

The Deployment has one replica, `progressDeadlineSeconds=30`, `revisionHistoryLimit=0`, strategy
`Recreate`, selector `app.kubernetes.io/name=sandbox-target`, the exact target account,
`runtimeClassName=kapsel-sandbox-runtime-v1`, no token, service links disabled, and a five-second
termination grace period. Deployment and Pod-template labels include the app name, run ID,
cleanup-owner, and policy revision so ReplicaSets and Pods inherit the complete owner identity. The
Deployment annotations freeze `kapsel.dev/policy-inventory-digest` and exact
`kapsel.dev/selected-image`; neither may change. Pod security fixes non-root UID/GID 65532 and
`RuntimeDefault` seccomp. Its exact ordered containers are `target` then `untargeted`. Both start
from
`registry.k8s.io/pause@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c`, run
only `[/pause]`, use `imagePullPolicy=IfNotPresent`, request CPU `100m`, memory `32Mi`, and
ephemeral storage `16Mi`, and limit CPU `250m`, memory `64Mi`, and ephemeral storage `64Mi`. Each
drops all capabilities, forbids privilege escalation, runs non-root, and has a read-only root.

Only `target` may change. The healthy requested image is
`registry.k8s.io/pause@sha256:8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c`; the
unavailable-image request is
`registry.k8s.io/pause@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`.
`untargeted` remains at the initial digest. Privileged mode, host PID/IPC/network, host paths,
writable root, added capability, service-account token, ambient credential, mutable tag, another
container, init/ephemeral container, volume, device, port, probe, lifecycle hook, or unapproved
field is forbidden.

Canonical observation removes only server identity/status fields `metadata.uid`, `resourceVersion`,
`generation`, `creationTimestamp`, `managedFields`, and `selfLink`, plus `status`. It may normalize
only these exact server defaults when they have the stated value: Namespace
`spec.finalizers=["kubernetes"]` and label `kubernetes.io/metadata.name=<exact namespace>`;
ServiceAccount `secrets=[]`; Deployment `minReadySeconds=0`, `paused=false`, Pod-template
`creationTimestamp=null`, Pod `dnsPolicy=ClusterFirst`, `restartPolicy=Always`,
`schedulerName=default-scheduler`, alias `serviceAccount=sandbox-target`, and for each fixed
container `terminationMessagePath=/dev/termination-log` and `terminationMessagePolicy=File`. The
explicit `Recreate` strategy is not a default and may not change. Absence of an expected field, a
changed named default, or any unknown server-added default fails closed.

### Pre-invocation composition verification

The controller-owned provisioner consumes bounded deterministic Kubernetes responses, never
caller-supplied digests. Each request has a ten-second deadline, each response is capped at 2 MiB in
the HTTP service before kube deserialization, each list has at most the applicable closed-inventory
count, and one complete cleanup attempt has a 30-second deadline. It derives kind, namespace, name,
immutable UID, owner, revision, and the canonical content digest; rejects duplicate, missing, extra,
stale-revision, wrong-digest, wrong-owner, wrong-UID, cross-run, fallback-runtime, widened-RBAC,
quota/limit, network, workload, default, canary, baseline, or generated-child evidence. Observed
objects are keyed by exact kind/namespace/name, duplicates are rejected before canonical identity
sorting, and only container and cleanup-plan order are semantic. Owner-marker scans cover only run
kinds readable by the fixed provisioner or cleanup role. Secrets, Services, EndpointSlices,
PersistentVolumeClaims, Jobs, and other forbidden payload-bearing kinds remain zero through exact
quota plus fail-closed admission; neither runtime role receives cluster-wide read authority merely
to prove absence. The bootstrap baseline scan owns RuntimeClass, Namespace, ClusterRole, and
ClusterRoleBinding drift.

One transaction appends every exact run-owned UID/owner row and commits the verified revision,
inventory digest, namespace UID, Deployment UID/resource version/current target image, complete
canonical Deployment digest, zero-owned-orphan observation, durable baseline/canary UID digest, and
closed provisioning generation. A later UID substitution under the same baseline/canary identity and
body fails closed. Before that commit, the controller revokes and fences the raw provisioner
credential; after it, `composition-v1` denies recreation or mutation by that generation. Only then
may the Slice 2 runner host receive authority or `Application` begin. Rejection creates no
invocation marker, gateway journal, provider request, receiver result, receipt, or capacity release;
owned rows remain append-only for cleanup.

### Exact conditional mutation

The controller's final full composition verification and closed provisioner generation are durable
pre-launch facts; the patch-time admission rule does not claim to reread other objects. The runner
may submit one conditional strategic merge patch only when the Deployment-local frozen facts still
match: run and operation identity; namespace and Deployment name; immutable Deployment UID;
cleanup-owner marker; policy revision; inventory and canonical Deployment digest annotations;
resource version; unique `target` container; current initial immutable image; and the exact
selected-image annotation. KAP-0038 commits `apply_started` with the UID, resource version,
strategy, and attempt marker before this request.

The new canonical Deployment may differ only at `spec.template.spec.containers[name=target].image`
and `metadata.annotations[kapsel.dev/kap0038-operation-id]`. Every other field, annotation, label,
container, image, owner, security setting, volume, account, and object remains canonically equal.
The response must preserve the Deployment UID and return a resource version. Missing or wrong
precondition, unknown default, admission denial/ambiguity, conflict, timeout, or transport failure
is never forced and never causes a second patch. After `apply_started`, recovery is
observation-only; no request or transport fact becomes receiver `SUCCEEDED` or `FAILED`, and
insufficient receiver facts remain `UNKNOWN`.

The target carries no Kubernetes or host authority. The runner and the most compromised target
posture must be denied metadata, other namespaces, the operator canary, unrelated objects, cleanup
actions, controller host/state/receipts, key sources, volumes, backup state, prior journals, and
arbitrary network destinations. Serialization replaces simultaneous visitor-run evidence with these
canary and prior-run temporal checks. It does not claim hard tenant isolation.

## Host-owned key and trust staging

Slice 4 is one closed six-family staging boundary: authorization, receipt, tombstone, Kubernetes
runner and cleanup, handoff, and public trust. One deployment-owned absolute authority root contains
only `incoming/`, `generations/generation-<20-digit generation>/`, the regular-file `current`
pointer, and `dispatch/<run-id>/lease-<20-digit epoch>/`. The key-staging identity owns only the
`0700` inbox and its exact `0400` files. Activated generations are controller-owned `0500`
directories with controller-owned `0400` files. Group and other authority are prohibited. The
installer and controller reader are separate crate-private roles: activation requires the configured
staging process identity and narrowly scoped create/chown/DAC deployment authority, while generation
reads require the configured controller identity and expose only one requested authority family.
Production configuration rejects equality of either the staging/controller UID or GID. A
`cfg(test)`-only same-identity constructor supports ordinary unprivileged unit fixtures without
weakening production constructors; distinct positive execution remains a later privileged Linux
lane. Absent privilege or a role/owner/mode mismatch fails closed. The root is controller-owned
exact `0700`; all mode checks include special bits.

A candidate contains exactly these thirteen regular, singly linked source files; missing, extra,
linked, replaced, wrong-owner, or wrong-mode entries fail closed:

| Family             | Fixed source                    | Exact schema and bound                                                                     |
| ------------------ | ------------------------------- | ------------------------------------------------------------------------------------------ |
| Authorization      | `authorization-signing-seed`    | Exactly 32 nonzero binary bytes                                                            |
| Authorization      | `authorization-signing-key-id`  | 1–128 visible ASCII bytes in the existing KAP-0038 key-id grammar                          |
| Receipt            | `receipt-signing-seed`          | Exactly 32 nonzero binary bytes, distinct from both other private keys                     |
| Receipt            | `receipt-signing-key-id`        | 1–128 visible ASCII bytes in the existing receipt key-id grammar                           |
| Tombstone          | `tombstone-digest-key`          | Exactly 32 nonzero binary bytes, distinct from both signing seeds                          |
| Kubernetes runner  | `runner-kubernetes-api-server`  | 1–512 visible ASCII bytes; absolute HTTPS URI without userinfo, query, or fragment         |
| Kubernetes runner  | `runner-kubernetes-ca.pem`      | 1–16 KiB bounded opaque CA bytes; certificate parsing remains consumer-owned               |
| Kubernetes runner  | `runner-kubernetes-token`       | 1–4 KiB visible non-whitespace ASCII bytes                                                 |
| Kubernetes cleanup | `cleanup-kubernetes-api-server` | Same endpoint grammar and bound as the runner endpoint                                     |
| Kubernetes cleanup | `cleanup-kubernetes-ca.pem`     | 1–16 KiB bounded opaque CA bytes; certificate parsing remains consumer-owned               |
| Kubernetes cleanup | `cleanup-kubernetes-token`      | 1–4 KiB visible non-whitespace ASCII bytes, distinct from the runner token                 |
| Handoff            | `handoff-endpoint`              | 1–64 visible ASCII bytes parsed as one loopback socket address                             |
| Public trust       | `public-receipt-trust.json`     | At most 1 KiB; exact version 1 key ID, public key, purpose, and nonempty validity interval |

Public trust must name the staged receipt key, contain the public key derived from its seed, and use
purpose `kapsel.kap0038.kubernetes-effect-receipt.v2`. Authorization trust is derived from the
staged authorization seed and key ID rather than supplied as another mutable source. The target
receives no staged authority. Receipt retrieval never appoints trust. The separate authority
controller returns unchanged validated trust bytes only for a publicly retained run with a receipt,
using that run's durable generation rather than `current`.

Installation validates the complete candidate before copying it descriptor-relatively with
no-follow, same-inode, owner, mode, link-count, and byte-bound checks. It writes and fsyncs every
file, then a canonical version-1 `manifest.json` containing the monotonic generation, previous
generation, fixed ordered names, sizes, and SHA-256 digests. After directory fsync and atomic
rename, it atomically replaces and fsyncs the regular `current` record containing only generation
and aggregate manifest digest. A generation directory alone is never active. On restart, the
installer descriptor-relatively validates and finishes an exactly adjacent, complete generation
renamed before `current`. Temporary recovery accepts at most the one exact canonical
`.generation-<20-digit generation>.tmp` implied by current, or generation 1 when current is absent;
malformed, nonadjacent, duplicate, or excessive debris fails closed. Refresh is explicit; no watcher
or ambient lookup exists.

A controller family read first validates only the pinned canonical manifest, aggregate manifest
digest, exact thirteen-name inventory, ordered names, declared lengths, and declared per-file
digests. It then opens, same-inode revalidates, hashes, and parses only the requested family.
Receipt reads additionally validate public trust; public-trust reads additionally validate the
receipt seed and key ID needed for public-key derivation. Unrelated payload corruption therefore
holds only its dependent family, while manifest or inventory corruption blocks every family.

The controller admits at most current plus one retained complete generation. A third activation
fails until the older generation has no run, tombstone, retained receipt, cleanup/recovery, or
dispatch-directory reference. Before fresh dispatch, the controller validates current authority; the
same SQLite transaction that reserves capacity stores its positive generation and 64-lowercase-hex
manifest digest. Queued rows have no pin. Recovery and cleanup use the durable pin and ignore
`current`; rotation affects only later dispatches. A pre-Slice-4 database may migrate only while
stopped and drained, with no dispatched or publicly retained run and no tombstone. Migration fails
closed rather than assigning legacy authority to current.

Each dispatch or recovery atomically creates one controller-owned `0700` lease directory containing
the accepted twelve controller-owned `0400` runner inputs. It derives the server-owned request,
exact per-run grant, authorization trust, namespace, lease ID, and credential, and copies only the
pinned runner, receipt, and handoff inputs. One canonical temporary lease directory is bounded,
recovered, fully fsynced, and atomically renamed before the final directory is reopened and proved
to be the same inode. The resulting private `PublishedRunnerInputs` owns only that descriptor;
`RunnerHost` accepts it directly, validates and opens all twelve files before replacement fencing,
and has no input path or shared input-root configuration. Old process/cgroup fencing and durable
retirement precede descriptor-relative removal of every lease directory and its run directory.
Restart retries removal when retirement was already committed.

Generation collection is one Service-owned transition, not a staging or caller-selected deletion
interface. While holding an immediate SQLite transaction it validates every authority pin, rejects
orphan receipt/publication/cleanup/application and dispatch ownership, and proves that the exact
noncurrent generation has no run, tombstone, retained receipt/trust, cleanup/recovery, or dispatch
reference. It then durably records only that generation and aggregate manifest digest before the
reader renames and descriptor-relatively removes the exact noncurrent directory. Startup resumes a
recorded pre-rename, partial-delete, or post-delete operation before requiring the complete
tombstone keyring. The current generation is never collectible.

Tombstones store the generation and manifest digest that produced them. Admission checks candidate
locators against the bounded current-plus-retained tombstone keyring, so rotation cannot resurrect
an old locator. Undispatched expiry uses current; dispatched expiry uses the durable pin. Private
key, credential, request, locator, receipt, journal, per-file digest, and trust-decision payloads
never enter arguments, environment, public fields, controller SQLite, diagnostics, logs, or
committed evidence. SQLite contains only generation and aggregate manifest digest.

Missing or malformed authority holds and retries only the dependent transition: fresh work stays
queued, recovery neither renews nor relaunches, cleanup starts no API attempt, and tombstone-
dependent admission or expiry returns unavailable. It never writes `service_failed`,
`not_attempted`, a KAP-0038 receiver result, an invocation marker, or a receipt. Frozen receipt
bytes are never re-signed. This offline contract selects no provider or credential source and claims
neither managed custody nor syscall/path confinement.

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
bounded `Service` transitions. Gate 1 Slice 1 implements a scheduler step that recovers active work
before FIFO dispatch, the existing periodic retention process through its concrete role, and cleanup
selection/start/failure/escalation/completion over the exact append-only inventory. They cannot
execute arbitrary SQL or widen lifecycle/result vocabulary. The runner launch, Kubernetes deletion
observer, and restart-before-serve composition remain later slices; eventual startup must run
fencing, restore validation, expiry/tombstone deletion, pending receipt convergence, active journal
reconciliation, stale-process denial, ownership scan, and cleanup before admission readiness.

## UID- and owner-safe cleanup

The controller keeps the append-only 64-row maximum inventory described above with exact kind,
namespace, name, immutable UID, and cleanup owner. Before `CleanupRole` selects work, durable
service state must record closed/revoked provisioning authority, Slice 2 runner credential
revocation, cgroup/process absence, journal/outbox retention handoff, and explicit fenced-generation
retirement. `CleanupWork` contains only those durable facts, the cleanup epoch, namespace UID, and
the complete ordered inventory; the observer accepts no caller-selected object, patch, delete,
credential, observation, or lifecycle input. The production entry is one closed cleanup attempt: it
lists and appends valid generated children, reloads durable work, GETs every recorded object, scans
the exact owner marker, derives and durably binds one private canonical delete plan, recomputes its
digest immediately before issue, executes it, and performs the fresh post-plan observation. Neither
the plan type nor its request fields are publicly re-exported.

The concrete cleanup observer uses only the fixed cleanup credential. For each child in the frozen
order it performs a bounded observation, compares exact kind/namespace/name/UID/owner/revision, and
only then issues deletion for that object. It never changes an image or annotation and never uses
runner authority. The Namespace is observed and deleted last under the fixed cleanup admission
backstop. Every delete carries `preconditions.uid=<recorded UID>` and the frozen propagation policy;
a reused name therefore conflicts atomically. Wrong UID or owner, an observation that omits an
inventory row, duplicate, changed order, extra current-run-owned orphan, canary or unrelated object,
unsupported kind, response above 2 MiB before deserialization, ten-second request timeout, 30-second
attempt timeout, unavailable API, deletion conflict, or object/finalizer still present at the
bounded deadline fails closed through the existing coalesced `CleanupRole::fail` transition. An
exact recorded object already absent is accepted as absence, not as missing inventory.

Every retry reselects the same work from durable state and is restart-safe. The first failure emits
at most one public cleanup-failed fact; exactly one durable operator escalation becomes due after 15
minutes from cleanup start. Retry, timeout, API failure, and escalation never alter `not_attempted`,
`SUCCEEDED`, `FAILED`, `UNKNOWN`, or frozen receipt bytes.

Success requires a new cleanup observation after the last delete attempt. Its one bounded snapshot
proves every append-only row absent with the exact recorded tuple, zero objects carrying the run
cleanup-owner marker across every supported kind, and Namespace absence. Evidence is stale unless
its cleanup epoch equals the current durable post-provisioning-fence epoch, its durable cleanup-
attempt sequence and request-list digest equal the latest deletion plan, the role has durably
recorded that every request in that exact plan was issued, and its service-issued post-plan
observation identifier has not previously been consumed. Only after those checks does the concrete
cleanup role invoke its bounded observer and derive ordered absence evidence; callers do not supply
or relabel the plan bytes, attempt, digest, or observation identity. Execution recomputes the digest
of the exact canonical request bytes and rejects any mismatch before a Kubernetes request. A later
plan invalidates evidence from an earlier attempt. Whole-second time is recorded for bounded
operations but is not causal freshness. Admission denies recreation throughout the closed epoch.
Capacity release rechecks the provisioning fence, runner revocation, process/cgroup absence, journal
handoff, runner-state retirement, exact-row absence, zero orphan, and Namespace absence in the same
transaction that commits cleanup success. Present or stale evidence releases nothing.

The existing confirmed-no-resource path remains valid only when the provisioner durably proves that
failure occurred before creating any Kubernetes object, before recording a Namespace UID, and before
`Application` invocation. It cannot invent absence. Public expiry and client abandonment never
release cleanup ownership or capacity. The operator canary, baseline, and unrelated resources are
never cleanup candidates.

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
gate, and independent architecture/security review passed. Gate 1 Slice 1 then accepted exactly one
durable active reservation through cleanup, fail-closed reopen and dispatch for corrupt capacity
state, active-first lease recovery, FIFO dispatch, coalesced cleanup retry, one 15-minute
escalation, and release only after exact absence. No row treats historical provider configuration or
Kubernetes-hosted controller composition as preservation evidence.

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
