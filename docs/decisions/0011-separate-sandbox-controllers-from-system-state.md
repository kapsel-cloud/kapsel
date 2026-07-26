# Separate sandbox controllers from system-state ownership

Status: accepted.

Kind: decision. Date: 2026-07-25.

Owns: Why the fixed public sandbox keeps system state in one singleton Pod while running scheduler
and cleanup as separately identified controllers over role-specific private state protocols.

## Context

The sandbox admission database, immutable receipt store, runner handoff, retention, and
initialization must have one system-state owner. The candidate uses SQLite on a `ReadWriteOncePod`
claim, so only one Pod may mount and write that state. Scheduler and cleanup meanwhile need
different Kubernetes resource authority, different network reachability, and no system-state or key
access.

Running scheduler and cleanup as sidecars would force API, scheduler, and cleanup into one Pod and
therefore one Kubernetes service account. That union identity would violate the deployment
contract's controller separation and least-authority requirements. Moving either controller to a
separate Pod while retaining direct `Service` calls would require an impermissible second mount,
shared SQLite filesystem, or copied durable truth.

The direct local controller implementations already expose the required bounded `Service`
transitions. The missing seam is private role-specific transport, not a new storage abstraction.

## Decision

The GKE sandbox candidate uses:

- one singleton system-state Pod for the native API, private runner handoff, periodic retention,
  durable-layout initialization, admission SQLite, and immutable receipt storage;
- one scheduler Pod and one cleanup Pod, each under its own Kubernetes service account and with no
  system-state or key mount; and
- two fixed private state protocols owned by the system process, one for scheduler transitions and
  one for cleanup transitions.

The protocols are bounded transport adapters over existing `Service` methods. They are not public
APIs, generic controller interfaces, storage backends, queues, or package seams. They accept only
the server-owned identities and exact facts required by their role. They accept no arbitrary SQL,
manifest, path, lifecycle choice, receiver result, provider fact, key, credential destination, or
receipt destination.

Each controller presents a short-lived bound Kubernetes service-account token for its fixed
application audience over authenticated encryption with pinned system trust. The system validates
that token with Kubernetes `TokenReview` and requires the exact role identity. Controllers receive
separate projected tokens for Kubernetes API access. The system identity receives only the cluster
authority needed to create `tokenreviews.authentication.k8s.io`; it receives no controller-resource
verbs.

Exact RBAC and NetworkPolicy permit each controller to reach only its named state port and to
perform only its fixed Kubernetes role. System and controller identities receive no Secret Manager
IAM. Separate staging identities produce the system Pod's tombstone input and the exact per-run
grant and receipt-signing channels. The system durably fixes every exact per-run external resource
slot before creation. After each fixed object is created or exactly observed, the scheduler
immediately appends immutable UID/owner evidence. Handoff assignment may prepare the bytes required
to stage its two channels after policy verification and registration of the six non-handoff
prerequisite slots, but Application invocation remains forbidden. Every prerequisite channel is
registered before the gated runner Pod is created, and the Pod itself is registered before its
scheduling gate or Application invocation can be released.

[`docs/SANDBOX_DEPLOYMENT.md`](../SANDBOX_DEPLOYMENT.md) remains the behavioral and deployment
contract. This decision explains the rationale and does not override that owner.

## Rejected alternatives

### Scheduler and cleanup sidecars

One Pod has one Kubernetes service account. Sidecars would require a union API, scheduler, cleanup,
and potentially key identity, broadening both resource and secret authority beyond the fixed roles.

### Separate Pods mounting system state

The system claim is `ReadWriteOncePod`. Mounting it in controller Pods would violate its single-Pod
ownership and create multiple SQLite participants over a filesystem boundary the contract forbids.

### Shared or multi-attach SQLite

A shared filesystem or multi-attach volume does not turn SQLite into a safe distributed state
service. It would weaken fencing, recovery, backup, and one-writer ownership.

### Copied or replicated SQLite truth

Copies would create competing lifecycle, lease, capacity, cleanup, or receipt truth and make crash
recovery dependent on an unowned replication protocol.

### Generic storage or backend seam

There is one durable implementation, and the storage-seam extraction trigger has not passed. A
generic seam would expose broader mutation than either controller needs and freeze an abstraction
inferred from one sandbox composition.

### Broad secret authority

Granting the system or controller identities Secret Manager access would make deployment easier only
by erasing the required custody boundary. Separate stagers keep key retrieval and staging out of
state and controller roles.

## Consequences

- Scheduler and cleanup can be deployed and denied independently without sharing SQLite or receipt
  ownership.
- Two strict private payload contracts and an authenticated transport must be implemented and tested
  before the incomplete workload fixture becomes deployable.
- The application audience, Kubernetes API audience, pinned trust delivery, token rotation,
  `TokenReview` behavior, exact RBAC, exact NetworkPolicy, and separate key stagers remain required
  composition work.
- The system Pod remains a singleton and a larger availability domain; this is accepted to preserve
  one durable owner rather than invent distributed state.
- Controller transport failure remains a sandbox orchestration failure. It cannot become a KAP-0038
  receiver result, lifecycle fact, or receipt change.
- The package graph remains `kapsel-sandbox -> kapsel`; no protocol, Kubernetes, storage, provider,
  or controller package is created.
- Gate 2 remains blocked. This decision selects no provider resource, credential, spend, endpoint,
  deployment, or public traffic.
