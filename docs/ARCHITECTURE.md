# Architecture

Status: current architecture for `v0.1.1` and the `0.2.0` source; exact release state is external
evidence.

Kind: design. Authority: current module ownership, dependency direction, and composition status.

Owns: The active experiment's modules, seams, and compile-time dependency direction.

Does not own: Exact lifecycle/result semantics, Kubernetes truth, exact receipt bytes, MCP protocol
semantics, or public-sandbox wire/deployment behavior.

## Short answer

KAP-0038 is one deep Rust product package, `kapsel`, for one bounded Kubernetes Deployment image
operation. `Application` is the caller-facing deep module; its private `Gateway` semantic engine
owns validation, journaling, conditional mutation, reconciliation, receiver classification, receipt
construction, immutable publication, and offline inspection. Concrete operation names, including
`SetDeploymentImageRequest`, keep the Kubernetes scope visible at the interface.

```text
bounded request + signed exact grant + application-configured trust
  -> Kubernetes effect-gateway module
       -> bounded grant verification
       -> SQLite journal
       -> concrete Kubernetes adapter
       -> receiver-fact classification
       -> durable receipt preparation and immutable publication

receipt bytes + explicit trust + time + limits
  -> offline inspector
```

The fixed evaluator command and thin fixed-schema MCP stdio adapter are implemented in `v0.1.1` and
their exact beta interfaces are adopted for v0.2.x. The `0.2.0` source implements the adopted
architecture. Source and package identity do not establish candidate acceptance or publication;
ordered release evidence owns that state.

## Implemented modules

| Module                              | Owns                                                                                             | Refuses to own                                                        |
| ----------------------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| `kapsel` / `Gateway`                | One request grammar, signed exact-grant verification, lifecycle, recovery, and finalization      | Another capability, generic runtime, or policy language               |
| SQLite journal                      | FULL-synchronous rollback journal, bounded operations, guarded transitions, frozen receipt bytes | Generic storage interface or distributed scheduling                   |
| Kubernetes Deployment image adapter | Safe target reads, one conditional strategic merge patch, and bounded rollout observation        | Generic Kubernetes abstraction or arbitrary manifests/patches         |
| Receiver-fact module                | Bounded Kubernetes facts and `SUCCEEDED`/`FAILED`/`UNKNOWN` classification                       | Provider truth, causation, or complete cluster health                 |
| Receipt module                      | Classifier-complete prototype bytes, signing, parsing, recomputation, trust/time/limits          | Stable package format, generic verifier, ambient trust, or `VERIFIED` |
| Publication module                  | Unix descriptor-relative, owner-private, collision-safe frozen-byte installation                 | Generic blob storage or hosted publication                            |

The source tree keeps these owners local. `lib.rs` is a compact workspace-visible interface map;
`application` owns the shared deep application interface and sequencing; `transport_support` owns
bounded operator-file composition plus domain report and application-error projection for the two
production adapters; `command` owns bounded CLI input, deterministic envelopes, and exit classes;
`mcp` owns protocol framing and lifecycle; and `main.rs` owns only process arguments, streams, and
exit handling. Deleting the private transport-support module would move operator loading, exact
application failure classification, and operation-state/result/rejection/receipt projection back
into both adapters. Authorization, lifecycle, the concrete Kubernetes adapter and classification,
receipt encoding/inspection, publication, and their private seam tests live beneath the private
`gateway` module. The journal retains one deep interface for rows, snapshots, worker locking,
capacity, and guarded transitions. Its private `schema` child concentrates exact layout recognition
and legacy migration, while its private `opening` child concentrates durable SQLite entry, v0.1.1
backup verification, rollback-file recovery, and owner-private Unix pathname identity. Gateway
callers cannot select either child, SQL, storage, or lifecycle sequencing. A concern earns another
file only when it owns policy or a durable fact behind a smaller internal interface.

The experiment owner defines the exact lifecycle, recovery, result, and receipt semantics:
[KAP-0038](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md).

## Application composition

The root `kapsel` package exposes one compile-time `Application` composition root. Its
`OperatorConfiguration` supplies one owner-signed exact grant, application-configured grant trust, a
concrete Kubernetes client, receipt signing material, journal path, and receipt directory. The
configuration type deliberately has no `Debug` implementation. Grant trust and canonical bytes,
receipt key identity, the private receipt directory, and an absolute journal path beneath a private
non-symlink directory are validated before the journal is opened. Journal and worker-lock files are
owner-private.

The caller submits only `AgentRequest`, an alias for the concrete `SetDeploymentImageRequest`; it
cannot provide grants, trust, Kubernetes authority, signing material, paths, or fault controls. The
`Application::execute` method submits intent and owns all subsequent lifecycle sequencing with the
configured Kubernetes and receipt authority. `Application::reconcile` resumes the exact configured
operation after restart, and both return one typed `OperationReport`. Submission and report-snapshot
helpers remain private so callers cannot sequence internal durable states. Application failures
expose only configuration, request-rejection, and operation-failure classes rather than low-level
gateway errors. Reconciliation and receipt finalization select that exact operation identity even if
the journal contains another operation. Provider execution/recovery and receipt
preparation/publication each have one private operation-selected implementation used by production
and deterministic fault proofs. Queue-oriented test helpers select one exact identity and delegate
without owning lifecycle transitions. Exact grant provisioning is a separate operator function
requiring signing material.

This Rust application interface is not itself a configuration-file or command grammar. The
[evaluator command contract](COMMANDS.md) owns the implemented local adapter, which converts its
fixed files into this same interface without sequencing durable states or exposing credentials. The
[MCP adapter contract](MCP.md) owns the implemented stdio transport, which converts only its five
request fields into the same `AgentRequest` and loads operator configuration out of band.

## Dependency direction

```text
local evaluator command or thin MCP adapter (both implemented)
  -> `kapsel` application composition
       -> KAP-0038 effect-gateway module
            -> private concrete implementation modules
```

The private Kubernetes adapter seam exists to prove provider call counts and crash recovery with a
deterministic fake. One production adapter does not establish a reusable provider model. The
repository-only `kapsel-dev` package owns development automation such as hook installation, hard
tidy checks, and advisory style audits; it is tooling, not part of the product package, gateway
interface, or dependency path.

Release assembly packages that same compile-time product composition for one supported target. The
ordinary executable remains feature-free. A separately named `libexec` executable contains the
compile-time `demo-harness` fault controls and is invoked only by the bundled owned demonstration.
Artifact metadata, checksums, installation docs, and smoke automation are distribution concerns;
they do not add a runtime plugin, provider interface, application seam, trust source, or result
vocabulary. [Release artifacts](RELEASE.md) owns the exact distribution contract.

The repository root is both the `kapsel` product package and the workspace root. This keeps the sole
product implementation together while allowing the unpublished `crates/kapsel-dev` tooling package,
the independently deployable `crates/kapsel-sandbox` consumer, and the excluded `fuzz` package. No
product package named `kapsel-core`, `kapsel-gateway`, `kapsel-k8s`, `kapsel-adapters`,
`kapsel-api`, or `kapsel-testing` exists. Product code may be extracted only after an independent
consumer, a one-way package dependency graph, or a measured dependency-isolation need proves that a
package seam is real. Neither the 0.1 release nor the adopted v0.2 beta establishes a supported
external Rust interface or justifies another package boundary. Public Rust visibility is retained
only where the ordinary binary adapters, offline inspection/provisioning composition, the real
`kapsel-sandbox -> kapsel` consumer, or package tests require it. The public exports, module tree,
and private adapter seams may change within v0.2.x without external migration support; crates.io,
docs.rs, and `cargo install` remain unsupported.

KAP-0052 implements the accepted [public sandbox API](SANDBOX_API.md) and the retained semantic
parts of the [deployment composition](SANDBOX_DEPLOYMENT.md) through one one-way
`kapsel-sandbox -> kapsel` package. The package owns bounded HTTP translation, a separate SQLite
admission/projection store, fixed-capacity scheduling and recovery leases, an admission-frozen
policy inventory, cleanup identity, and 180-second duration, a dispatch-established absolute
deadline, deterministic exact per-object UID/owner/content verification, immutable receipt-file
publication with durable pending ownership serialized against orphan collection, operator-triggered
and restart-before-serve retention sweeps, and cleanup completion gated by exact absence evidence
for every row in an append-only per-run kind/namespace/name/UID/owner inventory (with the separate
confirmed-no-resource path). The SQLite entry is created 0600, opened no-follow, and checked as the
same owner-private regular inode before and after open. These are service-model checks, not proof of
live Kubernetes enforcement. It invokes the same exported `Application` with server-owned
configuration only after policy verification and neither reads gateway journal rows nor introduces a
provider, storage, or public trait seam.

```text
browser -> optional edge -> kapsel-sandbox -> kapsel Application
                                |                 |
                                |                 -> unchanged KAP-0038 semantics
                                -> separate admission/projection/cleanup state
```

The sandbox directly pins `http` for typed in-process translation, `httparse` for bounded raw
HTTP/1.1 parsing without route duplication, `serde`/`serde_json` for exact bounded `v1` documents,
`rusqlite` with bundled SQLite for one local transactional service store, `getrandom` for opaque
128-bit run identities, `sha2` for exact receipt and keyed tombstone digests, and `rustix` for
owner-private Unix path checks. It reuses no transitive dependency implicitly. Historical KAP-0053
Authority Composition Proof (Gate 1) added the package-local native process, private stop commands,
provider-neutral exact-patch harness, and static-volume/backup composition lock. KAP-0069 retained
only the mapped listener, stop, patch, input, runner, scheduler, cleanup, and retention evidence and
superseded the Kubernetes-hosted controller/stager topology. KAP-0070 now owns contract correction
and fresh serialized host/cluster evidence before any provider selection, live transport,
durable-store placement and fencing, key custody, Kubernetes admission/isolation, or cleanup claim.

## Failure structure

- Invalid request or grant bytes, untrusted signatures, and tuple mismatches fail before persistence
  or Kubernetes calls.
- Application-configured trust is supplied out of band; agent input cannot select it.
- Safe target validation precedes either a terminal `not_attempted` rejection or an atomic
  target-identity plus mutation-attempt transition.
- Transient target-read errors are durably deferred with fair retry ordering so they cannot block
  later authorized operations.
- The journal distinguishes a mutation attempt from provider acceptance and receiver observation.
- Recovery after the durable mutation marker observes; it never blindly issues a second patch.
- Incomplete receiver facts become `UNKNOWN`.
- Receipt preparation uses only frozen facts; publication and recovery use durably frozen exact
  bytes.
- Offline inspection receives trust, evaluation time, and limits explicitly and performs no network
  or ambient lookup.

## Decisions

- [ADR 0008](decisions/0008-use-one-kubernetes-effect-gateway-canary.md) selects one Kubernetes
  operation as the effect-gateway canary.
- [ADR 0009](decisions/0009-use-conditional-kubernetes-image-patch.md) selects the conditional
  strategic merge patch for this one operation.
- [ADR 0010](decisions/0010-evolve-through-a-resident-effect-gateway.md) selects the prospective
  customer-resident product shape and earned package seams.
