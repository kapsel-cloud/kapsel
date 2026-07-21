# Architecture

Status: active experiment design.

Kind: design. Authority: current module ownership, dependency direction, and composition status.

Owns: The active experiment's modules, seams, and compile-time dependency direction.

Does not own: Exact lifecycle/result semantics, Kubernetes truth, exact receipt bytes, MCP protocol
semantics, or public-sandbox wire/deployment behavior.

## Short answer

KAP-0038 is one deep Rust product package, `kapsel`, for one bounded Kubernetes Deployment image
operation. Its `Gateway` module entry type owns validation, journaling, conditional mutation,
reconciliation, receiver classification, receipt construction, immutable publication, and offline
inspection. Concrete operation names, including `SetDeploymentImageRequest`, keep the Kubernetes
scope visible at the interface.

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

The fixed prototype evaluator command and thin fixed-schema MCP stdio adapter are implemented.

## Implemented modules

| Module                              | Owns                                                                                             | Refuses to own                                                        |
| ----------------------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| `kapsel` / `Gateway`                | One request grammar, signed exact-grant verification, lifecycle, recovery, and finalization      | Another capability, generic runtime, or policy language               |
| SQLite journal                      | FULL-synchronous rollback journal, bounded operations, guarded transitions, frozen receipt bytes | Generic storage interface or distributed scheduling                   |
| Kubernetes Deployment image adapter | Safe target reads, one conditional strategic merge patch, and bounded rollout observation        | Generic Kubernetes abstraction or arbitrary manifests/patches         |
| Receiver-fact module                | Bounded Kubernetes facts and `SUCCEEDED`/`FAILED`/`UNKNOWN` classification                       | Provider truth, causation, or complete cluster health                 |
| Receipt module                      | Classifier-complete prototype bytes, signing, parsing, recomputation, trust/time/limits          | Stable package format, generic verifier, ambient trust, or `VERIFIED` |
| Publication module                  | Unix descriptor-relative, owner-private, collision-safe frozen-byte installation                 | Generic blob storage or hosted publication                            |

The source tree keeps these owners local. `lib.rs` is a compact exported-interface map;
`application` owns the shared deep application interface and sequencing; `command` owns bounded
input, operator-file composition, deterministic rendering, and exit classes; and `main.rs` owns only
process arguments, streams, and exit handling. Authorization, lifecycle, journal/schema, concrete
Kubernetes I/O and classification, receipt encoding/inspection, publication, and their private seam
tests live beneath the private `gateway` module. A concern earns another file only when it owns
policy or a durable fact behind a smaller internal interface.

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
`Application::execute` submits intent and owns all subsequent lifecycle sequencing with the
configured Kubernetes and receipt authority. `Application::reconcile` resumes the exact configured
operation after restart, and both return one typed `OperationReport`. Reconciliation and receipt
finalization select that exact operation identity even if the journal contains another operation.
Exact grant provisioning is a separate operator function requiring signing material.

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
product implementation together while allowing the unpublished `crates/kapsel-dev` tooling package
and excluded `fuzz` package. No product package named `kapsel-core`, `kapsel-gateway`, `kapsel-k8s`,
`kapsel-adapters`, `kapsel-api`, or `kapsel-testing` exists. Product code may be extracted only
after an independent consumer, a one-way package dependency graph, or a measured
dependency-isolation need proves that a package seam is real. The 0.1 release does not establish a
stable library interface or justify another package boundary.

The prospective [V1 technical direction](VISION.md) records the accepted resident effect-gateway
target, next independently deployed sandbox package, future `kapseld` trigger, and
package-extraction rules. It does not change the current package graph or active experiment
contracts.

KAP-0051 now fixes the [public sandbox API](SANDBOX_API.md) and
[deployment composition](SANDBOX_DEPLOYMENT.md). Those contracts satisfy the design prerequisite for
a later one-way `kapsel-sandbox -> kapsel` package, but do not add that package, an HTTP framework,
a scheduler, a database, or a deployment. The future adapter must call the same exported
`Application` with server-owned configuration; it owns admission, public state, and cleanup in its
package and must not expose the gateway journal or add a public provider seam.

```text
browser -> optional edge -> future kapsel-sandbox -> kapsel Application
                                |                     |
                                |                     -> unchanged KAP-0038 semantics
                                -> separate admission/projection/cleanup state
```

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
