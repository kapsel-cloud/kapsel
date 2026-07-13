# Architecture

Status: active experiment design.

Kind: design. Authority: active module ownership, dependency direction, and composition status.

Owns: The active experiment's modules, seams, and compile-time dependency direction.

Does not own: Exact lifecycle/result semantics, Kubernetes truth, exact receipt bytes, or MCP
protocol semantics.

## Short answer

KAP-0038 is one deep Rust module for one bounded Kubernetes Deployment image operation. Its
implementation owns validation, journaling, conditional mutation, reconciliation, receiver
classification, receipt construction, immutable publication, and offline inspection.

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

There is no public application command or MCP entrypoint yet.

## Implemented modules

| Module                              | Owns                                                                                             | Refuses to own                                                        |
| ----------------------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| Kubernetes effect gateway           | One request grammar, signed exact-grant verification, lifecycle, recovery, and finalization      | Another capability, generic runtime, or policy language               |
| SQLite journal                      | FULL-synchronous rollback journal, bounded operations, guarded transitions, frozen receipt bytes | Generic storage interface or distributed scheduling                   |
| Kubernetes Deployment image adapter | Safe target reads, one conditional strategic merge patch, and bounded rollout observation        | Generic Kubernetes abstraction or arbitrary manifests/patches         |
| Receiver-fact module                | Bounded Kubernetes facts and `SUCCEEDED`/`FAILED`/`UNKNOWN` classification                       | Provider truth, causation, or complete cluster health                 |
| Receipt module                      | Classifier-complete prototype bytes, signing, parsing, recomputation, trust/time/limits          | Stable package format, generic verifier, ambient trust, or `VERIFIED` |
| Publication module                  | Unix descriptor-relative, owner-private, collision-safe frozen-byte installation                 | Generic blob storage or hosted publication                            |

The experiment owner defines the exact lifecycle, recovery, result, and receipt semantics:
[KAP-0038](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md).

## Planned adapters

Application composition will eventually supply owner-controlled configuration, Kubernetes authority,
signing material, journal path, and receipt directory. A later MCP adapter may convert one bounded
tool call into the same experiment request.

Both are planned. Neither is present in the current runnable command surface. They must remain thin,
compile-time-composed adapters; they must not sequence durable states or expose credentials.

## Dependency direction

```text
planned CLI or MCP adapter
  -> KAP-0038 effect-gateway module
       -> private concrete implementation modules
```

The private Kubernetes adapter seam exists to prove provider call counts and crash recovery with a
deterministic fake. One production adapter does not establish a reusable provider model.

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
