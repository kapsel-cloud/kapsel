# Keep provider authority in an operator-resident effect gateway

Status: accepted.

Kind: architecture decision.

Owns: The intended resident trust boundary and the evidence required before extracting public
packages or interfaces.

## Context

Effect execution needs a lifetime independent of the invoking process. Callers must be able to
reconnect and retrieve original evidence across a separate OS identity without acquiring provider
credentials. Remote scheduling, authority staging, and a second state store would add a separate
system rather than solve that local lifetime boundary.

## Decision

Provider credentials, grants, trust, signing material, durable state, and effect execution remain in
an operator-controlled resident process. The `kapsel-daemon -> kapsel` package composition separates
local admission, process lifetime, bounded concurrency, health, and diagnostics from the root
package's effect semantics.

A remote coordination layer must not become the source of provider truth or move provider authority
across the resident boundary.

Package and interface extraction requires a concrete technical reason:

- independent deployment;
- multiple maintained consumers;
- dependency isolation; or
- a compatibility contract that cannot remain private.

Conceptual genericity alone is insufficient.

## Consequences

- `kapsel-daemon` produces the `kapseld` binary and depends on `kapsel`; the root package does not
  depend on the Kapsel service adapter.
- The Kapsel service interface remains local and capability-specific.
- Receipt, protocol, SDK, provider, Kubernetes, storage, and separate CLI packages are not created
  without their named extraction condition.
- Another capability or provider does not justify a generic seam until concrete semantics repeat.
- Remote-coordinator failure cannot corrupt or redefine Kapsel service effect execution.
