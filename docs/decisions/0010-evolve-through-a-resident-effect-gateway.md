# Keep provider authority in an operator-resident effect gateway

Status: accepted.

Kind: architecture decision.

Owns: The intended resident trust boundary and the evidence required before extracting public
packages or interfaces.

## Context

The root `kapsel` package owns exact authorization, durable lifecycle, provider attempts,
observation-only recovery, receiver-bounded results, and receipts. The removed hosted sandbox showed
that remote admission, scheduling, authority staging, cleanup, and a second state store form a
separate system rather than a natural extension of that module.

CLI and stdio MCP preserve the root semantics but attach lifetime to the invoking process and do not
provide read-only reconnect/status or exact receipt retrieval across a separate authority identity.

## Decision

Provider credentials, grants, trust, signing material, durable state, and effect execution remain in
an operator-controlled resident process. The `kapseld -> kapsel` package may own local admission,
process composition, bounded concurrency, health integration, and diagnostics, while the deep root
package continues to own effect semantics.

A remote coordination layer must not become the source of provider truth or move provider authority
across the resident boundary.

Package and interface extraction requires a concrete technical reason:

- independent deployment;
- multiple maintained consumers;
- dependency isolation; or
- a compatibility contract that cannot remain private.

Conceptual genericity alone is insufficient.

## Consequences

- The hosted sandbox topology is not a production template.
- `kapseld` depends on `kapsel`; the root package does not depend on the Kapsel service adapter.
- The Kapsel service interface remains local and capability-specific.
- Receipt, protocol, SDK, provider, Kubernetes, storage, and separate CLI packages are not created
  without their named extraction condition.
- Another capability or provider does not justify a generic seam until concrete semantics repeat.
- Remote-coordinator failure cannot corrupt or redefine Kapsel service effect execution.
