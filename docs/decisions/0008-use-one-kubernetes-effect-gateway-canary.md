# Use one Kubernetes operation as the effect-gateway canary

Status: accepted.

Kind: decision. Date: 2026-07-14.

Owns: Why Kapsel exercises crash-safe effects with one Kubernetes Deployment image change.

## Context

Kapsel's critical seam lies between a bounded agent request and a consequential provider effect. The
system must durably identify an attempt, avoid blind retries across crashes, observe the receiver,
and explain uncertainty without claiming exactly-once execution.

A Kubernetes Deployment image change is consequential, locally reproducible with `kind`, visibly
ambiguous across process failures, and familiar to infrastructure developers. One operation is
enough to exercise authorization, mutation ordering, recovery, receiver observation, and receipt
inspection without introducing a generic provider abstraction.

## Decision

The canary operation is:

```text
kubernetes.set_deployment_image(namespace, deployment, container, immutable_image_digest)
```

The operation provides exact request matching, durable operation identity, one conditional
Kubernetes mutation opportunity, bounded receiver observation or `UNKNOWN`, and a signed
operation-scoped receipt.

Kubernetes is the first concrete receiver. The choice established a working starting point, not a
permanent capability limit. The current implemented boundary lives in [scope](../SCOPE.md).

## Consequences

- The public release must demonstrate recovery without a blind second mutation.
- The implementation remains deep around one operation rather than exposing a reusable provider
  interface.
- A selected new capability includes its concrete technical owner, design decisions, contracts, and
  tests in the implementation work. This canary decision does not require another adoption phase.
