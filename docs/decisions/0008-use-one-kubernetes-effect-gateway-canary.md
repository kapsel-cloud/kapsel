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

The experiment provides exact request matching, durable operation identity, one conditional
Kubernetes mutation opportunity, bounded receiver observation or `UNKNOWN`, and a signed
prototype-scoped receipt.

A second capability, generic provider seam, runtime plugin, policy engine, hosted service,
dashboard, external witness, and stable package format are outside the repository's current
technical scope.

## Consequences

- The public release must demonstrate recovery without a blind second mutation.
- The implementation remains deep around one operation rather than exposing a reusable provider
  interface.
- Any broader capability requires a separate technical owner and decision.
