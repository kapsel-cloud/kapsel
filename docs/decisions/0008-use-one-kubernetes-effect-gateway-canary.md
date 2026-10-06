# Use one Kubernetes operation as the effect-gateway canary

Status: accepted.

Kind: decision. Date: 2026-07-14.

Owns: Why Kapsel exercises crash-safe effects with one Kubernetes Deployment image change.

## Context

Kapsel's critical seam lies between a bounded agent request and a consequential provider effect. The
system must durably identify an attempt, avoid blind retries across crashes, observe the receiver,
and explain uncertainty without claiming exactly-once execution.

A Kubernetes Deployment image change has observable effects and is reproducible with `kind`. Process
failures can leave its outcome uncertain. One operation exercises authorization, mutation ordering,
recovery, observation, and receipt inspection without a generic provider abstraction.

## Decision

The canary operation is:

```text
kubernetes.set_deployment_image(namespace, deployment, container, immutable_image_digest)
```

The operation provides exact request matching, durable operation identity, one conditional
Kubernetes mutation opportunity, bounded receiver observation or `UNKNOWN`, and a signed
operation-scoped receipt.

Kubernetes is the first concrete receiver. The choice established a working starting point, not a
permanent capability limit. The current implemented boundary lives in [scope](../scope.md).

## Consequences

- The public release must demonstrate recovery without a blind second mutation.
- The implementation remains deep around one operation rather than exposing a reusable provider
  interface.
- Each new capability needs its own authority, recovery, result, and evidence rules, with contracts
  and tests. The canary does not establish those rules for another receiver.
