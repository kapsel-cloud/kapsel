# Evolve through a customer-resident effect gateway

Status: accepted.

Kind: decision. Date: 2026-07-20.

Owns: Why the intended production architecture keeps effect execution customer-resident and adds
package seams only when deployment or real consumers earn them.

## Context

The 0.1 experiment proves one deep Kubernetes effect lifecycle through a Rust `Application`, local
CLI, stdio MCP adapter, SQLite journal, and signed receipt. The next public product layer needs a
hosted sandbox, while a production product must eventually support real customer workflows,
upgrades, concurrency, and optional managed coordination.

Splitting the workspace into generic core, provider, protocol, receipt, storage, SDK, and adapter
packages now would freeze interfaces inferred from one capability and one production provider. At
the same time, leaving the intended deployment shape unstated would invite the sandbox to become an
accidental production control plane or move customer provider authority into the cloud.

## Decision

Kapsel's intended production identity is a customer-resident effect gateway. A resident `kapseld`
process will own supported local admission, process lifecycle, configuration, bounded concurrency,
health, upgrades, and diagnostics when a real pilot earns that package. The deep `kapsel` package
continues to own bounded authorization, durable effect lifecycle, provider attempt, recovery,
receiver observation, classification, and receipt behavior.

Managed Kapsel may coordinate configuration, upgrades, fleet health, and bounded receipt indexing.
Provider credentials and effect execution remain customer-resident by default.

Package seams are added only for independent deployment, measured dependency isolation, or repeated
real consumers. The public sandbox earns `kapsel-sandbox` as the next package after its contracts
are accepted. A future `kapseld` package remains trigger-gated by a real pilot. Receipt, protocol,
SDK, provider, Kubernetes, storage, and separate CLI packages remain trigger-gated by the conditions
in [V1 technical direction](../VISION.md).

Generic envelopes may own version, operation identity, capability identity, lifecycle, result
category, errors, and receipt signature metadata. Capability request fields, grant matching,
provider semantics, receiver evidence, classification, and classifier-complete receipt statements
remain concrete until multiple implementations prove a repeated seam.

## Consequences

- Kubernetes remains the reference integration rather than Kapsel's product identity.
- The 0.1 root package stays deep; it is not pre-emptively decomposed.
- The public sandbox remains a fixed demonstration and does not define the production resident
  interface.
- The first new package is `kapsel-sandbox`, with a one-way dependency on `kapsel`.
- `kapseld` design may be documented now, but implementation waits for a real pilot and explicit
  technical authorization.
- Managed-cloud disconnection cannot corrupt or redefine customer-resident effect execution.
- A future extraction cites its trigger and rejects unearned alternatives.
- V1 compatibility and proof obligations remain explicit release work, not consequences of package
  naming.
