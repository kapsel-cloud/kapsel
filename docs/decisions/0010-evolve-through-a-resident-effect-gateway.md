# Evolve through a customer-resident effect gateway

Status: accepted; KAP-0073 supersedes the sandbox-first sequencing while preserving the
customer-resident direction and earned-seam rule.

Kind: decision. Date: 2026-07-20.

Owns: Why the intended production architecture keeps effect execution customer-resident and adds
package seams only when deployment or real consumers earn them.

## Context

The 0.1 experiment proves one deep Kubernetes effect lifecycle through a Rust `Application`, local
CLI, stdio MCP adapter, SQLite journal, and signed receipt. This decision originally expected a
hosted sandbox before the resident preview. KAP-0073 later found that anonymous hosted operation
would add a second system without testing customer utility and retired that sequencing. A production
product still requires real customer workflows, upgrades, concurrency, and optional managed
coordination.

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
real consumers. The public sandbox temporarily earned `kapsel-sandbox`, but KAP-0073 archives and
removes that package after its product need disappeared. A future `kapseld` package remains
trigger-gated by KAP-0054 and a finite preview; production compatibility remains trigger-gated by
retained use. Receipt, protocol, SDK, provider, Kubernetes, storage, and separate CLI packages
remain trigger-gated by [V1 technical direction](../VISION.md).

Generic envelopes may own version, operation identity, capability identity, lifecycle, result
category, errors, and receipt signature metadata. Capability request fields, grant matching,
provider semantics, receiver evidence, classification, and classifier-complete receipt statements
remain concrete until multiple implementations prove a repeated seam.

## Consequences

- Kubernetes remains the reference integration rather than Kapsel's product identity.
- The 0.1 root package stays deep; it is not pre-emptively decomposed.
- The retired public sandbox does not define the preview or production resident interface.
- `kapsel-sandbox` remains historical evidence and is removed from the active workspace.
- KAP-0054 must test protected CLI/MCP first; a preview `kapseld` is permitted only if that decision
  proves one resident process is the smallest safe route.
- Production `kapseld` compatibility still waits for retained use and explicit authorization.
- Managed-cloud disconnection cannot corrupt or redefine customer-resident effect execution.
- A future extraction cites its trigger and rejects unearned alternatives.
- V1 compatibility and proof obligations remain explicit release work, not consequences of package
  naming.
