# Contributor guide

Read this file first. Current technical truth lives in the linked owners.

## Start here

1. Read [`README.md`](README.md), [`docs/SCOPE.md`](docs/SCOPE.md), and
   [`docs/INDEX.md`](docs/INDEX.md).
2. Read the direct contract, tests, and vectors for the surface you will change.
3. Run `cargo make fmt`; it formats Rust and Markdown and expands Markdown tables.
4. Select the narrowest meaningful gate from [`docs/BUILD.md`](docs/BUILD.md).
5. Review with [`docs/REVIEW.md`](docs/REVIEW.md).

## Current technical state

Kapsel publishes a verified v0.2.0 x86-64 GNU/Linux developer-beta artifact for the sole
`kubernetes.set_deployment_image` capability. The hosted sandbox was removed; its contracts are
historical evidence only.

The repository also contains an unpublished, source-qualified `kapseld -> kapsel` resident service.
It is not included in the published v0.2.0 artifact. The
[resident service contract](docs/RESIDENT_SERVICE.md) owns its exact boundary, evidence, and limits.

Lifecycle, receiver-result, and receipt semantics are owned by
[`docs/EFFECT_GATEWAY.md`](docs/EFFECT_GATEWAY.md). Use [`docs/INDEX.md`](docs/INDEX.md) for every
other owner.

## Correction protocol

When code and an owner disagree:

1. Stop the conflicting edit.
2. Compare against [`docs/SCOPE.md`](docs/SCOPE.md) and the direct owner.
3. Correct the canonical owner before implementation.
4. Record unresolved contradictions in the final report.

The technical-scope and effect-gateway owners outrank implementation. Decisions explain rationale;
they do not override current contract text.

## Change rules

- Keep `kubernetes.set_deployment_image` as the only active capability.
- Keep the caller interface bounded: no shell, `kubectl`, manifest, arbitrary patch, tag, wildcard,
  or credential input.
- Keep receipt, trust, authorization, lifecycle, and Kubernetes semantics inside the active deep
  module.
- Do not add runtime plugins, a generic capability SDK, policy engine, queue, hosted control plane,
  dashboard, public provider interface, or second capability.
- Treat MCP as one fixed stdio adapter for the sole capability, not as project identity or a generic
  interface.
- Do not promote a timeout, request acceptance, or provider ambiguity into receiver success or
  failure. Preserve explicit `UNKNOWN`.
- Contracts state behavior. Decisions state rationale. Guides describe commands that exist.
- Keep repository content public, reproducible, and technical; omit private operational context.
- Never create a shadow memory or context file instead of correcting the owner.

## Validation

Docs-only changes: check local links and anchors, run focused terminology searches,
`cargo make fmt-check`, `git diff --check`, and the narrowest repository gate. Contract or code
changes: add owner-specific tests before broadening to `./scripts/ci-local.sh`. The live Kubernetes
gate is separate and requires Docker plus `kind`.

Report meaningful work as:

```text
Contract: <owner document>
Surface: <authorization | lifecycle | receipt | kind demo | MCP | docs>
Gate: <commands and result>
Risk: <what remains unproved>
```
