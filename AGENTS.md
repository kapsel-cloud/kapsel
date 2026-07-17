# Contributor and agent router

Read this file first. It routes work; current technical truth lives in the linked owners.

## Start here

1. Read [`README.md`](README.md) and [`docs/SCOPE.md`](docs/SCOPE.md).
2. Read the [technical task route](tasks/README.md) and active packet,
   [`tasks/KAP-0045.md`](tasks/KAP-0045.md).
3. Use [`docs/INDEX.md`](docs/INDEX.md) to find the nearest owner.
4. **Name the contract before editing.** Read its tests and vectors when they exist.
5. Keep the active experiment as one deep, compile-time-composed module.
6. Run `cargo make fmt`; it formats Rust and Markdown and expands Markdown tables.
7. Select the narrowest meaningful gate from [`docs/BUILD.md`](docs/BUILD.md).
8. Review with [`docs/REVIEW.md`](docs/REVIEW.md).

## Current route

Kapsel is testing one Kubernetes effect-gateway capability. The active technical owner is
[`docs/experiments/KAP-0038-kubernetes-effect-gateway-boundary.md`](docs/experiments/KAP-0038-kubernetes-effect-gateway-boundary.md).
Use [`docs/INDEX.md`](docs/INDEX.md) for every other owner rather than recreating its routing here.

## Correction protocol

When code, a task, and an owner disagree:

1. Stop the conflicting edit.
2. Compare against [`docs/SCOPE.md`](docs/SCOPE.md) and the direct active owner.
3. Record any unresolved contradiction in the active task or final report.
4. Update the canonical owner before implementation; do not average incompatible designs.

The technical-scope owner and KAP-0038 experiment owner outrank implementation. Accepted ADRs
explain why a route was chosen; they do not override current contract text.

## Change rules

- Keep `kubernetes.set_deployment_image` as the only active capability.
- Keep the caller interface bounded: no shell, `kubectl`, manifest, arbitrary patch, tag, wildcard,
  or credential input.
- Keep receipt, trust, authorization, lifecycle, and Kubernetes semantics prototype-scoped inside
  the active experiment.
- One production adapter does not justify a public provider interface. Do not add runtime plugins, a
  generic capability SDK, policy engine, queue, hosted control plane, dashboard, or second
  capability.
- Treat MCP as one implemented 0.1 prototype transport adapter, not as project identity, a
  compatibility promise, or a generic API.
- Do not promote a timeout, request acceptance, or provider ambiguity into receiver success or
  failure. Preserve explicit `UNKNOWN`.
- Contracts state shared behavior. ADRs state rationale. Guides describe commands that exist. Tasks
  state remaining work and link owners.
- Keep private interviews, launch evidence, customer data, and company planning out of this public
  repository. Publish only aggregate technical facts approved for public use.
- Never create a shadow memory, summary, or context file instead of correcting the owner.

## Validation selection

Docs-only changes: local links and anchors, focused terminology/overclaim searches,
`cargo make fmt-check`, `git diff --check`, then the narrowest available repository gate. Contract
or code changes: add owner-specific tests before broadening to `./scripts/ci-local.sh`. The live
Kubernetes gate is separate and requires Docker plus `kind`.

Report meaningful work as:

```text
Contract: <owner document>
Surface: <authorization | lifecycle | receipt | kind demo | MCP | docs>
Gate: <commands and result>
Risk: <what remains unproved>
```
