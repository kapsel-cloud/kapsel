# Contributor and agent router

Read this file first. It routes work; current technical truth lives in the linked owners.

## Start here

1. Read [`README.md`](README.md), [`docs/SCOPE.md`](docs/SCOPE.md), and the prospective
   [`V1 technical direction`](docs/VISION.md) without treating the latter as current release scope.
2. Read the [technical task route](tasks/README.md), completed
   [`0.1.0` release record](tasks/KAP-0045.md), completed
   [self-serve hardening packet](tasks/KAP-0049.md), completed
   [v0.2.0 direction decision](tasks/KAP-0046.md), adopted [v0.2.0 release design](docs/V0.2.md),
   completed release-source locality packet [KAP-0064](tasks/KAP-0064.md), and accepted finite
   qualification packet [KAP-0061](tasks/KAP-0061.md), and completed distribution packet
   [KAP-0062](tasks/KAP-0062.md). Completed candidate-correction packet
   [KAP-0065](tasks/KAP-0065.md) produced the exact replacement candidate after fresh documentation
   review found bundled status contradictions. Completed release acceptance packet
   [KAP-0063](tasks/KAP-0063.md) published and publicly verified exact prerelease `v0.2.0`. The
   [evaluator evidence packet](tasks/KAP-0047.md) remains a supporting owner for exact-artifact
   findings. Completed [sandbox route decision KAP-0069](tasks/KAP-0069.md) selected one serialized
   reshape; active [KAP-0070](tasks/KAP-0070.md) exclusively owns its contract correction,
   implementation, and staged acceptance without pre-authorizing provider use or traffic. Only if
   KAP-0070 produces an exactly accepted public proof may the
   [resident preview decision](tasks/KAP-0054.md) begin; resident implementation remains separately
   gated.
3. Use [`docs/INDEX.md`](docs/INDEX.md) to find the nearest owner.
4. **Name the contract before editing.** Read its tests and vectors when they exist.
5. Keep the active experiment as one deep, compile-time-composed module.
6. Run `cargo make fmt`; it formats Rust and Markdown and expands Markdown tables.
7. Select the narrowest meaningful gate from [`docs/BUILD.md`](docs/BUILD.md).
8. Review with [`docs/REVIEW.md`](docs/REVIEW.md).

## Current route

Kapsel has a verified v0.2.0 mechanism and is reshaping its sandbox into one serialized product
proof for the same sole `kubernetes.set_deployment_image` capability. KAP-0069 retained the fixed
API, deterministic service, and separate runner while superseding the Kubernetes-hosted
remote-controller and key-stager topology. KAP-0070 is the only active route: one native controller
host, one separate per-run runner process, one dedicated synthetic cluster, and at most one active
run through complete cleanup. Its provider, private-live, and public-exposure gates remain
separately authorized. Only after exact KAP-0070 public-proof acceptance may KAP-0054 decide whether
the existing CLI/MCP process suffices or one finite resident boundary is justified; it does not
pre-authorize a daemon, transport, package, or production release. KAP-0047 remains available for
approved aggregate technical findings but is not the implementation route. The release owner is
[`docs/V0.2.md`](docs/V0.2.md); lifecycle, receiver-result, and receipt semantics remain owned by
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
- Treat MCP as one fixed stdio adapter for the sole capability, not as project identity, a generic
  interface, or authorization for another transport. Its exact v0.2.x compatibility remains owned by
  the MCP contract and KAP-0059.
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
