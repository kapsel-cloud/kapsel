# Technical scope

This page defines Kapsel's capabilities and support limits. The [README](../README.md) explains its
purpose. The [effect-gateway contract](reference/effect_gateway.md) defines exact behavior.

## Current boundary

Kapsel supports an exact Kubernetes Deployment image change and an exact local Git branch
transition. Both use operator-owned authority, stable operation identity, one worker, durable
attempt ordering, observation-only recovery, and immutable evidence. Each has its own result rules.

The operator retains credentials, signed grants, trust, receipt-signing material, and private
storage. The caller selects an approved identity through the fixed client or MCP bridge and
retrieves evidence. Model confidence cannot replace a grant or redefine a result. A signature
authenticates bytes. It cannot supply missing receiver facts.

The resident Linux service keeps operations alive independently of the caller. Startup is
read-first. Resumption is explicit and uses the same action ID. The surrounding workflow decides
when to select an operation and when to wait. There is no queue or automatic scheduler.
[Service contracts](reference/service.md) own the protocol and limits.

Neither effect coordinates independent journals or hosts. There is no fleet ordering, distributed
transaction, or system-wide invariant guarantee. Neither exposes a generic command or provider
interface.

## Concrete capabilities

### Kubernetes image change

```text
kubernetes.set_deployment_image(namespace, deployment, container, immutable_image_digest)
```

The caller selects an operator-prepared action ID. The approval fixes namespace, Deployment,
container, immutable image, and the Deployment UID/resourceVersion snapshot. Caller input cannot
supply credentials, trust, grants, shell commands, `kubectl`, manifests, arbitrary patches, tags,
wildcards, paths, or lifecycle controls.

A changed approved snapshot produces `NOT_ATTEMPTED / STALE_APPROVAL` before a PATCH. Retained
legacy grants remain readable under their original meaning but cannot authorize service advancement.
An existing action cannot acquire refreshed approval.

After recording an attempt, recovery only observes. It never resends the patch. `SUCCEEDED` and
`FAILED` classify bounded observations of the same target, image, and generation. `UNKNOWN` means
those observations established neither result, not that retrying is safe. See the
[lifecycle contract](reference/kubernetes_effect.md#operation-lifecycle).

### Git branch transition

`git.transition_ref` uses a separately signed approval for one repository, `refs/heads/approved`,
and exact SHA-1 commits A and prepared descendant B. Operator-only material selects private bare
repositories and Git 2.55.0. The caller cannot supply Git arguments, paths, credentials, or a
replacement tuple.

An original successful per-ref acknowledgement establishes the transition, not hook delivery, CI, or
deployment completion. Missing acknowledgement remains `UNKNOWN`, even if a later observation finds
B. Explicit receiver rejection or local pre-send rejection means `FAILED`, not absence of hook side
effects. See the [Git contract](reference/git_effect.md) and
[operator example](guides/git_transition.md).

## Evidence and retained state

SQLite commits original signed receipt bytes with terminal state. Status and receipt reads neither
acquire new observations nor revise a terminal result. Caller export is separate from completion.
Offline inspection checks authenticity and classifier consistency under independently supplied
trust. It does not prove causation or receiver truth.

Journal format 6 retains original signed grants and receipts and rejects older formats unchanged.
There is no migration, downgrade, pruning, automatic backup, or host-loss continuity guarantee. A
fresh journal or new identity is not permission to repeat an attempted action.
[Preserve operation history](guides/journal_retention.md) explains state custody. There is no
cross-version support commitment or stable public Rust API. The
[release process](contributing/release_process.md#compatibility-boundary) defines that policy.

## What is published

The latest release, [v0.3.0](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.3.0), is a
**pre-beta, non-production developer release** for `x86_64-unknown-linux-gnu`. It includes both
effects, four feature-free executables, operating assets, and an authenticated extraction route. Its
release page records exact bytes and qualification. The [operator guide](guides/operator.md) covers
preparation and operation.

## Maturity and exclusions

Qualification covers two effects, one platform, and named failure windows. It does not establish
production availability, support, remediation, high availability, backup automation, or a general
platform guarantee. Process-exit tests do not establish disk-backed power-loss durability.
Model-driven qualification covers one healthy approved action, not useful action selection or
application quality. Deterministic callers exercise the fault and recovery cases.

Kapsel has no general Kubernetes administration, arbitrary execution, provider SDK, policy language,
workflow engine, runtime plugins, public Rust SDK, hosted control plane, dashboard, fleet manager,
generic audit product, external witness, or universal capture mechanism.
