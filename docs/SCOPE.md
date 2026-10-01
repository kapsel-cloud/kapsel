# Technical scope

This page states what Kapsel implements and what its releases promise. The [README](../README.md)
owns purpose and ambition. The [effect-gateway contract](EFFECT_GATEWAY.md) owns exact
authorization, lifecycle, recovery, results, and receipts. Current limits are not a ban on further
development. Update this page with the implementation, contract, and tests when behavior changes.

## Current boundary

Current source supports an exact Kubernetes Deployment image change and an exact local Git branch
transition. Both use operator-owned authority, stable operation identity, worker exclusion, durable
attempt ordering, observation-only recovery, and immutable evidence. Each has its own result rules.

The operator retains credentials, signed grants, trust, receipt-signing material, and private
storage. The caller selects an approved identity and retrieves evidence. Model confidence cannot
replace a grant or redefine a result. A signature authenticates bytes; it cannot supply missing
receiver facts.

The Linux resident service keeps operations alive independently of the caller. Its bounded catalog
uses exact-snapshot approvals, durable admission, one active worker, and read-first startup.
Resumption is explicit and uses the same action ID. The surrounding workflow owns selection and
waiting. There is no queue or automatic scheduler. [Service contracts](KAPSEL_SERVICE.md) own the
protocol and limits.

Current source also includes an ID-only stdio MCP bridge to this service. It is separate from the
older five-field direct-execution MCP adapter and is not in the published preview.

Neither effect coordinates independent journals or hosts. There is no fleet ordering, distributed
transaction, or system-wide invariant guarantee. Git also has no hook-delivery guarantee. Neither
effect exposes a generic command or provider interface.

## Concrete capabilities

### Kubernetes image change

```text
kubernetes.set_deployment_image(namespace, deployment, container, immutable_image_digest)
```

The caller supplies a stable operation identity. Direct CLI/MCP requests also name the namespace,
Deployment, container, and immutable image. A service caller selects an operator-prepared action ID.
Caller input cannot supply credentials, trust, grants, shell commands, `kubectl`, manifests,
arbitrary patches, tags, wildcards, paths, or lifecycle controls.

### Git branch transition

`git.transition_ref` uses a separately signed approval for one repository, `refs/heads/approved`,
and exact SHA-1 commits A and B. Operator-only material selects private bare repositories and Git
2.55.0. The ID-only caller cannot supply Git arguments, paths, credentials, or a replacement tuple.

An original successful per-ref acknowledgement establishes the transition, not hook delivery, CI, or
deployment completion. Missing acknowledgement remains `UNKNOWN`, even if a later observation finds
B. Explicit receiver rejection or local pre-send rejection means `FAILED`, not absence of hook side
effects. See the [Git contract](EFFECT_GATEWAY.md#git-transition-boundary) and
[source example](GIT_REF_TRANSITION.md).

## Durable recovery and evidence

For Kubernetes, the sequence is:

```text
bounded request
  -> exact operator-owned authorization
  -> durable pre-attempt rejection or mutation marker
  -> one conditional patch opportunity
  -> bounded rollout observation
  -> SUCCEEDED / FAILED / UNKNOWN
  -> frozen signed receipt
```

Kapsel commits target identity and `apply_started` before attempting the patch. A private one-use
permission connects that fresh commit to dispatch. Recovery from attempted history only observes. It
never derives permission to resend from stored state.

`SUCCEEDED` and `FAILED` classify bounded observations of the same target, image, and generation.
`UNKNOWN` means reconciliation established neither result. It does not mean failure, no effect,
safety, or permission to retry.

A permanently missing or invalid target can finish as `NOT_ATTEMPTED` before the mutation marker. A
changed approved UID or resourceVersion produces `NOT_ATTEMPTED / STALE_APPROVAL`. These local
dispositions have no receiver result or effect receipt. The service requires snapshot approval.
Legacy CLI/MCP grants retain their late-bound meaning. An existing action cannot acquire refreshed
approval.

SQLite commits signed receipts with terminal state. Offline inspection, CLI/MCP export, and service
retrieval use those frozen bytes. Status and receipt reads neither acquire new observations nor
revise a terminal result.

Inspection checks authenticity and classifier consistency under separately supplied trust. It does
not prove causation, exactly-once effects, receiver truth, complete cluster health, complete
capture, or compliance.

## What is published

[v0.3.0-preview.1](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.3.0-preview.1) is a
**non-production** resident-service preview for `x86_64-unknown-linux-gnu`. Its release page
identifies exact source and artifact digests and qualification evidence. It contains feature-free
`kapsel`, `kapseld`, and `kapsel-service-client`, operating assets, and an authenticated extraction
route. The [operator guide](KAPSEL_SERVICE_OPERATOR.md) owns preparation and operation. There is no
custom installer or production-support promise.

Current journal format 6 retains original signed grants and rejects older formats without changing
them. There is no migration, downgrade, pruning, or host-loss continuity guarantee. Preserve
journals, sidecars, and original access materials under matching binaries. A fresh journal or new
identity is not permission to repeat an attempted action. [Journal retention](UPGRADE.md) owns the
procedure.

The earlier [v0.2.0 beta](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.2.0) retains its
[tagged contracts](https://github.com/kapsel-cloud/kapsel/tree/v0.2.0/docs). Its CLI, MCP, archive,
and historical journal-upgrade promises do not apply to the preview. Current source changes do not
alter published artifacts.

## Maturity and exclusions

Preview evidence covers one operation, receiver, platform, and named failure windows. It does not
establish production availability, support, remediation, high availability, backup automation, or a
general platform guarantee. Process-exit tests do not establish disk-backed power-loss durability.

Current source has no general Kubernetes administration, arbitrary execution, provider SDK, policy
language, workflow engine, runtime plugins, public Rust SDK, hosted control plane, dashboard, fleet
manager, generic audit product, external witness, or universal capture mechanism.
