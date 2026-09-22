# Technical scope

Kapsel is an open-source execution boundary beneath fallible callers. It binds concrete effects to
explicit authority and preserves trustworthy execution facts and uncertainty across partial failure.
Choosing a useful action and judging application quality belong to the surrounding system.

This page owns the implemented boundary and maturity. The
[effect-gateway contract](EFFECT_GATEWAY.md) owns exact authorization, lifecycle, recovery, result,
and receipt semantics. Linear owns accepted direction, planned work, priorities, assignments,
acceptance decisions, and progress. Work recorded there does not become an implemented capability
until its contracts, code, and evidence agree.

## Current boundary

The implementation is a bounded action broker for one Kubernetes Deployment image change. Its core
is exact authority, stable action identity, worker exclusion, durable attempt ordering,
observation-only recovery, bounded classification, and immutable evidence.

The operator retains credentials, signed grants, trust, receipt-signing material, and private
storage. The caller can select an approved identity and retrieve its evidence. Model confidence
cannot replace the exact grant or redefine the receiver result. A signature authenticates bytes; it
does not supply missing receiver knowledge.

The Linux resident service provides a caller-independent lifetime. Its bounded catalog uses
exact-snapshot approvals, durable admission, one active worker, and read-first startup with explicit
same-ID resumption. Selection and waiting remain with the caller's surrounding workflow. There is no
queue or automatic scheduler. [Service contracts](KAPSEL_SERVICE.md) own protocol and limits.

The local journal and conditional Kubernetes patch do not coordinate independent agents across
journals or hosts. They provide no fleet ordering, distributed transaction, or system-wide invariant
guarantee. A different effect needs its own authority, commit, and recovery semantics. The broader
motivation does not establish a generic interface or a second implemented capability.

## One capability

```text
kubernetes.set_deployment_image(namespace, deployment, container, immutable_image_digest)
```

The caller supplies a stable operation identity. Local CLI/MCP requests also name the namespace,
Deployment, container, and immutable digest-bound image; the service caller selects an operator-
prepared ID. Caller input cannot contain credentials, trust, grants, shell commands, `kubectl`,
manifests, arbitrary patches, tags, wildcards, paths, or lifecycle controls.

## One durable path

```text
bounded request
  -> exact operator-owned authorization
  -> durable pre-attempt rejection or mutation marker
  -> one conditional Kubernetes patch opportunity
  -> bounded rollout observation
  -> SUCCEEDED / FAILED / UNKNOWN
  -> frozen signed receipt
```

Kapsel commits target identity and `apply_started` before attempting the patch. A private one-use
dispatch permission connects fresh commitment to the concrete adapter. Recovery from attempted
history observes; it never derives permission to resend from stored state.

`SUCCEEDED` and `FAILED` are classifications over bounded observations of the same target, image,
and generation. `UNKNOWN` means reconciliation established neither result. It does not mean failure,
no effect, safety, or permission to retry.

A permanent missing or invalid target may finish as `NOT_ATTEMPTED` before the mutation marker.
Exact-snapshot approval rejects a changed UID or resourceVersion as
`NOT_ATTEMPTED / STALE_APPROVAL`. These are local dispositions with no receiver result or effect
receipt. The service requires snapshot approval; legacy CLI/MCP grants retain their late-bound
meaning. An existing action never acquires refreshed approval.

SQLite owns signed receipt completion. Offline inspection, CLI/MCP export, and service retrieval
consume that evidence. Status and receipt reads do not acquire later observations or revise a
terminal result. Inspection authenticates frozen bytes and classifier consistency under separately
supplied trust. It does not prove causation, exactly-once effects, complete cluster health, complete
capture, compliance, or Kubernetes truth.

## What is published

[v0.3.0-preview.1](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.3.0-preview.1) is the
published non-production resident-service preview for `x86_64-unknown-linux-gnu`. Its release page
identifies the exact source and artifact digests and finite qualification evidence. It includes
feature-free `kapsel`, `kapseld`, and `kapsel-service-client`, operating assets, and an
authenticated extraction route. The [operator guide](KAPSEL_SERVICE_OPERATOR.md) owns preparation
and operation. There is no custom installer or production-support promise.

Current journal format 5 retains original signed grants and refuses older formats unchanged, with no
migration, downgrade, pruning, or host-loss continuity guarantee. Preserve journals, sidecars, and
original access materials under matching binaries. A fresh journal or new identity is not permission
to repeat an attempted action. [Journal retention](UPGRADE.md) owns operating guidance.

The earlier [v0.2.0 beta](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.2.0) and its
[tagged contracts](https://github.com/kapsel-cloud/kapsel/tree/v0.2.0/docs) remain separate. Its
CLI, MCP, archive, and bounded historical journal upgrade promises do not apply to the preview. Tags
and published artifacts are unchanged by current-source cleanup.

## Maturity and exclusions

The preview has finite evidence for one operation, receiver, platform, and named failure windows. It
provides no production availability, remediation, support, high availability, backup automation, or
general platform promise. Process-exit tests do not establish disk-backed power-loss durability.

The current implementation includes no general Kubernetes administration, arbitrary execution,
provider SDK, policy language, workflow engine, runtime plugin system, public Rust SDK, hosted
control plane, dashboard, fleet manager, generic audit product, external witness, or universal
capture mechanism. Additional mechanisms require a concrete technical question and their own
executable evidence; an abstract reuse possibility is insufficient.
