# Technical scope

> Give an agent one bounded Kubernetes operation without giving it Kubernetes credentials.

Status: active experiment.

This document owns Kapsel's purpose, sole capability, maturity, and technical non-goals. The
[effect-gateway contract](EFFECT_GATEWAY.md) owns exact authorization, lifecycle, result, and
receipt semantics.

## What Kapsel does

Kapsel turns one authorized request into a durable provider attempt, receiver observation or
explicit uncertainty, and an inspectable receipt:

```text
agent request
  -> operator-owned exact grant and trust
  -> durable pre-attempt rejection or mutation marker
  -> conditional Kubernetes mutation
  -> receiver observation or UNKNOWN
  -> signed receipt
```

The sole capability is:

```text
kubernetes.set_deployment_image(namespace, deployment, container, immutable_image_digest)
```

The caller supplies only those bounded request fields. The operator separately owns the grant,
trust, Kubernetes authority, signing material, journal, and receipt paths.

## What exists

The published [v0.2.0 developer beta](V0.2.md) provides:

- one x86-64 GNU/Linux release;
- a local CLI and fixed-schema stdio MCP adapter;
- signed exact grants and receipts;
- SQLite-backed crash recovery;
- a disposable-`kind` demonstration; and
- upgrade and rollback evidence from v0.1.1.

The repository also contains an unpublished customer-resident [Kapsel service](KAPSEL_SERVICE.md).
It adds caller-independent process lifetime, reconnectable status, and exact receipt retrieval over
an authenticated local socket. It is not part of v0.2.0 and is not production-ready.

The hosted sandbox was removed. Its [historical record](HISTORICAL_SANDBOX.md) points to the retired
contracts and fixtures; none are current interfaces.

## Result meaning

Kapsel may report:

- `SUCCEEDED` when the bounded receiver facts satisfy the available-rollout classifier;
- `FAILED` when they contain the defined `ProgressDeadlineExceeded` condition;
- `UNKNOWN` when bounded reconciliation cannot establish either result; or
- `NOT_ATTEMPTED` when a permanent local target rejection occurs before mutation is recorded.

These results do not prove exactly-once effects, Kubernetes truth, causation, complete cluster
health, complete capture, or compliance. An inspected receipt authenticates its bytes under supplied
trust; it does not prove that every disclosed external fact is true.

## Maturity

Kapsel 0.2.0 is a developer beta, not production software. Its named CLI, MCP, grant, receipt,
archive, and journal-upgrade surfaces have bounded v0.2.x compatibility. Public Rust APIs, the
Kapsel service, another platform, and production support do not.

The [V1 technical direction](VISION.md) describes possible future requirements, not a roadmap or
commitment.

## Non-goals

Kapsel does not provide:

- arbitrary shell, `kubectl`, manifest, patch, tag, wildcard, or credential input;
- a second Kubernetes operation;
- a generic MCP host, provider SDK, policy language, or workflow engine;
- runtime plugins or a public Rust SDK;
- a hosted service, managed control plane, dashboard, or fleet manager;
- a generic receipt or compliance product;
- production support, high availability, or another platform target; or
- exactly-once mutation, universal capture, or independent witnessing.

A second capability or wider platform requires its own evidence and owner. It is not implied by the
current experiment.
