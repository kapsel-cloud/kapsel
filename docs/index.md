# Documentation

Choose a route for what you need to do. These pages describe the development checkout. Use the
[bundled guides or Git tag](https://github.com/kapsel-cloud/kapsel/tree/v0.3.0/docs) for v0.3.0.

Introductory pages stay here. `guides/` contains procedures, `reference/` contains exact contracts,
and `contributing/` contains implementation and qualification material. `decisions/` explains
rationale. The routes below link directly to each page.

## Start

1. [README](../README.md): what Kapsel does and when it helps.
2. [Run one approved operation](getting_started.md): see submission, inspection, and retrieval after
   restart.
3. [How Kapsel works](tour.md): understand authority, attempts, and uncertain outcomes.

For evaluation without installation, read the README, the tour, and
[capabilities and limits](scope.md).

## Use and operate

**Callers:** follow the [caller guide](guides/caller.md) to discover approvals, retain an operation
identity, submit, reconnect, and retrieve evidence. Use [MCP](reference/mcp.md) or the
[fixed client reference](reference/service.md#fixed-service-client) for integration details.

**Operators:** authenticate the
[release](reference/release.md#authenticate-and-extract-the-release), then follow the
[operator guide](guides/operator.md). Prepare a Kubernetes approval there or follow
[Git preparation](guides/git_transition.md#operator-preparation). For blocked work, start with
[diagnosis and same-ID resumption](guides/operator.md#diagnose-and-resume). Read
[preserve operation history](guides/journal_retention.md) before changing executables or storage.

## Reference

| Subject                                                   | Document                                            |
| --------------------------------------------------------- | --------------------------------------------------- |
| Capabilities, platform, and maturity                      | [Scope](scope.md)                                   |
| Journal bounds, capacity, and commit alternatives         | [Storage](reference/storage.md)                     |
| Authority, admission, lifecycle, and recovery             | [Effect gateway](reference/effect_gateway.md)       |
| Kubernetes approval and rollout rules                     | [Kubernetes effect](reference/kubernetes_effect.md) |
| Git approval, acknowledgement, and ref observations       | [Git effect](reference/git_effect.md)               |
| Signed receipts, trust, and offline inspection            | [Evidence formats](reference/evidence_formats.md)   |
| Service configuration, socket protocol, and process rules | [Service](reference/service.md)                     |
| Operator CLI grammar and files                            | [Commands](reference/commands.md)                   |
| Stdio tools, framing, and errors                          | [MCP](reference/mcp.md)                             |
| Security assumptions and threats                          | [Threat model](reference/threat_model.md)           |
| Disclosure and handling of operational metadata           | [Privacy](reference/privacy.md)                     |
| Release authentication, archive layout, and provenance    | [Release artifacts](reference/release.md)           |
| Vulnerability reporting                                   | [Security policy](../SECURITY.md)                   |

## Contribute

Start with [Contributing](../CONTRIBUTING.md) and [Build and test](contributing/build.md). Then read
the contract for your change and use [Architecture](contributing/architecture.md) to locate its
implementation.

- [Engineering conventions](../CONTRIBUTING.md#engineering-conventions): Rust, Python, and interface
  rules.
- [Testing](contributing/testing.md): where tests belong and which evidence class a change needs.
- [Evidence map](contributing/evidence.md): maintained guarantee-to-test mappings and boundary
  limits.
- [Qualification](contributing/qualification.md): environment-specific, robustness, and artifact
  commands.
- [Runtime ownership](contributing/service_runtime.md): admission races and physical retirement.
- [Storage capacity argument](contributing/storage_capacity.md): why admitted work fits, and which
  implementation changes require revalidation.
- [Release process](contributing/release_process.md): acceptance gates and publication sequence.
- [Decisions](decisions/README.md): rationale behind consequential design choices.

Contracts describe current behaviour. Decisions explain why the design works this way, but do not
override contracts. [Release tags](https://github.com/kapsel-cloud/kapsel/tags) retain prior
documentation, and the [changelog](../CHANGELOG.md) records release history.
