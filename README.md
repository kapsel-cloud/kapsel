# kapsel

[![CI](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/kapsel-cloud/kapsel?display_name=tag&sort=semver)](https://github.com/kapsel-cloud/kapsel/releases/latest)

A crash-recoverable effect-gateway experiment for autonomous agents.

Kapsel tests a simple idea: give agents bounded operations, not provider credentials. Its current
experiment accepts one authorized Kubernetes image change, records state before any mutation
attempt, recovers without blindly retrying, and returns an inspectable `SUCCEEDED`, `FAILED`, or
`UNKNOWN` result.

```text
bounded agent intent
  -> owner-signed exact grant under application-configured trust
  -> durable pre-attempt rejection or target identity
  -> conditional provider mutation when attempted
  -> receiver observation or UNKNOWN
  -> classifier-complete signed experiment receipt
```

> [!WARNING]
>
> Kapsel 0.1.1 is an experiment. It is not production-ready, a generic agent runtime, or a
> compliance product. Do not use it for consequential production changes.

## Active experiment

The only active capability is:

```text
kubernetes.set_deployment_image(namespace, deployment, container, immutable_image_digest)
```

The experiment runs against a disposable local `kind` cluster. Its release-owned demonstration
covers a healthy rollout and an unavailable-image `ProgressDeadlineExceeded` rollout, kills the real
command process after mutation and receipt-publication seams, and restarts without a blind second
mutation or changed frozen receipt bytes. Deterministic tests exercise the same two process seams
without a container.

The Rust `Application` interface separates request-only `AgentRequest` from operator-owned grant,
trust, Kubernetes authority, signing material, and paths. Operator composition supplies that
authority once; callers use `Application::execute` and `Application::reconcile` without sequencing
internal durable states. A local evaluator command and one fixed-schema stdio MCP tool expose the
same bounded request.

Kapsel reports `SUCCEEDED`, `FAILED`, or `UNKNOWN`. These are bounded receiver outcomes, not claims
of exactly-once mutation, causation, complete cluster health, complete capture, or Kubernetes truth.

The [Kapsel `0.1.1` release](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.1.1) is the
stable x86-64 GNU/Linux experiment artifact. “Stable” identifies a named, non-prerelease artifact;
it does not promise production support or compatibility for the CLI, configuration, Rust API, MCP
adapter, receipt format, or artifact layout. See the
[experiment boundary](docs/experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) before use.

## What exists today

| Surface                                          | Status                                                     |
| ------------------------------------------------ | ---------------------------------------------------------- |
| Signed exact grant and SQLite recovery lifecycle | Implemented in the product package                         |
| Conditional Deployment image mutation            | Implemented and exercised by an explicit live-kind gate    |
| Classifier-complete receipt and inspection       | Implemented in the experiment library                      |
| Process-kill mutation and publication recovery   | Implemented in deterministic subprocess tests              |
| Failed-rollout live-kind test proof              | Implemented in the explicit live-kind gate                 |
| Evaluator demo with real process termination     | Implemented through an owned disposable-kind harness       |
| Evaluator-facing operation and inspection CLI    | Implemented as a prototype local command                   |
| Thin fixed-schema MCP stdio adapter              | Implemented with deterministic black-box tests             |
| Versioned x86-64 Linux artifact and checksum     | Implemented as a reproducible stable release lane          |
| Fixed public sandbox service and Gate 1 fixture  | Service implemented; runner-composition correction pending |

The exact local evaluator grammar and file separation are owned by the
[evaluator command contract](docs/COMMANDS.md); the fixed protocol surface is owned by the
[MCP adapter contract](docs/MCP.md), and distribution by the
[release artifact contract](docs/RELEASE.md). The current engineering proof is:

```sh
cargo test --locked --test e2e_mcp_adapter
./scripts/ci-local.sh
cargo make test-demo-harness
cargo make test-release-artifact
cargo make test-release-reproducibility
cargo make demo-kind  # requires Docker, kind 0.32+, and kubectl 1.30+
```

Each live command creates and removes its own uniquely named cluster. This is demonstration
evidence, not part of the deterministic default gate. See [Build](docs/BUILD.md) for exact meaning
and prerequisites.

## Scope discipline

The repository has one capability and one Kubernetes adapter. Arbitrary execution, runtime plugins,
a generic provider SDK, a policy language, general hosted operation, a dashboard, and a second
capability are outside its technical scope. The sole hosted exception is one fixed non-consequential
public sandbox. Its deterministic service package is implemented, while the provider-neutral Gate 1
runner composition is under correction and not accepted. No provider is selected and no sandbox
deployment or public traffic is approved.

## Read next

- [Technical scope](docs/SCOPE.md)
- [Active experiment contract](docs/experiments/KAP-0038-kubernetes-effect-gateway-boundary.md)
- [Prospective V1 technical direction](docs/VISION.md)
- [Build and proof commands](docs/BUILD.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Public sandbox API](docs/SANDBOX_API.md)
- [Public sandbox deployment](docs/SANDBOX_DEPLOYMENT.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security policy](SECURITY.md)
- [Documentation index](docs/INDEX.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
