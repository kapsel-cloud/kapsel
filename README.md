# kapsel

A crash-recoverable effect-gateway experiment for autonomous agents.

Kapsel is testing whether agents can use bounded operations instead of receiving unrestricted
provider credentials. It verifies an owner-signed exact grant, records either a pre-attempt target
rejection or the validated target before the dangerous mutation seam, recovers without blindly
repeating the mutation, observes the receiver, and emits an inspectable result—including `UNKNOWN`
when reality cannot be established. The remaining release work includes MCP composition and
versioned distribution artifacts.

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
> Kapsel is a pre-release experiment. It is not production-ready, a generic agent runtime, or a
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
trust, Kubernetes authority, signing material, and paths. It is available as a pre-V1 alpha for Rust
evaluation. A prototype local evaluator command now provisions exact grants, runs or reconciles the
bounded operation, and inspects receipts offline.

Kapsel reports `SUCCEEDED`, `FAILED`, or `UNKNOWN`. These are bounded receiver outcomes, not claims
of exactly-once mutation, causation, complete cluster health, complete capture, or Kubernetes truth.

## Rust alpha

The crates.io alpha exposes the implemented fixed Kubernetes experiment and offline inspector:

```toml
[dependencies]
kapsel = "=0.1.0-alpha.1"
```

Operator composition constructs `OperatorConfiguration`, including the exact signed grant, external
trust, Kubernetes client, receipt signing material, journal path, and private receipt directory. A
request-only caller can then use `Application::execute`; restart recovery uses
`Application::reconcile`, and adapters consume the resulting `OperationReport` without sequencing
internal durable states.

This Unix-only alpha does not promise a stable CLI, configuration-file format, Rust API, receipt
format, or production readiness. See the
[experiment boundary](docs/experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) before use.

## What exists today

| Surface                                          | Status                                                  |
| ------------------------------------------------ | ------------------------------------------------------- |
| Signed exact grant and SQLite recovery lifecycle | Implemented in the product package                      |
| Conditional Deployment image mutation            | Implemented and exercised by an explicit live-kind gate |
| Classifier-complete receipt and inspection       | Implemented in the experiment library                   |
| Process-kill mutation and publication recovery   | Implemented in deterministic subprocess tests           |
| Failed-rollout live-kind test proof              | Implemented in the explicit live-kind gate              |
| Evaluator demo with real process termination     | Implemented through an owned disposable-kind harness    |
| Evaluator-facing operation and inspection CLI    | Implemented as a prototype local command                |
| MCP-compatible entrypoint                        | Not implemented                                         |
| V1 evaluator artifacts and checksums             | Not implemented                                         |

The exact prototype grammar and file separation are owned by the
[evaluator command contract](docs/COMMANDS.md). The current engineering proof is:

```sh
./scripts/ci-local.sh
cargo make test-demo-harness
cargo make demo-kind  # requires Docker, kind 0.32+, and kubectl 1.30+
```

Each live command creates and removes its own uniquely named cluster. This is demonstration
evidence, not part of the deterministic default gate. See [Build](docs/BUILD.md) for exact meaning
and prerequisites.

## Scope discipline

The repository has one capability and one Kubernetes adapter. Arbitrary execution, runtime plugins,
a generic provider SDK, a policy language, hosted operation, a dashboard, and a second capability
are outside its technical scope.

## Read next

- [Technical scope](docs/V1.md)
- [Active experiment contract](docs/experiments/KAP-0038-kubernetes-effect-gateway-boundary.md)
- [Build and proof commands](docs/BUILD.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security policy](SECURITY.md)
- [Documentation index](docs/INDEX.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
