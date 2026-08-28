# kapsel

[![CI](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml)
[![Developer beta](https://img.shields.io/badge/developer_beta-v0.2.0-orange)](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.2.0)

A crash-recoverable Kubernetes effect gateway for autonomous agents.

Kapsel gives an agent one bounded operation without giving it Kubernetes credentials. It records
state before attempting the change, recovers after process loss without blindly retrying, and
returns an inspectable `SUCCEEDED`, `FAILED`, or `UNKNOWN` result.

> [!WARNING]
>
> Kapsel 0.2.0 is a developer beta. It is not production-ready, a generic agent runtime, or a
> compliance product. Do not use it for consequential production changes.

## The one operation

```text
kubernetes.set_deployment_image(namespace, deployment, container, immutable_image_digest)
```

```text
agent request
  -> operator-owned exact grant, trust, and Kubernetes authority
  -> durable pre-attempt rejection or mutation marker
  -> conditional image change
  -> Kubernetes rollout observation or UNKNOWN
  -> signed receipt
```

The agent cannot supply credentials, shell commands, `kubectl`, manifests, arbitrary patches, tags,
wildcards, or lifecycle controls. The operator keeps authority and signing material outside caller
input.

`SUCCEEDED` and `FAILED` describe bounded Kubernetes rollout observations. `UNKNOWN` means Kapsel
could not establish either result after bounded recovery. None proves exactly-once mutation,
causation, complete cluster health, or Kubernetes truth.

## Try the published beta

The [v0.2.0 release](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.2.0) contains an
authenticated x86-64 GNU/Linux archive and a disposable-`kind` crash-recovery demonstration. Start
with the [evaluator guide](docs/EVALUATOR.md) to verify the download and run it.

From a source checkout, the shortest deterministic gate is:

```sh
./scripts/ci-local.sh
```

With Docker, kind 0.32+, kubectl 1.30+, and Python 3.11+:

```sh
cargo make demo-kind
```

The demonstration creates and removes its own cluster. It runs healthy and failed-rollout paths,
kills the real process around mutation and receipt publication, restarts without a blind second
mutation, and inspects the frozen receipt.

## What exists

| Surface                                               | Status                                                        |
| ----------------------------------------------------- | ------------------------------------------------------------- |
| Exact grant, SQLite recovery, image mutation, receipt | Published in v0.2.0                                           |
| Local CLI and fixed-schema stdio MCP adapter          | Published in v0.2.0                                           |
| Process-loss and disposable-`kind` demonstrations     | Published and tested                                          |
| Authenticated x86-64 GNU/Linux artifact and SBOM      | Published and verified                                        |
| Customer-resident Kapsel service and local socket     | Implemented candidate; unpublished                            |
| Hosted sandbox                                        | Removed; [historical record only](docs/HISTORICAL_SANDBOX.md) |

The unpublished service adds caller-independent lifetime, reconnectable status, and exact receipt
retrieval. It is absent from v0.2.0 and remains a non-production preview. Its approved installer
journey is not yet runnable.

## Choose a path

| Goal                                           | Read                                               |
| ---------------------------------------------- | -------------------------------------------------- |
| Understand exact result and recovery semantics | [Effect-gateway contract](docs/EFFECT_GATEWAY.md)  |
| Verify and run the published artifact          | [Evaluator guide](docs/EVALUATOR.md)               |
| Use the CLI or MCP adapter                     | [Commands](docs/COMMANDS.md) or [MCP](docs/MCP.md) |
| Build and test the repository                  | [Build and test](docs/BUILD.md)                    |
| Understand the unpublished service             | [Kapsel service](docs/KAPSEL_SERVICE.md)           |
| Contribute safely                              | [Contributor guide](AGENTS.md)                     |
| Find any other owner                           | [Documentation map](docs/INDEX.md)                 |

## Scope

Kapsel has one capability and one Kubernetes adapter. It does not provide a Kubernetes operation
suite, generic provider SDK, policy engine, workflow engine, hosted control plane, dashboard, public
Rust SDK, second platform, or production support. See [Technical scope](docs/SCOPE.md) and the
[threat model](docs/THREAT_MODEL.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
