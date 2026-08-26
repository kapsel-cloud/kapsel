# kapsel

[![CI](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml)
[![Developer beta](https://img.shields.io/badge/developer_beta-v0.2.0-orange)](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.2.0)

A crash-recoverable Kubernetes effect gateway for autonomous agents.

Kapsel's developer beta tests a simple idea: give agents bounded operations, not provider
credentials. It accepts one authorized Kubernetes image change, records state before any mutation
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
> Kapsel 0.2.0 is a developer beta. It is not production-ready, a generic agent runtime, or a
> compliance product. Do not use it for consequential production changes.

## Developer beta

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

The [Kapsel `0.2.0` release](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.2.0) is the
public x86-64 GNU/Linux developer-beta prerelease. It adopts bounded v0.2.x compatibility for the
CLI, fixed stdio MCP adapter, grant and retained-receipt bytes, archive layout, and journal upgrade.
It does not promise production support or external Rust API compatibility. See the
[effect-gateway boundary](docs/experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) before
use.

## What exists today

| Surface                                          | Status                                                   |
| ------------------------------------------------ | -------------------------------------------------------- |
| Signed exact grant and SQLite recovery lifecycle | Implemented in the product package                       |
| Conditional Deployment image mutation            | Implemented and exercised by an explicit live-kind gate  |
| Classifier-complete receipt and inspection       | Implemented in the experiment library                    |
| Process-kill mutation and publication recovery   | Implemented in deterministic subprocess tests            |
| Failed-rollout live-kind test proof              | Implemented in the explicit live-kind gate               |
| Evaluator demo with real process termination     | Implemented through an owned disposable-kind harness     |
| Evaluator-facing operation and inspection CLI    | Implemented as a prototype local command                 |
| Thin fixed-schema MCP stdio adapter              | Implemented with deterministic black-box tests           |
| Authenticated x86-64 Linux artifact and SBOM     | Published and publicly verified as developer-beta v0.2.0 |
| Hosted sandbox                                   | Removed; contracts and fixtures are historical only      |
| Resident systemd service and local socket        | Qualified from source; not in the published artifact     |

The exact local evaluator grammar and file separation are owned by the
[evaluator command contract](docs/COMMANDS.md); the fixed protocol surface is owned by the
[MCP adapter contract](docs/MCP.md), and distribution by the
[release artifact contract](docs/RELEASE.md). The current engineering proof is:

```sh
cargo test --locked --test e2e_mcp_adapter
./scripts/ci-local.sh
cargo make test-demo-harness
a_dir=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-release-a.XXXXXX")
archive_a=$(python3 scripts/assemble-release-artifact.py --output-directory "$a_dir")
python3 scripts/test-release-artifact.py --archive "$archive_a"
python3 scripts/test-release-reproducibility.py --reference-archive "$archive_a"
cargo make demo-kind  # requires Docker, kind 0.32+, and kubectl 1.30+
```

Each live command creates and removes its own uniquely named cluster. This is demonstration
evidence, not part of the deterministic default gate. See [Build](docs/BUILD.md) for exact meaning
and prerequisites.

## v0.2 developer beta status

Kapsel `0.2.0` is published and publicly verified as a finite developer-beta prerelease. Its exact
five assets, authenticated digest manifest, source identity, safe extraction, install, CLI/MCP,
inspection, `v0.1.1` upgrade and rollback, disposable-kind demonstration, cleanup, and uninstall
passed fresh public-download verification. A package version or source checkout alone does not
establish release identity; use the exact GitHub release and authenticate its signed manifest.

The beta keeps one production and crash-test lifecycle path, adopted CLI/MCP and retained
grant/receipt compatibility, proven `v0.1.1` upgrade and rollback, bounded hostile-input and
resource qualification, and one authenticated reproducible x86-64 GNU/Linux distribution. It does
not add a Kubernetes operation suite, generic provider interface, public Rust SDK, resident daemon,
hosted dependency, second target, or production-readiness claim.

The repository's separate resident service is unpublished. Its direct-source path has been qualified
on Debian 12/systemd 252 and Kubernetes 1.33, but the published v0.2.0 archive does not contain it.
See the [v0.2 beta design](docs/V0.2.md) and [technical task route](tasks/README.md).

## Scope discipline

The repository has one capability and one Kubernetes adapter. Arbitrary execution, runtime plugins,
a generic provider SDK, a policy language, hosted operation, a dashboard, and a second capability
are outside its technical scope. The removed hosted sandbox's contracts and fixtures are historical
only. The resident service adds local process lifetime, read-only status, and receipt retrieval
without changing capability or receiver-result semantics.

## Read next

- [Technical scope](docs/SCOPE.md)
- [Active experiment contract](docs/experiments/KAP-0038-kubernetes-effect-gateway-boundary.md)
- [Prospective V1 technical direction](docs/VISION.md)
- [Build and proof commands](docs/BUILD.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Resident service architecture decision](tasks/KAP-0054.md)
- [Resident service implementation record](tasks/KAP-0074.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security policy](SECURITY.md)
- [Documentation index](docs/INDEX.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
