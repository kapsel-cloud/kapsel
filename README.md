# kapsel

[![CI](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml)
[![Developer beta](https://img.shields.io/badge/developer_beta-v0.2.0-orange)](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.2.0)

**Let automation perform one operator-approved Kubernetes change without receiving cluster
credentials.**

Kapsel is a controlled execution component for automated workflows and AI agents. An operator
approves an exact Deployment image change and retains the credentials. Kapsel verifies that the
requested change matches that approval, records state before attempting it, and returns a result
with an inspectable receipt.

## Why Kapsel exists

A caller can disappear after Kubernetes accepts a change but before it learns the result. Retrying
may repeat the mutation. Giving the caller `kubectl` access also gives it more authority than one
approved change requires.

Kapsel provides a narrow execution boundary. After an uncertain attempt, recovery observes
Kubernetes rather than blindly sending the mutation again. Bounded rollout observations determine
`SUCCEEDED` or `FAILED`. If neither can be established, the result is `UNKNOWN`, not permission to
retry.

Permission, execution evidence and decision quality are separate. Kapsel does not decide which
change is useful, and a successful rollout does not prove application health. Kubernetes is its
first proving ground, not a promise of general infrastructure automation.

## What it does today

One operation: `kubernetes.set_deployment_image`. It changes one container's image in one Deployment
to an operator-approved immutable digest. It does not accept arbitrary manifests or shell commands,
and it is not a planner or workflow engine.

**Kapsel is not production-ready.** The published **v0.2.0 developer beta** provides CLI and MCP
interfaces. The resident service at repository HEAD is an **unpublished v0.3 preview**, not a
supported installation. Do not use either for consequential production changes.

## Try it

Start with the [published beta evaluation guide](docs/EVALUATOR.md#fastest-path). Its disposable
Kubernetes demo shows a healthy rollout, a failed rollout and recovery after process loss, then
inspects the recorded evidence.

You need a **disposable x86-64 GNU/Linux environment**, Docker, kind 0.32+, kubectl 1.30+, Python
3.11+, Cosign 3.1.2, `curl` and GNU `sha256sum`. The demo refuses to run if any kind clusters
already exist. This evaluation path is not currently set up for macOS, ARM, or an existing cluster.

[Download, authenticate and extract the beta](docs/EVALUATOR.md#verify-and-install), then run from
the extracted top-level directory:

```sh
./share/kapsel/demo-kind-crash-recovery.sh
```

Expect roughly two to five minutes, longer for the first node-image download. The demo creates and
removes its own cluster and temporary workspace. It does not need access to an existing cluster.

To explore the **unpublished service**, use the
[disposable fixture example](docs/KAPSEL_SERVICE_OPERATOR.md#one-command-disposable-example). It
needs no cluster credentials, but requires an exact accepted preview archive and a fresh native
x86-64 Debian 12 VM with systemd and root access. There is no published service download or
installer.

## Learn more

- [Technical tour](docs/TOUR.md): follow one operation through the execution boundary.
- [Technical scope](docs/SCOPE.md): current limits and published promises.
- [Service operator guide](docs/KAPSEL_SERVICE_OPERATOR.md): approvals, configuration and recovery.
- [Effect-gateway contract](docs/EFFECT_GATEWAY.md): exact recovery, result and receipt semantics.

## Develop

See [Contributing](CONTRIBUTING.md) and [Build and test](docs/BUILD.md) for source setup and checks.
The [documentation map](docs/INDEX.md) links the remaining guides and contracts.

Report vulnerabilities through the [security policy](SECURITY.md). See [privacy](docs/PRIVACY.md)
for handling sensitive evidence.

Licensed under [Apache 2.0](LICENSE).
