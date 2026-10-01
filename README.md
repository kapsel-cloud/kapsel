# kapsel

[![CI](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml)
[![Preview](https://img.shields.io/badge/preview-v0.3.0--preview.1-orange)](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.3.0-preview.1)

**Run an approved operation. Keep the evidence, including uncertainty.**

Kapsel is an open-source execution boundary for automated workflows and AI agents. An operator
approves one exact operation. A caller can request it without receiving the credentials used to
execute it. Kapsel records durable state before attempting an external change and retains execution
evidence across crashes or lost responses.

Permission to act, evidence of execution, and the quality of the caller's decision remain separate.

## Why Kapsel exists

A receiver can accept a change before the caller loses its connection. The caller then cannot tell
whether the change happened. Repeating the request can cause another effect. Broad credentials also
give the caller more authority than one approved operation needs.

Kapsel keeps a stable operation identity and enforces explicit execution and recovery rules. After
an uncertain Kubernetes attempt, it observes the target instead of sending the change again. If
bounded observations establish neither success nor failure, Kapsel returns `UNKNOWN`. Reconnecting
preserves that result. Uncertainty never grants permission to repeat the mutation.

The goal is to make delegated work easier to rely on: start an operation, disconnect, and return to
see what completed and what remains uncertain. Kapsel does not choose useful changes or guarantee
that receiver observations are true. Better caller decisions cannot prevent lost responses or remove
authority boundaries.

Different effects need different authority and recovery rules. Kapsel grows through concrete
implementations and tests, not a general execution framework.

## What it does today

Current source supports two effects:

- `kubernetes.set_deployment_image`: change one container image under approval for an exact
  Deployment snapshot and immutable image.
- `git.transition_ref`: move one fixed repository's branch from commit A to prepared descendant B.

The caller selects an operator-approved action ID. The resident Linux service retains the action and
its original signed receipt if the caller disconnects.

Each effect has its own result rules. Git acknowledgement establishes ref acceptance, not hook
delivery, CI completion, or deployment completion. A missing acknowledgement remains `UNKNOWN`.
There is no arbitrary shell execution, general agent runtime, workflow engine, or provider SDK. The
[Git source example](docs/GIT_REF_TRANSITION.md) covers provisioning, caller reconnection, and
offline inspection. It is not part of the published preview.

The published
[v0.3.0-preview.1](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.3.0-preview.1) is a
**non-production preview** for x86-64 GNU/Linux. It contains `kapsel`, `kapseld`, the fixed service
client, operating assets, and authenticated release companions. It is not a stable v0.3 release and
has no production-support promise.

## Try it

Use a **fresh disposable native x86-64 Debian 12 VM** with systemd and root access. The example is
not an installer for an existing host.

[Authenticate and extract the preview](docs/RELEASE.md#authenticate-and-extract-the-preview). Then
run the
[disposable service example](docs/KAPSEL_SERVICE_OPERATOR.md#one-command-disposable-example). It
starts the real service under systemd, submits one approved action, inspects its receipt, and
retrieves identical evidence after restart. A loopback receiver supplies observations. No cluster
credentials are required.

The [operator guide](docs/KAPSEL_SERVICE_OPERATOR.md) also covers Kubernetes authority and explicit
recovery with the same action ID. For the older CLI/MCP beta, use the
[v0.2.0 tagged evaluation guide](https://github.com/kapsel-cloud/kapsel/blob/v0.2.0/docs/EVALUATOR.md).
Its archive, extraction procedure, and storage compatibility differ from the service preview.

## Learn and contribute

- [Technical tour](docs/TOUR.md): follow one operation through Kapsel.
- [Technical scope](docs/SCOPE.md): implemented behavior and limits.
- [Effect-gateway contract](docs/EFFECT_GATEWAY.md): authority, recovery, results, and receipts.
- [Contributing](CONTRIBUTING.md) and [Build and test](docs/BUILD.md): engineering rules and checks.
- [Documentation map](docs/INDEX.md): find the document that owns each subject.

Licensed under [Apache 2.0](LICENSE).
