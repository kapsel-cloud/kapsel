# kapsel

[![CI](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml)
[![Preview](https://img.shields.io/badge/preview-v0.3.0--preview.1-orange)](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.3.0-preview.1)

**Narrow authority and honest execution evidence for fallible callers.**

Kapsel is an open-source execution boundary for automated workflows and AI agents. It binds an
operation to explicit authority, records durable state before an external effect, and preserves what
can be established after crashes or lost responses. Permission, execution evidence, and the quality
of the caller's decision remain separate.

## Why Kapsel exists

A caller can disappear after a receiver accepts a change but before the caller learns the result.
Repeating the request can cause another effect. Giving the caller broad credentials also grants more
authority than one approved operation requires.

Kapsel retains stable action identity and enforces bounded execution and recovery. Its current
Kubernetes path observes after an uncertain attempt rather than sending the mutation again. If
bounded observations establish neither success nor failure, it returns `UNKNOWN`. That uncertainty
is preserved across reconnects; it is never permission to repeat the mutation.

Better decisions do not remove lost acknowledgements, competing writers, or authority boundaries.
Kapsel gives callers inspectable execution facts with explicit limits. It does not decide which
change is useful or make receiver observations universally true.

## What we're building toward

We want reliable delegated execution to become a useful building block: start work, disconnect, come
back, and understand what completed and what remains uncertain. Different effects will expose
different authority and recovery problems. Building and using real implementations is how we learn
which mechanisms belong together.

Kapsel is a personal project built to learn through implementation and experimentation.

This repository is the home of Kapsel's technical work. An agreed feature includes the design,
implementation, tests, and documentation needed to make it work. A useful prototype is a step toward
integration, not an automatic handoff. We can change our own designs when experience gives us a
better one; we keep the claims about shipped behavior accurate as we do.

## What it does today

One operation: `kubernetes.set_deployment_image`. An operator approves an exact Deployment snapshot
and immutable image digest. A caller selects that approval without receiving cluster credentials.
The resident Linux service retains the action and its original signed receipt across caller loss.

Kubernetes is the current proving ground. The implemented operation remains deliberately concrete:
there is no arbitrary shell execution, general agent runtime, workflow engine, or provider SDK.

The published
[v0.3.0-preview.1](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.3.0-preview.1) is a
**non-production preview** for x86-64 GNU/Linux. It supplies `kapsel`, `kapseld`, the fixed service
client, operating assets, and authenticated release companions. It is not a stable v0.3 release and
provides no production-support promise.

## Try it

[Authenticate and extract the preview](docs/RELEASE.md#authenticate-and-extract-the-preview), then
follow the
[one-command disposable example](docs/KAPSEL_SERVICE_OPERATOR.md#one-command-disposable-example). It
runs the real service under systemd, submits one approved action, inspects its receipt, and
retrieves identical evidence after restart. A loopback receiver supplies observations; no cluster
credentials are required.

Use a fresh disposable native x86-64 Debian 12 VM with systemd and root access. The example is not
an installer for an existing host. The [operator guide](docs/KAPSEL_SERVICE_OPERATOR.md) also covers
operator-owned Kubernetes authority and explicit same-ID recovery.

For the older CLI/MCP beta, use the
[v0.2.0 tagged evaluation guide](https://github.com/kapsel-cloud/kapsel/blob/v0.2.0/docs/EVALUATOR.md).
Its archive, extraction procedure, and storage compatibility differ from the service preview.

## Learn and contribute

- [Technical tour](docs/TOUR.md): follow one operation through the boundary.
- [Technical scope](docs/SCOPE.md): implemented behavior and limits.
- [Effect-gateway contract](docs/EFFECT_GATEWAY.md): authority, recovery, results, and receipts.
- [Contributing](CONTRIBUTING.md) and [Build and test](docs/BUILD.md): development and proof.
- [Documentation map](docs/INDEX.md): current technical owners.

The README states the project's purpose and technical ambition. Linear owns the ordered roadmap,
priorities, assignments, and progress. The repository owns the implementation, current contracts,
and executable evidence. Keep daily engineering here and work ordering in Linear. Make technical
decisions as part of carrying the implementation through.

Report vulnerabilities through the [security policy](SECURITY.md). See [privacy](docs/PRIVACY.md)
for handling sensitive evidence. Licensed under [Apache 2.0](LICENSE).
