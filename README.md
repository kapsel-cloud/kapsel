# kapsel

[![CI](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/kapsel-cloud/kapsel/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-v0.3.0-orange)](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.3.0)

Give a workflow permission to make one reviewed change, not the credentials to make any change.
Kapsel runs operator-approved operations for automated workflows and AI agents. The caller selects
an approved ID. A resident service executes the operation and retains its history and signed
receipt. The caller can disconnect and return to the same operation.

```text
operator                         caller
  approves one exact change        selects its approved ID
  supplies credentials                   |
          |                              v
          +--------------------> Kapsel service ----> Kubernetes or Git
                                   |
                                   +----> durable history and signed receipt
```

## Why Kapsel exists

Suppose an agent has reviewed a new image for a Deployment. It needs to change one container, not
receive a kubeconfig that lets it improvise. The operator signs that exact change against the
Deployment's current UID and resourceVersion. The agent selects the approved ID. Kapsel checks the
approval and sends the conditional patch.

Then the connection disappears. Did it work?

A retry loop cannot answer that question. Kubernetes may have accepted the patch, and sending it
again can cause another effect even if a version conflict prevents another Deployment update.
Reporting failure would also be a guess.

Kapsel records the attempt before sending. After a crash, it observes the Deployment instead of
sending again. If those observations establish neither success nor failure, it records `UNKNOWN`.
Reconnecting returns the original evidence, not a new interpretation of today's cluster state.

There is a cost: a crash between recording and sending can leave an approved change unsent. Kapsel
chooses that possibility over granting another mutation opportunity after an ambiguous attempt. A
signed receipt preserves what it could establish, not proof of receiver truth or causation.

The operator decides what to approve. The surrounding workflow decides whether the change is useful
and what to do with its result. Kapsel handles execution and records what it could establish.

## Supported operations

- **Kubernetes:** change one Deployment container to an immutable image under approval for an exact
  UID and resourceVersion snapshot.
- **Git:** move one fixed local repository's branch from commit A to prepared descendant B. Success
  means acknowledged ref acceptance, not hook, CI, or deployment completion.

Both use stable operation identities, operator-owned authority, and retained original receipts.
Callers use the fixed client or MCP bridge. Kapsel is not an arbitrary command runner or workflow
engine. See [capabilities and limits](docs/scope.md) for the complete boundary.

## Try it

[Run one approved operation](docs/getting_started.md) on a fresh disposable native x86-64 Debian 12
VM. The example uses the release binaries, systemd, and a loopback Kubernetes fixture; no cluster
credentials are needed. It shows submission, receipt inspection, and identical evidence after
restart. It requires root access and leaves a stopped test installation in the VM.

The latest release, [v0.3.0](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.3.0), is a
**pre-beta, non-production developer release** for x86-64 GNU/Linux. This checkout documents the
development version. Use
[tagged documentation](https://github.com/kapsel-cloud/kapsel/tree/v0.3.0/docs) for that release and
the [changelog](CHANGELOG.md#unreleased) for unreleased differences.

## Documentation

- [How Kapsel works](docs/tour.md): follow an image change through a lost response and recovery.
- [Caller guide](docs/guides/caller.md): submit, reconnect, and retrieve evidence.
- [Operator guide](docs/guides/operator.md): install, prepare approvals, and diagnose blocked work.
- [Reference](docs/index.md#reference): exact lifecycle, protocol, formats, and security limits.
- [Contributing](CONTRIBUTING.md): build, test, and change Kapsel.

Licensed under [Apache 2.0](LICENSE).
