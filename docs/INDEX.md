# Documentation

Start with the [README](../README.md) for the mechanism and runnable preview, then follow the
[service operator guide](KAPSEL_SERVICE_OPERATOR.md). The [technical tour](TOUR.md) explains one
operation; direct contracts specify its behavior.

## Learn and operate

| Goal                                        | Read                                                                         |
| ------------------------------------------- | ---------------------------------------------------------------------------- |
| Understand the mechanism                    | [Technical tour](TOUR.md)                                                    |
| Identify the implemented boundary           | [Technical scope](SCOPE.md)                                                  |
| See implementation ownership                | [Architecture](ARCHITECTURE.md)                                              |
| Authenticate and extract the preview        | [Release artifacts](RELEASE.md#authenticate-and-extract-the-preview)         |
| Run one disposable fixture action           | [Service example](KAPSEL_SERVICE_OPERATOR.md#one-command-disposable-example) |
| Provision, submit, inspect, and recover     | [Operator guide](KAPSEL_SERVICE_OPERATOR.md)                                 |
| Preserve journals across binary replacement | [Journal retention](UPGRADE.md)                                              |

## Exact reference

| Question                                                     | Owner                                                     |
| ------------------------------------------------------------ | --------------------------------------------------------- |
| What do authorization, recovery, results, and receipts mean? | [Effect-gateway contract](EFFECT_GATEWAY.md)              |
| What are the service protocol and process rules?             | [Service contract](KAPSEL_SERVICE.md)                     |
| What commands and operator files exist?                      | [Commands](COMMANDS.md)                                   |
| What does the fixed stdio adapter accept?                    | [MCP](MCP.md)                                             |
| What threats and disclosure limits remain?                   | [Threat model](THREAT_MODEL.md) and [privacy](PRIVACY.md) |
| How do I report a vulnerability?                             | [Security policy](../SECURITY.md)                         |

## Contribute

| Goal                                      | Read                                                   |
| ----------------------------------------- | ------------------------------------------------------ |
| Change code or contracts                  | [Contributing](../CONTRIBUTING.md)                     |
| Build or choose a focused gate            | [Build and test](BUILD.md)                             |
| Understand proof placement                | [Testing](TESTING.md)                                  |
| Understand an active design choice        | [Accepted decisions](decisions/README.md)              |
| Run the independent kubectl client corpus | [Client-contract evidence](INDEPENDENT_TOOL_CORPUS.md) |

## Authority and history

Linear is the source of truth for accepted direction, planned work, priorities, assignments,
acceptance, and progress. Repository documents own current technical contracts; implementation and
tests provide executable evidence. A planned change in Linear is not a claim that behavior already
exists. Update the direct contract and its implementation together when adopting a change.

For current technical behavior, consult [scope](SCOPE.md), the
[effect-gateway contract](EFFECT_GATEWAY.md), and the direct surface contract. Decisions explain
rationale and do not override those owners. Resolve contradictions at the owning boundary.

Published versions retain their own contracts in Git tags. Use the
[v0.2.0 documentation](https://github.com/kapsel-cloud/kapsel/tree/v0.2.0/docs) for the older beta.
The [preview release](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.3.0-preview.1)
identifies its exact bytes and qualification. Retired proposals and experiment reports are removed
from the current tree; Git history retains previous revisions.
