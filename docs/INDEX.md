# Documentation

Start with the [README](../README.md) for purpose, behavior, and the runnable preview. Use the
[service operator guide](KAPSEL_SERVICE_OPERATOR.md) to run it. Read the [technical tour](TOUR.md)
to understand one operation. Use the tables below to find exact contracts and contributor guidance.

## Learn and operate

| Goal                                        | Read                                                                         |
| ------------------------------------------- | ---------------------------------------------------------------------------- |
| Understand the purpose and ambition         | [Why Kapsel exists](../README.md#why-kapsel-exists)                          |
| Understand the mechanism                    | [Technical tour](TOUR.md)                                                    |
| Identify the implemented boundary           | [Technical scope](SCOPE.md)                                                  |
| See implementation ownership                | [Architecture](ARCHITECTURE.md)                                              |
| Authenticate and extract the preview        | [Release artifacts](RELEASE.md#authenticate-and-extract-the-preview)         |
| Run one disposable fixture action           | [Service example](KAPSEL_SERVICE_OPERATOR.md#one-command-disposable-example) |
| Provision, submit, inspect, and recover     | [Operator guide](KAPSEL_SERVICE_OPERATOR.md)                                 |
| Use one caller for both effects             | [Shared caller guide](CALLER_GUIDE.md)                                       |
| Exercise an exact Git transition            | [Git service example](GIT_REF_TRANSITION.md)                                 |
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

| Goal                                      | Read                                                      |
| ----------------------------------------- | --------------------------------------------------------- |
| Understand v0.3 scope and release gates   | [Release path](RELEASE.md#path-to-v030)                   |
| Change code or contracts                  | [Contributing](../CONTRIBUTING.md)                        |
| Write or review documentation             | [Technical writing](../CONTRIBUTING.md#technical-writing) |
| Build or choose a focused gate            | [Build and test](BUILD.md)                                |
| Understand proof placement                | [Testing](TESTING.md)                                     |
| Understand an active design choice        | [Accepted decisions](decisions/README.md)                 |
| Run the independent kubectl client corpus | [Client-contract evidence](INDEPENDENT_TOOL_CORPUS.md)    |

## Authority and history

The README owns purpose and ambition. Contracts own current behavior; decisions explain rationale
without overriding contracts. Code and tests provide executable evidence. Resolve contradictions in
the document that owns the behavior.

Published versions retain their contracts in Git tags. Use the
[v0.2.0 documentation](https://github.com/kapsel-cloud/kapsel/tree/v0.2.0/docs) for the older beta.
The [preview release](https://github.com/kapsel-cloud/kapsel/releases/tag/v0.3.0-preview.1)
identifies its exact bytes and qualification. Git history retains removed proposals and reports.
