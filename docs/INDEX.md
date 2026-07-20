# Documentation index

Status: current.

Owns: Question-to-owner routing and document authority order.

## Owners

| Question                                     | Owner                                                                                   |
| -------------------------------------------- | --------------------------------------------------------------------------------------- |
| What is Kapsel testing and why?              | [Technical scope](SCOPE.md)                                                             |
| What exactly does the capability guarantee?  | [KAP-0038 experiment owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| How is it composed today?                    | [Architecture](ARCHITECTURE.md)                                                         |
| What is the intended v1 technical shape?     | [V1 technical direction](VISION.md)                                                     |
| What is the evaluator command contract?      | [Evaluator commands](COMMANDS.md)                                                       |
| What is the fixed MCP adapter contract?      | [MCP adapter](MCP.md)                                                                   |
| What can I run?                              | [Build](BUILD.md)                                                                       |
| What is the release artifact contract?       | [Release artifacts](RELEASE.md)                                                         |
| How do I evaluate an installed artifact?     | [Evaluator guide](EVALUATOR.md)                                                         |
| What proof is required?                      | [Testing](TESTING.md)                                                                   |
| What may Kapsel claim?                       | [Threat model](THREAT_MODEL.md)                                                         |
| What data can receipts and reports disclose? | [Privacy](PRIVACY.md)                                                                   |
| What do current terms mean?                  | [Glossary](GLOSSARY.md)                                                                 |
| How should Rust be shaped?                   | [Style](STYLE.md)                                                                       |
| How is a change reviewed?                    | [Review](REVIEW.md)                                                                     |
| What work remains?                           | [Technical task route](../tasks/README.md)                                              |
| Why were current durable choices made?       | [Decisions](decisions/README.md)                                                        |
| How do I report a vulnerability?             | [Security policy](../SECURITY.md)                                                       |

## Authority order

When documents disagree:

1. [Technical scope](SCOPE.md) and the KAP-0038 experiment owner;
2. the direct owner for the specific claim;
3. conforming implementation and tests;
4. the active task; then
5. accepted decisions, which explain rationale but do not override current contracts.
