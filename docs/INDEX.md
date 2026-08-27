# Documentation index

Status: current.

Owns: Question-to-owner routing and document authority order.

## Owners

| Question                                           | Owner                                                       |
| -------------------------------------------------- | ----------------------------------------------------------- |
| What is Kapsel testing and why?                    | [Technical scope](SCOPE.md)                                 |
| What exactly does the capability guarantee?        | [Effect-gateway contract](EFFECT_GATEWAY.md)                |
| How is it composed today?                          | [Architecture](ARCHITECTURE.md)                             |
| What is the intended v1 technical shape?           | [V1 technical direction](VISION.md)                         |
| What is the v0.2.0 release contract?               | [v0.2.0 Kubernetes effect-gateway beta](V0.2.md)            |
| What is the evaluator command contract?            | [Evaluator commands](COMMANDS.md)                           |
| What is the fixed MCP adapter contract?            | [MCP adapter](MCP.md)                                       |
| What was the retired public sandbox HTTP contract? | [Historical public sandbox API](SANDBOX_API.md)             |
| How was the retired sandbox intended to deploy?    | [Historical sandbox deployment](SANDBOX_DEPLOYMENT.md)      |
| What is the Kapsel service contract?               | [Kapsel service](KAPSEL_SERVICE.md)                         |
| How do I install the Kapsel service?               | [Kapsel service operator guide](KAPSEL_SERVICE_OPERATOR.md) |
| What can I run?                                    | [Build](BUILD.md)                                           |
| What is the release artifact contract?             | [Release artifacts](RELEASE.md)                             |
| How do I upgrade, restore, or downgrade?           | [Upgrade and rollback](UPGRADE.md)                          |
| How do I evaluate an installed artifact?           | [Evaluator guide](EVALUATOR.md)                             |
| What proof is required?                            | [Testing](TESTING.md)                                       |
| What may Kapsel claim?                             | [Threat model](THREAT_MODEL.md)                             |
| What data can receipts and reports disclose?       | [Privacy](PRIVACY.md)                                       |
| What do current terms mean?                        | [Glossary](GLOSSARY.md)                                     |
| How should Rust be shaped?                         | [Style](STYLE.md)                                           |
| How is a change reviewed?                          | [Review](REVIEW.md)                                         |
| Why were current durable choices made?             | [Decisions](decisions/README.md)                            |
| How do I report a vulnerability?                   | [Security policy](../SECURITY.md)                           |

## Authority order

When documents disagree:

1. [Technical scope](SCOPE.md) and the [effect-gateway contract](EFFECT_GATEWAY.md);
2. the direct owner for the specific claim;
3. conforming implementation and tests; then
4. accepted decisions, which explain rationale but do not override current contracts.
