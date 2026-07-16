# Documentation index

Status: current.

Owns: Question-to-owner routing and document authority order.

## Owners

| Question                                     | Owner                                                                                   |
| -------------------------------------------- | --------------------------------------------------------------------------------------- |
| What is Kapsel testing and why?              | [Technical scope](V1.md)                                                                |
| What exactly does the capability guarantee?  | [KAP-0038 experiment owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| How is it composed?                          | [Architecture](ARCHITECTURE.md)                                                         |
| What can I run?                              | [Build](BUILD.md)                                                                       |
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

1. [Technical scope](V1.md) and the KAP-0038 experiment owner;
2. the direct owner for the specific claim;
3. conforming implementation and tests;
4. the active task; then
5. accepted decisions, which explain rationale but do not override current contracts.
