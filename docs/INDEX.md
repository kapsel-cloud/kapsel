# Documentation map

Start with the shortest page that answers your question. Contracts own behavior; guides show how to
run it.

## I want to…

| Goal                                       | Read                                                      |
| ------------------------------------------ | --------------------------------------------------------- |
| Understand Kapsel in five minutes          | [README](../README.md)                                    |
| Run the published demonstration            | [Evaluator guide](EVALUATOR.md)                           |
| Build or test the repository               | [Build and test](BUILD.md)                                |
| Understand results, recovery, and receipts | [Effect-gateway contract](EFFECT_GATEWAY.md)              |
| Use the local CLI                          | [Evaluator commands](COMMANDS.md)                         |
| Use the fixed MCP tool                     | [MCP adapter](MCP.md)                                     |
| Verify a release                           | [Release artifacts](RELEASE.md)                           |
| Work on the unpublished service            | [Kapsel service](KAPSEL_SERVICE.md)                       |
| Review the planned installer journey       | [Service operator journey](KAPSEL_SERVICE_OPERATOR.md)    |
| Contribute a change                        | [Contributor guide](../AGENTS.md) and [Review](REVIEW.md) |

## Current product contracts

- [Technical scope](SCOPE.md) — purpose, sole capability, maturity, and non-goals.
- [Effect-gateway contract](EFFECT_GATEWAY.md) — authorization, lifecycle, receiver results,
  `UNKNOWN`, and receipts.
- [Architecture](ARCHITECTURE.md) — current composition and module ownership.
- [Threat model](THREAT_MODEL.md) and [Privacy](PRIVACY.md) — security assumptions, disclosures, and
  non-claims.

## Published v0.2.0

- [v0.2.0 contract](V0.2.md) — supported beta surfaces and acceptance.
- [Evaluator commands](COMMANDS.md) and [MCP adapter](MCP.md) — public interfaces.
- [Release artifacts](RELEASE.md), [Upgrade and rollback](UPGRADE.md), and
  [Evaluator guide](EVALUATOR.md) — distribution and operation.

## Unpublished and prospective

- [Kapsel service](KAPSEL_SERVICE.md) — accepted source implementation and installer contract.
- [Service operator journey](KAPSEL_SERVICE_OPERATOR.md) — approved plan; not yet runnable.
- [V1 technical direction](VISION.md) — possible future shape, not a commitment.

## Project reference

- [Testing](TESTING.md), [Rust style](STYLE.md), and [Review](REVIEW.md)
- [Glossary](GLOSSARY.md)
- [Accepted decisions](decisions/README.md)
- [Security policy](../SECURITY.md)
- [Historical hosted sandbox](HISTORICAL_SANDBOX.md)

## Authority order

When documents disagree:

1. [Technical scope](SCOPE.md) and [Effect-gateway contract](EFFECT_GATEWAY.md);
2. the direct contract for that surface;
3. conforming implementation and tests; then
4. accepted decisions, which explain rationale but do not override current contracts.
