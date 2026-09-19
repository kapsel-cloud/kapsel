# Documentation

Start with the [README](../README.md) for what Kapsel does and the first-action path. The
[service operator guide](KAPSEL_SERVICE_OPERATOR.md#one-command-disposable-example) describes the
unpublished preview example. The separate [evaluation guide](EVALUATOR.md) runs the published v0.2
beta. The [technical tour](TOUR.md) explains the mechanism; exact contracts remain the authority for
behavior.

## Learn

| Goal                              | Read                            |
| --------------------------------- | ------------------------------- |
| Understand Kapsel in five minutes | [README](../README.md)          |
| Follow one operation end to end   | [Technical tour](TOUR.md)       |
| Understand the product boundary   | [Technical scope](SCOPE.md)     |
| See how the code is composed      | [Architecture](ARCHITECTURE.md) |

## Use the published beta

| Goal                                  | Read                                                                                        |
| ------------------------------------- | ------------------------------------------------------------------------------------------- |
| Authenticate and run the artifact     | [Evaluation guide](EVALUATOR.md)                                                            |
| Use the local CLI                     | [v0.2 commands](https://github.com/kapsel-cloud/kapsel/blob/v0.2.0/docs/COMMANDS.md)        |
| Use the fixed stdio MCP tool          | [v0.2 MCP adapter](https://github.com/kapsel-cloud/kapsel/blob/v0.2.0/docs/MCP.md)          |
| Verify release artifacts              | [v0.2 release contract](https://github.com/kapsel-cloud/kapsel/blob/v0.2.0/docs/RELEASE.md) |
| Upgrade or roll back a v0.1.1 journal | [Upgrade guide](UPGRADE.md)                                                                 |

## Exact reference

| Question                                                     | Owner                                                     |
| ------------------------------------------------------------ | --------------------------------------------------------- |
| What is in scope now?                                        | [Technical scope](SCOPE.md)                               |
| What do authorization, recovery, results, and receipts mean? | [Effect-gateway contract](EFFECT_GATEWAY.md)              |
| What does v0.2.0 promise?                                    | [v0.2.0 release contract](V0.2.md)                        |
| What threats and disclosures remain?                         | [Threat model](THREAT_MODEL.md) and [privacy](PRIVACY.md) |
| How do I report a vulnerability?                             | [Security policy](../SECURITY.md)                         |

## Contribute

| Goal                           | Read                                      |
| ------------------------------ | ----------------------------------------- |
| Contribute code or docs        | [Contributing](../CONTRIBUTING.md)        |
| Build or choose a focused gate | [Build and test](BUILD.md)                |
| Understand the proof strategy  | [Testing](TESTING.md)                     |
| Understand why a design exists | [Accepted decisions](decisions/README.md) |

## Unpublished work

Repository HEAD contains an implemented resident service and packaging path. It is not part of
v0.2.0, a published preview or a supported installation. Check the operator guide's candidate
requirements before running commands. [Technical scope](SCOPE.md) owns the current boundary.

| Goal                                    | Read                                                                                   |
| --------------------------------------- | -------------------------------------------------------------------------------------- |
| Run one disposable fixture action       | [Service example](KAPSEL_SERVICE_OPERATOR.md#one-command-disposable-example)           |
| Authenticate and extract a preview      | [Preview preparation](RELEASE.md#authenticate-and-extract-the-preview)                 |
| Provision real operator-owned authority | [Operator guide](KAPSEL_SERVICE_OPERATOR.md#provision-authority-and-an-exact-approval) |
| Select an ID and inspect its evidence   | [Submit and inspect](KAPSEL_SERVICE_OPERATOR.md#submit-and-inspect)                    |
| Diagnose and resume the same ID         | [Recovery guidance](KAPSEL_SERVICE_OPERATOR.md#diagnose-and-resume)                    |
| Read exact service fields and lifecycle | [Service contract](KAPSEL_SERVICE.md)                                                  |

## Design and experiments

The proposal records the selected direction and adoption status. Historical experiments are not
supported features or commands available at HEAD.

- [Delegated-action preview proposal](DELEGATED_ACTION_PREVIEW.md)
- [Reconnectable agent action experiment](RECONNECTABLE_AGENT_ACTION.md)
- [Two pending operations and scheduling ownership](MULTIPLE_PENDING_OPERATIONS.md)
- [Two-action endpoint experiment](TWO_ACTION_ENDPOINT_PROTOTYPE.md) — historical reproduction only
- [Later-observation experiment](LATER_OBSERVATION_EXPERIMENT.md) — historical reproduction only
- [Independent kubectl failure corpus](INDEPENDENT_TOOL_CORPUS.md)
- [Protected typed-tool comparison](PROTECTED_TOOL_COMPARISON.md)

## Authority order

When documents disagree:

1. [Technical scope](SCOPE.md) and the [effect-gateway contract](EFFECT_GATEWAY.md);
2. the direct contract for that surface;
3. conforming implementation and tests; then
4. accepted decisions, which explain why but do not override current contracts.
