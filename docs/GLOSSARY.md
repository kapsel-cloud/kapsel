# Glossary

Status: active experiment vocabulary.

Owns: Concise definitions needed to understand the current KAP-0038 experiment.

Does not own: Normative behavior, implementation, or task status.

| Term                 | Meaning                                                                                                            | Owner                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| effect gateway       | Module that turns one bounded authorized intent into pre-attempt rejection or a durable effect and receipt.        | [Technical scope](SCOPE.md)                                                  |
| signed exact grant   | Owner-signed, fixed-purpose authorization for one exact operation tuple under application-configured trust.        | [KAP-0038 owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| operation identity   | Stable local identity for one bounded effect attempt and its crash recovery. It does not prove provider success.   | [KAP-0038 owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| not attempted        | Terminal pre-attempt disposition for a permanently missing or invalid target; it is not a receiver result.         | [KAP-0038 owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| mutation attempt     | The one conditional Kubernetes patch opportunity recorded by `apply_started`. Reads and observations are separate. | [KAP-0038 owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| request acceptance   | Provider acknowledgement of the conditional mutation request. It is not a receiver outcome.                        | [KAP-0038 owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| receiver observation | Bounded facts reported by Kubernetes after an attempt. They do not prove causation or universal truth.             | [KAP-0038 owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| experiment receipt   | Signed prototype disclosure of frozen request, receiver, result, and non-claim facts.                              | [KAP-0038 owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| offline inspection   | Bounded parsing, signature authentication, and supplied trust evaluation without network or ambient authority.     | [KAP-0038 owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| `SUCCEEDED`          | The owner-defined requested generation and available-rollout facts were observed.                                  | [KAP-0038 owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| `FAILED`             | The owner-defined requested generation and `ProgressDeadlineExceeded` facts were observed.                         | [KAP-0038 owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| `UNKNOWN`            | Bounded reconciliation established neither defined outcome. It does not mean failure, safety, or no effect.        | [KAP-0038 owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| `INSPECTED`          | Receipt structure, signature, and supplied prototype trust matched. It does not mean the disclosed facts are true. | [KAP-0038 owner](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
