# Glossary

Status: active Kapsel vocabulary.

Owns: Concise definitions needed to understand the current effect gateway and Kapsel service.

Does not own: Normative behavior or implementation.

| Term                 | Meaning                                                                                                            | Owner                                     |
| -------------------- | ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------- |
| effect gateway       | Module that turns one bounded authorized intent into pre-attempt rejection or a durable effect and receipt.        | [Technical scope](SCOPE.md)               |
| Kapsel service       | Operator-controlled local service that gives the effect gateway caller-independent lifetime and reconnect.         | [Kapsel service owner](KAPSEL_SERVICE.md) |
| signed exact grant   | Owner-signed, fixed-purpose authorization for one exact operation tuple under application-configured trust.        | [effect-gateway owner](EFFECT_GATEWAY.md) |
| operation identity   | Stable local identity for one bounded effect attempt and its crash recovery. It does not prove provider success.   | [effect-gateway owner](EFFECT_GATEWAY.md) |
| not attempted        | Terminal pre-attempt disposition for a permanently missing or invalid target; it is not a receiver result.         | [effect-gateway owner](EFFECT_GATEWAY.md) |
| mutation attempt     | The one conditional Kubernetes patch opportunity recorded by `apply_started`. Reads and observations are separate. | [effect-gateway owner](EFFECT_GATEWAY.md) |
| request acceptance   | Provider acknowledgement of the conditional mutation request. It is not a receiver outcome.                        | [effect-gateway owner](EFFECT_GATEWAY.md) |
| receiver observation | Bounded facts reported by Kubernetes after an attempt. They do not prove causation or universal truth.             | [effect-gateway owner](EFFECT_GATEWAY.md) |
| receipt              | Signed prototype disclosure of frozen request, receiver, result, and non-claim facts.                              | [effect-gateway owner](EFFECT_GATEWAY.md) |
| offline inspection   | Bounded parsing, signature authentication, and supplied trust evaluation without network or ambient authority.     | [effect-gateway owner](EFFECT_GATEWAY.md) |
| `SUCCEEDED`          | The owner-defined requested generation and available-rollout facts were observed.                                  | [effect-gateway owner](EFFECT_GATEWAY.md) |
| `FAILED`             | The owner-defined requested generation and `ProgressDeadlineExceeded` facts were observed.                         | [effect-gateway owner](EFFECT_GATEWAY.md) |
| `UNKNOWN`            | Bounded reconciliation established neither defined outcome. It does not mean failure, safety, or no effect.        | [effect-gateway owner](EFFECT_GATEWAY.md) |
| `INSPECTED`          | Receipt structure, signature, and supplied prototype trust matched. It does not mean the disclosed facts are true. | [effect-gateway owner](EFFECT_GATEWAY.md) |
