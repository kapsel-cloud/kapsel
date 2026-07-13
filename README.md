# kapsel

A crash-recoverable effect-gateway experiment for autonomous agents.

Kapsel is testing whether agents can use bounded operations instead of receiving unrestricted
provider credentials. It verifies an owner-signed exact grant, records either a pre-attempt target
rejection or the validated target before the dangerous mutation seam, recovers without blindly
repeating the mutation, observes the receiver, and emits an inspectable result—including `UNKNOWN`
when reality cannot be established. The remaining release work includes evaluator commands, MCP
composition, a release-owned process-kill demo, and versioned distribution artifacts.

```text
bounded agent intent
  -> owner-signed exact grant under application-configured trust
  -> durable pre-attempt rejection or target identity
  -> conditional provider mutation when attempted
  -> receiver observation or UNKNOWN
  -> classifier-complete signed experiment receipt
```

> [!WARNING]
>
> Kapsel is a pre-release experiment. It is not production-ready, a generic agent runtime, or a
> compliance product. Do not use it for consequential production changes.

## Active experiment

The only active capability is:

```text
kubernetes.set_deployment_image(namespace, deployment, container, immutable_image_digest)
```

The experiment runs against a disposable local `kind` cluster. Its live gate covers both a healthy
rollout and an unavailable-image `ProgressDeadlineExceeded` rollout after a fault-injected
post-patch reopen. Deterministic tests kill a separate gateway process at the mutation and receipt
publication seams. Recovery reconciles receiver state without a blind second mutation and publishes
only durably frozen receipt bytes.

Kapsel reports `SUCCEEDED`, `FAILED`, or `UNKNOWN`. These are bounded receiver outcomes, not claims
of exactly-once mutation, causation, complete cluster health, complete capture, or Kubernetes truth.

## What exists today

| Surface                                          | Status                                                  |
| ------------------------------------------------ | ------------------------------------------------------- |
| Signed exact grant and SQLite recovery lifecycle | Implemented in the experiment library                   |
| Conditional Deployment image mutation            | Implemented and exercised by an explicit live-kind gate |
| Classifier-complete receipt and inspection       | Implemented in the experiment library                   |
| Process-kill mutation and publication recovery   | Implemented in deterministic subprocess tests           |
| Failed-rollout live-kind test proof              | Implemented in the explicit live-kind gate              |
| Evaluator demo with real process termination     | Not implemented                                         |
| Evaluator-facing operation and inspection CLI    | Not implemented                                         |
| MCP-compatible entrypoint                        | Not implemented                                         |
| Versioned release artifacts                      | Not implemented                                         |

There is no quickstart yet because there is no supported public command. The current engineering
proof is:

```sh
./scripts/ci-local.sh
./scripts/test-kind-effect-gateway.sh  # requires Docker and kind 0.32+
```

The live gate creates and removes its own uniquely named cluster. It is demonstration evidence, not
part of the deterministic default gate. See [Build](docs/BUILD.md) for exact meaning and
prerequisites.

## Scope discipline

The repository has one capability and one Kubernetes adapter. Arbitrary execution, runtime plugins,
a generic provider SDK, a policy language, hosted operation, a dashboard, and a second capability
are outside its technical scope.

## Read next

- [Technical scope](docs/V1.md)
- [Active experiment contract](docs/experiments/KAP-0038-kubernetes-effect-gateway-boundary.md)
- [Build and proof commands](docs/BUILD.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security policy](SECURITY.md)
- [Documentation index](docs/INDEX.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
