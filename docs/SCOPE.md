# Technical scope

> A crash-recoverable effect-gateway experiment for autonomous agents.

Status: active experiment.

Kind: design. Authority: repository purpose, active capability, release maturity, and technical
non-goals.

Owns: Project identity, the Kubernetes `set_deployment_image` experiment, and the distinction
between the current 0.1 release and a future 1.0 compatibility commitment.

Does not own: Kubernetes request semantics, experiment receipt bytes, MCP protocol details, a
reusable provider interface, or task status.

## Short answer

Kapsel tests a technical proposition: give agents bounded capabilities, not provider credentials. It
turns one authorized request into a durable provider attempt, receiver observation or explicit
unknown, and an inspectable receipt.

```text
agent intent
  -> owner-signed exact grant under application-configured trust
  -> durable pre-attempt rejection or target identity
  -> provider attempt when eligible
  -> receiver observation or bounded unknown
  -> classifier-complete signed experiment receipt
```

The sole capability is `kubernetes.set_deployment_image` against a local `kind` cluster. Its
technical owner is the
[Kubernetes effect-gateway experiment boundary](experiments/KAP-0038-kubernetes-effect-gateway-boundary.md).

The current milestone is the stable `0.1.0` release target for this one experiment—not a broader
platform, production-support promise, or second provider.

## 0.1.0 release

`0.1.0` is defined as a non-prerelease Kapsel release. A fresh evaluator can:

1. install a versioned artifact for the supported x86-64 GNU/Linux target and identify its exact
   source revision;
2. provision operator-owned grant and trust inputs separately from agent intent, then submit the one
   bounded operation through a public local command;
3. run the documented healthy and unhealthy-image `kind` paths, including real process termination
   and restart at both the mutation and receipt-publication seams;
4. verify no blind second mutation, frozen receipt bytes across restart, and offline inspection from
   signed classifier inputs;
5. invoke the same fixed capability through a thin MCP adapter whose request schema contains no
   credentials, grant authority, or lifecycle controls; and
6. reproduce the release from a clean checkout using published setup, cleanup, checksums, license,
   limits, and expected output.

“Stable” means a published `0.1.0` artifact is a named, reproducible, non-prerelease distribution.
It does not promise production support or compatibility for the CLI, configuration, Rust API, MCP
adapter, receipt format, or artifact layout. Those surfaces remain explicitly versioned experiment
interfaces until a later release owns compatibility.

## Future v1.0.0 requirements

`v1.0.0` is not planned or implied by publishing `0.1.0`. It may be proposed only after approved
public-use evidence and an explicit technical-direction decision. Before a `v1.0.0` tag, Kapsel
must:

1. name every compatibility surface it will support and publish versioning, deprecation, and
   migration rules for the CLI, configuration, MCP behavior, receipt format, Rust API, and artifact
   layout;
2. define supported platforms, installation, upgrade, rollback, uninstallation, and support
   lifecycles with native clean-environment evidence;
3. authenticate release provenance beyond an adjacent checksum and define signing, attestation,
   verification, and key-rotation procedures;
4. complete a production-oriented security review covering credentials, Kubernetes RBAC, key and
   secret operations, filesystem isolation, dependency response, vulnerability handling, and
   incident boundaries;
5. prove bounded concurrency, load, resource use, crash recovery, upgrade behavior, and operational
   diagnostics under a documented reliability test plan;
6. publish a stable threat model, compatibility policy, operator guide, and residual-risk report for
   the supported use case; and
7. pass an explicit release review showing that real evaluator evidence justifies the support and
   compatibility promises.

A second capability, generic provider interface, hosted service, or wider platform is not required
for `v1.0.0`; each would need its own evidence and owner.

## Current claim

Kapsel may claim only that its experiment attempts to provide:

- exact parameter matching against an owner-signed, fixed-purpose single-operation grant under
  application-configured trust that agent input cannot choose;
- one stable local operation identity, a durable pre-attempt rejection or target identity, and
  crash-window recovery;
- no blind second provider attempt after `apply_started`;
- explicit `SUCCEEDED`, `FAILED`, or `UNKNOWN` result meaning based on bounded receiver observation;
  and
- a signed, offline-inspectable experiment receipt that states its limits.

Kapsel does not claim exactly-once real-world effects, Kubernetes truth, causation, complete
capture, complete history, compliance, or production readiness.

## Non-goals

The repository does not implement:

- a generic MCP tool host;
- arbitrary shell or `kubectl` execution;
- a policy engine;
- a Kubernetes operator framework;
- a hosted service;
- an agent observability platform;
- a compliance product;
- a generic receipt framework;
- runtime plugins, a generic provider SDK, or arbitrary tool execution;
- hosted storage, a dashboard, or an external witness; or
- a second capability.

[ADR 0008](decisions/0008-use-one-kubernetes-effect-gateway-canary.md) records why one Kubernetes
operation is the current technical canary.
