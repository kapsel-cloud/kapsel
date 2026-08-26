# Technical task route

Status: v0.2.0 is published and verified. The hosted sandbox is removed. The resident service is
implemented and qualified from source but is not distributed in the published artifact.

Tasks record finite engineering work and acceptance evidence. They do not redefine behavior owned by
`docs/` or the KAP-0038 experiment contract. Business strategy and private operational facts do not
belong here.

## Current implementation

```text
bounded request + operator-held authority
  -> Application
       -> durable pre-attempt facts
       -> conditional Kubernetes mutation opportunity
       -> observation-only recovery after ambiguity
       -> SUCCEEDED / FAILED / UNKNOWN
       -> frozen signed receipt
```

The root `kapsel` package owns the lifecycle and concrete Kubernetes adapter. The unpublished
`kapseld -> kapsel` package adds one authenticated Linux Unix socket, caller-independent process
lifetime, read-only status, and exact receipt retrieval. It reuses the root journal and application
semantics; it adds no scheduler, queue, controller framework, provider abstraction, or second store.

The supported v0.2.0 archive does not contain `kapseld`, its systemd assets, or a resident operator
guide. A future distribution change must define its artifact identity, install/uninstall behavior,
caller path, supported platform, and clean-environment proof without weakening the resident
boundary.

## Current owners

| Surface                          | Owner                                                                                     |
| -------------------------------- | ----------------------------------------------------------------------------------------- |
| Technical scope                  | [`docs/SCOPE.md`](../docs/SCOPE.md)                                                       |
| Lifecycle and result semantics   | [KAP-0038 experiment](../docs/experiments/KAP-0038-kubernetes-effect-gateway-boundary.md) |
| v0.2.0 release                   | [`docs/V0.2.md`](../docs/V0.2.md)                                                         |
| Release artifact                 | [`docs/RELEASE.md`](../docs/RELEASE.md)                                                   |
| Resident architecture            | [KAP-0054](KAP-0054.md)                                                                   |
| Resident implementation record   | [KAP-0074](KAP-0074.md)                                                                   |
| Build and qualification commands | [`docs/BUILD.md`](../docs/BUILD.md)                                                       |
| Proof requirements               | [`docs/TESTING.md`](../docs/TESTING.md)                                                   |

## Completed release records

| Packet                  | Result                                              |
| ----------------------- | --------------------------------------------------- |
| [KAP-0045](KAP-0045.md) | Published v0.1.0                                    |
| [KAP-0049](KAP-0049.md) | Published self-serve v0.1.1                         |
| [KAP-0046](KAP-0046.md) | Selected the bounded v0.2.0 stabilization direction |
| [KAP-0060](KAP-0060.md) | Proved v0.1.1 upgrade and rollback behavior         |
| [KAP-0061](KAP-0061.md) | Completed reliability/security qualification        |
| [KAP-0062](KAP-0062.md) | Produced the reproducible distribution              |
| [KAP-0065](KAP-0065.md) | Corrected bundled release status                    |
| [KAP-0063](KAP-0063.md) | Published and verified v0.2.0                       |

## Historical experiments

Sandbox packets KAP-0050 through KAP-0053, KAP-0055, KAP-0056, KAP-0069, KAP-0070, KAP-0072, and
KAP-0073 are historical. Their HTTP, deployment, scheduler, authority-staging, cleanup, and
provider-resource designs are not current compatibility surfaces. KAP-0054 remains the resident
architecture owner; KAP-0071 is an unrelated deferred tooling packet.

## Creating work

Create a finite task only when an implementation change is ready to begin. Link its direct owner,
state observable acceptance, add the narrowest reproducible gate, and record residual technical
risk. Keep task packets public, reproducible, and technical.
