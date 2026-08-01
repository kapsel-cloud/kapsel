# Technical task route

Status: the v0.2.0 Kubernetes effect-gateway mechanism is verified. KAP-0069 selected one serialized
reshape for the bounded public product proof; KAP-0070 is the sole active implementation and
acceptance packet. Only its exact accepted public proof may lead to the later customer-controlled
non-production integration decision. Exact-artifact evaluation remains supporting evidence; every
provider, deployment, traffic, and resident implementation act remains separately gated.

Tasks own remaining engineering work and acceptance evidence. They do not redefine behavior owned by
`docs/` or KAP-0038.

## Current direction

[KAP-0046](KAP-0046.md) selected **Stabilize** and produced the verified v0.2 mechanism around the
sole `kubernetes.set_deployment_image` capability. A new explicit maintainer product-scope decision
now authorizes two decision stages without widening that capability:

1. Completed [KAP-0069](KAP-0069.md) selected **reshape**: one native controller host, one separate
   per-run runner process, one dedicated synthetic Kubernetes cluster, and at most one active run
   through complete cleanup. It explicitly supersedes the remote Kubernetes controller and
   key-stager topology.
2. [KAP-0070](KAP-0070.md) corrects the direct contracts, removes the superseded path, and must pass
   offline composition, separately authorized private-live, failure-recovery, teardown/recreation,
   and bounded-public-exposure gates for one exact revision.
3. Only after KAP-0070's exact public proof passes acceptance, [KAP-0054](KAP-0054.md) decides
   whether CLI/MCP is sufficient for one customer-controlled non-production integration or whether
   one smallest resident boundary is justified.

Neither decision authorizes provider use, public traffic, a daemon, transport, package, production
compatibility, or another operation. [KAP-0047](KAP-0047.md) remains the supporting owner for
approved aggregate technical findings rather than the implementation route.

[`docs/V0.2.md`](../docs/V0.2.md) owns the finite promise:

```text
request-only CLI or MCP intent
  -> operator-owned exact authorization and Kubernetes authority
  -> durable conditional mutation opportunity
  -> restart without blind retry
  -> bounded SUCCEEDED / FAILED / UNKNOWN receiver result
  -> frozen signed receipt and offline inspection
```

This route is not externally validated, production-ready, a Kubernetes operation suite, or an
automatic v1 roadmap. [KAP-0047](KAP-0047.md) moves after the beta release; it no longer blocks
implementation.

## v0.2.0 ordered sequence

| Order | Packet                  | Status     | Required result                                                                                      |
| ----: | ----------------------- | ---------- | ---------------------------------------------------------------------------------------------------- |
|     0 | [KAP-0046](KAP-0046.md) | Complete   | Selected Stabilize and rejected widening, freeze, retirement, suite, daemon, and hosted alternatives |
|     0 | [KAP-0057](KAP-0057.md) | Complete   | Defined and adopted the finite release unit, compatibility classes, gates, and non-goals             |
|     1 | [KAP-0058](KAP-0058.md) | Complete   | One production lifecycle implementation crossed by every crash test                                  |
|     2 | [KAP-0059](KAP-0059.md) | Complete   | Adopted beta interfaces and deeper Application/CLI/MCP locality                                      |
|     3 | [KAP-0060](KAP-0060.md) | Complete   | Exact `v0.1.1` upgrade, migration, backup, rollback, and downgrade proof                             |
|     4 | [KAP-0064](KAP-0064.md) | Complete   | Stable, navigable private implementation locality across the root release source                     |
|     5 | [KAP-0061](KAP-0061.md) | Complete   | Accepted finite reliability, hostile-input, security, and performance qualification                  |
|     6 | [KAP-0062](KAP-0062.md) | Complete   | Authenticated, reproducible beta distribution candidate                                              |
|     7 | [KAP-0065](KAP-0065.md) | Complete   | Corrected bundled release truth and produced one exact replacement candidate                         |
|     8 | [KAP-0063](KAP-0063.md) | Complete   | Published, download-verified, and handed off exact prerelease `v0.2.0`                               |
|     9 | [KAP-0047](KAP-0047.md) | Supporting | Exact-artifact and preview findings remain bounded technical evidence                                |

Implement and independently review one packet at a time. Do not combine architecture, compatibility,
migration, locality, qualification, distribution, and publication into one change. A passing packet
does not pre-authorize the next packet's release act, provider use, or publication.

## Release shape

The v0.2 distribution is the root `kapsel` archive for the sole x86-64 GNU/Linux target. It supports
only the adopted CLI, one exact stdio MCP tool, grant v1 continuity, retained receipt v2 inspection,
and private operational journal migration named by `docs/V0.2.md` and their direct owners.

The Rust package remains unsupported for external consumers. [KAP-0048](KAP-0048.md) remains
conditional future work; v0.2 does not publish crates.io or docs.rs artifacts.

## Product-cycle and deferred programs

| Packet                  | Status      | Route                                                                                        |
| ----------------------- | ----------- | -------------------------------------------------------------------------------------------- |
| [KAP-0069](KAP-0069.md) | Complete    | Selected serialized reshape and mapped every retained, superseded, and historical artifact   |
| [KAP-0070](KAP-0070.md) | Active      | Prove one serialized public sandbox through separately authorized staged gates               |
| [KAP-0054](KAP-0054.md) | Queued      | After exact KAP-0070 public acceptance, select CLI/MCP or one resident boundary              |
| [KAP-0050](KAP-0050.md) | Superseded  | Historical umbrella; KAP-0070 exclusively owns any deployment completion                     |
| [KAP-0053](KAP-0053.md) | Superseded  | Preserve mapped offline evidence, but never resume its controller/stager deployment topology |
| [KAP-0048](KAP-0048.md) | Conditional | Cargo/docs.rs distribution requires a later explicit use and compatibility decision          |
| [KAP-0066](KAP-0066.md) | Deferred    | Release-artifact tooling is inactive without an observed product blocker                     |
| [KAP-0067](KAP-0067.md) | Deferred    | Qualification tooling remains behind KAP-0066 and an observed product blocker                |
| [KAP-0068](KAP-0068.md) | Deferred    | Interface minimization waits for the selected real consumers                                 |
| [KAP-0071](KAP-0071.md) | Deferred    | Optional Nix development shell waits for KAP-0070 closure and accepted pilot evidence        |

KAP-0051, KAP-0052, KAP-0055, and KAP-0056 remain accepted sandbox history. Their implementation and
the shared workspace version do not make the sandbox, private controller protocols, runner handoff,
manifests, provider resources, or hosted endpoint part of v0.2 compatibility.

No provider selection, credential access, provisioning, spend, image push, endpoint, DNS, or public
traffic is authorized. The beta release does not depend on the sandbox.

## Completed 0.1 release sequence

| Order | Packet                  | Outcome                                           |
| ----: | ----------------------- | ------------------------------------------------- |
|     0 | [KAP-0038](KAP-0038.md) | 0.1.0 release acceptance and evidence index       |
|     1 | [KAP-0039](KAP-0039.md) | Short, navigable deep gateway module              |
|     2 | [KAP-0040](KAP-0040.md) | Frozen evaluator application interface            |
|     3 | [KAP-0041](KAP-0041.md) | Commands and navigable deep product structure     |
|     4 | [KAP-0042](KAP-0042.md) | Public real-process crash and failed-rollout demo |
|     5 | [KAP-0043](KAP-0043.md) | Thin fixed-schema MCP adapter                     |
|     6 | [KAP-0044](KAP-0044.md) | Installable, documented 0.1.0 artifact            |
|     7 | [KAP-0045](KAP-0045.md) | Rehearsed and published 0.1.0                     |
|     8 | [KAP-0049](KAP-0049.md) | Published ten-minute self-serve `v0.1.1` patch    |

## After the bounded product cycle

The product cycle may justify evidenced corrections, one retained customer-controlled preview, one
additional operation completing a repeated workflow, maintenance-only scope, or retirement. A demo
run, feature request, download, star, website visit, release completion, or installation attempt
does not authorize another capability or generic interface. Production resident compatibility
requires retained use and a separate direction decision.

Future receipt, protocol, client SDK, provider, Kubernetes, storage, and separate CLI packages
remain behind the extraction triggers in [V1 technical direction](../docs/VISION.md). Create a
finite task only after the exact trigger passes.
