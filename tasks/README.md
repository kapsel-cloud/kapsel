# Technical task route

Status: the v0.2.0 Kubernetes effect-gateway mechanism is verified. KAP-0070 closed the hosted
sandbox through its accepted fixtures/local-demo fallback. KAP-0073 now owns archival and removal of
the deployable sandbox, while KAP-0054 is the sole active product-architecture decision for one
smallest customer-controlled non-production preview. Resident implementation, customer access,
credentials, production use, another capability, and every hosted act remain separately gated.

Tasks own remaining engineering work and acceptance evidence. They do not redefine behavior owned by
`docs/` or KAP-0038.

## Current direction

The product nucleus is the root `kapsel` package:

```text
bounded request + operator-held authority
  -> deep Application
       -> durable pre-attempt facts
       -> conditional Kubernetes mutation opportunity
       -> observation-only recovery after ambiguity
       -> receiver-bounded SUCCEEDED / FAILED / UNKNOWN
       -> frozen signed receipt and offline inspection
```

The unpublished sandbox proved substantial offline admission, process isolation, authority staging,
policy, and cleanup behavior, but its remaining work served anonymous hosted operation rather than a
customer-resident workflow. KAP-0073 accepts KAP-0070's fallback and commissions one bounded
archive-and-delete packet. Do not refactor or move sandbox machinery into root `kapsel` or a future
resident package.

KAP-0054 now compares protected deployment of the existing CLI/MCP adapters with one minimal local
resident process. It may create one finite implementation packet only if CLI/MCP cannot safely
provide caller/authority separation, caller-independent recovery, reconnect/status, and receipt
retrieval for one representative workflow. It does not pre-authorize a daemon, Unix socket, package,
customer work, or compatibility promise.

KAP-0047 remains the supporting owner for approved aggregate technical findings. Private customer,
commercial, buyer, acquisition, and continuation evidence remains outside this repository.

## Active work

|    Lane | Packet                  | Status          | Required result                                                                       |
| ------: | ----------------------- | --------------- | ------------------------------------------------------------------------------------- |
|       A | [KAP-0073](KAP-0073.md) | Active deletion | Archive and remove deployable sandbox while preserving root product proof             |
|       B | [KAP-0054](KAP-0054.md) | Active decision | Select protected CLI/MCP or one minimal customer-resident preview boundary            |
|    Next | New finite packet       | Gated           | Implement only the accepted preview within its explicit two-to-three-week cap         |
| Ongoing | [KAP-0047](KAP-0047.md) | Supporting      | Record approved aggregate installation, comprehension, defect, and retained-use facts |

Sandbox deletion and KAP-0054 research may proceed independently, but no resident implementation
begins until the deletion leaves one clean active workspace and KAP-0054 is accepted. Perform and
review one implementation packet at a time.

## Completed v0.2.0 sequence

| Order | Packet                  | Outcome                                                               |
| ----: | ----------------------- | --------------------------------------------------------------------- |
|     0 | [KAP-0046](KAP-0046.md) | Selected Stabilize without widening                                   |
|     1 | [KAP-0057](KAP-0057.md) | Adopted finite release unit and compatibility classes                 |
|     2 | [KAP-0058](KAP-0058.md) | Unified production and crash-test lifecycle                           |
|     3 | [KAP-0059](KAP-0059.md) | Adopted Application, CLI, MCP, grant, and receipt beta interfaces     |
|     4 | [KAP-0060](KAP-0060.md) | Proved exact v0.1.1 upgrade, backup, rollback, and downgrade behavior |
|     5 | [KAP-0064](KAP-0064.md) | Deepened root release-source locality                                 |
|     6 | [KAP-0061](KAP-0061.md) | Accepted finite reliability and security qualification                |
|     7 | [KAP-0062](KAP-0062.md) | Produced authenticated reproducible distribution                      |
|     8 | [KAP-0065](KAP-0065.md) | Corrected bundled release truth                                       |
|     9 | [KAP-0063](KAP-0063.md) | Published and publicly verified exact prerelease v0.2.0               |

The v0.2 distribution remains the root archive for one x86-64 GNU/Linux target. It supports only the
adopted CLI, fixed stdio MCP adapter, grant v1 continuity, retained receipt v2 inspection, and
private journal migration named by `docs/V0.2.md`. It is a developer beta, not a resident or
production product.

## Sandbox history

| Packet                  | Status   | Historical result                                               |
| ----------------------- | -------- | --------------------------------------------------------------- |
| [KAP-0051](KAP-0051.md) | Complete | Fixed public `v1` fixture contract                              |
| [KAP-0052](KAP-0052.md) | Complete | Deterministic admission/projection service and package consumer |
| [KAP-0055](KAP-0055.md) | Complete | Separate runner handoff and real process-loss recovery          |
| [KAP-0056](KAP-0056.md) | Complete | Accepted bounded website consumer contract                      |
| [KAP-0069](KAP-0069.md) | Complete | Selected serialized native-host reshape                         |
| [KAP-0072](KAP-0072.md) | Complete | Removed backup/restore and imposed finite fallback              |
| [KAP-0070](KAP-0070.md) | Complete | Closed hosted route through fixtures/local-demo fallback        |

These packets remain evidence and rationale. Their implementation, fixtures, private handoff,
controller state, manifests, provider resources, and HTTP vocabulary are not v0.2 or resident
compatibility surfaces. No sandbox gate may be resumed without a new explicit direction decision.

## Deferred and superseded programs

| Packet                  | Status      | Route                                                              |
| ----------------------- | ----------- | ------------------------------------------------------------------ |
| [KAP-0050](KAP-0050.md) | Superseded  | Historical hosted umbrella                                         |
| [KAP-0053](KAP-0053.md) | Superseded  | Historical provider/deployment topology; no live authority remains |
| [KAP-0048](KAP-0048.md) | Conditional | Cargo/docs.rs needs later explicit use and compatibility evidence  |
| [KAP-0066](KAP-0066.md) | Deferred    | Release automation requires an observed product blocker            |
| [KAP-0067](KAP-0067.md) | Deferred    | Qualification tooling requires an observed product blocker         |
| [KAP-0068](KAP-0068.md) | Deferred    | Interface minimization waits for real consumers                    |
| [KAP-0071](KAP-0071.md) | Deferred    | Optional Nix shell waits for accepted resident-pilot evidence      |

No provider selection, credential access, provisioning, spend, image push, endpoint, DNS, traffic,
customer cluster, production workload, second operation, generic abstraction, or automatic release
is authorized.

## Product continuation rule

A demo run, fixture, test count, release, download, star, website visit, feature request, or
installation attempt does not authorize another capability or production route. Retained external
use in a real caller workflow is required before production resident compatibility or another
product cycle.

Future receipt, protocol, SDK, provider, Kubernetes, storage, and separate CLI packages remain
behind the extraction triggers in [V1 technical direction](../docs/VISION.md). Create a finite task
only after the exact trigger passes.

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
|     8 | [KAP-0049](KAP-0049.md) | Published ten-minute self-serve v0.1.1 patch      |
