# Technical task route

Status: v0.2.0 Kubernetes effect-gateway beta selected. Upgrade and release-source locality are
complete; finite qualification is active, and distribution, publication, and all later packets
remain ordered and gated.

Tasks own remaining engineering work and acceptance evidence. They do not redefine behavior owned by
`docs/` or KAP-0038.

## Current direction

[KAP-0046](KAP-0046.md) selected **Stabilize** as an explicit maintainer technology bet. Kapsel will
ship one deep developer beta around the existing `kubernetes.set_deployment_image` capability before
using external beta adoption to choose another product cycle.

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

| Order | Packet                  | Status       | Required result                                                                                      |
| ----: | ----------------------- | ------------ | ---------------------------------------------------------------------------------------------------- |
|     0 | [KAP-0046](KAP-0046.md) | Complete     | Selected Stabilize and rejected widening, freeze, retirement, suite, daemon, and hosted alternatives |
|     0 | [KAP-0057](KAP-0057.md) | Complete     | Defined and adopted the finite release unit, compatibility classes, gates, and non-goals             |
|     1 | [KAP-0058](KAP-0058.md) | Complete     | One production lifecycle implementation crossed by every crash test                                  |
|     2 | [KAP-0059](KAP-0059.md) | Complete     | Adopted beta interfaces and deeper Application/CLI/MCP locality                                      |
|     3 | [KAP-0060](KAP-0060.md) | Complete     | Exact `v0.1.1` upgrade, migration, backup, rollback, and downgrade proof                             |
|     4 | [KAP-0064](KAP-0064.md) | Complete     | Stable, navigable private implementation locality across the root release source                     |
|     5 | [KAP-0061](KAP-0061.md) | Active       | Finite reliability, hostile-input, security, and performance qualification                           |
|     6 | [KAP-0062](KAP-0062.md) | Queued       | Authenticated, reproducible, documented beta distribution candidate                                  |
|     7 | [KAP-0063](KAP-0063.md) | Queued       | Independent acceptance, publication, downloaded verification, and website handoff                    |
|     8 | [KAP-0047](KAP-0047.md) | Post-release | Bounded evidence from the exact published beta selects what follows                                  |

Implement and independently review one packet at a time. Do not combine architecture, compatibility,
migration, locality, qualification, distribution, and publication into one change. A passing packet
does not pre-authorize the next packet's release act, provider use, or publication.

## Release shape

The v0.2 distribution is the root `kapsel` archive for the sole x86-64 GNU/Linux target. It supports
only the adopted CLI, one exact stdio MCP tool, grant v1 continuity, retained receipt v2 inspection,
and private operational journal migration named by `docs/V0.2.md` and their direct owners.

The Rust package remains unsupported for external consumers. [KAP-0048](KAP-0048.md) remains
conditional future work; v0.2 does not publish crates.io or docs.rs artifacts.

## Paused and conditional programs

| Packet                  | Status      | Route                                                                                            |
| ----------------------- | ----------- | ------------------------------------------------------------------------------------------------ |
| [KAP-0050](KAP-0050.md) | Paused      | Optional hosted sandbox umbrella; not release scope                                              |
| [KAP-0053](KAP-0053.md) | Paused      | Preserve accepted offline tranches; continuation requires a new scope and authorization decision |
| [KAP-0054](KAP-0054.md) | Conditional | Resident process requires a real post-beta pilot workflow                                        |
| [KAP-0048](KAP-0048.md) | Conditional | Cargo/docs.rs distribution requires a later explicit use and compatibility decision              |

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

## After v0.2.0

KAP-0047 evaluates the exact published beta. Its evidence may justify one of five routes: evidenced
corrections to the existing capability, one additional operation completing a repeated workflow, one
resident pilot, maintenance-only scope, or retirement. A feature request, download, star, website
visit, or release completion does not authorize another capability or generic interface.

Future receipt, protocol, client SDK, provider, Kubernetes, storage, and separate CLI packages
remain behind the extraction triggers in [V1 technical direction](../docs/VISION.md). Create a
finite task only after the exact trigger passes.
