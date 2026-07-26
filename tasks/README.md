# Technical task route

Status: completed self-serve release and accepted offline sandbox architecture tranches; the hosted
sandbox is paused at an explicit scope checkpoint. Bounded local `v0.1.1` evaluator evidence and the
design-only finite v0.2.0 release-unit inventory are active next. Release implementation remains
evidence- and decision-gated.

Tasks own remaining engineering work and acceptance evidence. They do not redefine behavior owned by
`docs/` or the active experiment contract.

## 0.1.0 sequence

KAP-0045 published `v0.1.0` after the clean-checkout rehearsal and acceptance review. KAP-0049
published the bounded `v0.1.1` self-serve patch. KAP-0050's sandbox sequence completed contracts,
service, runner handoff, architecture review, and several offline KAP-0053 composition tranches,
then paused before complete rendering/live proof. That optional hosted program no longer blocks
local artifact evaluation. KAP-0047 owns the active bounded local evidence cycle. KAP-0057 owns only
the prospective finite v0.2.0 release-unit design. KAP-0046 remains conditional on approved
aggregate evidence and is the sole selector of Stabilize, Specify, Freeze, or Retire.

| Order | Packet                  | Outcome                                           | Depends on |
| ----- | ----------------------- | ------------------------------------------------- | ---------- |
| 0     | [KAP-0038](KAP-0038.md) | 0.1.0 release acceptance and evidence index       | —          |
| 1     | [KAP-0039](KAP-0039.md) | Short, navigable deep gateway module              | foundation |
| 2     | [KAP-0040](KAP-0040.md) | Frozen evaluator application interface            | KAP-0039   |
| 3     | [KAP-0041](KAP-0041.md) | Commands and navigable deep product structure     | KAP-0040   |
| 4     | [KAP-0042](KAP-0042.md) | Public real-process crash and failed-rollout demo | KAP-0041   |
| 5     | [KAP-0043](KAP-0043.md) | Thin fixed-schema MCP adapter                     | KAP-0042   |
| 6     | [KAP-0044](KAP-0044.md) | Installable, documented 0.1.0 artifact            | KAP-0043   |
| 7     | [KAP-0045](KAP-0045.md) | Rehearsed and published 0.1.0                     | KAP-0044   |

[KAP-0038](KAP-0038.md) is the completed release-level acceptance and evidence index.

## After 0.1.0

| Packet                  | Status        | Outcome                                                                |
| ----------------------- | ------------- | ---------------------------------------------------------------------- |
| [KAP-0049](KAP-0049.md) | Complete      | Published the ten-minute self-serve local alpha patch                  |
| [KAP-0051](KAP-0051.md) | Complete      | Own the fixed public sandbox contracts                                 |
| [KAP-0052](KAP-0052.md) | Complete      | Implemented and accepted one-way `kapsel-sandbox -> kapsel` package    |
| [KAP-0055](KAP-0055.md) | Complete      | Implemented and accepted the provider-neutral private runner handoff   |
| [KAP-0056](KAP-0056.md) | Complete      | Found no pre-GKE blocker; resume KAP-0053 unchanged                    |
| [KAP-0053](KAP-0053.md) | Paused        | Preserve accepted offline tranches; require a continuation decision    |
| [KAP-0050](KAP-0050.md) | Paused        | Optional hosted umbrella, not local release scope                      |
| [KAP-0047](KAP-0047.md) | Active        | Gather bounded local `v0.1.1` evidence without capability expansion    |
| [KAP-0057](KAP-0057.md) | Active design | Define a prospective finite v0.2.0 release unit without implementation |
| [KAP-0046](KAP-0046.md) | Conditional   | Select one evidence-backed technical direction                         |
| [KAP-0054](KAP-0054.md) | Conditional   | Specify one real customer-resident `kapseld` pilot                     |
| [KAP-0048](KAP-0048.md) | Conditional   | Decide whether Cargo and docs.rs distribution is independently useful  |

KAP-0049 may harden only the existing evaluator, CLI, MCP, diagnostics, packaging, and documentation
surfaces. Accepted KAP-0051 through KAP-0053, KAP-0055, and KAP-0056 work remains one optional
public sandbox for the same fixed operation and preserves the package and authority rules in
[V1 technical direction](../docs/VISION.md). Continuing that hosted program requires a new explicit
scope decision. KAP-0057 may design but not implement or authorize v0.2.0. None of these packets
authorizes a second capability or production compatibility promise. KAP-0046 later converts approved
aggregate use evidence and technical findings into exactly one next route:

1. stabilize the existing capability;
2. specify one evidence-selected capability under a new owner;
3. freeze at maintenance-only scope; or
4. retire the experiment.

A Stabilize decision may adopt the reviewed KAP-0057 design and create finite release implementation
packets; another KAP-0046 route closes or replaces it rather than averaging directions.

KAP-0054 records the intended resident-daemon route without pre-authorizing implementation. It
requires both the evidence-selected KAP-0046 route and one real pilot workflow. KAP-0048 remains
blocked unless approved evidence independently selects Cargo installation or Rust-library use.

Future receipt, protocol, client SDK, provider, Kubernetes, storage, and separate CLI packages are
tracked by explicit extraction triggers in [V1 technical direction](../docs/VISION.md), not by
placeholder implementation packets. Create a finite task only after its trigger passes.

No second capability, generic provider interface, general hosted control plane, operator console, or
production-readiness program is pre-authorized. KAP-0050's fixed public sandbox is the sole hosted
exception. Community outreach copy, evaluator identities, company observation thresholds,
positioning, and commercial decisions remain private operations work.
