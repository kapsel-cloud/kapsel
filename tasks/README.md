# Technical task route

Status: completed self-serve release, sandbox contracts, and deterministic sandbox service; queued
live sandbox deployment, evaluator evidence cycle, and trigger-gated resident-v1 backlog.

Tasks own remaining engineering work and acceptance evidence. They do not redefine behavior owned by
`docs/` or the active experiment contract.

## 0.1.0 sequence

KAP-0045 published `v0.1.0` after the clean-checkout rehearsal and acceptance review. KAP-0049
published the bounded `v0.1.1` self-serve patch. KAP-0050 is the following sandbox umbrella; its
backend sequence is KAP-0051 contracts, KAP-0052 service package, and KAP-0053 live deployment,
followed by independently owned website integration acceptance. KAP-0047 owns the following
evaluator evidence cycle. KAP-0046 remains conditional on approved aggregate use evidence.

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

| Packet                  | Status      | Outcome                                                               |
| ----------------------- | ----------- | --------------------------------------------------------------------- |
| [KAP-0049](KAP-0049.md) | Complete    | Published the ten-minute self-serve local alpha patch                 |
| [KAP-0051](KAP-0051.md) | Complete    | Own the fixed public sandbox contracts                                |
| [KAP-0052](KAP-0052.md) | Complete    | Implemented and accepted one-way `kapsel-sandbox -> kapsel` package   |
| [KAP-0053](KAP-0053.md) | Next queued | Prove the isolated live sandbox deployment                            |
| [KAP-0050](KAP-0050.md) | Umbrella    | Accept the backend and independent public website together            |
| [KAP-0047](KAP-0047.md) | Queued      | Gather bounded external-use evidence without capability expansion     |
| [KAP-0046](KAP-0046.md) | Conditional | Select one evidence-backed technical direction                        |
| [KAP-0054](KAP-0054.md) | Conditional | Specify one real customer-resident `kapseld` pilot                    |
| [KAP-0048](KAP-0048.md) | Conditional | Decide whether Cargo and docs.rs distribution is independently useful |

KAP-0049 may harden only the existing evaluator, CLI, MCP, diagnostics, packaging, and documentation
surfaces. KAP-0051 through KAP-0053 may add only one public sandbox for the same fixed operation and
must preserve the package and authority rules in [V1 technical direction](../docs/VISION.md). These
packets do not authorize a second capability or production compatibility promise. KAP-0046 later
converts approved aggregate use evidence and technical findings into exactly one next route:

1. stabilize the existing capability;
2. specify one evidence-selected capability under a new owner;
3. freeze at maintenance-only scope; or
4. retire the experiment.

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
