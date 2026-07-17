# Technical task route

Status: completed 0.1.0 release, active evaluator evidence cycle, and conditional future technical
route.

Tasks own remaining engineering work and acceptance evidence. They do not redefine behavior owned by
`docs/` or the active experiment contract.

## 0.1.0 sequence

KAP-0045 published `v0.1.0` after the clean-checkout rehearsal and acceptance review. KAP-0047 is
the active evidence packet; there is no active implementation packet. KAP-0046 remains conditional
on approved aggregate use evidence.

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

| Packet                  | Status      | Outcome                                                                   |
| ----------------------- | ----------- | ------------------------------------------------------------------------- |
| [KAP-0047](KAP-0047.md) | Active      | Bounded independent evaluator evidence without speculative implementation |
| [KAP-0046](KAP-0046.md) | Conditional | One evidence-selected technical direction                                 |
| [KAP-0048](KAP-0048.md) | Conditional | Explicit decision on a future crates.io distribution                      |

KAP-0046 converts approved aggregate use evidence and technical findings into exactly one next
route:

1. stabilize the existing capability;
2. specify one evidence-selected capability under a new owner;
3. freeze at maintenance-only scope; or
4. retire the experiment.

KAP-0048 does not authorize retroactive crates.io `0.1.0` publication. It remains blocked unless
approved evidence selects Cargo installation or Rust-library use, then requires a new patch release
and full distribution evidence.

No second capability, generic provider interface, hosted control plane, or production-readiness
program is pre-authorized. Community outreach copy, evaluator identities, company observation
thresholds, positioning, and commercial decisions remain private operations work.
