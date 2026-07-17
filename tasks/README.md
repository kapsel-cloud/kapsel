# Technical task route

Status: completed 0.1.0 release, active self-serve hardening, queued public sandbox and evaluator
evidence cycle, and conditional future technical route.

Tasks own remaining engineering work and acceptance evidence. They do not redefine behavior owned by
`docs/` or the active experiment contract.

## 0.1.0 sequence

KAP-0045 published `v0.1.0` after the clean-checkout rehearsal and acceptance review. KAP-0049 is
the active bounded implementation packet. KAP-0050 then proves one live public sandbox over the same
fixed operation; KAP-0047 owns the following evaluator evidence cycle. KAP-0046 remains conditional
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

| Packet                  | Status      | Outcome                                                               |
| ----------------------- | ----------- | --------------------------------------------------------------------- |
| [KAP-0049](KAP-0049.md) | Active      | Ten-minute self-serve path over the existing CLI, MCP, and kind proof |
| [KAP-0050](KAP-0050.md) | Queued      | One isolated public sandbox run over the same fixed operation         |
| [KAP-0047](KAP-0047.md) | Queued      | Bounded independent evaluator evidence without capability expansion   |
| [KAP-0046](KAP-0046.md) | Conditional | One evidence-selected technical direction                             |
| [KAP-0048](KAP-0048.md) | Conditional | Explicit decision on a future crates.io distribution                  |

KAP-0049 may harden only the existing evaluator, CLI, MCP, diagnostics, packaging, and documentation
surfaces. KAP-0050 may add only one public sandbox service for the same fixed operation after its
threat, privacy, API, deployment, and test contracts are owned. Neither packet authorizes a second
capability or compatibility promise. KAP-0046 later converts approved aggregate use evidence and
technical findings into exactly one next route:

1. stabilize the existing capability;
2. specify one evidence-selected capability under a new owner;
3. freeze at maintenance-only scope; or
4. retire the experiment.

KAP-0048 does not authorize retroactive crates.io `0.1.0` publication. It remains blocked unless
approved evidence selects Cargo installation or Rust-library use, then requires a new patch release
and full distribution evidence.

No second capability, generic provider interface, general hosted control plane, operator console, or
production-readiness program is pre-authorized. KAP-0050's fixed public sandbox is the sole hosted
exception. Community outreach copy, evaluator identities, company observation thresholds,
positioning, and commercial decisions remain private operations work.
