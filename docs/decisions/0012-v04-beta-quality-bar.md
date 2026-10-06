# Define the v0.4 beta quality bar

Status: scope accepted; qualification targets proposed. Date: 2026-10-04. Scope approval:
2026-10-06. The [release process](../contributing/release_process.md#compatibility-boundary) owns
current support policy; no v0.4.x cross-version commitment is adopted.

This decision records the execution boundary and proposed assurance/resource bar for beta. The
[gateway](../reference/effect_gateway.md), [service](../reference/service.md), [scope](../scope.md),
and [release contract](../reference/release.md) own implemented behavior. The proposed targets below
do not establish beta readiness.

## Approved execution scope

Use the resident service and fixed ID-only client/MCP bridge for both effects. Preserve operator
provisioning, offline inspection, and caller export; remove direct `operate`/`mcp` execution. This
loses direct/local and macOS-source execution. It is not transparent migration.

The service supports disconnected callers without maintaining a second request grammar, operator
configuration, cancellation lifetime, and export dependency. Keeping both paths would require
qualifying both. Coverage must follow guarantees, not code or test counts: removal requires
equivalent attempt-loss and receipt-loss checks at retained service/process/artifact boundaries.
Service-consumed checkpoint controls remain private test tooling.

Reconnect and restart preserve same-ID history, original authority and exact grant/receipt bytes
under the current contracts. These execution requirements do not imply cross-version support.
Published tags, bytes and signed purposes retain their original meanings.

Do not add another effect, target, scheduler, parallel worker, provider framework, installer, or
production-support promise as part of this convergence.

## Assurance requirements

Keep parser/classifier matrices at their owning interfaces. Higher layers establish composition,
authority separation, physical ownership, disclosure, and original-byte preservation. The
[evidence map](../contributing/evidence.md) identifies those owners and evidence limits.

Defensive review must cover:

- exact external authority before admission and immutable original authority after reconnect;
- fresh-commit-only dispatch, one physical worker, and observation-only attempted recovery;
- receipt candidates matching frozen facts before terminal commitment;
- byte/count/work bounds before allocation or I/O, including malformed and overflow boundaries;
- narrow, justified production lint exceptions and typed operating failures;
- configured completion capacity, full/corrupt/missing storage, and ambiguous commits without false
  non-admission or permission to repeat an effect; and
- release-feature exclusion and tested operator recovery guidance.

Keep operator assumptions explicit: stable private roots, cooperative lock-using launches, trusted
receiver hooks, and independently assessed action independence. No dependency engine is proposed.

### Lifecycle exploration

Use a bounded test-only model around existing owners, not a production runtime or simulated SQLite
implementation. Preserve the existing simulation until a replacement passes its unique obligations.

- Track two to four identities with explicit caller, worker, and receiver events. Cover competing
  submissions, disconnect/cancellation, reopen, catalog/trust/material withdrawal, stale targets,
  response loss, varied observations, and frozen completion for both effects.
- Model authority, attempts, and evidence independently of production classifiers, builders, and SQL
  phases. Check safety after each event; check progress only after faults stop and resources return.
- Drive real continuation through private seams. Inject enumerated commit failures with known
  durable alternatives. Keep real SQLite, process, ENOSPC, receiver, and artifact lanes.
- Enumerate small schedules before generating longer seeded schedules. Include actor interleavings
  and physical-retirement barriers; sequential transitions alone are not concurrency exploration.
- Retain source/executable identity, seed, initial state, and full event trace. Minimize by removing
  events/identities and simplifying values while preserving prerequisites and the same failure.
  Replay the trace directly; seed-only replay depends on generator version and earlier cases.

Proposed feedback targets are 60 seconds after build for deterministic exploration and an explicit
30-minute, two-CPU, 4-GiB exploration job. Choose workload size from measured coverage and
throughput, not a test-count target. Retain robustness supervision and evidence bounds.

The relevant precedents are controlled faults and independent state checking in
[TigerBeetle VOPR](https://github.com/tigerbeetle/tigerbeetle/blob/6f8e6b58d1811bb21cd6ea4fb93cb2e9d77abd81/docs/internals/vopr.md)
and [FoundationDB testing](https://apple.github.io/foundationdb/testing.html).
[Proptest's state-machine strategy](https://github.com/proptest-rs/proptest/blob/master/proptest-state-machine/src/strategy.rs)
is an option for generation/shrinking, not an adopted dependency or concurrency scheduler. Compare
it with a small owned generator before adding machinery. None of these methods is formal
verification.

### Hostile-input exploration and negative controls

Exercise production Kubernetes/Git receipt, signed-grant, and service-document parsers with
canonical valid/invalid seeds, explicit trust/time/limits, bounded fuzz smoke, and persistent
exploration. [libFuzzer](https://llvm.org/docs/LibFuzzer.html) discovers coverage; it does not
establish semantic correctness. Retain explicit crash-input minimization and replay.

Before retiring coverage, the replacement and applicable real-boundary lane must reject isolated
negative controls:

| Seeded defect                                                              | Required detector                                             |
| -------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Permission before commit or reconstructed from history                     | Fresh-commit invariant and independent mutation counts        |
| Authority refreshed from current catalog                                   | Original-authority invariant and withdrawal/replacement trace |
| Ownership released when only the supervisor ends                           | Blocking-job and retirement barriers                          |
| Acceptance, wrong identity/generation, or present Git B treated as success | Independent receiver oracle and classifier tables             |
| Frozen evidence reobserved or re-signed                                    | Byte equality with zero receiver I/O                          |
| Same-ID receipt finalized for different frozen facts                       | Completion rejection with unchanged row                       |
| Duplicate/trailing input accepted or trust/byte limits bypassed            | Negative corpus and fuzz replay                               |
| Aggregate capacity exceeded or facts lost on failed write                  | Capacity/SQLite faults and real bounded ENOSPC                |

Run controls only in disposable source copies. The baseline must pass, each control must fail for
its intended assertion, and minimized replay must preserve that failure. A surviving required
control blocks coverage retirement; a mutation score is not proof of all faults.

## Proposed native resource budgets

Qualify release binaries on an explicit native x86-64 Debian 12/systemd VM with two vCPUs, 4 GiB
RAM, and local persistent storage. Record CPU, hypervisor, kernel, filesystem/mount options,
storage, and background load. The following are proposed targets, not contractual deadlines.

The workload is one service/worker, at most 32 approvals, 128 trust appointments, eight admitted
connections, and 504 retained/32 unfinished identities. Use bursts of at most eight callers and up
to ten stored reads per second. Capacity means predictable refusal, not indefinite growth. At ten
completed actions daily, 504 IDs last about 50 days; resetting history is not a remedy.

| Metric                   | Proposed target and measurement                                                                                                                                                 |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Idle daemon              | After 30 seconds warmup, at most 0.1% of one core over five minutes and 32 MiB peak RSS; zero receiver I/O                                                                      |
| Active memory            | At most 128 MiB summed sampled peak RSS for daemon/Git descendants; report daemon RSS and cgroup peak separately, with bridge/client separately                                 |
| Socket reads             | At most 100 ms p95, 250 ms p99; 1,000 status/receipt exchanges after 100 warmups, idle and during receiver waiting                                                              |
| Durable admission        | At most 250 ms p95, 1 second p99 on healthy storage; no missed two-second decision bound in the finite run                                                                      |
| Startup/reopen           | At most 1 second p95 on small histories, 5 seconds on valid maximal 64-MiB layouts; 20 runs each, separating warm/cache-cold                                                    |
| Refusal/saturation       | No ninth admitted connection/job, second worker, or unbounded tasks/FDs/RSS; refused new work makes zero receiver calls and preserves history                                   |
| Repeated clients/waiting | After ten minutes and retirement, RSS/FDs return within 10%/two FDs of warmed baseline; report allocator high-water separately                                                  |
| Persistent storage       | Preserve 64-MiB database, 65-MiB main rollback, and 504/32 limits; measure directory/temp-file peaks with 256 MiB initial disposable state space, not a total-storage guarantee |

Include healthy/unavailable receivers, stalled responses, the 180-second observation pass, worker
contention, eight concurrent/slow clients, disconnect, SIGKILL/restart, capacity limits, maximal
records/layouts, and Git descendants. Keep Git's 15-second subprocess bounds. Startup and stored
reads must add zero receiver calls; unavailable material cannot be forced into a terminal result to
meet a benchmark.

Use five repetitions per request workload. Report p50/p95/p99, bounded raw samples, CPU/wall time,
peak memory/FDs, and independent I/O counts. Missing or truncated evidence is not a pass. Compare
identical workloads on the same host; flag over 20% latency/memory regression against an accepted
baseline, using absolute targets to avoid tiny-value noise. Approve or revise budgets from native
evidence without weakening safety checks.

## Proposed beta definition of done

For one exact clean revision and artifact:

- Approved scope and current support limits appear in their contract owners. Same-ID restart and
  reconnect preserve original authority and receipts; older formats remain rejected unchanged.
- Defensive checks, storage failure/repair behavior, and operator guidance satisfy the assurance
  requirements above without inventing receiver outcomes or replay permission.
- Lifecycle exploration, fuzzing, replay/minimization, and required negative controls pass before
  replacing existing coverage. Independent HTTP, SQLite, Git, Linux, live, and artifact evidence
  remains necessary.
- [Release gates](../contributing/release_process.md#graduation-gates) pass with fresh security/SBOM
  results, reproducibility, native systemd, both packaged receiver journeys, and fresh-session
  caller continuity. Native fixture success cannot substitute for packaged crash or live receiver
  proof.
- Native workloads meet approved resource budgets and saturation/refusal checks. Publish only
  sanitized technical summaries; missing prerequisites remain missing evidence.

Beta excludes production availability/support, HA, fleet ordering, automatic backups, host-loss
continuity, stale-state restore, migration/downgrade, hostile-host containment, power-loss
certification, exactly-once effects, universal capture, receiver truth/causation, and Git
hook/CI/deployment completion. A signed receipt authenticates evidence, not these excluded facts.
