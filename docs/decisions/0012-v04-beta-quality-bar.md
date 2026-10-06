# Define the v0.4 beta quality bar

Status: proposed. Date: 2026-10-04.

This review recommends the scope, assurance work, and resource targets for a v0.4 beta. It does not
change current contracts or establish beta readiness. Product-surface changes require maintainer
approval. Implementation and candidate qualification remain separate work.

## Recommendation

Qualify one caller lifecycle: list an approval, select its ID, disconnect, read the same ID, and
explicitly resume when appropriate. Use the resident service for both current effects. Retain exact
authority, one worker, observation-only recovery, immutable evidence, and configured completion
capacity. Add broader lifecycle exploration and native resource qualification before beta.

Recommend removing direct CLI/MCP **execution** from HEAD after approval, not keeping an indefinite
unqualified execution path beside the service. Preserve operator provisioning, offline inspection,
and caller receipt export. Published releases retain their original bytes and contracts.

The alternative is to retain both execution paths and qualify both. Direct execution offers useful
local experimentation and macOS source execution, but maintains a second caller grammar, operator
configuration, cancellation lifetime, export dependency, and legacy-grant execution policy. The
service already supplies the intended disconnected caller workflow and both effects. Removal loses
those direct workflows; it is a deliberate product tradeoff, not a security fix or transparent
migration. If retention is selected, both paths stay supported and their unique checks stay
required.

Do not weaken guarantees to reduce code or test counts. Do not add an effect, fleet coordination,
scheduler, parallel worker, policy language, provider framework, installer, or production-support
promise. [Scope](../SCOPE.md), [gateway](../EFFECT_GATEWAY.md), [service](../KAPSEL_SERVICE.md), and
[release](../RELEASE.md) remain the current owners.

## Observed source and maintained value

The reviewed source is `b51420f9833bb85ea3f481e0266a82d411f78e52`, before this documentation change.
The line inventory motivating the review is not a redundancy audit or evidence of correctness.

`ServiceApplication` owns catalog selection and historical authority; the gateway owns advancement;
the journal owns conditional writes and capacity; the daemon owns physical task lifetime. Git and
Kubernetes share admission and receipt-envelope mechanisms but retain distinct receiver semantics.
These are useful ownership boundaries, not candidates for a generic effect framework.

| Asset                                                                    | Recommended disposition      | Unique value or retirement condition                                                                                                                                                                                                                                                                         |
| ------------------------------------------------------------------------ | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Service, fixed client, ID-only MCP bridge, fresh-session caller          | Keep                         | Caller loss does not end execution; original ID and evidence survive reconnection.                                                                                                                                                                                                                           |
| Direct `operate` / direct `mcp`, legacy operator execution configuration | Remove after scope approval  | Retire their adapters, exclusive configuration/export dependencies and tests together; preserve shared gateway and inspector owners.                                                                                                                                                                         |
| Provisioning CLI, receipt codecs, vectors, inspection and export         | Keep                         | Operator authority and detached evidence remain necessary without direct execution. Legacy receipts must remain inspectable under their original purposes.                                                                                                                                                   |
| Source-only direct crash demo and `demo-harness` seams                   | Retire with direct execution | Packaged service journeys must first cover its attempt/receipt-loss guarantees; do not mistake graceful restart for interrupted recovery. The v0.2 tag retains the old demo.                                                                                                                                 |
| Receiver fixture, real Git/process/live/native/artifact lanes            | Keep                         | They establish different composition, receiver, custody and installed-byte facts. Simulation does not replace them.                                                                                                                                                                                          |
| Contributor tooling, privacy/security scans, robustness supervision      | Keep                         | Objective enforcement and bounded evidence handling have current owners. Do not replace them with another command framework.                                                                                                                                                                                 |
| Standalone release verifier                                              | Keep for this beta           | Its exclusive bounded extraction is independently valuable. Cosign authenticates the manifest externally; the Python verifier checks its named bytes, not publisher identity by itself. Remove direct smoke only with the approved surface change; retain independent archive rejection and native fixtures. |

The verifier is 61,055 bytes against its 64-KiB distributed limit. Splitting it now would introduce
new fixture-delivery and authenticated-file obligations. Prefer removing superseded direct smoke
first. Revisit a split only if the remaining responsibilities cannot fit clearly within that bound;
do not duplicate archive validation in a second extractor.

## Guarantee and evidence map

The following maps existing mechanisms, not newly passed qualification. Commands and exact lane
limits remain in [Build](../BUILD.md); [Testing](../TESTING.md) owns proof placement.

| Guarantee / invariant                                                                      | Implementation owner                                                                                                      | Existing evidence to retain                                                                                        | Limit                                                                                                          |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| Exact external authority precedes admission; caller bytes cannot appoint it                | `kapsel-authority`, application selection, gateway binding                                                                | Grammar/grant vectors; service contract and hostile protocol tests; OS custody probes                              | Trust, operator approval and host confinement remain assumptions.                                              |
| Only a fresh confirmed attempt commit issues one-use dispatch permission                   | Kubernetes `journal::begin_attempt`; Git `begin_git_attempt`                                                              | Dispatch contention, foreign snapshot, lost acknowledgement and dropped-permission tests; HTTP mutation counts     | The marker does not prove transmission. Custom clients and intermediaries require their own no-retry evidence. |
| Attempted history never redispatches, including ABA                                        | Effect drivers and worker-excluded journal continuation                                                                   | Recovery faults, independent HTTP receiver matrix, real Git ABA/loss tests, Linux and packaged crash journeys      | Finite seams, not exactly-once effects, arbitrary network behavior or power loss.                              |
| Original authority and terminal evidence never refresh on reconnect                        | Retained-grant snapshots, receipt completion and service reads                                                            | Snapshot/receipt tests; catalog-removal and missing-trust tests; cold replacement and original-byte process checks | Missing trust or storage can block access. Export is not continuity authority.                                 |
| One physical worker and bounded jobs survive response/supervisor loss                      | Journal worker lease; daemon runtime/jobs/startup                                                                         | Contention, blocking-job retirement, SIGTERM/startup exclusion, publication and Linux-process tests                | Cooperative launches and stable roots; hung storage can block retirement indefinitely.                         |
| Hostile work is bounded before allocation or I/O                                           | Authority/receipt records, operator parser, HTTP body cap, socket framing, journal opening, Git subprocess/custody checks | Owner table-driven cases; HTTP/frame limits; accepted physical layouts; inspection fuzz target                     | A size cap is not a measured RSS ceiling or hostile-host sandbox.                                              |
| Acceptance, observation and causation remain distinct; incomplete facts preserve `UNKNOWN` | Effect-specific facts/classifiers and receipt parsers                                                                     | Pure classifier tables, independent receiver cases, Git acknowledgement-loss, live receiver checks                 | Kubernetes observations do not prove causation/truth; seeing Git B does not attribute an uncertain attempt.    |
| Configured capacity permits completion but never reserves disk space                       | `journal/capacity`, opening/schema and owned SQL                                                                          | Write-plan/source argument, physical layouts, 504/32 contention/full-capacity cases and actual tmpfs ENOSPC        | No total temporary-storage bound, arbitrary stale restore or disk-backed power-loss certification.             |
| Explicit resumption can progress when authority, material and storage permit               | Gateway continuation and service execution guidance                                                                       | Preflight retry, signing-only completion, same-ID process and packaged journeys                                    | No automatic scheduling, fairness, unconditional completion or cumulative observation deadline.                |

One concrete enforcement gap merits strengthening: Kubernetes `commit_receipt` checks candidate
operation ID and phase but does not compare its signed statement with the frozen row before writing.
Its private driver builds the correct candidate immediately beforehand. Git additionally decodes and
compares at its journal transition. No caller-accessible receipt-injection path was demonstrated.
Require a same-ID/mismatched-statement candidate to fail before finalization, rather than relying
only on the private call convention. Revalidate the owned SQL capacity argument if the write
changes.

Existing safeguards include private non-Clone dispatch permissions, typed loaded phases, conditional
SQL, no-follow custody, parser/transport caps and release builds without test features. CI enforces
unsafe-code prohibition, panic/unwrap restrictions, rustdoc, lint/types and formatting. These do not
mechanically enforce every engineering rule. Explicit ambient-authority use, exhaustive policy
matches, pre-allocation bounds and justified `expect` exceptions still need boundary review.

For beta, audit the reachable parsers/I/O and narrow production lint exceptions. Give each exception
an internal invariant or replace it with a typed operating failure. Check release-feature exclusion
and malformed/count/overflow boundaries. Do not impose an assertion-count target or fail the service
on ordinary caller, receiver, filesystem or SQLite errors. Action independence remains an
operator-enforced provisioning rule; this review does not propose a dependency engine.

## Layer-specific assurance decision

Keep pure parser and classifier matrices once at their owning interfaces. Higher layers retain
framing, disclosure, error projection, authority separation, physical ownership and original-byte
assertions. For example,
`e2e_mcp_adapter::application_outcomes_preserve_domain_parity_across_cli_and_mcp` checks transport
vocabulary/composition, not another independent classification oracle. Its `UNKNOWN` is prepared
with paused time and replayed by binaries. It is removable only with the direct surface or an
equivalent transport-specific replacement, not because another test returns `UNKNOWN`.

The current `simulation_tests` lane processes sequential Kubernetes identities, with up to three
target deferrals/reopens, one of seven apply faults, one of three receipt faults, and a fixed failed
observation. Its expected mutation count is tied to that fault choice. It has reproducible seeds and
bounded histories but no independent general model, actor-interleaving scheduler or automatic
failure minimizer. Replaying many schedules increases repetition, not the missing semantic breadth.
It does not currently explore Git, competing actors, changing receivers or arbitrary storage faults.

Recommend one bounded, test-only lifecycle model around the existing owners, not a new production
runtime or simulated SQLite implementation:

- Track two to four identities and explicit caller, worker and receiver events. Cover duplicate and
  competing submissions, cancellation/disconnect, service reopen, catalog/trust/material withdrawal,
  stale/replaced targets, acceptance/response loss, varied receiver facts and frozen completion.
- Model authority, attempt counts and immutable evidence independently of production classifiers,
  receipt builders and SQL phases. Check both effects with their distinct outcome rules. A test
  receiver must not fabricate success for a permission dropped before send.
- Drive real gateway/application continuation through private test seams. Inject only enumerated
  commit failures/ambiguities with known durable alternatives. Keep real SQLite, process, ENOSPC and
  receiver lanes for facts the model cannot establish.
- Enumerate small bounded schedules, then generate longer schedules from explicit seeds. Include
  selected A/B contention and physical-retirement barriers; sequential transition generation alone
  is not concurrency exploration. Check safety after each event. Check progress only after faults
  stop and required resources become available, within the modeled domain.
- Save source/executable identity, seed, initial state and full event trace. Minimize by deleting
  events/identities and simplifying values while preserving valid prerequisites and the same
  failure. Replay the trace directly; seed-only reproduction depends on generator version and
  earlier cases.

Use owner tables for exhaustive small predicates, property tests for value combinations, model
schedules for lifecycle interactions, byte fuzzing for hostile decoders, process tests for physical
ownership, and real receivers/artifacts for their actual boundaries. None is formal verification.

Before retiring existing coverage, require the replacement and applicable real-boundary lane to
reject representative isolated negative controls:

| Deliberately seeded bug                                                             | Required detector                                                                         |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Return permission before confirmed commit, or reconstruct it from attempted history | Fresh-commit/model invariant plus independent zero/one mutation counts on reopen          |
| Refresh grant/snapshot from the current catalog                                     | Original authority invariant plus service withdrawal/replacement case                     |
| Release execution/connection ownership when only the supervisor ends                | Runtime blocking-job/retirement barrier; a sequential adapter model alone is insufficient |
| Classify acceptance, wrong UID/generation or Git present-ref B as success           | Independent receiver/acknowledgement oracle and owner classifier tables                   |
| Reobserve or re-sign frozen evidence under changed material                         | Byte-identical status/receipt assertions with zero receiver I/O                           |
| Finalize a same-ID receipt for different frozen facts                               | Journal completion rejection and unchanged retained row                                   |
| Accept duplicate/trailing records or bypass trust/byte limits                       | Targeted parser/inspection negative corpus and fuzz replay                                |
| Admit past aggregate limits or discard facts after a failed write                   | Capacity/SQLite fault tests and actual bounded ENOSPC lane                                |

Run mutations only in disposable source copies; never ship them or reset attempted history. Baseline
must pass, each control must fail for the intended assertion, and replay/minimization must retain
that failure. Record any surviving control. A surviving required control blocks coverage retirement;
do not report a synthetic mutation score as a proof of all faults.

Keep the existing simulation until the new mechanism passes these checks and preserves every unique
old obligation. Proposed feedback targets are at most 60 seconds after build for the deterministic
model lane, and an explicit 30-minute/two-CPU/4-GiB exploration job. Choose workload size from
measured coverage and throughput, not a desired test count. Keep robustness supervision/evidence
bounds.

### Primary-source basis

The reviewed
[TigerBeetle VOPR documentation](https://github.com/tigerbeetle/tigerbeetle/blob/6f8e6b58d1811bb21cd6ea4fb93cb2e9d77abd81/docs/internals/vopr.md)
uses production code with controlled clock, network and disk behavior, fault injection, replay by
seed/revision, always-on assertions and additional checkers. Its
[state checker](https://github.com/tigerbeetle/tigerbeetle/blob/6f8e6b58d1811bb21cd6ea4fb93cb2e9d77abd81/src/testing/cluster/state_checker.zig)
checks commit/reply histories across replicas. This is not equivalent to Kapsel's fixed fake-adapter
flow. No TigerBeetle test-count target is adopted.

[FoundationDB](https://apple.github.io/foundationdb/testing.html) separates deterministic simulated
failures from live performance and hardware failure testing. The applicable lesson is controlled
failure schedules plus independent checks, not adopting its distributed runtime.

[Proptest's reference-machine strategy](https://github.com/proptest-rs/proptest/blob/master/proptest-state-machine/src/strategy.rs)
uses state-dependent transitions, prerequisite checks and transition/initial-state shrinking. Its
[runner](https://github.com/proptest-rs/proptest/blob/master/proptest-state-machine/src/test_runner.rs)
currently implements sequential execution. It is a concrete option for generation/minimization, not
a concurrency scheduler or an adopted dependency. Compare it with a small owned event generator
before adding a test dependency; avoid rejection-heavy invalid schedule generation.

[LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html) mutates a corpus using instrumented coverage.
The existing target exercises Kubernetes receipt/trust inspection at fixed time/default limits. Add
Git receipt inspection, signed-grant and service-document parser entry points with canonical
valid/invalid seeds. Retain short smoke plus bounded persistent exploration and explicit crash-input
minimization. Coverage discovery does not establish semantic correctness.

## Resource observations and proposed budgets

### Diagnostic application sample

A disposable external consumer called production `ServiceApplication`, not a fake gateway, at the
reviewed source revision. Environment: Apple M1 Pro, eight logical CPUs, 16 GiB RAM, macOS 27.0.1
arm64, Rust 1.98.0 dev-profile dependencies, Python 3.14.7 loopback HTTP fixture and local temporary
storage. The consumer was compiled with `rustc --edition=2021` against the locked Cargo build's
rlibs. `/usr/bin/time -l` measured that consumer, excluding the independent Python receiver.

Method: create private fresh journals; sign exact v2 approvals under one deterministic fixture key;
open catalogs of at most 32 actions; call `select` sequentially. One history admits 32 actions
without receiver material. Another completes 504 independent healthy targets with signing material
and a production Kubernetes client. Catalog changes occur through application reopening, not daemon
publication. At 1/32/128/504 rows, measure 200 stored reads and 20 empty-catalog reopens. Measure
selection-to-callback separately from selection-to-return; client construction and grant preparation
are outside selection latency but inside whole-process CPU/RSS. Independently count receiver I/O and
query final stored rows. No recorded attempt is reset or reused.

| Observed quantity                                        | Sample result                                                                   |
| -------------------------------------------------------- | ------------------------------------------------------------------------------- |
| 32 unfinished admissions / next refusal                  | All retained `authorized`; 33rd refused; refusal 0.512 ms; journal 45,056 bytes |
| 504 healthy admissions / next refusal                    | All retained `finalized / SUCCEEDED`; 505th refused in 0.689 ms                 |
| Selection-to-durable-acknowledgement, 504 samples        | Median 1.057 ms; p95 1.402 ms                                                   |
| Selection-to-return, 504 samples                         | Median 8.076 ms; p95 10.230 ms                                                  |
| Stored status / receipt, 200 samples each at 504 rows    | p95 0.544 / 0.551 ms                                                            |
| Empty-catalog reopen, 20 samples at 1 / 504 rows         | p95 0.988 / 5.245 ms                                                            |
| 32-entry catalog open, sampled batches                   | Approximately 24–27 ms; includes grant validation, not daemon bind/startup      |
| Healthy journal growth at 1 / 32 / 128 / 504 rows        | 20,480 / 86,016 / 282,624 / 1,060,864 bytes                                     |
| Original receipt / all 504 receipt payloads              | First receipt 848 bytes; total 428,290 bytes                                    |
| Independent receiver I/O, including stored reads/reopens | 1,008 GETs, 504 PATCHes; no additional I/O from stored reads/reopens            |
| Healthy consumer CPU / wall / peak RSS                   | 4.10 user + 1.13 system seconds / 6.06 seconds / 19,808,256 bytes               |
| Unavailable-receiver consumer peak RSS                   | 13,058,048 bytes                                                                |

These are one diagnostic sample, not a maintained benchmark or beta pass. Percentiles use sorted
samples at index `floor((n-1)*0.95)`. The whole-process figures include fixture signing and
sampling; RSS is not isolated daemon memory or a universal peak. Small records and warm local reads
do not represent maximal physical layouts, cold disk, saturated sockets, Git descendants or slow
rollouts. Idle daemon CPU/RSS, native startup, socket/client/MCP latency, receiver-wait costs,
rollback peaks, Git costs and mixed-effect saturation were **not measured**. No supported-platform
performance claim follows from the macOS result.

### Intended workload and falsifiable targets

Propose a native x86-64 Debian 12/systemd, local Linux-socket beta with one service, one worker, at
most 32 approvals, 128 trust appointments, eight admitted connections, and 504 retained/32
unfinished identities. Use short bursts of at most eight callers and up to ten stored reads per
second. Scalability means bounded behavior and predictable refusal within that envelope, not
indefinite operation growth or throughput proportional to callers. At ten completed actions daily,
504 retained IDs last about 50 days; there is no pruning or permission to reset the journal at that
point.

The following are **proposed qualification targets**, not new contractual deadlines. Select an
explicit reference VM with two vCPUs, 4 GiB RAM and local persistent storage. Record actual CPU,
hypervisor, kernel, filesystem/mount options, storage and background load; qualify release binaries.

| Metric                          | Proposed target / measurement                                                                                                                                                                                       |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Idle daemon                     | After 30 seconds warmup, at most 0.1% of one core over five minutes and 32 MiB peak RSS; no receiver I/O                                                                                                            |
| Active memory                   | At most 128 MiB summed peak sampled RSS for daemon and Git descendants; report daemon RSS and cgroup peak separately. Include fixed bridge/client separately, not Python/kind/model/build costs.                    |
| Local socket reads              | At most 100 ms p95, 250 ms p99; 1,000 status/receipt exchanges after 100 warmups, both idle and during receiver waiting                                                                                             |
| Durable admission               | At most 250 ms p95, 1 second p99 on healthy local storage; no missed two-second decision bound in the finite run. Receiver completion is separate.                                                                  |
| Startup/reopen                  | At most 1 second p95 socket-ready startup on small histories, 5 seconds on valid maximal 64-MiB layouts; 20 runs each, separating warm and cache-cold measurements                                                  |
| Refusal/saturation              | No ninth admitted connection/job or second worker; no unbounded retained tasks, FDs or RSS. Refused new work makes zero receiver calls and preserves history. Existing IDs remain readable at capacity.             |
| Long waiting / repeated clients | Ten-minute fixed-read/receiver-wait exercise: final RSS/FD counts return within 10%/two FDs of the warmed baseline after owned jobs retire. Report allocator high-water separately.                                 |
| Persistent storage              | Preserve 64-MiB database, 65-MiB main rollback and 504/32 enforcement. Measure actual directory and temporary-file peaks; provision 256 MiB disposable state space initially, not a guaranteed total-storage bound. |

Measure healthy/unavailable receiver, stalled response/180-second pass, worker contention, eight
concurrent/slow clients, disconnect, SIGKILL/restart, both capacity limits, maximal records/layouts
and Git descendants. Include current Git 15-second subprocess bounds and Kubernetes read/PATCH/pass
counts; stored reads/startup must add zero receiver calls. Unavailable material leaves work
unfinished; it must not be forced into a terminal result to satisfy a latency benchmark.

Use five repetitions per request workload. Report p50/p95/p99, raw bounded samples, CPU seconds,
wall time, peak memory/FDs and independent I/O counts. Refuse a resource pass on truncated or
missing evidence. Compare identical workloads on the same host; flag more than 20% latency/memory
regression against an accepted baseline, using absolute targets to avoid tiny-value noise. Keep
performance qualification separate from deterministic semantic CI. Budgets must be approved or
revised from native evidence before adoption; do not relax safety checks to hit them.

## Proposed beta definition of done

A beta candidate needs all of the following, for one exact clean source revision and artifact.
Propose freezing the service version-1 request grammar and existing grant/receipt/trust purposes
across v0.4.x. Preserve same-ID format-6 history and original evidence. Changes to projections need
explicit compatibility review; incompatible formats need new identifiers and a retention policy.
Qualification must demonstrate v0.3 format-6 retention under the candidate, not infer it from a
version number. This proposal includes no migration, downgrade or stable public Rust API.

- Approved execution scope and compatibility notes, reflected in current contract owners. Preserve
  format-6 history and original receipts; older formats remain rejected unchanged. Retain legacy
  inspection purposes. Any incompatible format change needs an explicit separate decision.
- The guarantee map above has passing owning checks, reviewed defensive enforcement and tested
  operator guidance. Make host/operator assumptions explicit: stable private roots, cooperative
  lock-using launches, trusted receiver hooks and independently assessed action independence.
- KAP-96's storage failure and repair output is complete. Full/corrupt/missing storage or
  indeterminate writes never become a receiver outcome, definite non-admission or permission to
  repeat an effect.
- The model, fuzz and negative-control acceptance above passes before replacing coverage. Keep
  independent HTTP, SQLite, real Git, Linux process, live Kubernetes and installed-artifact
  evidence.
- The [existing release lanes](../RELEASE.md#graduation-gates) pass for the selected v0.4 surface,
  with fresh security/SBOM results, reproducible assemblies, native systemd, both packaged receiver
  journeys and fresh-session caller continuity. Remove direct lanes only with the approved removal.
  Native fixture success does not substitute for packaged crash or live receiver evidence.
- Native resource workloads pass approved budgets and saturation/refusal checks. Record missing
  prerequisites as missing evidence, not a likely pass. Publish only sanitized technical summaries.

Beta still excludes production availability/support, HA, fleet ordering, automatic backups,
host-loss continuity, arbitrary stale-state restore, migration/downgrade, hostile-host containment,
power-loss certification, exactly-once effects, universal capture, Kubernetes truth/causation, and
Git hook/CI/deployment completion. A signed receipt authenticates evidence, not these excluded
facts.

## Implementation slices and dependencies

These define deliverable boundaries, not a second execution queue. Linear owns implementation
selection, status, dependencies and authorized ticket sequencing. Ticket creation does not approve
the open scope or compatibility decisions.

| Slice and affected owners                                                                                    | Acceptance and dependency rationale                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Scope convergence: `command`, `mcp`, `Application`, demo, contracts and release smoke                        | Requires maintainer scope approval. Remove only direct-execution owners and obsolete dependencies; keep provisioning, inspection, export and shared service semantics. Show equivalent packaged attempt/receipt-loss coverage before retiring demo seams. Update commands, archive/help and current docs together; leave tags unchanged.                                                                           |
| Defensive completion and input audit: journal receipt transition, parser/I/O owners, lint exceptions         | Reject same-ID/wrong-statement completion before terminal write; preserve original bytes and fields under operating failure. Map reachable byte/count/work limits and narrow justified exceptions. Run owner regressions and full deterministic gate; revalidate capacity premises for altered SQL. Independent of surface removal.                                                                                |
| Storage operations: KAP-96, service admission/completion/diagnostics and operator guide                      | Extend existing completion capacity, do not redesign it. Inventory current fault tests first; fill actual admission/receipt failure, corrupt/missing-state and actionable-output gaps. Require same-ID recovery after repair without another mutation, preserved frozen facts/receipts, full-capacity/refusal and real ENOSPC evidence. No pruning, reset or stale rollback. Independent of direct surface choice. |
| Lifecycle exploration: `simulation_tests`, private gateway/application/runtime test seams, robustness runner | Independent authority/outcome model, bounded actor schedules, replay traces, shrinking and negative-control detections. Preserve real boundary tests and old simulation until replacement obligations pass. Storage-fault composition consumes KAP-96's defined failures; model development otherwise proceeds independently.                                                                                      |
| Hostile-input exploration: `fuzz`, authority/service document/receipt parsers and vectors                    | Add distinct production parser targets/corpora, both effect purposes and limit/value properties. Demonstrate negative-control replay/minimization; retain canonical compatibility cases. No network or ambient trust. Independent of lifecycle model; no provider framework.                                                                                                                                       |
| Native resource baseline: qualification owners and `BUILD`/`TESTING`                                         | Reproducible released-binary workloads and accounting above, including physical layout, refusal and Git children. Obtain disposable native host access and explicit qualification authority first. Functional KAP-96 cases inform storage-pressure measurements; other resource workloads can proceed independently.                                                                                               |
| Candidate integration: `SCOPE`, `RELEASE`, artifact/lifecycle/caller lanes                                   | Requires accepted scope, completed owning slices and native resources. Identify exact source/artifact bytes and pass all retained gates. Any changed bytes requalify affected evidence. Publication/signing/deployment remain separately authorized actions.                                                                                                                                                       |

Open decisions are the service-only scope, beta compatibility promise, final native budgets, and
whether generation/minimization merits a test dependency. No evidence here supports weakening the
completion guarantee or observation-only recovery. Missing qualification includes the new model and
negative controls, expanded fuzz targets, KAP-96 acceptance, and native resource/candidate lanes.
Completing this review means an actionable proposal exists; it does not mean those implementations
or v0.4 beta acceptance are complete.
