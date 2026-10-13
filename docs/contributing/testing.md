# Test strategy

Suppose a receipt test passes, but a reconnecting caller receives different bytes. The signature
code may be correct while the service still breaks its promise. Conversely, running every malformed
receipt through a systemd installation would make a parser regression painfully expensive to find.

Test each rule at the lowest interface that owns it. Then test the connections between those
interfaces. This page explains where tests belong and what each kind of check can tell you.

## Assurance cutover

The replacement keeps seven shared laws: external authority; confirmed fresh dispatch; original
identity; observation-only recovery; immutable evidence; read and peer isolation; useful progress
after prerequisite repair. [The gateway contract](../reference/effect_gateway.md) defines their
meaning. `kernel_simulation_tests` observes original intent, actual I/O and raw retained facts. It
must not calculate expected lifecycle transitions through production policy.

Retire semantic journeys in gateway lifecycle, recovery, snapshot and receipt suites, application
contracts and retry selection. Extract their distinct admission, SQL, legacy and configured-client
facts into small checks. Keep parser vectors and physical capacity premises at their owners.
Physical harnesses establish transactions, TCP requests, custody and job retirement; they do not
repeat lifecycle matrices. Qualification must exercise the documented source and artifact entry
points, not substitute test-feature binaries for installed production bytes.

Linux socket checks keep one real application admission with parked preflight, same-ID contention
and concurrent stored reads. Direct Unix fixtures own peer denial, aggregate frame deadlines,
oversized replies, saturation and physical permit retirement. Protocol tests own the complete
status/receipt vocabulary. Request partitions start from accepted versioned objects, so a missing
version cannot mask the intended malformed field. Independently authored service wire vectors have
one test-only owner, `tests/fixtures/service_wire.rs` in the daemon package. Renderer and decoder
checks share those expectations; the vectors do not calculate authority or lifecycle outcomes. MCP
discovery schemas and call/reply partitions live at the bridge owner. They retain exact members,
effect-specific fields, nullable observed facts and independently pinned receipt digests. One
renderer witness binds execution fields to the complete decoder tuple table. Three black-box
stdio/socket checks retain all five requests, fixed discovery, explicit submission, unchanged
service facts, pre-I/O argument rejection and honest transport uncertainty. Transport header
partitions call their decoder directly; compact socket witnesses retain actual framing, half-close,
original bytes and failure classification. The Python caller tests its production `requires_resume`
predicate and reply decoder directly. Finite partitions own malformed and contradictory guidance;
reference and pipe tests own actual filesystem custody, byte limits and child retirement. One
fresh-process exchange binds the caller to the real bridge, with lost acknowledgement and explicit
same-ID resume. It does not model a receiver or durable lifecycle.

Native public checks share the actual fresh-session caller. One daemon recovery trace invokes
`resume` through MCP after process loss, retaining the reference bytes. It also covers death after
receipt commitment, original-byte export, signer rotation and corrupt-receipt startup refusal.
`mcp_caller_loss_preserves_reference_and_service_admission` separately owns undelivered
acknowledgement, without reconstructing completion. Fixed-client tests own exclusive export errors.
Adapter clock tests and the packaged live workflow own observation ceilings and late availability;
shared laws own frozen `UNKNOWN` and no-resend. Adapter HTTP partitions share one finite
request/reply fixture that rejects unused planned replies and additional requests. An independent
PATCH wire vector and unequal generation/replica values bind request construction and all decoded
receiver fields. Paused-clock checks retain the production deadlines, read ceilings and fresh
invocation budgets. The configured HTTP fixture owns success/error request counts and shared-target
preflight, not separate cancellation/restart lifecycle worlds.

The runtime's production `contended_admission` decision uses retained admission and captured owner
facts. Its finite table compares typed admission decisions, not copied wire JSON. It owns definite
busy, access error and indeterminate partitions. The runtime retains generation pins around those
facts; scheduled tests still own completion during the absence probe and physical retirement.
Startup tests own descriptors, socket inodes and optional-material snapshots. They do not construct
a receiver to prove that the receipt directory is unused. Diagnostic tests own suppression and sink
mechanics; one protocol binding checks shared suppression across status/history/receipt reads and
its separation from explicit-selection diagnostics.

Operator commands keep one public provisioning/configuration trace in `e2e_operator_commands`.
Actual snapshot HTTP reads, authenticated grant fields, private output files and static validation
bind the executable to its application. Command-local tests own intent objects, option grammar,
failure classes, bounded regular-file descriptors and exclusive publication. Static approval
partitions own independent trust and unique snapshot IDs without opening history. Offline inspection
keeps one exact machine-record vector and a rejected signature; receipt suites own authentication,
trust, classification and hostile-byte partitions. There is no CLI lifecycle simulator.

Artifact composition delegates bounded format validation to the standalone verifier. Its offline
regressions use one independently authored archive/SBOM fixture with pinned layout and metadata,
hostile-member vectors, sidecar tampering and exclusive extraction under an isolated interpreter.
The assembled-artifact check adds exact source/asset correspondence, ELF identity and execution of
the checksum-bound companion. The bundled operator-guide trace owns the default installed service
checks, including custody and MCP, rather than repeating a successful operation/restart journey. The
standalone verifier never executes binaries or changes the host. The archive's explicit maintainer
qualification program owns smoke and one installed procedure with direct-process/systemd profiles;
packaged crash/live receiver lanes remain separate. Signer repair, trust withdrawal and unsupported
history partitions stay with shared laws, command/startup checks and packaged receiver owners, not
another installed lifecycle matrix. Packaged Git and Kubernetes qualification each select one clean
artifact. Their standalone fixtures reinstall the same selected bytes at retained cold replacement
windows; they do not maintain a second producer/extraction/mount path for upgrades.

Journal decoder checks use a concrete independently authored SQLite history builder. Expected
request, authority, attempt, receiver and receipt fields do not come from production row writers.
Unequal generation and replica values expose field swaps. Every corruption vector starts from a
checked-valid row and exercises writable, retained-history and read-only publication readers.
Kubernetes and Git retain their distinct typed-table checks. Shared SQL fixtures also supply format,
capacity-layout, receipt-candidate and full-capacity records. Production writes own actual
completion; independent row comparisons own unchanged authority, frozen facts and original bytes.
One maximal mixed-phase completion witness replaces the insertion-order/phase lifecycle matrix. A
two-row process fixture owns before-SQL, SQL-executed/precommit, hot rollback and committed-receipt
observations. Competing-writer read views, rollback records and genuine ENOSPC remain separate
physical owners.

Kubernetes live qualification uses one packaged-binary workflow rather than source/test-hook
journeys. Its operator-owned HTTP barriers establish actual conditional conflicts and process-loss
placement; API-server audit, receiver/controller reads and admission logs supply independent facts.
Compact adapter composition binds exact HTTP requests and receiver facts to signed receipts. Shared
histories retain interruption, original authority and frozen recovery laws. Live audit controls must
reject duplicate product requests, shortened observation windows and per-pass read overruns.

The whole-suite working budget is 17,400 charged lines, including all replacement support:

| Owner                                                    | After-budget |
| -------------------------------------------------------- | -----------: |
| Shared histories, independent laws, controls and replay  |        3,200 |
| Decoders, hostile inputs, classifiers and frozen formats |        2,400 |
| SQL, capacity, OS faults and concrete receivers          |        3,100 |
| Runtime, custody and compact public journeys             |        3,100 |
| Python, artifact/native qualification and CI support     |        3,400 |
| Positive net production additions and external support   |        2,200 |

This is a construction budget, not measured savings or qualification evidence. The fixed baseline
and census below remain the acceptance authority. Git retains removed examples; unique observations
must have a maintained owner before retirement.

## Place the test

| Location                      | Responsibility                                                             |
| ----------------------------- | -------------------------------------------------------------------------- |
| Inline `#[cfg(test)]` modules | Parsing, classification, SQL/filesystem invariants, private fault seams    |
| Root `tests/application_*.rs` | Service composition and independently counted receiver requests            |
| Root `tests/e2e_*.rs`         | Executable output, exits, restart, and operator workflows                  |
| `crates/<crate>/tests/`       | Exported interfaces of meaningful workspace packages                       |
| `fuzz/`                       | Hostile bytes entering production decoders                                 |
| Simulation targets            | Seeded lifecycle schedules and recovery invariants                         |
| Linux process tests           | Socket identity, physical job lifetime, process loss, and retained history |
| Live-receiver lanes           | Real receiver behaviour in disposable environments                         |
| Artifact lanes                | Extracted production bytes, installation, and packaged caller journeys     |

Keep implementation-local tests beside their owner in an inline `mod tests`. Do not detach them
merely to shorten a file. Cross-component and process scenarios can use separate ordinary modules,
named for their behaviour. Do not use textual `include!` fragments or widen production interfaces
just to expose a test seam. A shared support crate or provider interface needs real consumers.

For receipt retrieval, that division looks like this:

1. Parser and classifier tests check malformed records and result rules beside their
   implementations.
2. Journal tests check that completion commits the exact signed bytes with terminal state.
3. Application and service tests check that reads return those original bytes after restart, even
   when current signing material changes.
4. Client tests check digest validation and exclusive export. An export failure must not reopen the
   operation.

Each test adds a fact the lower test could not establish. It does not repeat the entire lower-layer
matrix. At higher layers, check authority separation, durable ordering, observable output, original
evidence, and non-disclosure. Count receiver requests independently of the classifier being tested.

## Keep deterministic tests deterministic

Use fixed keys, explicit evaluation time, private temporary directories, seeded inputs, and sorted
output. Default semantic tests must not depend on live services, ambient trust, locale, or polling
order. Test intentional SQLite lock conflicts with a zero busy timeout and assert the lock error.
Use paused Tokio time for in-memory deadlines. Process fixtures should acknowledge admission,
handler completion, or readiness rather than assume it after a sleep. A bounded monotonic
coordination timeout does not define result meaning.

Crash tests must cover both loss after mutation and loss after receipt commitment but before export.
Recovery must preserve the original ID, avoid another mutation, and return original receipt bytes. A
successful action followed by graceful restart does not cover those interrupted windows.

## Choose the evidence class

- **Deterministic:** repeatable semantic rules, composition, and hostile-input rejection.
- **Process:** real disconnect, termination, restart, OS identities, and job retention.
- **Live receiver:** Kubernetes or Git behaviour beyond scripted observations.
- **Artifact:** extracted production binaries rather than test-feature executables.
- **Native installation:** the shipped systemd assets on a fresh native target host.
- **Exploration:** fuzz or seeded schedules that search for failures; retain inputs and replay them.

Process exit does not prove disk-backed power-loss durability. Emulated containers do not qualify a
native installation. A fuzz smoke pass does not replace canonical vectors or explicit failure cases.
Record exact source/artifact identities and missing lanes when reporting a result.

## Maintained source accounting

Use the source census before retiring assurance implementations:

```sh
python3 tools/dev/assurance_census.py > /tmp/kapsel-assurance-census.json
```

The default comparison is committed `a009071896cf394062d31159ff1e3c5783430efa` against the working
tree, including untracked, non-ignored source additions. Use `--after <revision>` for a committed
comparison. The command reads source without checking out either revision. Keep the same classifier
for both sides; each report records its SHA-256 digest.

The report lists every maintained Rust, Python, shell and SQL source file, its content digest,
physical line count, and non-overlapping assurance ranges. Counts include blanks and comments. Whole
test directories, fuzz sources, named test modules and explicitly listed qualification support count
as assurance. In mixed Rust files, exclusively test- or harness-gated items and statements count as
assurance. Their physical lines count once, including nested gates. Shared platform gates remain
product source. The scanner masks comments and literals; it does not expand macros or infer
conditional compilation. Audit the emitted ranges when adding a new gating form or relocating
support, and update the explicit support classification for new nonstandard owners.

General setup, formatting, release assembly and the standalone artifact-verifier format core remain
tooling, not removable assurance. The classifier charges historical receiver/process/installed
procedures inside that verifier and the entire separated qualification program as assurance. Apply
that same classifier to baseline, start and end; relocation earns no savings. The accepted baseline
and threshold below do not change when correcting this historical classification. Report the revised
baseline census separately for comparison. The census and its regressions count as replacement
assurance. Generated files, binaries, corpus data and documentation are outside this source
denominator; moving maintained code into data or generated output cannot establish savings.

Charge the after-assurance count plus any positive net product-source increase. Product source
includes non-assurance Rust and the maintained fresh-session caller, including its production
policy. A product-source decrease earns no deletion credit. This prevents relocated policy from
inflating savings. Reports include all source ranges, not only changed files. General tooling growth
remains visible separately; new assurance machinery belongs in assurance regardless of its
directory.

Under this classification, the fixed baseline is **36,599 lines**: 27,452 Rust, 8,698 Python, 404
shell and 45 SQL. At least 50% net retirement requires a final charged total of at most **18,299**.
Include replacement support and positive net production additions. External qualification support
remains charged separately; relocation, forecasts and fewer test names do not establish retirement.

## Atomic record-I/O simulation

`src/kernel_simulation_tests/` drives one to four Kubernetes or Git identities through one real
service application and shared journal. Its private test-only owners are:

| Module           | Responsibility                                                                 |
| ---------------- | ------------------------------------------------------------------------------ |
| `mod.rs`         | Stable root replay selector and narrow executed-SQL probe re-export            |
| `trace.rs`       | Serialized actions, effect/cut enums, findings and unchanged defaults          |
| `world.rs`       | Concrete peers, original material and raw record-store fixtures                |
| `run.rs`         | Real selections, cancellation, reopen and operating faults                     |
| `laws.rs`        | Independent original-intent, I/O, retained-fact, byte and progress comparisons |
| `cases.rs`       | Deterministic witnesses and reached defect controls on both stores             |
| `exploration.rs` | Generation, minimization, exclusive persistence and replay                     |

`src/test_scratch.rs` owns private temporary-directory custody and cleanup for journal tests and
simulation. Journal tests do not depend on the simulator. The Python supervisor still selects
exactly `kernel_simulation_tests::kernel_trace_exploration_or_replay`; deterministic cases now have
the `kernel_simulation_tests::cases::` prefix. All modules and neutral support remain charged
assurance.

Each identity has distinct intent, target, authority and receipt signing material. Every event
checks every peer's raw facts and independently counted receiver I/O. Every selection also requires
all nonselected peers' complete rows and I/O counters to remain unchanged, including the first
receipt commitment. Generated three-identity schedules use Kubernetes-only, Git-only and mixed
assignments. They interleave selections, receiver changes, catalog removal, trust withdrawal and
restored prerequisites. Conflicting catalog replacement must fail application construction without
changing any peer's retained facts or receiver counts. Withdrawn trust must permit neither I/O nor
retained fact changes. Substituting a different public key under the original key ID must disclose
neither targets nor receipt bytes. After raw-history and receiver laws pass, every peer checks exact
stored status, admitted phase, original targets and receipt readiness/bytes. Unadmitted identities
must return absence without catalog target disclosure. Execution-status reads check every process
observation against independently specified disposition pairs. Unfinished history distinguishes
operator remediation from explicit same-ID resumption; terminal history supersedes stale
observations. Unknown process knowledge never supplies a historical stop cause, including after
reopen. Both point reads and authenticated SQLite history entries preserve access failures and
original status/targets. Real SQLite additionally checks the ordered history identities and their
authenticated projections. Unaffected peers remain readable. Reads must change neither retained
rows, receiver counts nor durable-write counts. These traces contain at most four identities;
full-page pagination and wire/process readers retain their direct owners. Restoring trust does not
substitute current catalog authority for history. Signer rotation before receipt commitment may
choose the new signer. Rotation after commitment must return the original bytes and signer. Invalid
signing material at frozen history must change no facts or receiver counts. Production journal
policy validates authority, transitions and frozen facts. Its private record-I/O owner reads
complete bounded rows from either typed table and conditionally commits against the original row.
SQLite updates only changed columns. The test-only virtual store implements atomic records, not
lifecycle policy. Neither backend selection nor fault controls are caller inputs.

The slice checks original intent, confirmed dispatch provenance, initial classification, complete
receiver-fact and inspected receipt-payload binding, frozen no-I/O continuation, original receipt
bytes and healthy eligible progress. It injects no-commit and commit-with-lost-acknowledgement
histories with the same returned error. Receiver response loss is separate. Both effects run the
delivery laws on virtual records and real SQLite; named physical columns and executed write plans
provide independent SQLite evidence.

Git checks exact original acknowledgement independently of the frozen ref. A seeded control that
infers an acknowledgement from externally established B must fail `git_acknowledgement_binding`,
including after an unsent attempt. Its minimized input must fail on both stores and pass without the
control. The shared stale-record control also runs against Git rows.

Seeded remint, wrong-initial-result, no-op, wrong-signer, accepted catalog conflict, wrong-peer
lookup, physical replica-field-swap, receipt-decoder field-swap and unconditional-write controls
must violate their intended law and report the reached faulty branch. Stale-trust and
ignored-custody controls separately establish original-key non-disclosure and post-I/O binding.
Status and target projection controls alter the real application's read output without changing
retained facts. They must fail `stored_read_projection` under Kubernetes, Git and mixed assignments,
including full/minimized witnesses on both stores and passing defect-free counterparts. The
disposition control falsely marks unfinished history complete and must fail
`execution_disposition_projection` under the same effect assignments, stores and replay
requirements. The disposition law replaces the inline projector matrix and synthetic history-entry
projection checks in `application::service::disposition`, and procedural application disposition
journeys. Local next-action/owner and error-to-stop classification checks remain. Compact
application checks own missing-material admission, callback-time grant visibility and worker
exclusion, full-page pagination, cold validation and SQLite file-byte preservation.
Configured-client tests own actual success/ambiguous-response request counts and shared-target
preflight conflict. These read laws do not establish physical job ownership, outcome-cache
invalidation or socket rendering. Wrong-peer lookup deliberately misroutes the selected identity
before grant binding; a wrong lower-layer row alone is refused by the existing identity guard. An
unrelated bounded refusal does not qualify as detection. Generated schedules record their actions
and retain an explicit healthy suffix. Progress requires a restored receiver, healthy storage,
original trust and an available signer for every identity. Minimized progress witnesses must
preserve eligibility for every peer, not only the first peer checked. Minimized safety witnesses
need not finish the operation; correct code must pass those same prefixes on both stores.

Run the deterministic slice:

```sh
cargo test --locked -p kapsel --lib kernel_simulation_tests
cargo test --locked -p kapsel --lib atomic_record_binding
```

The atomic-delivery workload and remint control replace the procedural unsent-attempt recovery
scenario in `gateway::tests::dispatch`: acknowledgement loss or a dropped fresh permission adds no
send, recovery freezes honest `UNKNOWN`, and later selection retains original bytes with no I/O. The
competing-claimants check still owns stale Authorized-snapshot refusal; foreign snapshots and actual
cancellation retain their local owners.

`suspended_io_rechecks_original_custody_before_advancing_any_peer` suspends real selection at
preflight, mutation and observation. While the future is pending, it replaces retained grant bytes,
then releases the receiver. The continuation must refuse without changing the attacked record or
performing further I/O. The checker restores only the externally altered grant bytes before same-ID
recovery. Frozen and finalized neighbours remain unchanged. Both effects run this law on both
stores, with reached ignored-custody defects and minimized replay. These checks replace the local
changed-grant-during-apply matrix; they do not replace filesystem/process custody.

`replacement_catalog_and_rotated_material_preserve_retained_history` checks admitted, authorized,
attempted, frozen and finalized history across catalog conflicts and signer changes. Receipt
no-commit leaves all receipt columns absent in `receiver_observed`; acknowledgement loss leaves all
three committed together in `finalized`. The all-peer checker binds stored bytes, digest and key
identity to the completion material, then inspects returned bytes under that key. Together with
atomic-delivery laws, this replaces the deterministic receipt-commit/rotation matrix. Actual
process-exit, configured-client HTTP and native receipt owners remain separate.

Fresh-checkpoint enumeration runs before any cancellation can consume the attempt. Both stores and
effects check all seven interruption windows against healthy, failed, pending, replaced, stale,
wrong-generation and unavailable receivers. Eligible fresh selections must reach the selected
checkpoint, with matching returned error, durable writes and exact receiver call counts. Recovery's
`ReceiverRead` interruption remains fresh-only.

Suspended service selections contend with the same or another identity at preflight, mutation and
observation. The contender must acknowledge only existing responsibility or busy refusal, changing
neither peer's facts nor receiver counts. Dropping the real selection future releases the worker;
same-ID continuation still cannot resend. Retained schedules enumerate the six orders of
cancellation, conflicting catalog construction and reopen. Physical blocking-job retirement remains
a separate runtime owner.

Eight deliberate recovery joins use those same actions and all-peer laws under Kubernetes-only,
Git-only and mixed assignments. SQLite query-only refusal and virtual no-commit refusal preserve
previous facts through reopen and same-ID repair. Progress findings require current healthy
prerequisites and an eligible selection for every remaining identity. Reduction can remove
identities, actions and selected values only while reproducing the same law and reached defect.

For retained local exploration, select a new private directory outside the checkout:

```sh
export KAPSEL_KERNEL_EVIDENCE="$(mktemp -d)"
cargo test --locked -p kapsel --lib \
  kernel_simulation_tests::kernel_trace_exploration_or_replay -- --ignored --exact --nocapture
```

Set `KAPSEL_KERNEL_DELIBERATE=1` to retain the 24 deliberate inputs for direct replay. Set
`KAPSEL_KERNEL_DEFECTS=1` to retain thirty-two inputs for sixteen lifecycle defects and their
minimized findings. Catalog-conflict, wrong-signer, stale-trust and ignored-custody controls include
Kubernetes, Git and mixed assignments. The atomic-record binding control has its separate
deterministic owner. Each document is created exclusively before execution and records
source-content and executable digests. These digests are not build attestations. Replay a retained
document without regenerating its schedule:

```sh
KAPSEL_KERNEL_REPLAY=/absolute/retained/finding-0.json cargo test --locked -p kapsel --lib \
  kernel_simulation_tests::kernel_trace_exploration_or_replay -- --ignored --exact --nocapture
```

Use the retained executable for original-binary reproduction. Rebuilding runs the same actions
against new code. This local route does not replace supervised exploration custody, physical worker
lifetime, capacity/ENOSPC, configured-client HTTP, actual Git transport, live-receiver or
installed-artifact evidence. Those owners remain separate.

## Lifecycle exploration

The [atomic-record simulator](#atomic-record-io-simulation) owns fresh interruption enumeration,
suspended service contention, deliberate recovery joins and generated schedules. It exercises one
real application and shared journal, not a predicted lifecycle implementation. Every event checks
all peers' original authority, raw history and independently counted I/O, including peers whose
external trust is unavailable. Application reads must still refuse disclosure under unavailable
original trust.

`exploration`, `simulation` and `soak` use this same owner through the existing robustness
supervisor. The local `KAPSEL_KERNEL_*` commands above accept uncommitted source. Supervised runs
require clean committed source, bounded resources and retained evidence. See
[supervised exploration](qualification.md#background-sweep-and-retained-evidence). Retained older
inputs require their original test executable; rebuilding does not recreate that executable
identity.

The runtime's `enumerated_lifecycle_physical_retirement_barriers` separately exercises tracked jobs.
It parks work before or after admission acknowledgement, disconnects the caller and aborts the
supervisor in both orders. Same-ID and different-ID contention must leave drain and capacity blocked
until physical release. This does not replace Linux socket/process or native-service qualification.

### Consolidated crash-matrix obligations

Fresh enumeration and deliberate joins jointly establish these obligations. Checkpoint reach alone
cannot establish interaction equivalence.

| Window                                    | Simulator obligation                                                                                                |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `TargetObserved`                          | `BeforeAttempt`: no first send; safe retry under original authority before later failed observation                 |
| `ApplyStartedCommitted`                   | `Unsent`: zero original sends; observation-only recovery, including present Git B without acknowledgement           |
| `AttemptCommitAcknowledgementLost`        | Lost confirmation creates no dispatch permission; receiver replacement cannot create success                        |
| `ApplyReturned` / `ApplyOutcomeCommitted` | Response-loss and recorded-response cuts join unavailable or wrong-generation recovery                              |
| `ReceiverRead`                            | `ObservationLost`: recovery freezes its current observation; the interruption is fresh-only                         |
| `ReceiverObservedCommitted`               | `Frozen`: receiver replacement and trust withdrawal add no observation; completion retains original facts and bytes |

The local `receiver_read_fault_is_fresh_only_and_recovery_freezes_its_own_observation` regression
retains its direct driver check. An unsent Kubernetes receiver stays unchanged; a preloaded failed
observation is not evidence of a sent mutation. Legacy grants retain the
`service_reads_but_cannot_advance_retained_legacy_authority` and snapshot/binding owners. Format-6
inert `target_read_failures` checks remain in gateway lifecycle/storage tests.

### Old simulation obligations

| Obligation                                                      | Replacement or retained owner                                                                                                                                                            |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Transient target deferral preserves authority and sends nothing | Unavailable-receiver actions and restored progress; bounded read-budget adapter checks remain                                                                                            |
| Seven fresh windows recover without resend                      | Fresh-checkpoint enumeration and suspended cancellation, with reached remint controls                                                                                                    |
| Frozen history survives reopen and changed receiver facts       | All-peer raw-fact and no-I/O laws; Git observation substitution changes the ref without changing acknowledgement/result; receipt rewrite replaces bytes and digest under withdrawn trust |
| Receipt loss and signer rotation preserve original evidence     | Atomic delivery and material-replacement laws; actual process-exit checkpoints remain separate                                                                                           |
| Shared history retains facts and completion headroom            | One shared simulator journal; full-capacity/layout and storage-failure owners remain                                                                                                     |
| Seed/shard accounting and evidence custody                      | Existing supervisor, exclusive full-input retention, reached-defect reduction and Rust-owned replay of every document                                                                    |

The simulator also replaces the procedural authorized-reopen, writer/decoder phase, target-read
interruption and post-apply recovery traces in gateway `lifecycle` and `recovery`. Fresh
checkpoints, atomic response/receipt delivery and deliberate joins check their durable phases and
exact I/O; all-peer read laws exercise the production decoder. Snapshot target/receipt binding and
ambiguous apply recovery use the same original-intent, attempt-binding and receipt-payload laws,
with remint, wrong-initial-result, target-projection and receipt-binding controls. The shared
gateway fixture retains its independent SQLite attempt check at mutation, without per-scenario
capture fields.

Compact direct checks retain single-field snapshot conflicts, legacy downgrade and the gateway's
immediate typed apply error. The simulator additionally checks the application's bounded apply stop,
without observation or a result. Its preflight law binds newly retained target fields to actual
identify I/O; a refused write must preserve earlier evidence, not adopt the latest read. Rejected
rows remain immutable across reselection and reopen. Single-field receiver drift after authorized
reopen uses those same laws. Admission acknowledgement, real capacity races, physical locks, process
loss and the inert format-6 field keep direct owners.

The independent historical recovery-policy comparison is retired. Its decision and pinned live
admission counterexample remain in ADR 0011; the simulator drives current product recovery rather
than maintaining a second hypothetical lifecycle. A representative receiver-result contract change
now changes `result_from_io` and the independent classifier partitions, not copied expected results
in gateway receipt, application disposition and A/B journey worlds.

Independent HTTP counts, actual Git transport, SQLite OS-failure, Linux process, live-receiver,
ENOSPC and packaged-artifact evidence remain separate. A failed or unrun required negative control
blocks retirement even when deterministic checks pass.

## Robustness runner ownership

`tools/dev/run_robustness.py` owns command launching, bounded output, evidence custody, completion,
and explicit triage. Direct protocol cases cover build records, exact generation/replay markers,
trace header custody and fuzz outcomes. One wiring witness per controller checks source/binary and
corpus retention without reconstructing simulation worlds. The Rust directory replay owns action
interpretation and the simulation laws; successful headers and markers cannot substitute for it.

Real process fixtures retain separate witnesses for EOF/exit ordering, first failed peers,
descendants, inherited locks, FIFO refusal and cancellation at spawn, retirement and finalization.
Retained metadata does not authorize cleanup. Only successful completion removes the freshly owned
scratch directory; failed or interrupted evidence requires explicit triage.

## Commands and detailed mappings

Use [Build and test](build.md#focused-gates) for the ordinary loop and
[Qualification](qualification.md) for additional environments. The [evidence map](evidence.md)
contains maintained test names, boundary limits, and guarantee-to-test matrices. Release acceptance
is defined by the [release process](release_process.md), not test counts or coverage percentages.
