# Test strategy

Suppose a receipt test passes, but a reconnecting caller receives different bytes. The signature
code may be correct while the service still breaks its promise. Conversely, running every malformed
receipt through a systemd installation would make a parser regression painfully expensive to find.

Test each rule at the lowest interface that owns it. Then test the connections between those
interfaces. This page explains where tests belong and what each kind of check can tell you.

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

General setup, formatting, release assembly and standalone artifact-verifier implementations remain
tooling, not removable assurance. The census and its regressions count as replacement assurance.
Generated files, binaries, corpus data and documentation are outside this source denominator; moving
maintained code into data or generated output cannot establish savings.

Charge the after-assurance count plus any positive net product-source increase. A product-source
decrease earns no deletion credit. This prevents relocated policy from inflating savings. Reports
include all source ranges, not only changed files. General tooling growth remains visible
separately; new assurance machinery belongs in assurance regardless of its directory.

Under this classification, the fixed baseline is **36,599 lines**: 27,452 Rust, 8,698 Python, 404
shell and 45 SQL. This replaces the approximate 36,391-line planning census; the 208-line
classification difference is not a retirement. At `4925c6d`, assurance is 38,254 lines and the net
product charge is 258 lines. The charged total is 38,512: **1,913 lines above baseline**, not a
reduction. Subsequent accounting support is also charged by the working-tree comparison.

## Atomic record-I/O simulation

`src/kernel_simulation_tests.rs` drives one to four Kubernetes or Git identities through one real
service application and shared journal. Each identity has distinct intent, target, authority and
receipt signing material. Every event checks every peer's raw facts and independently counted
receiver I/O. Generated three-identity schedules use Kubernetes-only, Git-only and mixed
assignments. They interleave selections, receiver changes, catalog removal, trust withdrawal and
restored prerequisites. Conflicting catalog replacement must fail application construction without
changing any peer's retained facts or receiver counts. Withdrawn trust must permit neither I/O nor
retained fact changes. Substituting a different public key under the original key ID must disclose
neither targets nor receipt bytes. Every retained peer checks status, admission and receipt reads;
real SQLite additionally checks history-page projections. Unaffected peers remain readable.
Restoring trust does not substitute current catalog authority for history. Signer rotation before
receipt commitment may choose the new signer. Rotation after commitment must return the original
bytes and signer. Invalid signing material at frozen history must change no facts or receiver
counts. Production journal policy validates authority, transitions and frozen facts. Its private
record-I/O owner reads complete bounded rows from either typed table and conditionally commits
against the original row. SQLite updates only changed columns. The test-only virtual store
implements atomic records, not lifecycle policy. Neither backend selection nor fault controls are
caller inputs.

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
Wrong-peer lookup deliberately misroutes the selected identity before grant binding; a wrong
lower-layer row alone is refused by the existing identity guard. An unrelated bounded refusal does
not qualify as detection. Generated schedules record their actions and retain an explicit healthy
suffix. Progress requires a restored receiver, healthy storage, original trust and an available
signer for every identity. Minimized progress witnesses must preserve eligibility for every peer,
not only the first peer checked. Minimized safety witnesses need not finish the operation; correct
code must pass those same prefixes on both stores.

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
identities, actions and selected values only while reproducing the same law and reached defect. The
older lifecycle explorer remains until these replacement workloads and exploration custody qualify
its retirement.

For retained local exploration, select a new private directory outside the checkout:

```sh
export KAPSEL_KERNEL_EVIDENCE="$(mktemp -d)"
cargo test --locked -p kapsel --lib \
  kernel_simulation_tests::kernel_trace_exploration_or_replay -- --ignored --exact --nocapture
```

Set `KAPSEL_KERNEL_DELIBERATE=1` to retain the 24 deliberate inputs for direct replay. Set
`KAPSEL_KERNEL_DEFECTS=1` to retain twenty inputs for eleven lifecycle defects and their minimized
findings. Catalog-conflict, wrong-signer, stale-trust and ignored-custody controls include
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

`src/lifecycle_exploration_tests.rs` explores private Kubernetes and Git gateway continuation
against real SQLite. Each of two to four identities has a distinct target and an independently
counted receiver. Expected authority comes from the trace's original approval, not retained
production output. The oracle tracks mutation opportunities, frozen results, and original receipt
bytes without calling production classifiers or receipt builders. The Git oracle checks the exact
retained acknowledgement and frozen ref, then inspects receipt facts under the original selected
signer. Observing the requested commit cannot replace a missing acknowledgement.

Fresh-operation schedules enumerate every interruption point before cancellation can consume an
attempt. Eligible fresh continuations must report the selected interruption checkpoint. Separate
schedules enumerate cancellation and competing selection around suspended preflight, mutation, and
observation calls. Seeded traces interleave submissions, receiver changes, trust withdrawal, reopen,
stale/replaced targets, attempt/response/observation loss, and receipt precommit or acknowledgement
loss. Application events exercise real `ServiceApplication::select` with removed or replaced catalog
entries and optional signing material. Real SQLite write refusal checks previous facts and same-ID
repair; admission commit-loss events retain the committed responsibility. These seams enumerate
understood alternatives, not arbitrary SQLite I/O failures.

The deterministic interaction owner, `bounded_lifecycle_exploration`, runs eight deliberate traces
under Kubernetes-only, Git-only, and mixed assignments. It replaces the generated outer stop ×
receiver × effect matrix, not the fresh-boundary enumeration or contention schedules. Each trace
includes transient preflight deferral, competing submission, a reached contention barrier, trust
withdrawal, catalog removal/replacement, missing signing material, and same-ID continuation. The
independent oracle checks every peer throughout these interactions.

| Deliberate trace                     | Distinct join                                                                                                                    |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `safe_retry_then_failure`            | Before-attempt interruption permits safe retry; later failed observation freezes                                                 |
| `unsent_present_b`                   | Committed unsent permission stays observation-only; present Git B is not acknowledgement                                         |
| `ambiguous_attempt_replaced`         | Lost attempt acknowledgement sends nothing; replacement cannot create success                                                    |
| `lost_response_unavailable`          | Sent mutation loses response; Kubernetes waits for observation availability, while Git freezes `UNKNOWN` acknowledgement and ref |
| `recorded_response_wrong_generation` | Retained response does not excuse mismatched observed generation                                                                 |
| `lost_observation_pending`           | Read-but-uncommitted observation is replaced by recovery's current observation                                                   |
| `frozen_before_replacement`          | Frozen success survives replacement and trust withdrawal; signing completes without catalog restoration or receiver I/O          |
| `terminal_before_stale_version`      | Frozen evidence survives later version changes and terminal signer rotation                                                      |

`ProductiveSummary` reports reached interruption checkpoints by effect and boundary, and counts
ineligible selected stops separately. It counts first attempts, observation freezes, and receipt
commits only after the durable-state oracle validates a transition from prior facts. Repeated
terminal events do not increase these counts. Barrier records identify the owner and contender's
identities and effects. Withdrawal records identify trust, catalog, or signing material, the phase
at withdrawal, and a productive same-ID transition after restoration. Catalog removal does not
revoke retained authority; these records do not imply that restoring the catalog is required. A
missing signer can defer receipt completion without preventing an earlier observation freeze. Run
with `--nocapture` to see the bounded summaries. They describe these traces, not universal coverage,
throughput, or a coverage score.

Safety checks run after each event. Progress requires an explicit healthy suffix with restored
trust, writes, receiver availability, authorization, and completion opportunities. Shrinking
preserves that suffix for progress findings. Longer development traces use 48 generated steps per
identity rather than the deterministic checks' eight.

The runtime's `enumerated_lifecycle_physical_retirement_barriers` separately exercises real tracked
jobs. It parks execution before or after admission acknowledgement, disconnects the caller and
aborts the supervisor in both orders, contends with same and different IDs, and verifies that drain
and worker capacity remain blocked until physical release. Panic-safe fixture cleanup releases
parked work when an assertion fails. These checks do not replace Linux socket/process or
native-service qualification.

The test-only generator uses no new dependency. Its explicit event format supports direct replay and
reduction of identities, events, and selected values. A failing run preserves the full trace before
execution, then writes and replays its minimized finding. Trace records include the seed, initial
identities, source-content digest, and executable digest. The source digest describes the checkout
at invocation; it is not a build attestation.

This replaces the prescribed fixed-failure simulation after seeded-defect detection, minimized
replay, and supervised exploration evidence passed. The mapping below preserves the old obligations.
Keep the existing HTTP, SQLite, Git, Linux process, live-receiver, ENOSPC, and artifact checks.

### Consolidated crash-matrix obligations

Fresh enumeration and deliberate interactions jointly own the retired
`every_apply_window_recovers_without_a_second_mutation` matrix. Enumeration alone establishes
checkpoint reach, not interaction equivalence.

| Retired window                            | Consolidated obligation and owner                                                                                                                                                  |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TargetObserved`                          | `BeforeAttempt` enumeration and `safe_retry_then_failure`: no first send, safe retry under original authority                                                                      |
| `ApplyStartedCommitted`                   | `UnsentAttempt` enumeration and `unsent_present_b`: zero original sends, observation-only recovery, `UNKNOWN` without acknowledgement                                              |
| `ApplyReturned` / `ApplyOutcomeCommitted` | Response-loss/recorded-response enumeration and deliberate unavailable/wrong-generation recovery                                                                                   |
| `ReceiverRead`                            | `ObservationLost` enumeration and `lost_observation_pending`; retained `receiver_read_fault_is_fresh_only_and_recovery_freezes_its_own_observation` checks fresh-only interruption |
| `ReceiverObservedCommitted`               | `ObservationRecorded` enumeration and `frozen_before_replacement`: zero-I/O continuation, unchanged frozen history, original receipt bytes                                         |

The retired matrix's preloaded failed observation in its zero-send window was not receiver evidence.
The explorer leaves an unsent Kubernetes receiver unchanged and preserves `UNKNOWN`. Legacy grants
remain covered by `service_reads_but_cannot_advance_retained_legacy_authority` and snapshot/binding
tests. The inert format-6 `target_read_failures` checks remain in gateway lifecycle/storage tests.

The generated outer matrix's other obligations retain direct owners: fresh receiver/result variants
in `enumerated_fresh_lifecycle_boundaries`, assignment/order/barrier joins in
`enumerated_two_identity_barrier_schedules`, SQLite refusal in
`sqlite_write_refusal_preserves_previous_facts_and_same_id_repair`, and admission ambiguity in
`admission_commit_loss_retains_original_responsibility`. Deliberate interactions preserve catalog
conflicts, withdrawn trust, changed receivers, receipt precommit loss, and original signer/byte
retention. Their healthy suffix includes receipt acknowledgement loss and rotated-key continuation.
Random longer traces remain available for exploration and minimization; they are not a second
maintained outer matrix.

### Old simulation obligations

The replacement preserves these obligations, not merely the old test name:

| Old obligation                                                                                                     | Replacement or retained owner                                                                                                                                                  |
| ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Repeated transient target deferral leaves authority unchanged and sends nothing                                    | `Receiver::Unavailable` / `WorkerAdvance`, followed by restored-receiver progress; bounded observation/read-budget adapter tests remain                                        |
| Seven fresh attempt/response/observation interruption points recover without resend                                | Explicit `Stop` events, independently counted receivers, and preflight/mutation/observation cancellation schedules                                                             |
| Dropped permission and lost attempt acknowledgement send nothing                                                   | Unsent and acknowledgement-loss traces; journal dispatch regressions remain. The old adapter's preloaded failed observation is not evidence of a sent mutation                 |
| Frozen observation survives repeated reopen without receiver I/O                                                   | Frozen-result oracle checks every identity after every event; real process/recovery tests remain                                                                               |
| Receipt precommit, finalized checkpoint, lost commit acknowledgement and signer rotation preserve durable evidence | Atomic receipt-delivery and material-replacement laws; `CompletionStop` events and process-exit checks retain their distinct checkpoints                                       |
| Legacy and snapshot grants retain their original interpretation                                                    | Snapshot/binding tests and `service_reads_but_cannot_advance_retained_legacy_authority` remain; service exploration does not admit legacy authority                            |
| Many retained identities share a journal without losing facts or completion headroom                               | Two-to-four-identity exploration checks all peers; full-capacity/layout, storage-failure and retained-history tests remain rather than being replaced by fresh trace databases |
| Seed/shard accounting, scratch custody and retained failure evidence                                               | Existing robustness supervision plus explicit full-trace retention, minimization, Rust replay and exact shard markers                                                          |

The explorer does not replace independent HTTP counts, actual Git transport, SQLite OS-failure,
Linux process, live-receiver, ENOSPC, or packaged artifact evidence. A failed or unrun required
negative control blocks retirement even when the deterministic checks pass.

Run the deterministic checks:

```sh
cargo test --locked -p kapsel --lib lifecycle_exploration_tests
```

For a small development exploration, select a new private directory outside the checkout. This
command accepts uncommitted source and does not provide the robustness supervisor's job limits. Do
not use it as the supervised 30-minute qualification lane.

```sh
export KAPSEL_LIFECYCLE_EVIDENCE="$(mktemp -d)"
KAPSEL_LIFECYCLE_CASES=100 cargo test --locked -p kapsel --lib \
  lifecycle_exploration_tests::lifecycle_trace_exploration_or_replay -- --ignored --exact
```

To retain the deliberate interaction inputs instead of generated cases, set
`KAPSEL_LIFECYCLE_DELIBERATE=1` with the same evidence-directory command. It writes one named trace
per assignment and uses the same oracle, minimizer, and direct replay entry point. This mode also
supports isolated negative controls against those exact inputs.

Each case creates its JSON input exclusively; existing evidence is never overwritten. A safety
finding can reduce to a trace that ends before completion. Its `require_progress` flag is false;
progress findings retain their recovery preconditions. Replay the recorded events directly, without
regenerating earlier cases:

```sh
KAPSEL_LIFECYCLE_REPLAY=/absolute/retained/finding-N.json cargo test --locked -p kapsel --lib \
  lifecycle_exploration_tests::lifecycle_trace_exploration_or_replay -- --ignored --exact
```

Replay under the retained executable for exact binary reproduction. Rebuilding tests exercises the
same events against the new source, not the original executable identity. `KAPSEL_LIFECYCLE_STEPS`
selects 8 through 48 generated steps per identity. Shard variables partition the same generated case
sequence; each completed shard reports its exact count.

The existing robustness supervisor's `exploration`, `simulation`, and `soak` modes all use this
explorer. They retain full traces and their hashes, then use the owning Rust parser and oracle to
replay every retained document. A generation marker or matching header hashes alone cannot qualify a
run. See [supervised exploration](qualification.md#background-sweep-and-retained-evidence) for
custody, clean-source requirements, resource limits, and commands.

## Commands and detailed mappings

Use [Build and test](build.md#focused-gates) for the ordinary loop and
[Qualification](qualification.md) for additional environments. The [evidence map](evidence.md)
contains maintained test names, boundary limits, and guarantee-to-test matrices. Release acceptance
is defined by the [release process](release_process.md), not test counts or coverage percentages.
