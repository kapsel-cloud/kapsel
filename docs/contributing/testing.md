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

This is not yet a replacement for `src/simulation_tests.rs`. Coverage retirement requires the full
seeded-defect matrix, supervised exploration, and an explicit mapping of the old obligations. Keep
the existing HTTP, SQLite, Git, Linux process, live-receiver, ENOSPC, and artifact checks.

### Old simulation obligations

Retirement must preserve these obligations, not merely replace the old test name:

| Old obligation                                                                                                     | Replacement or retained owner                                                                                                                                                  |
| ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Repeated transient target deferral leaves authority unchanged and sends nothing                                    | `ReceiverChange::Unavailable` / `WorkerAdvance`, followed by restored-receiver progress; bounded observation/read-budget adapter tests remain                                  |
| Seven fresh attempt/response/observation interruption points recover without resend                                | Explicit `Stop` events, independently counted receivers, and preflight/mutation/observation cancellation schedules                                                             |
| Dropped permission and lost attempt acknowledgement send nothing                                                   | Unsent and acknowledgement-loss traces; journal dispatch regressions remain. The old adapter's preloaded failed observation is not evidence of a sent mutation                 |
| Frozen observation survives repeated reopen without receiver I/O                                                   | Frozen-result oracle checks every identity after every event; real process/recovery tests remain                                                                               |
| Receipt precommit, finalized checkpoint, lost commit acknowledgement and signer rotation preserve durable evidence | `CompletionStop` events and immutable-byte checks; `receipt_commit_freezes_bytes_and_signer_under_acknowledgement_loss` retains all checkpoint variants                        |
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

Each case creates `case-N.json` exclusively; existing evidence is never overwritten. A safety
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
