# Code-quality review

This record explains the consistency pass's source coverage, correction decisions, and retained
boundaries. [Contributing](../../CONTRIBUTING.md#engineering-conventions) owns the conventions;
[ADR 0001](../decisions/0001-kapsel-style.md) owns the design criterion. This page is not a second
style guide or a release qualification claim.

The initial review covered 140 maintained Rust, Python, shell, and hook files, 14 configuration or
workflow files, and three convention owners. Changed and newly added source was reviewed separately.
The coverage table also includes deployment assets, formatting and coverage configuration, the
webhook Dockerfile, and the frozen format-5 SQL fixture omitted from that initial enumeration.
Dependency source, generated output, and binary vector/corpus data are not authored-source review
coverage. Frozen fixtures retain their bytes.

**Review status:** source coverage, correction integration, exception review, and focused
independent review are complete. The validated candidate is identified below. Mainline integration
and publication are separate actions.

## Correction decisions

Actual source or contract defects take priority over cosmetic and prospective design changes.

| Owner                                                                | Finding                                                                                                                      | Decision and preserved boundary                                                                                                                                                                                                                                | Regression owner                                                                                                                                    |
| -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `xtask/src/main.rs`                                                  | Compile-time checkout routing can run another worktree's scripts when a binary is reused.                                    | Accept invocation-owned Git root discovery, clear redirecting Git environment, validate the fixed checkout files, and retain the exact command grammar. No compile-time fallback.                                                                              | `xtask/tests/checkout_root.rs`: one binary, two checkouts, nested invocation, redirected Git environment, and refusal cases.                        |
| `src/command/mod.rs`                                                 | Snapshot provisioning maps malformed operator kubeconfig to caller input failure.                                            | Accept exhaustive application-error mapping. Operator configuration remains exit 3; invalid grant input remains exit 2. Do not expose raw diagnostics or create an output on failure.                                                                          | `tests/e2e_provisioning_command.rs`: exact command/error class, exit, and output absence.                                                           |
| `crates/kapsel-daemon/src/bin/kapsel-service-mcp.rs`                 | Status guidance and nested target objects can carry unknown or inconsistent fields.                                          | Accept fixed response-shape validation using execution types and the actual service renderer's vocabulary. Preserve valid service values; malformed replies become response errors, not fresh permission or inferred outcomes.                                 | `crates/kapsel-daemon/tests/service_mcp.rs`; Linux process journeys exercise the real bridge and service together.                                  |
| `tools/release/scan_sbom.py`, `tools/checks/scan_source_security.py` | Malformed scanner reports or noncanonical severity strings can be treated as clean; capture lacks local resource bounds.     | Accept bounded capture and shape/severity checks before policy evaluation. Keep legitimate omitted empty Trivy collections, canonical `UNKNOWN`, database identity checks, and the existing `HIGH`/`CRITICAL` policy.                                          | `tools/release/test_scan_sbom.py`, `tools/checks/test_source_checks.py`: fake tools, malformed reports, overflow, deadlines, and retained identity. |
| Socket and process frame fixtures                                    | Global text replacement deletes nested `version` fields while extracting a payload.                                          | Accept parsed top-level envelope removal and structured payload comparison. Original receipt hex strings and digests remain exact.                                                                                                                             | `crates/kapsel-daemon/src/server/linux_tests.rs`, `crates/kapsel-daemon/tests/linux_process.rs`: nested-version preservation.                       |
| Inspection and process receipt fixtures                              | Hex decoding silently ignores an odd trailing nibble.                                                                        | Accept an explicit empty-remainder assertion. Malformed fixture evidence must fail, not become different bytes.                                                                                                                                                | `tests/e2e_inspection_command.rs`; Linux process receipt retrieval.                                                                                 |
| `src/gateway/receiver_recovery_tests.rs`                             | The fixture retries every initial error.                                                                                     | Accept only the known post-marker `preflight-race` apply conflict. Unexpected setup, storage, or target failures stop the fixture. Product recovery remains unchanged.                                                                                         | `receiver_recovery_scenarios`: independent receiver counts and retained facts across all named cases.                                               |
| `examples/fresh_session_caller.py`                                   | Bridge output is capped after allocation; reference metadata and content are read through different path opens.              | Accept bounded exchange capture and descriptor-validated reference reads. Preserve exclusive creation, fsync, read-first same-ID selection, and `exchange_uncertain`; never add a retry.                                                                       | `examples/test_fresh_session_caller.py`: actual subprocess and filesystem fixtures.                                                                 |
| Qualification runner process owner                                   | Ordinary tool capture lacks the bounded lifecycle already used for model output.                                             | Accept reuse of that process owner for simultaneous bounded pipes, input, deadlines, and cleanup. Preserve caller retirement and independent product-evidence reads.                                                                                           | `tests/qualification/test_kind_agent_action_exercise.py`: offline actual subprocess fixtures.                                                       |
| `tests/qualification/caller_custody_probe.py`                        | An absent executable passes a negative writability test.                                                                     | Accept positive existence, regular-file, root ownership, executable access, and protected-parent checks. Missing or caller-replaceable binaries cannot establish custody.                                                                                      | `tests/qualification/test_caller_custody_probe.py`; the packaged journey runs the probe as the confined caller.                                     |
| `tests/qualification/run_storage_enospc.py`                          | Untracked source capture follows paths and allocates without file or aggregate bounds.                                       | Accept descriptor-bound regular-file capture and archive retained bytes rather than rereading paths. Compare retained content and modes after qualification; a mode-only change is a source change.                                                            | `tests/qualification/test_storage_enospc.py`: dirty/untracked identity, hostile file types, growth, bounds, and archive fidelity.                   |
| Source privacy and Markdown checkers                                 | Selected files are read wholly before type or size checks.                                                                   | Accept bounded regular-file reads. Preserve secret non-disclosure, relative paths, Markdown line numbers, and link/anchor semantics.                                                                                                                           | `tools/checks/test_source_checks.py`, `tools/checks/test_check_markdown_links.py`.                                                                  |
| Release assembly and standalone verification                         | Several tool calls have no local deadline or capture limit; a Docker client timeout does not retire its build container.     | Accept bounded capture and deadlines. Establish a container ID before starting the producer, explicitly remove that ID, and retain failed-build targets when cleanup is unconfirmed. Preserve standalone verifier independence and published archive mappings. | `tools/release/test_assemble_artifact.py`, `tools/release/test_verify_artifact.py`: capture, retirement control flow, and retained service stderr.  |
| `src/gateway/receipt/mod.rs`                                         | A module-wide naming allowance suppresses unrelated future structs.                                                          | Narrow `struct_field_names` to public `InspectionLimits`; explain the instance-level `non_claims` API. Do not rename public fields or change bytes.                                                                                                            | Receipt tests and all-target Clippy.                                                                                                                |
| Gateway, record I/O, and live evidence comments                      | Two mutable-borrow allowances and live-print exceptions lack local reasons; the record header incorrectly says columns only. | Explain the exclusive async borrow and qualification output. Describe record projection accurately without moving lifecycle validation or changing transitions.                                                                                                | Existing owner tests and Clippy; these corrections do not change execution.                                                                         |

The earlier receipt-publication spacing, snapshot output-write command label, and command-owned
inspection target rendering corrections are retained. None changes signed receipt or grant bytes.

## Retained boundaries and deferred refactors

### Journal worker-token parity

Kubernetes transition methods rely on their private gateway callers to hold the worker lease; Git
writes also receive and check the token. A possible deeper interface changes `transition(facts)` to
`transition(&worker, facts)` at the Kubernetes journal owner.

Defer that structural change. Current callers acquire the lease across reload, receiver I/O, and
completion, and deterministic laws exercise exclusion and no resend. No current unleased mutation
was found. Signature changes would cross many durable transitions and their independent models.
Before adoption, test wrong-owner or absent-token refusal, preserve lease-free terminal reads, and
run the journal, simulation, recovery, and Linux retirement gates. Do not equate the two effect
implementations' transition rules.

### Record projection ownership

The atomic-record module maps columns into lifecycle-owned snapshots and receipt rows as well as
performing conditional I/O. Correct its header; retain that concrete boundary for now.

A possible future interface makes one journal-owned `decode(record)` own the snapshot/receipt
projection, while atomic I/O returns a complete bounded record. Alternatively, a concrete mapping
could reduce repeated field knowledge. Either changes schema, projection, and simulation consumers.
First demonstrate a real field addition with less change amplification, then prove complete-record
binding, hostile-row rejection, original evidence, and unchanged inert columns. A table or generic
row framework is not justified merely by repeated field names.

### Grant and receipt framing

Keep the separate grant/trust and receipt parsers and purpose-selected signing paths. They share
record mechanics, but have different public error mappings, field ceilings, formats, and trust
owners. Current vectors and hostile-input tests do not show drift.

A future shared `Records(bytes, magic).take(tag)` or signed-preimage primitive would need a real
maintenance benefit that outweighs exposing a new cross-crate interface. Validate exact bytes,
malformed-input error classes, cross-purpose rejection, and independent vectors before moving it.
Canonical fuzz round trips are not an independent cryptographic oracle. The duplicate Git-purpose
seed name remains explicit in the target-independent corpus table; equal bytes are not additional
coverage and do not require a conditional seed-building API.

### Explorer and receiver fixtures

Keep independent expected facts separate from production classifiers. The initial explorer's
diagnostic strings and sole initial-state variant were test-local vocabulary, not evidence of a
wrong replay. During integration, parallel simulation work retired that separate exploration module
in favor of the shared model in `src/kernel_simulation_tests.rs`. The initial coverage and exception
ledger retain the reviewed historical paths. Future vocabulary changes must preserve persisted
replay names, minimization, and independent result rules.

A test-local receiver model or shared bounded HTTP request reader could reduce actual repeated
fixture knowledge. Defer extraction until one retry fixture and one process fixture demonstrate a
smaller interface without hiding receiver counts, hostile inputs, deadlines, or object replacement.
Do not turn every comparison into a helper or combine ordered recovery traces just to reduce length.

### Process and startup custody

Reuse concrete process ownership within the qualification runner. Do not create a universal runner
shared by the installed caller, release verifier, and source tools: their packaging, I/O,
diagnostics, and custody requirements differ. The caller and artifact verifier must remain
standalone.

Startup already retains verified directory and lease descriptors through publication. A named
custody aggregate could help a second real consumer, but adding one now would duplicate rather than
hide knowledge. Preserve original descriptors, response abandonment versus physical retirement, and
meaningful drop order. Local client exit does not establish retirement of a remote model.

## Rejected or narrowed review claims

- Pyright is not Linux-only: the deterministic gate checks both Linux and Darwin. Keep both checks.
- The fuzz crate is excluded from workspace execution, not from validation: the gate explicitly
  checks its manifest, Clippy, metadata, and corpus tests. Document that route rather than change
  workspace membership.
- Rejected inspection output is not required to contain the successful statement's target fields.
  Keep its established bytes. Adding explicit nulls would be a separate machine-schema decision, not
  a reason to split the classifier renderer or remove its length allowance.
- The custom `disallowed_macros` policy duplicates direct print/debug lints. Remove the inactive
  duplicate configuration; retain standard production denies and narrow CLI/evidence allowances.
- The census's conservative handling of unsupported `cfg(any(...))` forms is not a current counting
  defect. Current source has no exclusively assurance-gated `any` form; the mixed runtime gate must
  remain product source. Extend classification only when a new form needs emitted-range review.
- Numeric lint thresholds are review prompts, not universal size or parameter quotas. Preserve
  exhaustive hostile-row decoders, explicit fact groups, and ordered custody traces when splitting
  would hide the owning guarantee.

## Lint exception decisions

Every initial local allow/expect attribute, workspace allowance, Ruff/ShellCheck exception, and the
four test-wide Clippy settings was assessed. The individual-site ledger below records the final
scope. A reason states an intent; the containing code and its tests determine whether it remains
valid.

Retain controlled test failure assertions, schema-constant lookup assertions, public domain names,
cohesive ordered codecs and decoders, async exclusive borrows, and physical-resource drop order.
These are not interchangeable with suppressing operating failures in production. Direct
`print_stdout`, `print_stderr`, and `dbg_macro` denies still own production diagnostics; test-wide
print/debug allowances do not permit caller-controlled diagnostics in product code.

### Individual exception ledger

The 84 identifiers below refer to the initial reviewed snapshot, not current line numbers. Each row
records one suppression site, which can contain several lints. Parallel journal changes are not
silently included in the quality patch; owner-deferred cleanup is stated explicitly.

| Initial site                                                    | Lint or check                                    | Decision       | Rationale                                                                                                                                                                                                                                |
| --------------------------------------------------------------- | ------------------------------------------------ | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Cargo.toml:114`                                                | `module_name_repetitions`                        | Retain         | This lint is primarily naming/style. Current conventions prefer precise domain names over mechanical shortening; no concrete invariant loss found.                                                                                       |
| `Cargo.toml:116`                                                | `must_use_candidate`                             | Retain         | Rust already enforces `Result` must-use. No concrete current site showed a lost recovery/authority result because of this allow.                                                                                                         |
| `Cargo.toml:119`                                                | `cargo_common_metadata`                          | Retain         | Root package has public metadata; workspace helper crates may be unpublished/internal. No fix-worthy evidence in assigned scope.                                                                                                         |
| `Cargo.toml:121`                                                | `multiple_crate_versions`                        | Retain         | Version duplication is usually transitive/ecosystem-driven. No direct contract or recovery consequence identified from the suppression itself.                                                                                           |
| `Cargo.toml:122`                                                | `missing_const_for_fn`                           | Retain         | Const-qualification does not own current safety/recovery invariants; blanket allow avoids churn.                                                                                                                                         |
| `Cargo.toml:124`                                                | `missing_enforced_import_renames`                | Retain         | No enforced rename policy is evident in `clippy.toml`; no current defect found.                                                                                                                                                          |
| `Cargo.toml:125`                                                | `redundant_pub_crate`                            | Retain         | Conventions prefer narrow visibility, but this lint is cosmetic where visibility is already non-public. No concrete issue found.                                                                                                         |
| `Cargo.toml:126`                                                | `doc_markdown`                                   | Retain         | Public docs are still guarded by `missing_docs` and rustdoc link lints. No assigned evidence showed a misleading contract due to this allow.                                                                                             |
| `Cargo.toml:127`                                                | `disallowed_macros`                              | Remove         | Remove the inactive custom-macro allowance and duplicate policy; standard print/debug denies remain.                                                                                                                                     |
| `crates/kapsel-daemon/src/bin/kapsel-service-client.rs:270`     | `unwrap_used`                                    | Retain         | The unwraps are fixture assertions over local JSON/hex cases; failure should stop the test immediately. Scope is limited to `#[cfg(test)] mod tests`.                                                                                    |
| `crates/kapsel-daemon/src/bin/kapsel-service-mcp.rs:2`          | `needless_pass_by_value`, `option_if_let_else`   | Retain         | The file is an adapter around owned JSON messages. Suppression is style-only and does not relax authority/recovery semantics. Prior full review already found a separate response-shape hardening issue, not caused by this suppression. |
| `crates/kapsel-daemon/src/diagnostics.rs:83`                    | `unwrap_used`, `panic`                           | Retain         | Fixture failures should be immediate. The production `ReadFailures` path remains non-panicking and bounded.                                                                                                                              |
| `crates/kapsel-daemon/src/server/linux_tests.rs:2`              | `panic`, `unwrap_used`                           | Retain         | Controlled socket/process fixtures intentionally fail fast. Suppression is confined to tests and preserves black-box contract assertions.                                                                                                |
| `crates/kapsel-daemon/src/server/linux_tests.rs:214`            | `significant_drop_tightening`                    | Retain         | Tightening drop order would obscure or risk the physical-lifetime invariant being tested: the finite server must wait for the admitted execution before cleanup.                                                                         |
| `crates/kapsel-daemon/src/server/linux_tests.rs:1002`           | `too_many_lines`                                 | Retain         | Keeping the matrix in one table preserves hostile-row sequencing and makes “no application effect” counts meaningful across the whole set. Splitting would reduce lint noise but weaken reviewability of the invariant.                  |
| `crates/kapsel-daemon/src/server/runtime.rs:431`                | `significant_drop_tightening`                    | Retain         | The comment and code establish the non-local invariant: a moved lease must span failed-acquisition/read/probe decision so a completed admission cannot be hidden. Do not cosmetically shorten this lifetime.                             |
| `crates/kapsel-daemon/src/server/runtime/jobs.rs:108`           | `unwrap_used`                                    | Retain         | The unwraps assert controlled semaphores/channels and should fail immediately if the fixture contract breaks. Production `Jobs::drain` recovery semantics are not relaxed.                                                               |
| `crates/kapsel-daemon/src/server/runtime/retirement_tests.rs:2` | `unwrap_used`                                    | Retain         | Barrier setup and synchronization failures should stop tests immediately; no caller-controlled facts are unwrapped in production.                                                                                                        |
| `crates/kapsel-daemon/src/server/runtime/retirement_tests.rs:6` | `significant_drop_tightening`                    | Retain         | Physical resource drop order is the tested behavior. Tightening would be cosmetic at best and potentially misleading.                                                                                                                    |
| `crates/kapsel-daemon/src/startup.rs:336`                       | `unwrap_used`                                    | Retain         | Startup tests create exact private roots and files; fixture failure must be immediate. Production startup still returns typed I/O errors.                                                                                                |
| `crates/kapsel-daemon/src/startup.rs:956`                       | `used_underscore_binding`                        | Retain         | The field name communicates retention-for-drop in production, while tests intentionally inspect it to prove retained-descriptor identity. Suppression is local to the test submodule.                                                    |
| `crates/kapsel-daemon/src/startup/publication.rs:209`           | `panic`                                          | Retain         | The panic is the controlled-test failure mechanism for the invariant “contention precedes candidate consumption.” It is test-only and should remain loud.                                                                                |
| `crates/kapsel-daemon/tests/command_interface.rs:2`             | `unwrap_used`                                    | Retain         | Unwraps are over controlled command outputs/UTF-8 in tests; failures should stop the test.                                                                                                                                               |
| `crates/kapsel-daemon/tests/linux_process.rs:4`                 | `panic`, `unwrap_used`                           | Retain         | Process fixtures rely on fail-fast setup/teardown assertions. This does not weaken production recovery semantics.                                                                                                                        |
| `crates/kapsel-daemon/tests/linux_process.rs:914`               | `too_many_lines`                                 | Retain         | The long test preserves admission loss, completion loss, reconnection, and single receiver mutation in one ordered transcript. Splitting risks losing causal evidence.                                                                   |
| `crates/kapsel-daemon/tests/linux_process.rs:1315`              | `too_many_lines`                                 | Retain         | The recovery/export/no-replay proof depends on one ordered physical-process trace. Keeping it together preserves the invariant.                                                                                                          |
| `crates/kapsel-daemon/tests/service_mcp.rs:3`                   | `unwrap_used`, `needless_pass_by_value`, `panic` | Retain         | Test helper failures should stop the test, and owned `Value` fixtures match JSON-RPC exchange construction. Scope is integration-test-only.                                                                                              |
| `src/application/mod.rs:315`                                    | `enum_variant_names`                             | Retain         | Variants preserve distinct error classes (`InvalidOperatorConfiguration`, `InvalidGrantProvisioning`, `InvalidJournalPath`). Renaming just to satisfy the lint would weaken clarity.                                                     |
| `src/application/operator_tests.rs:3`                           | `unwrap_used`                                    | Retain         | The unwraps are in tests that should fail immediately on fixture/setup errors. Scope is limited to the test module.                                                                                                                      |
| `src/application/service.rs:779`                                | `needless_pass_by_value`                         | Retain         | The value-taking signature fits `map_err(map_gateway_error)` call sites and preserves straightforward error classification.                                                                                                              |
| `src/application/service/document.rs:196`                       | `unwrap_used`                                    | Retain         | Controlled malformed-parser regression; `unwrap()` fails the test if the expected error is absent.                                                                                                                                       |
| `src/command/mod.rs:527`                                        | `too_many_lines`                                 | Retain         | Keep the ordered classifier renderer. Rejected output has no successful statement; adding null target fields would change its established schema.                                                                                        |
| `src/gateway/git.rs:652`                                        | `needless_pass_by_ref_mut`                       | Retain         | Reason is concrete and matches the function: `advance(&mut Journal, ...)` uses exclusive borrowing to keep the future `Send` without requiring SQLite to be `Sync`. Preserve.                                                            |
| `src/gateway/git.rs:1253`                                       | `too_many_lines`                                 | Retain         | Cohesive matrix; splitting would hide hostile/recovery sequencing. Preserve.                                                                                                                                                             |
| `src/gateway/git.rs:1399`                                       | `too_many_lines`                                 | Retain         | The long test keeps drop/removal order and service restart evidence visible. Preserve.                                                                                                                                                   |
| `src/gateway/journal/git.rs:359`                                | `too_many_lines`                                 | Retain         | Reason matches one snapshot decoder. No suppression-specific issue found; broader journal ownership is excluded from change proposals except owner-flagged.                                                                              |
| `src/gateway/journal/mod.rs:100`                                | `dead_code`                                      | Retain         | Validated authorization provenance remains part of each authenticated phase even when no current projection reads it.                                                                                                                    |
| `src/gateway/journal/mod.rs:362`                                | `too_many_lines`                                 | Retain         | Keep the exhaustive hostile-row state matrix visible.                                                                                                                                                                                    |
| `src/gateway/journal/mod.rs:569`                                | `too_many_arguments`                             | Retain         | Preserve the explicit persisted fact group at the private validator.                                                                                                                                                                     |
| `src/gateway/journal/records.rs:25`                             | `expect_used`                                    | Retain         | Column names are fixed internal code, not caller input.                                                                                                                                                                                  |
| `src/gateway/journal/records.rs:241`                            | `unused_self`                                    | Retain         | The instance carries decoder defect controls in test builds.                                                                                                                                                                             |
| `src/gateway/journal/records.rs:253`                            | `unused_self`                                    | Owner-deferred | Virtual reads moved into `read_table`; the old delegating `read` allowance is redundant and remains with the atomic-I/O owner.                                                                                                           |
| `src/gateway/journal/records.rs:319`                            | `unused_self`                                    | Retain         | The instance carries receipt-projection defect controls in test builds.                                                                                                                                                                  |
| `src/gateway/mod.rs:181`                                        | `struct_field_names`                             | Retain         | Preserve public contract terminology with a struct-local allowance.                                                                                                                                                                      |
| `src/gateway/mod.rs:985`                                        | `needless_pass_by_ref_mut`                       | Explain        | Record the exclusive async borrow and SQLite Send-without-Sync requirement; preserve lease ownership.                                                                                                                                    |
| `src/gateway/mod.rs:1006`                                       | `needless_pass_by_ref_mut`                       | Explain        | Record the exclusive async borrow and SQLite Send-without-Sync requirement; preserve lease ownership.                                                                                                                                    |
| `src/gateway/receipt/mod.rs:6`                                  | `struct_field_names`                             | Narrow         | Move the module-wide exception to public `InspectionLimits`; retain public field names.                                                                                                                                                  |
| `src/gateway/receipt/mod.rs:217`                                | `unused_self`                                    | Explain        | Retain the instance-level `non_claims` API and explain its fixed value.                                                                                                                                                                  |
| `src/gateway/receipt/mod.rs:222`                                | `too_many_lines`                                 | Retain         | Keep fixed field order visible in one codec.                                                                                                                                                                                             |
| `src/gateway/receiver_recovery_tests.rs:2`                      | `unwrap_used`, `panic`, `print_stdout`           | Retain         | Controlled fixture failures stop immediately; bounded output records independent receiver evidence. The separate setup-retry defect is corrected above.                                                                                  |
| `src/gateway/receiver_recovery_tests.rs:213`                    | `too_many_lines`                                 | Retain         | Keep the independent receiver and journal assertions together.                                                                                                                                                                           |
| `src/gateway/tests/legacy_service.rs:7`                         | `too_many_lines`                                 | Retain         | Keep the ordered recovery and authority trace together.                                                                                                                                                                                  |
| `src/gateway/tests/mod.rs:27`                                   | `panic`                                          | Retain         | Controlled fixture failure, not a production path.                                                                                                                                                                                       |
| `src/gateway/tests/mod.rs:153`                                  | `unused_async_trait_impl`                        | Retain         | Test fakes implement the asynchronous boundary without artificial waits.                                                                                                                                                                 |
| `src/gateway/tests/mod.rs:230`                                  | `unused_async_trait_impl`                        | Retain         | Test fakes implement the asynchronous boundary without artificial waits.                                                                                                                                                                 |
| `src/gateway/tests/mod.rs:287`                                  | `unused_async_trait_impl`                        | Retain         | Test fakes implement the asynchronous boundary without artificial waits.                                                                                                                                                                 |
| `src/gateway/tests/mod.rs:379`                                  | `panic`                                          | Retain         | Controlled fixture failure, not a production path.                                                                                                                                                                                       |
| `src/gateway/tests/receipt.rs:271`                              | `too_many_lines`, `panic`                        | Retain         | Keep the ordered evidence-custody trace and immediate fixture failures.                                                                                                                                                                  |
| `src/gateway/tests/receipt.rs:449`                              | `too_many_lines`                                 | Retain         | Keep the ordered recovery-evidence trace together.                                                                                                                                                                                       |
| `src/gateway/tests/storage.rs:265`                              | `too_many_lines`                                 | Retain         | Preserve physical resource ownership and cleanup order in one trace.                                                                                                                                                                     |
| `src/kernel_simulation_tests.rs:241`                            | `unused_async_trait_impl`                        | Retain         | Preserve the independent model's implementation of the asynchronous boundary.                                                                                                                                                            |
| `src/kind_tests.rs:752`                                         | `print_stdout`                                   | Explain        | State the qualification purpose of bounded live receiver evidence.                                                                                                                                                                       |
| `src/kind_tests.rs:1055`                                        | `print_stdout`                                   | Explain        | State the qualification purpose of bounded rollout diagnostics.                                                                                                                                                                          |
| `src/kind_tests.rs:1247`                                        | `too_many_lines`, `print_stdout`                 | Retain         | Preserve the ordered live-evidence trace and bounded diagnostics.                                                                                                                                                                        |
| `src/lifecycle_exploration_tests.rs:205`                        | `struct_excessive_bools`                         | Retain         | Keep independent expected facts explicit rather than deriving them from production classifiers.                                                                                                                                          |
| `src/lifecycle_exploration_tests.rs:248`                        | `unused_async_trait_impl`                        | Retain         | Preserve the independent model's implementation of the asynchronous boundary.                                                                                                                                                            |
| `src/lifecycle_exploration_tests.rs:661`                        | `too_many_lines`                                 | Retain         | Keep hostile-row sequencing and recovery facts visible.                                                                                                                                                                                  |
| `src/lifecycle_exploration_tests.rs:2038`                       | `too_many_lines`                                 | Retain         | Keep the ordered model scenario together.                                                                                                                                                                                                |
| `src/lifecycle_exploration_tests.rs:2719`                       | `panic`                                          | Retain         | Controlled fixture failure preserves evidence custody.                                                                                                                                                                                   |
| `src/lifecycle_exploration_tests.rs:2723`                       | `too_many_lines`                                 | Retain         | Keep the ordered model scenario together.                                                                                                                                                                                                |
| `src/recovery_policy_tests.rs:316`                              | `too_many_lines`                                 | Retain         | Keep the recovery matrix visible.                                                                                                                                                                                                        |
| `tests/application_retry.rs:3`                                  | `unwrap_used`, `panic`                           | Retain         | Fixture failures and unexpected early completion stop immediately; retain physical cleanup order and request counts.                                                                                                                     |
| `tests/application_retry/service_selection.rs:13`               | `too_many_lines`                                 | Retain         | Keep hostile-row sequencing and worker/read-application distinctions visible.                                                                                                                                                            |
| `tests/application_retry/service_selection.rs:206`              | `too_many_lines`                                 | Retain         | Keep the two bounded traces and retained-row comparisons together.                                                                                                                                                                       |
| `tests/application_retry/service_selection.rs:558`              | `too_many_lines`                                 | Retain         | Keep exclusive future borrowing, physical drop order, no resend, and frozen-history checks together.                                                                                                                                     |
| `tests/e2e_inspection_command.rs:3`                             | `unwrap_used`                                    | Retain         | Fixture decode/process failures stop the test; strict hex decoding is corrected separately.                                                                                                                                              |
| `tests/e2e_provisioning_command.rs:3`                           | `unwrap_used`                                    | Retain         | Invalid fixture state stops the test immediately.                                                                                                                                                                                        |
| `tests/e2e_service_configuration.rs:2`                          | `unwrap_used`                                    | Retain         | The test owns its temporary files and commands; setup failures stop immediately.                                                                                                                                                         |
| `tests/fixtures/recovery-policy-webhook/webhook.py:16`          | `N802`                                           | Retain         | The standard-library HTTP dispatch requires this method name.                                                                                                                                                                            |
| `tests/service_application_contract.rs:2`                       | `unwrap_used`                                    | Retain         | Controlled fixture failures stop immediately; production handling is unchanged.                                                                                                                                                          |
| `tools/checks/check-rust-width.sh:2`                            | `SC2016`                                         | Retain         | Single quotes preserve literal shell text for the checker.                                                                                                                                                                               |
| `tools/dev/dev-tools.sh:2`                                      | `SC2034`                                         | Retain         | The CI, format, and setup scripts consume these sourced variables.                                                                                                                                                                       |
| `xtask/src/main.rs:12`                                          | `print_stderr`                                   | Retain         | The CLI emits a bounded error on stderr through a function-local allowance.                                                                                                                                                              |
| `xtask/src/main.rs:59`                                          | `print_stdout`                                   | Retain         | CLI help belongs on stdout through a function-local allowance.                                                                                                                                                                           |

The four test-wide settings in `clippy.toml` retain unwrap, expect, panic, and print allowances for
recognized tests. Fixture/setup failures must remain loud. These settings do not relax production
diagnostics, operating-error handling, or the local helper ownership recorded above.

### New local exceptions

The MCP regression adds two function-local `too_many_lines` exceptions:

- `status_response_accepts_only_canonical_execution_guidance` keeps the complete canonical tuple
  matrix next to the exact unchanged-value assertions.
- `malformed_status_guidance_and_extra_fields_are_response_errors` keeps hostile shape variants next
  to their common opaque-error assertions.

Both are in `crates/kapsel-daemon/tests/service_mcp.rs`, carry local reasons, and affect only those
regression functions. They do not suppress the lint for other tests or product code.

## Coverage and validation

Each primary path was read completely in its owning domain. The initial read-range inventory was
checked against successful reads, not inferred from a report summary. Changed and new files received
focused refresh or implementation review; configuration and immutable SQL additions are listed
explicitly. Public documentation, headers, semantic spacing, names, tests, and lint exceptions were
part of those reviews. A clear disposition does not claim the absence of every possible defect.

The owning evidence gate remains [Build and test](build.md), with platform and artifact lanes in
[Qualification](qualification.md). Tests must run on the combined tree, not just individual patches.
Offline fake-tool tests do not establish a successful live Trivy scan, Docker/kind run, or published
artifact qualification. Source changes do not change v0.3.0's published bytes or claims.

The refreshed candidate at `c44760bd10d01cdc95c5ee83b494ce718be34b9a`, based on
`470bb1199fb035931b50a514da1fcfaef0b9fabe`, passed the full deterministic gate on macOS and Linux,
22 Linux real-process tests, 11 MCP tests, and all 19 fresh-session caller tests. One supplementary
Docker-group process test remained intentionally ignored. Its packaged consumer suite passed 27
tests with one skip, and a second assembly passed the maintained reproducibility check. Focused
independent review found no concrete correction needed in the refreshed gateway comments, lint
reasons, or review record.

These results establish that candidate's execution, not a published release. This record's final
status update is documentation-only. Live security scans, live receiver qualification, and
privileged native-service qualification remain separate lanes; ignored or skipped tests are not
passing evidence.

### Initial authored-source coverage

Full-read means that successful read ranges covered the complete initial file. Findings are
dispositioned in the sections above; clear means no concrete finding was reported, not a proof that
the file is defect-free. Domain names identify the technical scope of each review.

| Path                                                                     | Review domain          | Initial read                 |
| ------------------------------------------------------------------------ | ---------------------- | ---------------------------- |
| `crates/kapsel-authority/src/git.rs`                                     | authority-evidence     | Full; findings dispositioned |
| `crates/kapsel-authority/src/lib.rs`                                     | authority-evidence     | Full; findings dispositioned |
| `crates/kapsel-authority/src/record.rs`                                  | authority-evidence     | Full; findings dispositioned |
| `fuzz/examples/replay.rs`                                                | authority-evidence     | Full; no concrete finding    |
| `fuzz/examples/seed_corpus.rs`                                           | authority-evidence     | Full; no concrete finding    |
| `fuzz/fuzz_targets/inspect_git_receipt.rs`                               | authority-evidence     | Full; no concrete finding    |
| `fuzz/fuzz_targets/inspect_receipt.rs`                                   | authority-evidence     | Full; no concrete finding    |
| `fuzz/fuzz_targets/service_document.rs`                                  | authority-evidence     | Full; no concrete finding    |
| `fuzz/fuzz_targets/verify_git_grant.rs`                                  | authority-evidence     | Full; no concrete finding    |
| `fuzz/fuzz_targets/verify_kubernetes_grant.rs`                           | authority-evidence     | Full; no concrete finding    |
| `fuzz/smoke.sh`                                                          | authority-evidence     | Full; no concrete finding    |
| `fuzz/src/fixtures.rs`                                                   | authority-evidence     | Full; findings dispositioned |
| `fuzz/src/lib.rs`                                                        | authority-evidence     | Full; findings dispositioned |
| `fuzz/tests/corpus.rs`                                                   | authority-evidence     | Full; findings dispositioned |
| `src/gateway/authorization.rs`                                           | authority-evidence     | Full; no concrete finding    |
| `src/gateway/receipt/git.rs`                                             | authority-evidence     | Full; findings dispositioned |
| `src/gateway/receipt/mod.rs`                                             | authority-evidence     | Full; findings dispositioned |
| `src/gateway/receipt/publication.rs`                                     | authority-evidence     | Full; no concrete finding    |
| `src/gateway/demo_control.rs`                                            | journal-kernel         | Full; no concrete finding    |
| `src/gateway/journal/capacity.rs`                                        | journal-kernel         | Full; no concrete finding    |
| `src/gateway/journal/git.rs`                                             | journal-kernel         | Full; no concrete finding    |
| `src/gateway/journal/mod.rs`                                             | journal-kernel         | Full; findings dispositioned |
| `src/gateway/journal/opening.rs`                                         | journal-kernel         | Full; no concrete finding    |
| `src/gateway/journal/records.rs`                                         | journal-kernel         | Full; findings dispositioned |
| `src/gateway/journal/schema.rs`                                          | journal-kernel         | Full; no concrete finding    |
| `src/gateway/mod.rs`                                                     | journal-kernel         | Full; findings dispositioned |
| `src/kernel_simulation_tests.rs`                                         | journal-kernel         | Full; no concrete finding    |
| `src/gateway/git.rs`                                                     | receivers              | Full; no concrete finding    |
| `src/gateway/git/exploration.rs`                                         | receivers              | Full; no concrete finding    |
| `src/gateway/kubernetes/adapter.rs`                                      | receivers              | Full; no concrete finding    |
| `src/gateway/kubernetes/facts.rs`                                        | receivers              | Full; no concrete finding    |
| `src/gateway/kubernetes/mod.rs`                                          | receivers              | Full; no concrete finding    |
| `src/gateway/receiver_recovery_tests.rs`                                 | receivers              | Full; findings dispositioned |
| `src/gateway/receiver_recovery_tests/receiver.rs`                        | receivers              | Full; no concrete finding    |
| `src/kind_tests.rs`                                                      | receivers              | Full; findings dispositioned |
| `src/recovery_policy_tests.rs`                                           | receivers              | Full; no concrete finding    |
| `src/application/mod.rs`                                                 | application-command    | Full; no concrete finding    |
| `src/application/operator_tests.rs`                                      | application-command    | Full; no concrete finding    |
| `src/application/service.rs`                                             | application-command    | Full; no concrete finding    |
| `src/application/service/disposition.rs`                                 | application-command    | Full; no concrete finding    |
| `src/application/service/document.rs`                                    | application-command    | Full; no concrete finding    |
| `src/command/mod.rs`                                                     | application-command    | Full; findings dispositioned |
| `src/command/service.rs`                                                 | application-command    | Full; no concrete finding    |
| `src/lib.rs`                                                             | application-command    | Full; no concrete finding    |
| `src/main.rs`                                                            | application-command    | Full; no concrete finding    |
| `crates/kapsel-daemon/src/bin/kapsel-service-client.rs`                  | daemon-runtime         | Full; no concrete finding    |
| `crates/kapsel-daemon/src/bin/kapsel-service-mcp.rs`                     | daemon-runtime         | Full; findings dispositioned |
| `crates/kapsel-daemon/src/client_transport.rs`                           | daemon-runtime         | Full; findings dispositioned |
| `crates/kapsel-daemon/src/diagnostics.rs`                                | daemon-runtime         | Full; no concrete finding    |
| `crates/kapsel-daemon/src/lib.rs`                                        | daemon-runtime         | Full; no concrete finding    |
| `crates/kapsel-daemon/src/main.rs`                                       | daemon-runtime         | Full; no concrete finding    |
| `crates/kapsel-daemon/src/server.rs`                                     | daemon-runtime         | Full; no concrete finding    |
| `crates/kapsel-daemon/src/server/harness.rs`                             | daemon-runtime         | Full; no concrete finding    |
| `crates/kapsel-daemon/src/server/protocol.rs`                            | daemon-runtime         | Full; findings dispositioned |
| `crates/kapsel-daemon/src/server/runtime.rs`                             | daemon-runtime         | Full; no concrete finding    |
| `crates/kapsel-daemon/src/server/runtime/jobs.rs`                        | daemon-runtime         | Full; no concrete finding    |
| `crates/kapsel-daemon/src/startup.rs`                                    | daemon-runtime         | Full; no concrete finding    |
| `crates/kapsel-daemon/src/startup/publication.rs`                        | daemon-runtime         | Full; no concrete finding    |
| `src/gateway/tests/capacity_layout.rs`                                   | core-tests             | Full; no concrete finding    |
| `src/gateway/tests/dispatch.rs`                                          | core-tests             | Full; no concrete finding    |
| `src/gateway/tests/legacy_service.rs`                                    | core-tests             | Full; no concrete finding    |
| `src/gateway/tests/lifecycle.rs`                                         | core-tests             | Full; no concrete finding    |
| `src/gateway/tests/migration.rs`                                         | core-tests             | Full; no concrete finding    |
| `src/gateway/tests/mod.rs`                                               | core-tests             | Full; no concrete finding    |
| `src/gateway/tests/receipt.rs`                                           | core-tests             | Full; no concrete finding    |
| `src/gateway/tests/recovery.rs`                                          | core-tests             | Full; no concrete finding    |
| `src/gateway/tests/snapshot.rs`                                          | core-tests             | Full; no concrete finding    |
| `src/gateway/tests/storage.rs`                                           | core-tests             | Full; no concrete finding    |
| `src/gateway/tests/v011_upgrade.rs`                                      | core-tests             | Full; no concrete finding    |
| `src/gateway/tests/validation.rs`                                        | core-tests             | Full; no concrete finding    |
| `src/lifecycle_exploration_tests.rs`                                     | core-tests             | Full; findings dispositioned |
| `crates/kapsel-daemon/src/server/linux_tests.rs`                         | integration-tests      | Full; findings dispositioned |
| `crates/kapsel-daemon/src/server/runtime/lifecycle_exploration_tests.rs` | integration-tests      | Full; no concrete finding    |
| `crates/kapsel-daemon/src/server/runtime/retirement_tests.rs`            | integration-tests      | Full; no concrete finding    |
| `crates/kapsel-daemon/tests/command_interface.rs`                        | integration-tests      | Full; no concrete finding    |
| `crates/kapsel-daemon/tests/install_assets.rs`                           | integration-tests      | Full; no concrete finding    |
| `crates/kapsel-daemon/tests/linux_process.rs`                            | integration-tests      | Full; findings dispositioned |
| `crates/kapsel-daemon/tests/linux_process/cold_publication.rs`           | integration-tests      | Full; no concrete finding    |
| `crates/kapsel-daemon/tests/linux_process/disposition.rs`                | integration-tests      | Full; no concrete finding    |
| `crates/kapsel-daemon/tests/service_mcp.rs`                              | integration-tests      | Full; no concrete finding    |
| `tests/application_retry.rs`                                             | integration-tests      | Full; findings dispositioned |
| `tests/application_retry/service_selection.rs`                           | integration-tests      | Full; findings dispositioned |
| `tests/e2e_inspection_command.rs`                                        | integration-tests      | Full; findings dispositioned |
| `tests/e2e_provisioning_command.rs`                                      | integration-tests      | Full; no concrete finding    |
| `tests/e2e_service_configuration.rs`                                     | integration-tests      | Full; no concrete finding    |
| `tests/e2e_version_command.rs`                                           | integration-tests      | Full; no concrete finding    |
| `tests/service_application_contract.rs`                                  | integration-tests      | Full; no concrete finding    |
| `tests/service_application_contract/disposition.rs`                      | integration-tests      | Full; no concrete finding    |
| `tests/service_application_contract/git.rs`                              | integration-tests      | Full; no concrete finding    |
| `tests/service_application_contract/storage.rs`                          | integration-tests      | Full; no concrete finding    |
| `examples/fresh_session_caller.py`                                       | qualification-examples | Full; findings dispositioned |
| `examples/mcp_bridge_fixture.py`                                         | qualification-examples | Full; no concrete finding    |
| `examples/test_fresh_session_caller.py`                                  | qualification-examples | Full; no concrete finding    |
| `tests/fixtures/recovery-policy-webhook/webhook.py`                      | qualification-examples | Full; no concrete finding    |
| `tests/qualification/caller_custody_probe.py`                            | qualification-examples | Full; findings dispositioned |
| `tests/qualification/git_artifact_exercise.py`                           | qualification-examples | Full; no concrete finding    |
| `tests/qualification/git_receiver_hook.py`                               | qualification-examples | Full; no concrete finding    |
| `tests/qualification/kind_agent_action_exercise.py`                      | qualification-examples | Full; no concrete finding    |
| `tests/qualification/retire_callers.py`                                  | qualification-examples | Full; no concrete finding    |
| `tests/qualification/run-kind-effect-gateway.sh`                         | qualification-examples | Full; no concrete finding    |
| `tests/qualification/run-simulation.sh`                                  | qualification-examples | Full; no concrete finding    |
| `tests/qualification/run_git_artifact.py`                                | qualification-examples | Full; no concrete finding    |
| `tests/qualification/run_git_service.py`                                 | qualification-examples | Full; no concrete finding    |
| `tests/qualification/run_kind_agent_action_workflow.py`                  | qualification-examples | Full; findings dispositioned |
| `tests/qualification/run_storage_enospc.py`                              | qualification-examples | Full; findings dispositioned |
| `tests/qualification/snapshot_receipt.py`                                | qualification-examples | Full; no concrete finding    |
| `tests/qualification/submit_without_ack.py`                              | qualification-examples | Full; no concrete finding    |
| `tests/qualification/test_git_artifact.py`                               | qualification-examples | Full; no concrete finding    |
| `tests/qualification/test_git_service.py`                                | qualification-examples | Full; no concrete finding    |
| `tests/qualification/test_kind_agent_action_exercise.py`                 | qualification-examples | Full; no concrete finding    |
| `tests/qualification/test_storage_enospc.py`                             | qualification-examples | Full; findings dispositioned |
| `.githooks/pre-commit`                                                   | checks-dev             | Full; no concrete finding    |
| `.githooks/pre-push`                                                     | checks-dev             | Full; no concrete finding    |
| `scripts/ci.sh`                                                          | checks-dev             | Full; no concrete finding    |
| `scripts/fmt.sh`                                                         | checks-dev             | Full; no concrete finding    |
| `scripts/setup.sh`                                                       | checks-dev             | Full; no concrete finding    |
| `tools/checks/check-rust-width.sh`                                       | checks-dev             | Full; no concrete finding    |
| `tools/checks/check_markdown_links.py`                                   | checks-dev             | Full; findings dispositioned |
| `tools/checks/check_source_privacy.py`                                   | checks-dev             | Full; findings dispositioned |
| `tools/checks/scan_source_security.py`                                   | checks-dev             | Full; findings dispositioned |
| `tools/checks/test_check_markdown_links.py`                              | checks-dev             | Full; no concrete finding    |
| `tools/checks/test_source_checks.py`                                     | checks-dev             | Full; no concrete finding    |
| `tools/dev/dev-tools.sh`                                                 | checks-dev             | Full; no concrete finding    |
| `tools/dev/robustness_process_fixture.py`                                | checks-dev             | Full; no concrete finding    |
| `tools/dev/run-nightly-soak.sh`                                          | checks-dev             | Full; no concrete finding    |
| `tools/dev/run_robustness.py`                                            | checks-dev             | Full; no concrete finding    |
| `tools/dev/test_dev_tools.py`                                            | checks-dev             | Full; no concrete finding    |
| `tools/dev/test_format.py`                                               | checks-dev             | Full; no concrete finding    |
| `tools/dev/test_robustness.py`                                           | checks-dev             | Full; no concrete finding    |
| `xtask/src/main.rs`                                                      | checks-dev             | Full; findings dispositioned |
| `tools/release/assemble_artifact.py`                                     | release-verification   | Full; findings dispositioned |
| `tools/release/background_caller_fixture.py`                             | release-verification   | Full; no concrete finding    |
| `tools/release/caller_custody_exercise.py`                               | release-verification   | Full; no concrete finding    |
| `tools/release/operator_example_exercise.py`                             | release-verification   | Full; no concrete finding    |
| `tools/release/scan_sbom.py`                                             | release-verification   | Full; findings dispositioned |
| `tools/release/test_artifact.py`                                         | release-verification   | Full; no concrete finding    |
| `tools/release/test_reproducibility.py`                                  | release-verification   | Full; no concrete finding    |
| `tools/release/test_scan_sbom.py`                                        | release-verification   | Full; findings dispositioned |
| `tools/release/trivy_fixture.py`                                         | release-verification   | Full; no concrete finding    |
| `tools/release/verify_artifact.py`                                       | release-verification   | Full; findings dispositioned |
| `.cargo/config.toml`                                                     | conventions-config     | Full; no concrete finding    |
| `.github/workflows/ci.yml`                                               | conventions-config     | Full; findings dispositioned |
| `.github/workflows/release-candidate.yml`                                | conventions-config     | Full; findings dispositioned |
| `CONTRIBUTING.md`                                                        | conventions-config     | Full; findings dispositioned |
| `Cargo.toml`                                                             | conventions-config     | Full; no concrete finding    |
| `clippy.toml`                                                            | conventions-config     | Full; findings dispositioned |
| `crates/kapsel-authority/Cargo.toml`                                     | conventions-config     | Full; no concrete finding    |
| `crates/kapsel-daemon/Cargo.toml`                                        | conventions-config     | Full; no concrete finding    |
| `docs/contributing/build.md`                                             | conventions-config     | Full; findings dispositioned |
| `docs/decisions/0001-kapsel-style.md`                                    | conventions-config     | Full; no concrete finding    |
| `fuzz/Cargo.toml`                                                        | conventions-config     | Full; findings dispositioned |
| `pyrightconfig.json`                                                     | conventions-config     | Full; findings dispositioned |
| `ruff.toml`                                                              | conventions-config     | Full; no concrete finding    |
| `rust-toolchain.toml`                                                    | conventions-config     | Full; no concrete finding    |
| `rustfmt-nightly.toml`                                                   | conventions-config     | Full; no concrete finding    |
| `rustfmt.toml`                                                           | conventions-config     | Full; no concrete finding    |
| `xtask/Cargo.toml`                                                       | conventions-config     | Full; no concrete finding    |

### Additional inventory and changed-source review

| Path or scope                                                                  | Coverage and disposition                                                                                                         |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `.dockerignore`                                                                | Read completely after the initial enumeration; retain its current policy or frozen bytes.                                        |
| `.gitattributes`                                                               | Read completely after the initial enumeration; retain its current policy or frozen bytes.                                        |
| `.gitignore`                                                                   | Read completely after the initial enumeration; retain its current policy or frozen bytes.                                        |
| `.prettierrc.json`                                                             | Read completely after the initial enumeration; retain its current policy or frozen bytes.                                        |
| `codecov.yml`                                                                  | Read completely after the initial enumeration; retain its current policy or frozen bytes.                                        |
| `crates/kapsel-daemon/deploy/kapseld-rbac.yaml`                                | Read completely after the initial enumeration; retain its current policy or frozen bytes.                                        |
| `crates/kapsel-daemon/deploy/kapseld.conf`                                     | Read completely after the initial enumeration; retain its current policy or frozen bytes.                                        |
| `crates/kapsel-daemon/deploy/kapseld.service`                                  | Read completely after the initial enumeration; retain its current policy or frozen bytes.                                        |
| `tests/fixtures/recovery-policy-webhook/Dockerfile`                            | Read completely after the initial enumeration; retain its current policy or frozen bytes.                                        |
| `src/gateway/tests/format5-before-direct-create.sql`                           | Read completely after the initial enumeration; retain its current policy or frozen bytes.                                        |
| `xtask/tests/checkout_root.rs`                                                 | Added correction regression; read with its owning implementation and included in the deterministic gate.                         |
| `tests/qualification/test_caller_custody_probe.py`                             | Added correction regression; read with its owning implementation and included in the deterministic tooling gate.                 |
| `tools/release/test_assemble_artifact.py`                                      | Added correction regression; read with its owning implementation and included in the deterministic tooling gate.                 |
| `tools/release/test_verify_artifact.py`                                        | Added correction regression; read with its owning implementation and included in the deterministic tooling gate.                 |
| Changed Rust command, MCP, xtask, and receipt owners                           | Focused source refresh and independent review of the integrated correction diff.                                                 |
| Changed Python caller, scanner, qualification, release, and storage owners     | Implementation review, parent corrections, independent changed-source review, and owner-level subprocess/filesystem regressions. |
| Parallel atomic-I/O and simulator work                                         | Preserved from the integration base; not a second broad audit or an additional quality-owned structural change.                  |
| Contributor conventions, build instructions, index, changelog, and this record | Parent-owned technical and terminology review, formatting, and local links/anchors.                                              |
