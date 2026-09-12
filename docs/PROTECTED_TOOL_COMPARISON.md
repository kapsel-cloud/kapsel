# Kapsel and an equally protected typed tool

Kind: historical test-only comparison. Available at the evidence commit, not HEAD. Not a supported
alternative.

Evidence commit: `cad49d7881c19abe666215d7fd8fd76c2f1a5019`. The [accepted scope](SCOPE.md) retains
the broker and existing signed interfaces. Private approval rows and unsigned evidence are not
supported substitutes.

## Current test coverage

The typed tool is not maintained because it duplicates lifecycle policy without an adopted consumer.
[Testing](TESTING.md#receiver-recovery-evidence) maps current Kapsel receiver-recovery coverage and
its direct proof owners.

Current tests do not prove ongoing unsigned-tool equivalence. The historical comparison never
established equal multi-user isolation or hostile-input hardening, and neither signature removal nor
a supported alternative is adopted.

Use [the current build commands](BUILD.md#receiver-recovery-regressions) for HEAD. The active suite
is `gateway::receiver_recovery_tests`, with reduced selection through `KAPSEL_RECEIVER_ONLY`. The
old `protected_tool_tests` selector and `KAPSEL_COMPARISON_ONLY` variable belong only to the
historical checkout below.

Everything below records the historical experiment at the evidence commit, including its source
manifest, implementation descriptions, counts and recommendation. It is not a description of current
HEAD code or a promise to maintain equivalence.

## Requirements frozen before execution

Both arms execute one exact approved Deployment image change. Caller input is only operation ID,
namespace, Deployment, container, and immutable image. Credentials, approval, private storage and
lifecycle control belong to the operator composition, not that request. A mismatched request must be
rejected before receiver I/O. Approval freezes the original UID and opaque resourceVersion. Neither
status churn nor recreation permits refreshing that approval.

Both retain stable identity and commit an attempted record before the mutation, with worker
exclusion through I/O. Only a fresh commit permits dispatch. After ambiguity, recovery only
observes. They send the same strategic merge patch with original preconditions and an operation
annotation. Both observe immediately, then at most 29 times at one-second intervals, within 30
seconds. An available rollout or progress-deadline failure must bind the original target, image,
operation marker and requested generation. Acceptance and timeout alone establish neither result.
UNKNOWN stops dependent automation and hands retained evidence to a human. Finalized reads stay
offline.

These are equivalent authority and evidence requirements, not a requirement to reuse Kapsel's grant
wire, classifier implementation, signed receipt, or runtime. The alternative uses operator-private
SQLite approval and outcome records. It has no Kapsel imports. Both were implemented in this
repository for the experiment, so this is not independent implementation authorship or a study of
external users.

## Baseline

The Kapsel implementation is `426c17f0152f9cdb5036895c25cdcbed11b20e43`. Its canonical owner is
[Effect gateway](EFFECT_GATEWAY.md). SQLite-owned receipt completion and sequential dispatch
permission are adopted in this unreleased source, not the published beta. The alternative's
experiment-only requirements are the section above. Executable files are identified by that base
revision plus a SHA-256 manifest before each run. Neither arm uses JSON Patch or supplementary
observations.

## Reproduction

Select a detached checkout of the exact evidence commit before running the comparison. From an
owning checkout whose `master` contains that commit, use a new scratch directory outside the tree:

```sh
source_repo=$(git rev-parse --show-toplevel)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-tool-history.XXXXXX")
git init "$scratch/history"
git -C "$scratch/history" fetch --no-tags "$source_repo" master
git -C "$scratch/history" checkout --detach cad49d7881c19abe666215d7fd8fd76c2f1a5019
cd "$scratch/history"
git rev-parse HEAD
git ls-tree -r HEAD -- src/gateway/protected_tool_tests.rs \
  src/gateway/protected_tool_tests/alternative.rs src/gateway/protected_tool_tests/receiver.rs
shasum -a 256 src/gateway/protected_tool_tests.rs src/gateway/protected_tool_tests/*.rs
unset KAPSEL_COMPARISON_ONLY
cargo test --locked -p kapsel --lib gateway::protected_tool_tests -- --nocapture
```

To request the evidence commit from the public source instead of the local fetch above:

```sh
git -C "$scratch/history" fetch --no-tags https://github.com/kapsel-cloud/kapsel.git \
  cad49d7881c19abe666215d7fd8fd76c2f1a5019
```

Continue with the same detached checkout and test commands. Availability in a local checkout does
not guarantee future remote retention or identify a published release.

The HTTP service fixture supplies the same controlled receiver states to each implementation and
retains requests and state independently of either classifier. It uses kube's service seam, not a
TCP listener or Kubernetes server. Virtual time preserves the full observation schedule without
waiting thirty wall-clock seconds. Process loss uses an actual subprocess exit without destructors.
This tests SQLite reopen and crash-released locks, not power-loss durability or live admission.

The final executable input manifest, captured before the passing full deterministic run (which
includes the focused matrix), is SHA-256:

```text
src/gateway/mod.rs
d2ad7e268a5356f495e22ad53c9fdd547ba57cc917302911eeaede951d64aa78
src/gateway/protected_tool_tests.rs
b4ce7bf37b3f1c2de1b37765a913f2588393abe5f31dba5ee253e1ce199e0570
src/gateway/protected_tool_tests/alternative.rs
464665eb06ca4cd7680867fc04255a806ef228bbf5780cd260ec3c15e6670887
src/gateway/protected_tool_tests/receiver.rs
9f6474b656b61ca661d14d2937499f3389a8150c80cec5b049f8a63a7d9cd367
Cargo.lock
ca6a81aa993a795f7c1468a4226ebc7713c76f76b35883118729d8e5046e35ce
rust-toolchain.toml
2d4ec63fa017442c601706b110ad05a05a7a075714832a9eb7f0914565fa30ad
```

The reduced pre-send replay is:

```sh
KAPSEL_COMPARISON_ONLY=pre-send cargo test --locked -p kapsel --lib \
  gateway::protected_tool_tests::protected_tool_comparison -- --exact --nocapture
```

Unknown case names fail rather than reporting an empty passing comparison. Successful runs remove
only their created temporary workspaces. Failed runs preserve them for inspection. The complete
receiver log is asserted before cleanup, and stdout retains per-case counts, conclusions and frozen
byte digests. This historical manifest identifies the tested source atop the named base,
subsequently preserved in the evidence commit above. It does not identify a published release.

## Executed result

Both implementations ran. All thirteen cases produced identical complete receiver request logs and
final fixture state across arms, not merely equal result labels. Counts below include preflight and
all recovery observations. Every finalized case was reopened in a fresh process. Repeated submission
and evidence retrieval then added zero requests and preserved exact evidence bytes.

| Case                                                 | PATCH / GET | Fixture persisted patches | Both conclusions                |
| ---------------------------------------------------- | ----------- | ------------------------- | ------------------------------- |
| Healthy                                              | 1 / 2       | 1                         | SUCCEEDED                       |
| Progress deadline exceeded                           | 1 / 2       | 1                         | FAILED                          |
| Process exit after attempt commit, before send       | 0 / 31      | 0                         | UNKNOWN                         |
| Accepted mutation, lost response and process exit    | 1 / 2       | 1                         | SUCCEEDED                       |
| Caller reconnect after completion                    | 1 / 2       | 1                         | SUCCEEDED                       |
| Status-only approval churn                           | 0 / 1       | 0                         | NOT_ATTEMPTED / STALE_APPROVAL  |
| Unrelated annotation approval churn                  | 0 / 1       | 0                         | NOT_ATTEMPTED / STALE_APPROVAL  |
| Recreated UID before submission                      | 0 / 1       | 0                         | NOT_ATTEMPTED / STALE_APPROVAL  |
| Recreated UID after lost response, same image/marker | 1 / 2       | 1                         | UNKNOWN                         |
| Another writer changes image before recovery         | 1 / 31      | 1                         | UNKNOWN                         |
| Later template generation retains image/marker       | 1 / 2       | 1                         | SUCCEEDED, no causation claim   |
| Version changes between preflight and PATCH          | 1 / 31      | 0                         | UNKNOWN, not NOT_ATTEMPTED      |
| Rollout settles only after the observation budget    | 1 / 31      | 1                         | UNKNOWN, unchanged on reconnect |

Per arm the suite counts nine PATCH requests, eight persisted patches, and 139 GETs. The first
focused run completed in 2.77 seconds excluding compilation. Virtual time makes this a deterministic
schedule test, not a performance comparison. There is no frequency or latency inference from these
selected faults. The fixture's persistence and writer counters do not establish admission effects,
controller changes or real Kubernetes persistence. Those remain the separate pinned live evidence.

Every invocation actually rejects five individually changed operation fields before receiver I/O.
After insertion and on reopen, both also reject replacement UID and resourceVersion approvals under
that same handle. Original authority and retained evidence remain unchanged. Independent assertions
compare retained approval, observations and requested generation with fixture-owned facts, not just
result labels or byte stability. The healthy fixture omits `unavailableReplicas`, exercising the
ordinary zero default rather than requiring an explicit zero field.

Both also reject execution while another independently opened worker-lock handle is held. The loss
cases exit with code 73 after real SQLite commitment, without running destructors. Recovery starts a
new process and reopens its own database. This proves the two retained process-loss cuts, not all
schedules, contention fairness, commit-acknowledgement ambiguity or power loss.

The pre-send cut strands the still-approved action in both arms. The lost-response cut returns
useful availability in both without a second PATCH. A later writer retaining identity, image and
marker also supplies a matching generation in both, so neither result proves original causation. A
slow rollout becoming healthy after terminalization improves neither historical result. The scripted
caller selects the same next step in both: application-behavior inspection after SUCCEEDED, receiver
failure investigation after FAILED, human handoff with no retry after UNKNOWN, and an operator
decision about a new approval after STALE_APPROVAL. No new approval is generated by the test.

## Implementation and operator work

This was a preparation exercise, not a timed developer usability study. Engineering preparation time
was not measured. The source at the evidence commit separates three responsibilities:

- `src/gateway/protected_tool_tests.rs` composes the operator-owned inputs, real Kapsel gateway and
  concrete adapter, fault wrapper, subprocess caller, offline inspection and assertions.
- `src/gateway/protected_tool_tests/alternative.rs` implements a separate typed operation, private
  approval record, worker exclusion, conditional attempt transition, strategic PATCH, bounded
  observations and unsigned frozen JSON evidence. It calls no Kapsel API or policy helper.
- `src/gateway/protected_tool_tests/receiver.rs` owns HTTP request capture, exact payload
  assertions, independent receiver state and explicit writer interventions. It imports neither arm.

Both operator compositions perform four setup tasks: create private storage, select the receiver
client, approve the exact operation and snapshot, and invoke the resident operation. The one Cargo
command scripts all four for both arms. Original snapshot values come from the independent fixture's
known initial state, not production snapshot-acquisition commands. Counts exclude
approval-acquisition GETs. Kapsel additionally provisions grant signing/trust and receipt
signing/inspection material. Both callers need the stable handle and a mapping from terminal result
to the next action. Process restart is operator composition work, not a caller-supplied lifecycle
argument. The comparison runner supplies it for both. No model, queue, service install, recruited
operator or additional shell launcher is involved.

| Obligation                         | Kapsel arm                                                                                                          | Typed arm                                                                                        |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Approval preparation               | Exact grant, grant signing key and configured verifying key                                                         | Operator inserts exact request and snapshot in a private row                                     |
| Provider authority                 | Operator constructs kube client                                                                                     | Operator constructs kube client                                                                  |
| Persistent components              | Format-4 SQLite journal, rollback journal and worker lock                                                           | SQLite action table, rollback journal and worker lock                                            |
| Execution and recovery             | Existing gateway, journal and Kubernetes adapter                                                                    | New explicit sequential tool implementation                                                      |
| Frozen outcome                     | Signed classifier-complete receipt in SQLite, or durable rejection facts                                            | Unsigned JSON evidence in the same action row                                                    |
| Evidence consumer                  | Offline signature/trust inspection, stable retrieval                                                                | Read original row bytes under local operator trust                                               |
| Export                             | None required by this gateway composition. CLI/MCP exporters and service retrieval remain separate integration work | No required filesystem export. A caller wanting portable evidence must retain the returned bytes |
| Dependencies used by the operation | Existing Kapsel, SQLite, kube, Tokio, JSON, Ed25519 and SHA-256 machinery                                           | Existing SQLite, kube, Tokio and JSON libraries, no Kapsel policy or cryptography                |
| Recovery-specific caller code      | None. The operator restarts the gateway with the same storage and request                                           | None. The operator restarts the tool with the same storage and request                           |
| Human handoff branches             | Five UNKNOWN cases, explicit new-approval decision for three stale cases                                            | The same handoffs and decisions                                                                  |

The five UNKNOWN cases are pre-send, replacement, intervening writer, slow rollout and the
post-preflight conflict control. These are scripted handoff branches, not observed human decisions.
No automatic retry or operator reapproval is hidden in either arm. Restart and test receiver
interventions are scripted fixture work, not evidence that real operators require no commands.
Neither alternative installs a safe multi-user service boundary in this experiment. Credentials are
absent from the fixture and caller requests. The operator/caller separation is exercised through
typed calls, not distinct OS identities or a hostile caller process. Existing service isolation
evidence is not attributed to the new tool.

At the evidence commit, the alternative is 293 formatted lines. The composition/caller/fault test is
another 583 lines and the receiver another 192, so its cost is not just the short tool module. This
supporting size evidence is not a LOC target or a comparison with all of Kapsel's broader
obligations.

The alternative is shorter than Kapsel, but it is not a production replacement. It deliberately
omits portable signed evidence, wire compatibility, migration policy, private-path attack defenses,
hostile database and receiver-input qualification, service installation and transport adapters. Its
fixture-scoped storage failures panic instead of providing a supported diagnostic contract. The
shared test executable links Kapsel because it runs both arms, while the alternative module has no
Kapsel imports. Shared kube and SQLite libraries are actual dependencies, not hidden Kapsel runtime.
The receiver is a controlled small service fixture, not a hostile-input qualification suite. Both
clients use a supplied HTTP service without automatic retry layers. This does not requalify proxy,
TCP-loss, HTTP/2 or operator-document client behavior. Existing application retry tests own those
separate finite client-construction checks.

## Recommendation

**Simplify, while keeping the durable action mechanism.** Neither recovery outcomes nor scripted
handoff branches distinguish the two tested compositions. This does not measure installed-service
operator effort or establish equal security hardening. The typed operation reconstructed the same
recurring core: exact frozen authority, worker exclusion, a durable dispatch boundary,
observation-only recovery, bounded uncertainty and immutable evidence. Deleting those mechanisms
would break the demonstrated requirements.

The useful simplification to steal is an operator-private approval row and ordinary evidence
retrieval when the consumer already trusts the resident component. A signature changed no next
consumer action here. A separately trusted or portable consumer may need signed evidence, but that
requires its own demonstrated decision rather than being imposed on every protected operation. Keep
adapters, signed grant/receipt formats and export outside the minimum conceptual core. This is a
design hypothesis, not a change to existing compatibility or safety requirements. It does not
qualify this test module as a production replacement or generalize beyond the tested compositions.
