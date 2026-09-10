# Testing

This page owns proof strategy, test placement, deterministic inputs, hostile-input coverage, and
crash recovery expectations. [Build and test](BUILD.md) owns runnable commands; direct contracts own
exact behavior and evidence limits.

## Test through the owning interface

Place each test at the lowest layer whose interface states the behavior. Moving a test outward must
not require widening a production seam. A higher layer should add a composition or external-contract
assertion rather than repeat an implementation matrix.

| Location                              | Owns                                                                                             |
| ------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Implementation-local `#[cfg(test)]`   | Pure parsing, classification, SQL and filesystem invariants, and private adapter or fault seams. |
| Root package `tests/application_*.rs` | Exported `Application` behavior with the product compiled without `cfg(test)`.                   |
| Root package `tests/e2e_*.rs`         | Production binaries, machine output, exit classes, restart, and operator workflows.              |
| `crates/<crate>/tests/`               | Exported interfaces of independently meaningful workspace packages.                              |
| `fuzz/`                               | Hostile bytes entering only through production interfaces.                                       |
| Ignored simulation targets            | Seeded lifecycle schedules, repeated recovery, and invariant checks.                             |
| Explicit live-kind scripts and tests  | Disposable-cluster behavior and real process termination.                                        |

The root is both workspace root and product package, so `application_` and `e2e_` prefixes
distinguish package integration from binary end-to-end tests. A test-support crate or public
provider seam requires multiple real consumers; one production Kubernetes adapter does not justify
either.

Assert pure implementation rules exhaustively once at their owner. At higher layers, assert
authority separation, durable outcomes, composition, observable output, and non-disclosure. Prefer
table-driven cases with shared setup, and use separate precise assertions when distinct contract
facts matter.

## Action-boundary evidence

The [accepted scope](SCOPE.md#direction-and-current-boundary) retains the bounded broker. This map
separates improvements adopted into unreleased source from evidence that did not change production
behavior. None changes the published v0.2.0 artifact.

| Evidence                          | Exact retained revision                                                                                | Result and limit                                                                                                                                                                                                                                                    |
| --------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Recovery policies                 | `93552ccf220d605c02671f0e66259191d730efec`                                                             | [ADR 0011](decisions/0011-retain-observation-only-recovery.md) retains no-replay after live stale strategic PATCH repeated admission effects. Temporal is a projection, not an executed workflow.                                                                   |
| Snapshot approval and proof       | `39c66c929a0df2a9a484a40358d88cdc179b706d`, `9df5fad32723d2da3a988c66aea44c7e25ba63ed`                 | Adopted exact UID/version approval and zero-PATCH stale rejection. Live race proof complements deterministic restart/receipt cases.                                                                                                                                 |
| Real-agent reconnect              | `30567790892164d6e3eb4353f5667cc93fa90bd6`                                                             | [Workflow report](RECONNECTABLE_AGENT_ACTION.md) establishes reconnect and slow-rollout friction, not relative operator effort or a representative stale-rejection rate.                                                                                            |
| Independent kubectl               | `b73d30753347faa8523aceb02b572fcb7caab2e0`                                                             | [Corpus](INDEPENDENT_TOOL_CORPUS.md) found ordinary adapter risks, no added standalone failure-kit value in seven fixed cases. No project demotion adopted.                                                                                                         |
| SQLite receipt completion         | `b27d8e0a6c3dea91d2d4333ea111d32629a04f26`                                                             | Adopted format 4. Signed bytes and terminal state commit together. Removed publication-dependent completion, durable output paths and receipt-root startup coupling. Older journals rejected.                                                                       |
| Event kernel and retry correction | `21f0a2534e9555130025a4082e935194886a6cb2`                                                             | Kernel rejected before integration. Bounded explorer and scratch SQLite runner share test-only decisions. Separately fixed hidden HTTP retries.                                                                                                                     |
| Sequential dispatch               | `0b79ff646b1bc38cfa59fbe1b9477fe8bcb8b6dc`, consolidated as `59b4f04f513f1dfd4131f722b6c44b210d73b453` | Adopted private consumed permission at the real adapter boundary. [ADR 0011](decisions/0011-retain-observation-only-recovery.md#sequential-boundary-comparison) records removed apply arguments, request counts and I/O obligations. No shared pure kernel claimed. |
| Guarded JSON Patch                | `430e7f20aed71ef8daec81b681625a641d98ee18`                                                             | [Live comparison](#frozen-json-patch-receiver-comparison) reduced some stale admissions but retained pending/unpersisted ambiguity. Keep strategic merge/no-replay.                                                                                                 |
| Later observation                 | `426c17f0152f9cdb5036895c25cdcbed11b20e43`                                                             | [Prototype](LATER_OBSERVATION_EXPERIMENT.md) supplies useful later evidence without changing UNKNOWN or mutating again. Test-only, not a supported lifecycle.                                                                                                       |
| Protected typed tool              | `cad49d7881c19abe666215d7fd8fd76c2f1a5019`                                                             | [Comparison](PROTECTED_TOOL_COMPARISON.md) executed thirteen fixed cases per arm with identical receiver evidence. Durable core recurs. No production equivalence or signature-removal decision.                                                                    |

These revisions were verified locally. Another checkout must obtain them from a repository
containing them, for example `git fetch /path/to/owning/kapsel master`; local availability does not
imply a remote push. The two original kernel/dispatch branch commits can be fetched from a
containing local branch or tag. Current master contains their retained executable evidence in
`59b4f04`.

The kernel's former report is historical at
`21f0a2534e9555130025a4082e935194886a6cb2:docs/APPROVAL_KERNEL_EXPERIMENT.md`. It was removed during
consolidation to avoid parallel rationale. The retained `approval_kernel_prototype` tests cover
1,714 explored states through depth 7, 252 healthy interleavings, and duplicate-acknowledgement and
recovery-resend counterexamples. No production orchestration was replaced by that event machine. Its
fresh acknowledgement and driver/I/O correspondence remain assumptions, not durability proof.

Receipt consumers were checked through the application/service retrieval path, not just SQL.
`gateway::tests::receipt` covers signing failure, commit-acknowledgement loss, process exit before
and after commitment and frozen observation/signer bytes. `e2e_demo_recovery` covers real executable
restart and export under changed settings. The Linux service process lane retrieves and inspects
original bytes while the export destination is unavailable. The application client retry and
snapshot regressions retain independent request counts. Process exits do not prove power loss.

Reproduce the retained deterministic evidence on the current checkout:

```sh
cargo test --locked -p kapsel --lib approval_kernel_prototype
cargo test --locked -p kapsel --lib gateway::tests
cargo test --locked -p kapsel --lib gateway::protected_tool_tests
cargo test --locked -p kapsel --test application_retry
cargo test --locked -p kapsel --test later_observation
./scripts/ci-local.sh
```

The reports and [build guide](BUILD.md) own separate live/platform commands and historical input
manifests. This map does not claim those lanes were rerun during documentation reconciliation.

## Core effect-gateway proof matrix

| Layer                | Required proof                                                                                         |
| -------------------- | ------------------------------------------------------------------------------------------------------ |
| Request validation   | Bounds for identity, namespace, Deployment, container, digest, and authorization.                      |
| Authorization        | Signed grant, configured trust, exact tuple, and rejection before persistence.                         |
| Journal transition   | Deterministic fault injection at every durable state.                                                  |
| Target disposition   | Permanent invalid targets are pre-attempt `NOT_ATTEMPTED`; transient reads defer fairly.               |
| Provider attempt     | Safe GET precedes atomic target identity and `apply_started`; mutation follows that commit.            |
| Recovery             | Every injected window and process kill reopens without a blind second mutation.                        |
| Receiver observation | Request acceptance, timeout, transport completion, and rollout result remain distinct.                 |
| Classification       | Timeout and unresolved evidence are `UNKNOWN`, never false success or failure.                         |
| Receipt/inspection   | Canonical vectors carry all classifier inputs; inspection recomputes under explicit trust and limits.  |
| Receipt completion   | Frozen observation precedes signing; bytes, digest, signer and finalized state commit together.        |
| Export               | Collision-safe export uses committed bytes. Failure cannot reopen completion or block later retrieval. |
| Compatibility        | Format 4 rejects older journals before action processing; grant/receipt wire meanings remain explicit. |
| Hostile input        | Malformed, oversized, duplicate, reordered, unknown, and trailing records fail closed.                 |
| Disclosure           | Secrets and unbounded provider bodies stay out of SQLite, receipts, reports, errors, and logs.         |

`INSPECTED` means authenticated bytes and classifier consistency under supplied trust. It is not
receiver truth, causation, complete capture, compliance, or `VERIFIED`.

## Determinism and crash proof

Default semantic tests do not depend on wall-clock time, random keys, live services, ambient trust,
locale, or filesystem order. Use fixed keys, explicit evaluation time, private temporary
directories, seeded inputs, and sorted output. A subprocess test may use a bounded monotonic
coordination deadline; result meaning must not depend on polling order or timing.

Fault tests, simulations, process recovery, and compile-time demonstration controls cross the same
private operation-selected provider and receipt-completion implementations used by `Application`.
Queue-oriented helpers may select one identity but own no lifecycle transition. Process-kill proof
crosses the ambiguous mutation and receipt-commit seams, establishes no second mutation request, and
preserves committed bytes without re-signing. Export may use a new destination without changing the
durable action or signing identity.

A live `kind` lane is explicit, environment-owning evidence. It complements but never replaces
fault-injection around every journal window.

## Evidence classes

### Deterministic suite

The default suite contains implementation-local tests, package integration tests, binary tests
needing no external service, and documentation tests. It owns repeatable semantic and hostile-input
proof. Source coverage is an informational review aid only; no percentage establishes crash safety,
Kubernetes semantics, release integrity, or production readiness.

The MCP subprocess lane proves bounded newline-delimited framing, one five-field tool, operator
configuration outside caller input, typed `SUCCEEDED`, `FAILED`, `UNKNOWN`, and `NOT_ATTEMPTED`
vocabulary, restart, protocol-only standard output, bounded hostile input, and secret-free failures.
Cancellation, EOF, or transport completion never determines receiver outcome.

The current version-rejection test proves older journals remain untouched. Historical v0.1.1
migration/restore fixtures describe the published pre-format-4 baseline, not a current migration
path. The [upgrade contract](UPGRADE.md) owns compatibility meaning.

### Robustness

Fuzzing calls production hostile-input interfaces from canonical corpus vectors without network or
ambient authority. Failures retain a minimized artifact and exact replay information.

Long simulations generate bounded lifecycle schedules, crash windows, retry deferrals, and reopen
operations from an explicit seed. Every step checks durable state, provider-call count, terminal
state, and frozen-receipt invariants. The seed is always replayable; wall-clock duration may change
only how many cases run, not their semantics.

### Live Kubernetes and demonstration

The live-kind gate owns real Kubernetes success, defined failed rollout, bounded `UNKNOWN`, and
process loss against a uniquely owned disposable cluster. It must show no blind second patch and
must clean up or export bounded failure evidence. Its recovery-policy case uses an instrumented
mutating webhook to separate PATCH requests and admission effects from persisted Deployment and
controller effects when an identical stale patch is replayed.

The exact-snapshot case separately acquires the operator target through the production adapter. It
proves one matching PATCH, preflight stale rejection for both version drift and same-name recreation
without a PATCH, and a changed receiver version between preflight and the gateway PATCH. That final
conflict remains `apply_started`, not a pre-attempt conclusion; deterministic fault tests own the
exhaustive restart and receipt-projection matrix around it.

The public demonstration adds an observable evaluator path through healthy,
`ProgressDeadlineExceeded`, mutation-loss, and receipt-commit-loss cases in current source. The
published v0.2.0 artifact instead uses its historical publication seam. Compile-time harness
controls remain outside caller input and the ordinary executable. A visual demonstration is finite
evidence, not exhaustive recovery proof.

#### Frozen JSON PATCH receiver comparison

JSON Patch can reject stale values before mutating admission. It does not make replay safe. This
comparison retains the production strategic adapter and observation-only recovery. Both arms use the
same unreleased sequential dispatch and format-4 receipt baseline. Experimental requests bypass
fresh dispatch permission only inside the test module. No production replay path is added.

The JSON document freezes the original independently read UID, opaque resourceVersion, and container
index. It tests UID, version, and the name at that index before replacing the image. Both strategies
set the same operation annotation and preserve unrelated annotations and the untargeted container.
No later observation refreshes either document. The JSON pointer escapes `/` as `~1`, and an absent
annotations map requires adding the parent map rather than just its member.

The boundary follows the pinned receiver source:

- [RFC 6902 sections 4.6 and 5](https://www.rfc-editor.org/rfc/rfc6902#section-4.6) define ordered
  tests and patch failure.
- The
  [v1.33.12 PATCH handler](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/patch.go#L388-L425)
  returns `422` when JSON Patch application fails. Its transformer sequence applies the patch before
  mutating admission. Strategic metadata preconditions are checked later by
  [registry update](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go#L649-L733).
- [GuaranteedUpdate](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/storage/etcd3/store.go#L436-L520)
  may start with a cached object and re-evaluate the transformers. A cached original can pass JSON
  tests even after a writer has persisted. Earlier tests therefore do not guarantee zero admission
  for every request sent after a writer. One strategic request can invoke admission repeatedly.

`kind_tests::patch_experiment` compares the production strategic document builder with a test-only
JSON builder. The HTTP client disables automatic server-response retries. Dispatch counters are
cross-checked against independent API-server `RequestReceived` audit events, identified by a fixed
experimental user-agent. The webhook records AdmissionReview UIDs in a ledger and flushes one
out-of-band log effect for each invocation. Tests cross-check that ledger against pod logs.

GETs establish desired spec, annotation, UID, version, and generation changes separately. ReplicaSet
counts and controller-observed generation and replicas provide bounded controller evidence. HTTP
statuses are reported separately as `not-classified`, never promoted into rollout results. The
existing gateway cases retain responsibility for recovery, classification, and receipt evidence.

The overlap case holds both requests in admission after their log effects. Both futures remain
pending while a GET proves the original version and spec remain unchanged. The test releases the
first request, awaits its response, then releases the second. The unpersisted case allows admission
but returns a webhook mutation setting `replicas: -1`. Built-in validation rejects the candidate.
After the response and an unchanged-version/spec check, the fixture allows an exact replay. This
exercises failure after mutating admission, not an injected etcd outage. Barriers establish
ordering. Polling only retrieves facts. Limits are 20 seconds per barrier, 32 configured cases, 16
invocations per case, and 240 seconds for the matrix.

A complete run on arm64 macOS with Docker 29.4.0, kind 0.32.0, kubectl 1.33.9, and the pinned
Kubernetes v1.33.12 node image measured these counts. Each admission produced one log effect. Counts
are observations of this run, not universal admission cardinalities. A second complete run with
stronger rollout-readiness and full-spec/annotation-preservation assertions measured one rather than
two strategic admissions in the preflight-writer row. Other counts below matched. The server
reported gitCommit `1f348c8e82cf0f170df4ac2b1e859ea0d398ff09`.

| Scenario or checkpoint                              | PATCHes per strategy | Strategic admissions / logs | JSON admissions / logs | Experimental persisted updates / new ReplicaSets |
| --------------------------------------------------- | -------------------- | --------------------------- | ---------------------- | ------------------------------------------------ |
| Persisted response discarded, then exact replay     | 2                    | 2 / 2                       | 1 / 1                  | 1 / 1                                            |
| Writer between preflight and PATCH                  | 1                    | 2 / 2                       | 0 / 0                  | 0 / 0                                            |
| Same-name recreation before PATCH                   | 1                    | 1 / 1                       | 0 / 0                  | 0 / 0                                            |
| Container reordering before PATCH                   | 1                    | 1 / 1                       | 0 / 0                  | 0 / 0                                            |
| Both overlapping requests held in admission         | 2                    | 2 / 2                       | 2 / 2                  | 0 / not sampled at barrier                       |
| Overlapping requests after ordered release          | 2                    | 3 / 3                       | 2 / 2                  | 1 / 1                                            |
| Admitted but invalid first candidate, then replay   | 2                    | 2 / 2                       | 2 / 2                  | 1 / 1                                            |
| Before-send fault and journal reopen, before replay | 0                    | 0 / 0                       | 0 / 0                  | 0 / not sampled before replay                    |
| Counterfactual replay after the unsent fault        | 1                    | 1 / 1                       | 1 / 1                  | 1 / 1                                            |

Audit confirmed 20 experimental PATCHes across 14 cases. Stale strategic requests returned `409`,
while stale JSON requests returned `422`. Both invalid first candidates returned `422` without
changing the original version. Exact replay then returned `200` with a second admission effect. Both
overlapping JSON requests also reached admission before either persisted. These are live
counterexamples to treating JSON tests as receiver-wide deduplication.

Successful image changes advanced generation and ReplicaSet count from 1 to 2, with controller
observed generation 2 and one available and updated replica. The annotation writer created no
ReplicaSet. The reorder writer created its own ReplicaSet, not attributed to the rejected PATCH.
Recreation changed UID. The matrix records before/after controller counts, not an exhaustive history
of controller actions or workload correctness.

Fault placement matters. The before-send case injects an error at `ApplyStartedCommitted`, closes
and reopens the real journal, and proves attempted state with no caller result and zero applies.
This is not SIGKILL or power loss. Its subsequent raw replay is counterfactual, not gateway
recovery. The response-discard case receives a successful response in the harness before discarding
it for comparison purposes. It is not TCP loss. Existing process and loopback transport tests remain
separate evidence, not an executed JSON adapter integration.

Recommendation: retain strategic merge and no-replay. JSON tests reduced stale admission exposure in
these traces but did not eliminate pending or unpersisted ambiguity. Replacement adds original index
binding, annotation-parent handling, and write-strategy compatibility work without removing recovery
machinery. Earlier rejection may still justify future adoption on its own merits. This experiment
adopts nothing and adds no production dependency. Arbitrary webhook behavior, proxies, other
Kubernetes versions, actual storage failure, and power-loss durability remain unproved.

The measured baseline is `59b4f04f513f1dfd4131f722b6c44b210d73b453`. The test-only changes and this
report are preserved at `430e7f20aed71ef8daec81b681625a641d98ee18`. Obtain a checkout containing
that revision and run:

```sh
cargo test --locked -p kapsel --lib \
  kind_tests::patch_experiment::frozen_json_document -- --nocapture
./scripts/format.sh
./scripts/ci-local.sh
TMPDIR=/tmp ./scripts/test-kind-effect-gateway.sh
```

The launcher records the base revision and binary working-tree diff SHA-256. Untracked source is
refused rather than omitted from evidence. The pinned node image is
`kindest/node:v1.33.12@sha256:3f5c8443c620245e4d355cfe09e96a91ead32ceaa569d3f1ca9edf0cb2fe2ff4`. The
audit policy and unauthenticated webhook control port are disposable test infrastructure only. The
launcher creates a uniquely named cluster and removes only its owned cluster, image, and workspace.
The local evidence commit is not a published release or proof of remote availability.

### Release artifact

Artifact proof crosses extracted `x86_64-unknown-linux-gnu` bytes rather than a Cargo test binary.
Two isolated assemblies must produce identical archive, checksum, SBOM, and digest-manifest bytes.
Hostile archive validation precedes extraction; smoke uses only extracted files to prove identity,
grant provisioning, operation and restart, offline inspection, MCP equivalence, demonstration-binary
separation, cleanup, and uninstall. It kills the extracted demonstration executable at both owned
seams and preserves one provider attempt and frozen receipt bytes under rotated settings. The
Sigstore bundle receives identity and failure checks rather than a false reproducibility
requirement.

The live artifact demonstration is a separate environment-owning gate. Exact layout, publisher
authentication, provenance, and evidence limits belong to [Release artifacts](RELEASE.md).

### Kapsel service

The unpublished service evidence remains layered around `Application`:

- projection reads status and frozen receipts without Kubernetes access or lifecycle advancement;
- Unix-socket tests cover effective-group peer credentials, framing, allocation, hostile fields,
  disclosure, one in-flight submission, and no queue;
- process tests cover `ACCEPTED` as process ownership only, immediate `BUSY`, caller disconnect,
  concurrent status, one provider attempt, and one journal;
- process-loss tests require startup reconciliation before bind and preserve frozen receipt bytes;
- startup and asset tests freeze fixed roots, no-follow file rules, exact argv, stale-socket
  handling, systemd, sysusers, and namespaced RBAC bytes; and
- deterministic root-substitution tests rename and replace state and runtime names after validation,
  then prove journal creation and socket bind stay with the retained directory identities. Receipt
  retrieval uses the journal, with no receipt-root dependency.

Service-client tests freeze its three-command grammar, bounded framing, receipt digest verification,
exclusive mode-`0600` output, and refusal to replace an existing file. `kapsel-authority` tests
freeze shared grant/trust vectors and consistency. Its `grammar_tests` own the table-driven request
bounds and spelling cases. Gateway and service tests prove field-error projection and rejection
before persistence or application access rather than repeating that grammar matrix. This does not
turn the authority package into a public SDK. The [Kapsel service contract](KAPSEL_SERVICE.md) owns
the complete unpublished boundary.

The service is absent from v0.2.0 and remains unpublished. Installer-only tests and launchers were
removed with their implementation. [Installer retirement](KAPSEL_SERVICE.md#installer-retirement)
records the deletion boundary and historical retrieval instructions. Service asset, process,
authority and core safety coverage above remains active.
