# Retain observation-only recovery after an ambiguous patch

Status: accepted.

Kind: decision. Date: 2026-09-05.

Owns: Whether recovery after `apply_started` observes, replays the frozen conditional patch, or
hands retry scheduling to a durable-workflow runtime.

Does not own: Receiver-result classification, a workflow-engine integration, another capability, or
receipt bytes.

## Context

A process can die after Kapsel commits `apply_started` but before any network send. Observation-only
recovery abandons that still-authorized action. Replaying the exact frozen operation could complete
it while the original Deployment UID and resource version remain current.

The same journal state also covers a request accepted by Kubernetes whose response was lost. A
recovery policy cannot distinguish those windows. UID and resource-version preconditions bound
persistence, but they do not protect all earlier Kubernetes request processing.

The comparison used one immutable operation tuple:

```text
operation ID + Deployment UID + resourceVersion + immutable image +
conditional-strategic-merge-patch
```

Every replay used those original values. It never refreshed authorization, target identity, or a
precondition from later state.

## Evidence

Evidence revision: `93552ccf220d605c02671f0e66259191d730efec`. The live observations below qualify
that source snapshot and its pinned receiver, not an arbitrary current checkout.

The deterministic test
`recovery_policy_tests::frozen_recovery_policy_matrix_separates_requests_admission_and_effects` uses
an independent receiver model rather than Kapsel's classifier. It compares:

1. current observation-only recovery;
2. exactly one replay of the frozen patch; and
3. a projection of a Temporal Activity with explicit `MaximumAttempts: 2`.

The Temporal row is a semantic projection of documented at-least-once Activity execution. The test
does not claim to execute Temporal.

Each cell below is
`caller invocations / PATCH requests / mutating admission invocations / out-of-band admission effects / persisted Deployment changes / controller effects / authorized actions left unsent / caller conclusions`.

| Scenario                                         | Observe only                      | One frozen replay                 | Temporal projection               |
| ------------------------------------------------ | --------------------------------- | --------------------------------- | --------------------------------- |
| Death immediately before send                    | `1/0/0/0/0/0/1/UNKNOWN`           | `1/1/1/0/1/1/0/SUCCEEDED`         | `1/1/1/0/1/1/0/SUCCEEDED`         |
| Accepted mutation, response lost                 | `1/1/1/0/1/1/0/SUCCEEDED`         | `1/2/2/0/1/1/0/SUCCEEDED`         | `1/2/2/0/1/1/0/SUCCEEDED`         |
| Two callers, identical original preconditions    | `2/2/2/0/1/1/0/SUCCEEDED+UNKNOWN` | `2/2/2/0/1/1/0/SUCCEEDED+UNKNOWN` | `2/2/2/0/1/1/0/SUCCEEDED+UNKNOWN` |
| Intervening writer before recovery               | `1/0/0/0/1/1/1/UNKNOWN`           | `1/1/1/0/1/1/0/UNKNOWN`           | `1/1/1/0/1/1/0/UNKNOWN`           |
| Target deletion and recreation                   | `1/0/0/0/1/1/1/UNKNOWN`           | `1/1/1/0/1/1/0/UNKNOWN`           | `1/1/1/0/1/1/0/UNKNOWN`           |
| Later template change retaining marker/image     | `1/1/1/0/2/2/0/SUCCEEDED*`        | `1/2/2/0/2/2/0/SUCCEEDED*`        | `1/2/2/0/2/2/0/SUCCEEDED*`        |
| Admission out-of-band effect after response loss | `1/1/1/1/1/1/0/SUCCEEDED`         | `1/2/2/2/1/1/0/SUCCEEDED`         | `1/2/2/2/1/1/0/SUCCEEDED`         |

The concurrent row has two separately authorized operation IDs with the same frozen Deployment
identity, resource version, image, and strategy. Both initial requests run, one persists, and the
other returns a conflict. No ambiguous result is injected in that row, so none of the three recovery
policies adds a request.

`SUCCEEDED*` is only a conclusion from the later observed state. A writer changed the template after
the original patch while retaining its image and marker. The current classifier can use that later
current generation as the requested generation. Neither replay nor Temporal identifies the original
patch generation, so this row is not evidence that the original effect caused the later rollout. The
receipt's no-causation claim remains material.

The live command `./tests/qualification/run-kind-effect-gateway.sh` adds a pinned Kubernetes
v1.33.12 proof. An instrumented mutating webhook records each unique AdmissionReview UID and
operation ID as an out-of-band log effect. The first frozen strategic patch persists and creates one
new ReplicaSet. Replaying the identical stale patch invokes the webhook again, then returns
Kubernetes API `409 Conflict`. The post-replay Deployment UID, resource version, generation,
complete desired spec, operation annotation, both container images, and ReplicaSet count equal the
post-first-patch state.

That ordering is expected from the pinned Kubernetes source. Strategic PATCH invokes mutating
admission while producing the updated object inside `GuaranteedUpdate`; storage checks the stale
resource version afterward:

- [PATCH handler admission and update, Kubernetes v1.33.12](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/patch.go#L628-L704)
- [registry storage update checks, Kubernetes v1.33.12](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go#L649-L733)

Kubernetes'
[admission webhook good practices](https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/)
say webhooks should avoid out-of-band side effects and be idempotent. They also permit real-request
side effects through `sideEffects: NoneOnDryRun`. The frozen operation annotation is not a
receiver-enforced idempotency key, so Kapsel cannot assume every admission component deduplicates
it.

### Concluded receiver research

Current source retires the PostgreSQL transaction-boundary probe and SQL fixture, independent
kubectl corpus/report, unsigned Git receiver probe, and frozen JSON Patch builder/live comparison.
Git history retains their implementations and reports. These experiments introduced no product
capability or dependency. Current contracts and [Testing](../TESTING.md) own maintained guarantees
and qualification; historical comparisons do not qualify current source.

The PostgreSQL experiment established database-local atomic visibility, not atomicity with external
effects. A function result before commit was visible within its transaction but was not durable
admission. Rolling back SQL left a separately written external file intact. Its privilege,
serialization and database-crash cases were unsigned research, not a product guarantee. The
[PostgreSQL transaction tutorial](https://www.postgresql.org/docs/17/tutorial-transactions.html)
explains database-local all-or-nothing visibility, not external-effect rollback. SQLite admission,
completion and storage-failure checks remain at their existing owners.

The kubectl experiment distinguished image-update acceptance from rollout completion. Fresh name- or
revision-based status could describe an intervening writer or a recreated Deployment, not the
original action. The continuing kubectl comparison and equivalence claim are withdrawn, not Kapsel's
receiver guarantees. Current receiver and classifier tests retain original identity and intent
without claiming causation.

The unsigned Git probe explored exact leases, ancestry and receiver binding, ABA, present-ref
uncertainty, and pre/post-receive acknowledgement loss. Maintained real-Git tests cover these
boundaries, with service and artifact journeys owning process and custody composition. An explicit
unsent-present-B case drops permission, lets another sender establish B, and still requires
`UNKNOWN` with zero original update packets. An exact lease is neither ancestry proof nor replay
permission; seeing B does not establish original causation.

#### Frozen JSON Patch evidence

The later comparison at `430e7f20aed71ef8daec81b681625a641d98ee18` used baseline
`59b4f04f513f1dfd4131f722b6c44b210d73b453`. It did not adopt JSON Patch. Current source retires its
experimental builder and two-arm matrix; Git history retains their code and report. Production
strategic merge, observation-only recovery and required live receiver checks remain.

The experimental JSON document tested the original UID, opaque resourceVersion and container name at
the original index before replacing the image. It preserved unrelated annotations, escaped `/` as
`~1`, and added the annotations parent when absent. No later read refreshed either strategy. HTTP
response retries were disabled. Raw comparison requests bypassed dispatch permission only in the
experiment; they were not a production recovery path.

The pinned primary sources explain both earlier rejection and its limits:

- [RFC 6902 sections 4.6 and 5](https://www.rfc-editor.org/rfc/rfc6902#section-4.6) define ordered
  tests and patch failure.
- The
  [v1.33.12 PATCH handler](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/patch.go#L388-L425)
  returns `422` for failed JSON Patch application, before mutating admission in that transformer.
- [Registry update](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go#L649-L733)
  checks strategic metadata preconditions later.
- [GuaranteedUpdate](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/storage/etcd3/store.go#L436-L520)
  can start with a cached object and re-evaluate transformers. Cached original values can pass JSON
  tests after another writer persists. One strategic request can invoke admission repeatedly.

The live run used arm64 macOS, Docker 29.4.0, kind 0.32.0, kubectl 1.33.9 and Kubernetes v1.33.12
(server commit `1f348c8e82cf0f170df4ac2b1e859ea0d398ff09`). The node image was
`kindest/node:v1.33.12@sha256:3f5c8443c620245e4d355cfe09e96a91ead32ceaa569d3f1ca9edf0cb2fe2ff4`.
Independent API-server audit counted 20 experimental PATCH requests across 14 cases. Each admission
flushed one out-of-band log effect; a separate AdmissionReview UID ledger cross-checked pod logs.

| Scenario or checkpoint                          | PATCHes per strategy | Strategic admissions / logs | JSON admissions / logs | Persisted updates / new ReplicaSets |
| ----------------------------------------------- | -------------------- | --------------------------- | ---------------------- | ----------------------------------- |
| Persisted response discarded, then exact replay | 2                    | 2 / 2                       | 1 / 1                  | 1 / 1                               |
| Writer between preflight and PATCH              | 1                    | 2 / 2                       | 0 / 0                  | 0 / 0                               |
| Same-name recreation before PATCH               | 1                    | 1 / 1                       | 0 / 0                  | 0 / 0                               |
| Container reordering before PATCH               | 1                    | 1 / 1                       | 0 / 0                  | 0 / 0                               |
| Both overlapping requests held in admission     | 2                    | 2 / 2                       | 2 / 2                  | 0 / not sampled at barrier          |
| Overlap after ordered release                   | 2                    | 3 / 3                       | 2 / 2                  | 1 / 1                               |
| Admitted-invalid first candidate, then replay   | 2                    | 2 / 2                       | 2 / 2                  | 1 / 1                               |
| Before-send fault and reopen, before replay     | 0                    | 0 / 0                       | 0 / 0                  | 0 / not sampled before replay       |
| Counterfactual replay after unsent fault        | 1                    | 1 / 1                       | 1 / 1                  | 1 / 1                               |

These are observed counts, not universal cardinalities. A second complete run with stronger
readiness and spec/annotation assertions measured one strategic admission in the preflight-writer
row; the other counts matched. Stale strategic requests returned `409`, stale JSON requests `422`.

The pending counterexample held both requests after their admission log effects. Both futures stayed
pending while a GET showed the original version and spec unchanged. Ordered release produced one
persisted update. Both JSON requests reached admission before either persisted.

The unpersisted counterexample admitted the first candidate, then a webhook mutation set
`replicas: -1`. Built-in validation returned `422`; a GET confirmed unchanged version and spec.
Allowing an exact replay returned `200` with a second admission effect. This is failure after
mutating admission, not an injected etcd outage. Barriers established ordering; polling retrieved
facts. Bounds were 20 seconds per barrier, 32 configured cases, 16 invocations per case and 240
seconds for the matrix.

Successful changes advanced generation and ReplicaSet count from 1 to 2, with observed generation 2
and one available/updated replica. The annotation writer created no ReplicaSet. The reorder writer
created its own ReplicaSet, not attributable to the rejected PATCH. Recreation changed UID. These
are bounded controller observations, not workload correctness or exhaustive controller history.

The before-send fault returned at `ApplyStartedCommitted` and reopened the real journal with zero
applies; it was not SIGKILL or power loss. Raw replay afterward was counterfactual. The
response-discard case received success in the harness before discarding it; it was not TCP loss.
Product process and transport-loss checks remain separate evidence.

JSON tests reduced stale admission exposure in these traces but did not remove pending or
unpersisted ambiguity. Index binding, annotation-parent handling and strategy compatibility would
add work without removing recovery machinery. Earlier rejection could justify a future decision, but
this experiment adds no product dependency. Other receivers, arbitrary webhooks/proxies, actual
storage failure and power-loss durability remain unproved. Historical reproduction requires the
experiment revision above, not the current live gate.

## Workflow baseline

Temporal provides durable Workflow Event History, Activity timeouts, and retry scheduling. Its
[Activity execution](https://docs.temporal.io/activity-execution) is at least once, so a worker loss
can execute the Activity again.
[Retry policies](https://docs.temporal.io/encyclopedia/retry-policies) must be explicitly bounded
for this comparison; the projected second attempt uses the original opaque Activity payload and
treats conflict as ambiguity before observation. Temporal does not make the Kubernetes effect atomic
with Activity completion.

An equivalent implementation still needs resident provider authority, a frozen versioned operation
payload, Kubernetes-aware conflict handling, read-only receiver classification, durable receipt
semantics, and admission-side-effect idempotence outside Temporal. Self-hosting also adds the
[Temporal service](https://docs.temporal.io/temporal-service), persistence, schema, worker, upgrade,
and backup operations. The official [SDK Core repository](https://github.com/temporalio/sdk-core)
states that its Rust SDK is under development, adding either an experimental SDK or another worker
language to this Rust repository.

## Decision

Retain observation-only recovery after `apply_started`.

Without replay, death before send can abandon an authorized action. Kapsel reports `UNKNOWN`, not
success or failure. Exact replay could complete that unsent action. After a lost response, conflict,
or replacement, however, replay adds another mutating-admission invocation. It can repeat
out-of-band effects that frozen UID and resource version cannot prevent. Retaining no-replay avoids
that concrete receiver risk.

Do not adopt Temporal for this operation. Its bounded Activity retry has the same receiver exposure
as exact replay and does not replace the capability-specific authority, receiver, or receipt logic.
It adds materially more implementation and operational machinery.

For reconnectable callers, continuation is exact: after `apply_started`, a new caller or process
resumes the same operation by observation only. It must not issue a new operation identity, refresh
authority or preconditions, or resend through caller or workflow retry. `UNKNOWN` stops dependent
automation and hands the frozen evidence to a human.

## Current sequential design

The implementation keeps durable attempt, dispatch permission, observation-only recovery, and
receipt completion distinct. A durable attempt records that dispatch may have happened, so recovery
cannot derive permission from it. Dispatch permission is a private, one-use value issued after a
successful fresh attempt commit and consumed by the adapter. Observation-only recovery determines
what can be concluded without sending the mutation again. Receipt completion commits the original
signed evidence in SQLite, independently of export. The
[effect-gateway contract](../EFFECT_GATEWAY.md#fresh-dispatch-permission) owns the exact rules.

The adapter interface enforces part of the dispatch discipline without an event machine. Binding the
complete authorized snapshot inside the attempt transaction prevents substitution of different facts
under the same operation ID. Consuming the permission prevents ordinary repeat-dispatch and
history-dispatch calls. Disabling automatic server-response retries separately prevents one
permitted dispatch from expanding into repeated PATCH requests.

Worker exclusion, conditional database writes, the driver's no-retry obligation, and honest UNKNOWN
remain necessary. Deterministic and loopback HTTP evidence does not extend the pinned live
Kubernetes or durability claims below.

### Sequential boundary comparison

Journal phases, conditional writes, worker exclusion and lexical control flow can enforce fresh
dispatch in correct callers. But an adapter accepting independently selected, clonable request and
target values also accepts accidental repeat calls or arguments reconstructed from attempted
history.

| Candidate                                      | Benefit                                                                         | Cost or reason not selected                                                                      |
| ---------------------------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Existing sequential flow plus retry correction | Correct existing ordering and observation-only recovery                         | Reusable apply arguments leave dispatch discipline to callers                                    |
| Private consumed dispatch permission, adopted  | Prevents ordinary repeat/history dispatch and binds the exact committed payload | One private type, one bounded row load, and a short transaction                                  |
| Extract only pure snapshot decisions           | Could move the existing comparison into a function                              | No second production comparison to delete. Does not establish commitment or prevent repeat apply |

`begin_attempt` returns a `DispatchPermission`; the gateway calls `adapter.apply(permission).await`.
The journal's private constructor runs only after successful commit acknowledgement. The concrete
adapter consumes the permission into its bound request and target before building the strategic
merge PATCH.

The complete authorized snapshot is checked in one immediate transaction before the conditional
attempt write. That prevents a phase-typed snapshot from another journal supplying different
request, approval, or authorization provenance under the same operation ID. A losing transition or
commit error returns no permission. No transaction spans a network call or await.

Snapshot comparison belongs to `Journal::begin_attempt`. The seeded harness executes the same
journal/gateway decisions as production.

A separate event-machine kernel duplicated policy without replacing production orchestration. Its
bounded explorer assumed fresh acknowledgements and correspondence between driver decisions and I/O;
it did not prove durability. The historical prototype and report are available at
`21f0a2534e9555130025a4082e935194886a6cb2:docs/APPROVAL_KERNEL_EXPERIMENT.md`, not current
production evidence.

### Sequential boundary evidence

Dispatch and application-retry tests establish different facts: a consumed permission constrains
ordinary calls, while HTTP request counts check actual client behavior.

| Trace                                                | Observed result                                                                          |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Two real connections race fresh commitment           | Exactly one permission with the frozen request and target                                |
| Same ID, different action from another journal       | No permission or durable change                                                          |
| Commit succeeds, acknowledgement is lost             | No permission returned. Recovery only observes and freezes UNKNOWN for an unsent action  |
| Unused permission is dropped                         | Zero applies, no NOT_ATTEMPTED, honest UNKNOWN and preserved receipt bytes across reopen |
| Stale Authorized snapshot is reused after commitment | No permission reminted                                                                   |
| Continuation is cancelled during target read         | Remains Authorized. A later fresh run may commit and dispatch once                       |
| Continuation is cancelled after dispatch             | Remains ApplyStarted. Recovery does not send again                                       |
| Process is killed while apply is pending             | Subprocess regression recovers without another mutation                                  |

`tests/application_retry.rs` uses the ordinary operator-document client construction and a real
loopback HTTP receiver. Healthy execution, 429/503/504 responses, complete-request connection loss,
and cancellation after receipt of PATCH each count exactly one complete PATCH through restart,
reconciliation and repeat execution. The receiver remains available for the complete trace. Each
case checks two GETs and preserved receipt retrieval. The ambiguity matrix checks approved UID,
opaque resourceVersion and image in captured PATCH bodies. Success comes from separate receiver
observation, not the error response or request count.

Run the sequential checks on the current checkout with:

```sh
cargo test --locked -p kapsel --lib gateway::tests::dispatch -- --nocapture
cargo test --locked -p kapsel --test application_retry
KAPSEL_SIMULATION_SEED=21182435914953528 KAPSEL_SIMULATION_CASES=256 \
  KAPSEL_SIMULATION_SHARDS=1 ./tests/qualification/run-simulation.sh
cargo xtask ci
```

## Consequences and limits

- Dispatch permission is not lifetime-bound to `WorkerLock`. The driver must retain worker exclusion
  through I/O. The type does not constrain hostile code already holding raw credentials, or an
  adapter deliberately resending its extracted payload.
- The shared application client disables hidden server-response retries. Custom clients, proxies,
  HTTP/2 behavior and admission reinvocation remain separate obligations.
- Attempt-commit acknowledgement loss is injected after real commitment. This does not prove actual
  SQLite I/O failures, torn writes, power-loss or hardware durability, or unbounded schedules. The
  cancellation tests drop futures. Process-kill tests provide separate finite evidence, not
  before-send or commit-acknowledgement process-kill proof.
- The seeded receiver fixture may report an independent failed rollout even for an unsent action.
  That tests classifier consistency, not causation. The dedicated unsent tests supply no receiver
  facts and require UNKNOWN.
- Kapsel prevents recovery-induced duplicate admission effects. It cannot prevent admission
  reinvocation internal to one API request or duplicates from independent pre-attempt callers.
- Frozen UID/resource-version replay does prevent overwriting an intervening writer or replacement
  Deployment in the tested races. It does not prevent the extra request or admission effect.
- The live result qualifies the pinned v1.33.12 kind receiver, not every Kubernetes version or
  admission implementation.
- Reconsider replay only with a receiver-enforced idempotency key covering the whole admission and
  persistence pipeline, or an enforced admission profile that excludes side effects.
- The later-generation attribution limitation is shared by all three policies and remains visible.
  It is not a reason to count replay as useful completion.
