# Reconnectable agent action experiment

Evidence revision: `30567790892164d6e3eb4353f5667cc93fa90bd6`. The experiment ran against the
unpublished service and a disposable kind environment, including live inconclusive and
stale-approval outcomes.

Kind: experiment evidence. The 30-second budget and startup reconciliation described below belong to
the evidence revision. Current source uses read-first startup with explicit resumption and the
[initial observation policy](EFFECT_GATEWAY.md#result-meaning). This historical experiment does not
qualify that newer behavior.

Owns: The recorded outcome of the reconnectable agent action workflow: setup, invocation, caller and
service loss, reconnect, receiver observation, stale approvals, human handoff, and the measured
practical cost of exact-snapshot approval.

Does not own: A new grant format, authorization policy, observation lifecycle, agent integration, or
product decision. Canonical behavior remains owned by [effect-gateway](EFFECT_GATEWAY.md) and the
[service contract](KAPSEL_SERVICE.md). Reproduction commands live in
`scripts/test-kind-agent-action-workflow.sh`.

## Intended workflow

The experiment asked whether an operator could approve one exact Deployment image change, let an
agent submit it through the fixed service client, lose both caller and service processes, and let a
later caller continue from the same durable operation identity without guessing or mutating again.
The approval had to bind the target identity and expected-state preconditions so a change or
recreation after approval could not silently refresh them.

## Setup

One disposable kind cluster (pinned Kubernetes v1.33.12) hosted the receiver: namespace `demo`,
Deployment `agent-api`, one container running a pinned `registry.k8s.io/pause` digest. One
disposable Linux container ran the unpublished `kapseld` composition with the documented fixed
paths, a dedicated service identity, a caller identity whose effective group matched the socket's
caller group, and a scoped RBAC kubeconfig (`get` and `patch` on the single named Deployment). The
operator binary ran on the host: `provision-snapshot-grant` acquired the Deployment UID and
resourceVersion through the administrator kubeconfig and signed the exact-snapshot grant. Every step
above is a command of the harness script.

The caller boundary was the fixed `kapsel-service-client` grammar exposed through a thin wrapper
that forwards only `submit`, `status`, and `receipt`. Real agent sessions (Claude Code, driven
non-interactively with the wrapper as their sole executable capability) proposed the change, invoked
the handle, and reconnected after their own session loss.

## What was exercised

1. An agent proposed an immutable image change; the operator authorized the exact operation, target
   identity, and expected snapshot with `provision-snapshot-grant`.
2. An agent session read the operator's handle record, verified the configured boundary, checked
   status, and submitted the handle; the service returned `ACCEPTED` and the session ended while the
   rollout was still executing.
3. The service was lost at the `after_apply` seam (the existing demonstration pause point, after the
   conditional patch persisted) by SIGKILL, then restarted. Startup reconciliation observed the
   receiver without resending; the operation finalized while the rollout was still settling.
4. A new agent session reconnected to the same handle, polled status, retrieved the frozen receipt,
   and reported without re-submitting.
5. Stale approvals terminated as `NOT_ATTEMPTED / STALE_APPROVAL` with zero PATCHes. The recorded
   evidence does not resolve which receiver changes caused the rejections.
6. An inconclusive action was handed to a human: the operator retrieved the frozen receipt and
   verified it offline with `kapsel inspect`.

## Results

- Healthy run, no faults: `ACCEPTED` at T+0, `SUCCEEDED` with the rollout complete inside the
  service's observation window; the frozen receipt shows `write_strategy`
  `conditional-strategic-merge-patch`, the requested operation marker on the receiver, and
  `approved_target` distinct from `observed_target` (same UID, later resourceVersion).
- Service loss at the mutation seam: recovery stayed observation-only, never re-sent, and the
  receipt froze one observation snapshot. That snapshot caught the previous replica still
  terminating (`unavailable_replicas` 1, `Available` condition already `True`), so the result was
  terminal `UNKNOWN` even though Kubernetes completed the rollout roughly forty seconds later. The
  human handoff worked exactly as designed: the signed receipt gave the operator every receiver fact
  needed to decide, but the operation itself was already terminal.
- The service's receiver-observation window is bounded at 30 seconds. The experiment's rollout
  (60-second `minReadySeconds`) could not settle inside it after a restart, which is what produced
  the `UNKNOWN` above. The bounded window is shorter than the 45-180 second observation span this
  workflow asks for.
- Stale approvals: two of five submission attempts were reported as `NOT_ATTEMPTED / STALE_APPROVAL`
  with zero PATCHes and resourceVersion changes `500` to `591` and `494` to `586`. Those opaque
  version pairs do not identify the writes that caused them. The records conflict on status churn
  versus recreation and contain no per-attempt ledger to resolve the causes. The count is neither a
  representative rejection rate nor evidence that both changes were intent-irrelevant. Reapproval
  was reported as two seconds and three operator commands (new snapshot grant, service restart to
  load it, new handle record). No existing handle acquired replacement authority.
- Real agents and asserted authority: on first contact, both real agent sessions refused a
  submission requested through prompt-asserted authority alone, treating it as an injection. The
  invocation succeeded only after the operator published standing caller configuration and a handle
  record the agent could read and verify itself. In these two sessions, the caller needed a
  verifiable handle record as well as the operator-owned grant. Prompt-asserted authority alone was
  insufficient.
- Reconnecting agent behavior: the reconnected session checked status before anything else, refused
  to re-submit a handle that already had an outcome, attempted receipt retrieval for a status-only
  rejection (correctly refused by the client with no output), and reported the honest result. No
  caller-side recovery code was written by any agent session.
- The frozen receipt was sufficient for the human decision; signature verification added no
  additional consumer decision in this experiment beyond trusting that the frozen bytes were the
  journal's.

## Outcome

No agent session wrote bespoke recovery code. Kapsel retained attempted-action receipts and
status-only rejection facts, so reconnect did not require guessing an outcome or repeating the
mutation. The short observation window produced a concrete `UNKNOWN` handoff for a later healthy
rollout. Strict snapshot approval also produced reapproval work, with the rejection causes bounded
as above.

No equally protected typed tool ran in this experiment, so it establishes no relative operator
effort. The [protected-tool comparison](PROTECTED_TOOL_COMPARISON.md) tests equivalence in a
separate fixed-case fixture, not this live workflow.

## Smallest concrete gaps recorded

- The 30-second receiver-observation window is shorter than this workflow's own 45-180 second
  observation span, so post-`apply_started` recovery can terminalize a still-settling rollout as
  `UNKNOWN`.
- Whole-object resourceVersion churn invalidates exact-snapshot approval even when the desired image
  change is unaffected. This is an accepted semantic cost, not a defect or a frequency established
  by this experiment's mixed rejection accounting.

## Evidence boundary

The workflow results above summarize one disposable environment created by the harness and destroyed
afterwards. Raw per-case timestamps, status projections, and receipts are not included in this
repository, so the summary alone cannot resolve the mixed rejection accounting. No claim here
extends past the single operation, the pinned receiver, and the unpublished service composition.
Deterministic regressions for the same semantics run without any model call.

## Initial-observation policy follow-up

A separate source run exercised the approved [per-pass policy](EFFECT_GATEWAY.md#result-meaning)
through `ServiceApplication`, not the historical agent harness above. The tested source was base
`efb4b96ec7488172fb544035977edf42efd46ace` plus binary worktree diff SHA-256
`93f40082a2e88ca25766f66a4a9d414dff5f63c101ed7506dcda0225a274c813`. Both `./scripts/ci-local.sh` and
`./scripts/test-kind-effect-gateway.sh` passed on that snapshot. Reproduction and evidence
boundaries are described in [Build and test](BUILD.md#initial-observation-policy).

The host was Darwin 25.5 arm64 with Rust/Cargo 1.98.0, Docker 29.4.0, kind 0.33.0 and kubectl
1.33.9. The disposable receiver used
`kindest/node:v1.33.12@sha256:3f5c8443c620245e4d355cfe09e96a91ead32ceaa569d3f1ca9edf0cb2fe2ff4`. The
fixture created healthy original Deployments with 60- and 210-second minimum readiness periods
before acquiring exact approvals. It then changed the image through the service application.

| Readiness   | Frozen result | Worker duration                     | Audited PATCHes | Execution-window GETs |
| ----------- | ------------- | ----------------------------------- | --------------- | --------------------- |
| 60 seconds  | `SUCCEEDED`   | 57,646 ms after explicit resumption | 1               | 64                    |
| 210 seconds | `UNKNOWN`     | 180,041 ms                          | 1               | 180                   |

The first action was interrupted during observation and explicitly resumed after reopening the
application. API-server audit established a GET after PATCH and before cancellation. Total elapsed
time was 62,675 ms. The second action became available at 211,368 ms without changing its frozen
`UNKNOWN` or receipt. GET counts include preflight and are independent API-server counts within the
recorded execution window, not adapter-call counters.

Both cases reconnected stored reads while the worker survived and rejected B as `BUSY` without
admitting it. The stored status/receipt pair measured below one millisecond at the harness's
millisecond resolution. That is finite fixture evidence, not a read-latency guarantee. Worker timing
includes selection and completion around observation; it is not a direct measurement of timer
overshoot. The observation bound is not a hard real-time promise. Repeated interruptions have no
cumulative deadline under this policy.

This establishes the concrete longer-rollout benefit and honest cutoff in one disposable receiver.
It does not establish a success rate, installed-socket workflow, native-host qualification or
release support. The live run's application cancellation is not an OS process crash. Separate Linux
process tests own the socket/process boundary. Raw logs are not included here; the launcher emits
timings and independent audit totals and removes its owned cluster.
