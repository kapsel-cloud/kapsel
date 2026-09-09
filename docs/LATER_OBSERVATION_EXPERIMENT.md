# Later evidence without another mutation

Kind: experiment evidence. Not a supported command, new receipt, or production lifecycle.

The question is whether a later observation can help after `UNKNOWN` without turning that old result
into success or creating another mutation opportunity. The smallest useful answer is a separate
statement about the receiver **now**, beside the immutable statement about what Kapsel could
establish **earlier**. Even matching image, UID, generation, and operation marker do not establish
causation.

## Baseline and choice

The source baseline is `f787758ff3059c4340bac8a0382440a31c5ecb7e`. SQLite-owned receipt completion
is adopted in that unreleased source, not experimental or present in the published v0.2.0 beta.
Journal format 4 rejects older journals. The experiment uses only
`Application::read_set_deployment_image_receipt` to obtain the original signed bytes and digest. No
receipt file or direct journal query is a retrieval dependency. The
[effect-gateway contract](EFFECT_GATEWAY.md) remains authoritative.

Two approaches were compared before implementation:

- One bounded read reported beside the original receipt needs no result store. However, after caller
  or observer loss there is no durable distinction between an unused observation and lost output.
  Enforcing one acquisition across restart still needs a durable consumed slot.
- One separately retained observation needs that same slot plus one optional result. Reconnect can
  read the result without acquiring another observation. This is the chosen prototype.

The prototype is confined to `tests/later_observation.rs`. It is not callable by service, CLI, or
MCP consumers. The disposable runner acts as both the operator composition and scripted caller. It
introduces no production exports, wire formats, configuration, or dependencies. The only Cargo
change enables Tokio's test clock in development dependencies.

## Smallest semantics

1. Retrieve and inspect the original receipt through the application. Require the original operation
   identity, an inspected v3 receipt, matching SHA-256, and historical `UNKNOWN`.
2. In a separate operator-private disposable SQLite database, insert one row keyed by the original
   operation identity and bound to that original digest. Commit consumption before receiver I/O.
3. The winning insertion permits one GET of the namespace and Deployment from the inspected original
   receipt. The container and requested image also come from those bytes. No continuation argument
   selects a target, credential, grant, path, signing identity, or image.
4. Bound that GET at two seconds, with client retry disabled and a 1 MiB response-body limit in the
   live client. Retain a projection no larger than 4 KiB, including original identity/digest,
   `earlier_result: UNKNOWN`, an operator-clock acquisition start time, current availability,
   identity/image/marker comparisons, and generation relationship. The clock is not trusted
   ordering.
5. Retain read errors and deadlines explicitly. If the process loses its consumed slot before
   storing output, reconnect reports `consumed_without_evidence`. It never retries that slot.
6. Read the same retained result on reconnect. The original receipt remains the sole signed
   historical result. Supplementary evidence is unsigned and always says attribution is
   `not_established`. It never supplies a new `SUCCEEDED` or `FAILED` result.

A healthy replacement is still a replacement. A later generation is explicitly superseding. Unknown
or backward generation relationships remain unestablished. An image or marker can be written by
another actor. None of these observations renews approval or requests a replacement action. Ordinary
application status and receipt reads remain offline and do not invoke the prototype.

## Reproduction and proof placement

From the baseline plus this experiment's working-tree files:

```sh
cargo test --locked --test later_observation -- --nocapture
python3 scripts/test-kind-later-observation.py --self-test
python3 scripts/test-kind-later-observation.py
./scripts/format.sh
./scripts/ci-local.sh
```

No commit or publication is performed by these commands. The live launcher prints the baseline and
SHA-256 of each executable experiment input, including untracked source, without staging files. The
experiment must be committed separately before another checkout can consume it by Git revision.

The deterministic matrix executes the real application and adapter through a mock HTTP service. The
pending fixture remains pending for the actual 30-attempt observation loop, with virtual time rather
than a shortened production budget. The fixture asserts one PATCH and counts each GET at the HTTP
request boundary. After follow-up, restart, repeated retrieval, and status inspection it checks that
no further request arrives. It covers healthy later state, same-name replacement, superseding
generation, another actor's same-image state without the marker, a later template generation
retaining the marker, unavailable receiver, and the two-second deadline. These are controlled
receiver projections, not live Kubernetes proofs of those writers.

A subprocess exits with code 73 immediately after durable slot consumption. A fresh process/runtime
and reopened application retain the original bytes, successfully inspect them offline, and refuse
another acquisition from the consumed slot. This establishes a real process-loss seam, not
power-loss durability or all interruption schedules.

The separate live lane reuses the pinned pause digests and `minReadySeconds: 60` fixture from the
[reconnectable action experiment](RECONNECTABLE_AGENT_ACTION.md). Docker, kind 0.32+, kubectl,
Python 3.11+, and the repository Rust toolchain are required. It creates one uniquely named
Kubernetes v1.33.12 cluster, performs an exact-snapshot-authorized image change through Application,
waits for historical `UNKNOWN`, and waits outside the prototype for current availability before the
single follow-up. Application restart/reconcile and receipt reinspection must preserve exact bytes.
API-server metadata audit records independently require exactly one execution PATCH and exactly one
follow-up GET, with no other follow-up verb. This does not infer requests from adapter call counts
or from the historical classifier. The caller receives no kubeconfig. The test operator owns the
explicit disposable kubeconfig and uses the same credentials for execution and observation.

The Python launcher uses direct subprocess arguments, per-command deadlines, and an 8 MiB combined
output cap. Its focused regressions check audit rejection, command failure, timeout, and output
bounds without Docker. Configuration is emitted as JSON, with no YAML dependency or embedded
interpreter. Rust still owns the attempted-action experiment.

The launcher deletes only its owned cluster. It retains its local workspace path for inspection,
including result and audit logs. That workspace also contains the now-disposable administrator
kubeconfig and should be kept private and removed by its operator after reviewing evidence.

## Recorded results

The deterministic matrix passed all seven projections. Each preserved the original signed receipt
hash `da90021fec406fd6e5738005ac2f976df66fb830378f0c2a882a6d79cb8a94f1` across follow-up and
application reopen. The original result remained `UNKNOWN`. The loss child exited with code 73, and
reconnect produced no GET or PATCH. Failed reads and deadlines consumed the slot rather than
allowing another attempt. The full deterministic gate passed with the live test separately ignored.

The live slow rollout also reproduced `UNKNOWN` followed by current availability at the same UID and
generation 2. The API-server audit counted 31 execution GETs and one execution PATCH, then one
follow-up GET and no follow-up mutation. Restart and repeated retrieval did not increase those
counts. The next-action branch selected application-behavior inspection without another image
change. No signature, original receipt byte, or historical receiver result was rewritten.

The live-tested executable inputs are SHA-256 pinned below. These hashes identify the uncommitted
experiment on the baseline above, not a published artifact. The Python launcher passed the live
experiment with the same request counts. Its regression tests were subsequently folded into
`--self-test`, without changing the live experiment functions. The hash below predates that
mechanical consolidation; self-tests and static checks passed afterwards. Each live run records its
current input hashes in `source.sha256`:

```text
Cargo.toml
670abc2cbe254d849a4fae1baeba7c7f967695f98a626e31ac5da11b8efc8bce
tests/later_observation.rs
0a94aa0b54d9d72fe7e669b90de220fd1fd162def33244388956af2cc43d63aa
scripts/test-kind-later-observation.py
e5f31d1caf0fff82128606bb4a1c3d00947be82d5ad7e1645950c0b6c6780d2d
```

## Operator and caller work

The operator creates the receiver, keys, exact snapshot approval, application, and private storage.
In the experiment those are fixture functions, not an installer. After `UNKNOWN`, the operator waits
for the slow fixture outside the two-second follow-up budget. A real invocation would need an
explicit operator decision about when to spend its sole observation. There is no scheduler, polling
service, new caller authority, approval refresh, or automatic retry/rollback.

The scripted continuation retrieves the old receipt, invokes one explicitly separate observation,
then retrieves the same old bytes and retained supplementary result after restart. That continuation
is new experiment-specific code. It has not eliminated caller integration work or demonstrated an
advantage over an equally protected typed tool.

For the slow healthy fixture, the concrete next action changes from inspecting a still-pending
rollout to checking application behavior without retrying the image change. For a replacement,
superseding generation, or missing image/marker, investigation of intervening state remains needed.
For read failure or consumed-without-evidence, the old human handoff remains. None of these branches
proves the original request caused current health.

## Recommendation and residual risk

Retain this as evidence for a separate contract decision, not production adoption. One later
snapshot can answer a useful current-state question. It does not repair the historical result or
solve attribution. Choosing the acquisition time is operator work, and a one-shot budget can be
spent too early or lost with the process.

The extra private database is deliberate experiment apparatus, not a proposed general store. Its
small consumed/result protocol still adds retention, backup, ownership, and crash-window
obligations. Deletion or rollback of that database defeats its at-most-one acquisition assumption. A
production choice must resolve those obligations with the canonical journal owner rather than
install a second unmanaged store. SQLite/process fixtures do not prove hardware durability, hostile
filesystem safety, HA, credentials with revoked read permission, or unbounded schedules. Current
availability is only Deployment availability, not application health or a trustworthy Kubernetes
state claim.

## Complexity delta

- Contract owner: unchanged effect-gateway and service contracts. This document owns only evidence.
- Knowledge hidden: the test-only slot combines original receipt binding, consumption, and result
  retention. It cannot dispatch a mutation.
- New surface: one test module, one disposable launcher, one private experimental row, development
  test-clock support. No production command or configuration.
- Existing rule duplicated: no historical receiver classifier. The current-availability projection
  checks ordinary Deployment fields and is explicitly not an action result.
- Rejected alternative: output-only follow-up loses useful reconnect evidence while still needing
  durable consumption to enforce the issue's acquisition bound.
- Removed code: none. No production path is superseded or silently adopted.
- Proof boundary: real application retrieval and offline inspection, independently asserted HTTP
  methods, process exit/reopen, and live API-server request audit.
