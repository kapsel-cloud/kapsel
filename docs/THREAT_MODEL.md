# Threat model

> A durable operation record narrows crash ambiguity. It does not make a provider action exactly
> once, prove the receiver is truthful, or prove no action bypassed Kapsel.

Status: active experiment design.

Kind: design. Authority: adversaries, surviving claims, and explicit non-claims for the Kubernetes
effect-gateway experiment.

Owns: Experiment threat analysis, result limits, and security assumptions.

Does not own: Kubernetes authorization policy, credential operations, public-sandbox HTTP grammar or
deployment configuration, or production assurance.

## Assets and seams

The experiment protects the integrity of disclosed experiment receipt bytes, the distinction between
a durable Kubernetes attempt and an observed outcome, bounded offline inspection, and the ability to
identify an unresolved crash window.

The relevant seams are:

- request-only agent intent and the application composition boundary;
- separately provisioned owner-signed exact grant and out-of-band application-configured grant
  trust;
- effect-gateway journal and signing key;
- Kubernetes credentials and API;
- Kubernetes deployment controller and observed rollout state;
- receipt transport and offline inspector; and
- externally supplied inspection trust.

Collusion, compromised credentials, or a bypassed gateway remove independence. The receipt must not
imply otherwise. Historical [public sandbox API](SANDBOX_API.md) and
[deployment](SANDBOX_DEPLOYMENT.md) documents preserve analysis of the retired hosted controls.

## Surviving claims

| Event                | What Kapsel can establish                                                       | What remains unproven                                                             |
| -------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Authorized request   | An owner-trusted key signed the exact fixed-purpose operation grant.            | That Kubernetes RBAC permits it or a human made the decision.                     |
| `not_attempted`      | A permanent target rejection occurred before any mutation attempt was recorded. | A receiver failure, unknown receiver state, or Kubernetes write outcome.          |
| `apply_started`      | Target identity and the attempt marker committed before the Kubernetes attempt. | That Kubernetes received, applied, or rejected the request.                       |
| Receiver observation | Kubernetes reported the disclosed classifier inputs at the observation point.   | Causation, complete cluster state, or that no other actor changed the deployment. |
| Signed receipt       | The signing key authenticated classifier-complete bytes and recomputed result.  | Truth, authority beyond the grant, or completeness.                               |
| `UNKNOWN`            | Defined bounded reconciliation could not establish a result.                    | Failure, success, safety, or harmlessness.                                        |

## Principal threats

### Ambiguous provider attempt

Permanent missing or invalid targets become terminal `not_attempted` dispositions before the
mutation marker; transient reads are deferred fairly so one operation cannot block all later work.
Neither path becomes a receiver result.

The process can fail after Kubernetes receives a request but before Kapsel records the response.
Kapsel first safely validates the target, atomically records target identity with `apply_started`,
and then reconciles by observation after ambiguity. It must not blindly apply again or promote a
timeout into `SUCCEEDED` or `FAILED`.

### Demonstration fault-control misuse

The release harness must stop processes at two exact crash windows without adding lifecycle control
to agent input. Ordinary builds contain no demonstration pause behavior. The separately built
`demo-harness` executable accepts only two fixed environment-selected seams and one owner-private
control directory; malformed, partial, symlinked, or repeated controls fail closed. This feature is
an evaluator mechanism, not an authorization boundary or a production-safe binary. Anyone able to
replace the executable or its process environment already controls that local demonstration process.
Markers and the harness-owned apply counter make no claim about Kubernetes truth or exactly-once
real-world effects.

### MCP transport confusion and hostile input

The local MCP client can send malformed, duplicated, oversized, out-of-order, or unknown protocol
messages, attempt another tool, or place operator authority in tool arguments. The fixed stdio
adapter bounds each frame before JSON allocation, rejects duplicate and extra fields, exposes one
five-field tool, loads operator configuration separately at process startup, and returns only
bounded protocol or typed application vocabulary. Standard output is protocol-only. Cancellation,
disconnect, or transport completion cannot establish that an application operation was unattempted,
failed, rolled back, or safe; restart uses the same application reconciliation semantics.

### Release substitution or provenance overclaim

An archive or checksum can be replaced, built from a dirty tree, mislabeled for another target, or
presented as authenticated because its SHA-256 matches. Release assembly records the exact source
revision, dirty state, target, pinned builder, and binary digests; normalizes archive bytes; and
checks the final archive digest before extraction. Clean smoke rejects unsafe entries and executes
only extracted bytes. These controls detect mismatches and make assembly repeatable; they do not
sign the archive, authenticate a publisher, witness build inputs, prove source review, support other
targets, or establish production safety.

### Authorization mismatch or excessive authority

An agent can request destructive or broader operations or construct self-asserted authorization. The
experiment accepts only one exact namespace, deployment, container, and immutable image digest in a
fixed-purpose grant signed by the configured owner key. The application receives that grant, trust,
Kubernetes client, signing material, and paths through operator configuration; its request-only
caller cannot select them. Trust is never taken from agent or grant contents. This reduces the
gateway input surface; it does not replace Kubernetes RBAC or prevent credential misuse outside
Kapsel.

### Gateway bypass

Another actor holding Kubernetes credentials can change the deployment without Kapsel. The
experiment cannot detect universal capture. Receipts name one Kapsel operation, not all operations.

### False or changing receiver state

Kubernetes reports may be stale, incomplete, or overwritten by another change after observation.
Kapsel records bounded facts, including deployment identity and generation, and states result
meaning narrowly. It does not claim Kubernetes truth or causal attribution.

### Secret, response, and receipt disclosure

Agent input, SQLite, reports, and receipts must not contain Kubernetes credentials, signing keys, or
unbounded provider response bodies. Private paths are validated before use. Receipt fields can still
disclose deployment identifiers, image digests, timing, and operational relationships.

### Malicious receipt input

Offline inspection input may be malformed, oversized, self-trusting, or substituted. Parsing and
reports are bounded, inspection uses explicit external trust, and no inspection step performs
network access.

## Historical public sandbox threats

KAP-0070 closed the hosted route through fallback and KAP-0073 removed its deployable
implementation. This section preserves the threat analysis for historical evidence; none of these
controls is an active product or deployment claim.

The sandbox was designed to be anonymous and intentionally disclose fixed synthetic demonstration
evidence. A high-entropy run locator limits opportunistic enumeration but is a bearer locator, not
authentication or confidentiality. Anyone who obtains it before expiry can read that run's public
projection and unchanged receipt.

### Abuse, enumeration, and denial of service

An attacker can flood admission, vary idempotency keys, replay requests, guess run identifiers, hold
capacity, or exhaust cluster, subnet, store, signer, receipt, telemetry, and cleanup resources. The
required same-origin edge enforces the authoritative per-source bound before forwarding through a
private authenticated channel; visitor-supplied forwarding and source headers are stripped. The
native listener is not publicly reachable and enforces global connection/body bounds, global stop,
queue bound, active reservation, and idempotency before committing a run. The edge stores no source
identity in sandbox run state or public output. Saturation creates no run and retry hints disclose
no capacity count. Malformed and absent run identities receive the same `run_not_found`; expired
tombstones reveal no scenario or outcome. These controls bound owned work but do not guarantee
availability or fair use under a distributed attack.

Idempotency keys are caller-generated 128-bit correlation and bearer replay locators, not browser or
authority identities. The service stores only their required private mapping and a keyed digest in
bounded diagnostics, never echoes them, and reserves them through the expiry tombstone. During live
retention, a repeated key and changed scenario fails before dispatch; during tombstone retention,
any matching key returns only `run_expired` regardless of scenario.

### Admission, scheduling, and outcome confusion

HTTP success establishes durable sandbox admission only. It does not establish Kapsel submission,
Kubernetes request acceptance, mutation, rollout, receipt publication, or cleanup. Scheduler lease
expiry, runner crash, edge timeout, disconnect, replay failure, sandbox deadline, store failure, and
cleanup failure remain sandbox facts. Only an unchanged KAP-0038 `OperationReport` can populate a
receiver result or pre-attempt rejection, and recovery uses the same operation identity without a
blind second mutation.

### Correlation and disclosure

Run locators, whole-second admission/event times, scenario, synthetic operation identity, result,
and classifier-complete receipt can be correlated across requests or copied outside the service. The
fixed scenarios use no visitor, customer, or production data. Public receipt identifiers are
server-chosen synthetic evidence. Private host runner identities, leases, journal/outbox paths,
controller-volume and staged-input paths, cluster/provider identifiers, credentials, raw journal
rows, uncontrolled logs, and fault controls are excluded. Bounds and retention reduce exposure but
do not establish anonymity or unlinkability.

### Compromised workload and namespace escape

A fixed image or dependency can attempt Kubernetes API access, cross-namespace discovery,
metadata/identity access, network egress, volume reads, resource exhaustion, or a container/runtime
escape. The one active run receives a policy-complete namespace, target identity, quota, limits,
default-deny network policy, restricted security context, server-owned deadline, and independently
proved sandboxed-runtime-or-equivalent boundary in a dedicated synthetic cluster. The target must be
denied the operator canary, unrelated resources, host/controller state, receipts, keys, runner and
cleanup authority, and prior-run artifacts.

Namespaces, RBAC, quotas, NetworkPolicy, and a runtime label were not hard isolation or enforcement
proof. The retired Gate 3 would have tested the selected runtime, network implementation, metadata
path, and Kubernetes authority; KAP-0073 cancelled that live gate. A container or kernel escape can
still compromise the dedicated cluster. No production or customer workload may share it.

### Compromised native runner and host boundary

A compromised native runner can use its loaded exact grant, receipt-signing input, and scoped
Kubernetes credential; corrupt its journal/outbox; forge its authenticated handoff; or attack paths
and services reachable from its OS identity. It is more powerful than the target workload. The
selected route uses one fresh least-privilege OS identity and directory per run, fixed read-only
descriptor-relative inputs, exact owner/mode/no-follow and same-inode checks, stale
process/descriptor/lease denial, and separate cleanup authority. The runner must be denied
controller SQLite, immutable receipts, staged sources, prior journals, the canary, and unrelated
cluster resources.

The accepted Slice 2 boundary pins roots before dispatch, opens only fixed names no-follow, checks
exact controller owner/group and `0400` mode plus same-inode reopen, and transfers the individual
read-only descriptors through one fixed `SCM_RIGHTS` message. A fixed reviewed C helper clears
supplementary groups, installs the generation's real/effective/saved UID/GID, closes unrelated file
descriptors and the parent-death race, and enables `no_new_privs` before Rust runner runtime. One
private cgroup-v2 generation fences descendants. Durable reopen, exact journal transition recovery,
production composition, complete denial evidence, its x86-64 Linux execution gate, and fresh review
passed for the accepted offline Slice 2 host boundary. That proof does not establish cluster
runtime, CNI, RBAC, admission, metadata, or network enforcement.

The focused KAP-0070 follow-up freezes the privileged controller/helper bootstrap at exact
`E=P=B={CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_KILL,CAP_SETGID,CAP_SETUID,CAP_SETPCAP,CAP_SYS_ADMIN}`
and `I=A={}`. `CAP_NET_RAW` represents unexpected inherited authority. The helper rejects a helper
or runner `security.capability` observed at each pinned check, normalizes unlocked supersets,
refuses locked `KEEP_CAPS` or `NO_SETUID_FIXUP`, and verifies securebits and all five capability
sets at zero with `no_new_privs=1` before the Rust runtime can receive descriptors. A Rust
`/proc/self/status` backstop independently rejects nonzero inherited capability state. A privileged
parent can race a file-capability xattr between checks; the zero bounding/permitted/effective sets,
`no_new_privs`, and Rust backstop contain resulting authority rather than proving independence from
that parent. Linux subset constraints mean some hostile cases necessarily carry the representative
in prerequisite sets; this does not weaken the separately asserted target-set coverage.

The mount namespace prevents propagation and creates the fixed state alias but does not conceal the
remaining host filesystem. This follow-up selected no seccomp, Landlock, or equivalent syscall/path
confinement; the unrestricted native path/syscall surface remains an explicit historical non-claim.
The pinned C-source/compiler identity and exact helper/runner bytes remain supply-chain inputs to
the planned authenticated bundle rather than proof of final bundle reproducibility.

OS users and a sandboxed process are not hard tenant isolation. Symlink/path substitution, parent or
inode replacement, leaked descriptors, permissive groups, stale processes, ptrace/kernel escape, and
local network reachability are explicit adversaries. Detection activates durable stop, preserves
frozen facts, revokes the runner generation, rotates affected inputs through separately owned trust,
and reconciles/cleans the admitted run without rewriting its receiver result. No receipt claims
independence from the runner or signing authority.

Journal loss, rollback, cloning, or concurrent execution can omit facts or create unsafe recovery.
Runner-process loss with the same journal remains a KAP-0038 seam; controller-process restart may
resume only from the same present, validated state. Controller-host or storage loss is catastrophic
sandbox unavailability. Independent exposure authority withdraws traffic; no old run gains a result,
receipt, cleanup absence, or capacity release. A new controller cannot initialize against a possibly
surviving old cluster. The operator must revoke reachable authority, tear down the complete fixed
provider inventory, prove cluster/volume/process/cgroup/state/endpoint/DNS absence independently of
the lost database, create a fresh stopped composition, validate readiness, and explicitly reopen.
Failure to prove absence retires the hosted proof.

### Controller-host, key, storage, and receipt failure

The controller host concentrates admission, projection, receipt, scheduler, cleanup, cluster
credentials, and staged-input coordination. Host compromise can alter public state, suppress
cleanup, substitute runner inputs, or deny all service. Host/storage loss can erase admitted
projections and receipts before nominal expiry; Kapsel reconstructs none of them and makes no
availability or disaster-recovery claim.

Authorization, receipt, tombstone, public trust, runner Kubernetes, cleanup Kubernetes, and handoff
inputs retain separate fixed owners and exact staged-generation validation while state is intact.
Missing or malformed authority holds dependent transitions and cannot manufacture lifecycle or
receiver facts. The narrowed route deletes backup generations, backup references, restore markers,
backup identities, and replacement-host commands. Possession of old source or archived checkpoint
`bde1e3b` is not a deployable recovery route.

Independent endpoint cutoff and automatic exposure expiry must remain usable when controller state
is absent or suspect. Cutoff does not cancel, classify, revoke all already held authority, or prove
cleanup. Complete provider-level absence—not a name or label scan—precedes clean recreation.

### Cleanup failure and unsafe deletion

Namespace deletion is asynchronous and can stall on finalizers or API/controller failure. The local
cleanup role uses a separate fixed credential, recorded UIDs and ownership labels, durable retry,
owned-orphan scans, and bounded escalation; it never deletes by a reusable name alone. Public expiry
and client disconnect do not release cleanup ownership or the sole capacity reservation, and no next
run dispatches before complete recorded absence. A compromised cleanup credential can still exceed
software checks within its RBAC. Wrong UID/owner, canary access, stale inventory, host loss, API
outage, and failure to erase prior-run state before dispatch require explicit denial/recovery proof.

### Dependency and image compromise

The HTTP, database, Kubernetes client, base image, scenario image, CNI, runtime, cluster, receipt
store, and key service are supply-chain inputs. Exact versions, provenance, vulnerability response,
rollback, and image immutability would have required fresh live evidence; KAP-0073 cancelled that
route, and historical KAP-0053 fixtures are not authority. Pinning and scanning reduce but do not
eliminate malicious dependencies or registry/control-plane compromise.

### Global stop misuse or failure

An attacker or operator mistake can activate the global stop, prevent activation, or scale away the
components needed for recovery. Stop state is durable and fail-closed for new admission while intact
validated state keeps retained reads, recovery, receipt retrieval, retention, and cleanup available.
Its control path is separately authenticated and not public. Host/storage loss instead uses
independent endpoint withdrawal and clean-start stop. Neither mechanism can undo an admitted run,
revoke all already held cluster authority, classify an outcome, or prove cleanup.

## Non-claims

The experiment does not establish:

- exactly-once real-world Kubernetes mutation;
- Kubernetes truth, workload correctness, or complete cluster health;
- authorization legality, policy compliance, or complete capture;
- causation between a Kapsel request and a receiver state;
- complete history, non-omission, or no gateway bypass;
- independent witnessing, trusted existence time, or `VERIFIED`; or
- production readiness, authenticated confidentiality, anonymous fairness, or hard tenant isolation.

## Security assumptions

- The owner protects Kubernetes credentials, SQLite storage, and signing keys.
- Kubernetes RBAC limits the configured credential to the experiment's intended scope.
- The `kind` cluster is disposable and controlled by the demonstrator.
- The deployment controller exposes the documented receiver facts needed for the experiment's result
  classification.
- External trust supplied to offline inspection is reviewed separately from receipt bytes.
- The public sandbox cluster contains only synthetic non-consequential targets plus an operator
  canary; the operator protects the native controller host/volume, staged inputs, and fixed
  controller, runner, cleanup, target, key, exposure, and operator authorities.
- The host OS identities/path controls and the selected Kubernetes runtime, network implementation,
  RBAC/admission policy, storage, and cleanup behavior enforce the exact serialized configuration
  were never proved live. KAP-0073 cancelled that route; contract text and historical KAP-0053
  Pod/PVC, workload-identity, stager, or provider evidence cannot establish enforcement.
