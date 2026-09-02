# Threat model

> A durable operation record narrows crash ambiguity. It does not make a provider action exactly
> once, prove that the receiver is truthful, or prove that no action bypassed Kapsel.

This page owns adversaries, surviving claims, assumptions, and non-claims for the active Kubernetes
effect gateway and the unpublished service boundary. The
[effect-gateway contract](EFFECT_GATEWAY.md) owns exact semantics; [technical scope](SCOPE.md) owns
maturity and support posture.

## Assets, trust, and seams

Kapsel protects the integrity of disclosed receipt bytes, the distinction between a durable attempt
and an observed outcome, bounded offline inspection, and visible unresolved crash windows.

The relevant seams are:

- request-only caller intent and the `Application` composition boundary;
- a separately provisioned owner-signed exact grant and operator-configured grant trust;
- the private journal, receipt directory, and signing key;
- Kubernetes credentials, API, controller, and observed rollout state;
- receipt transport and the offline inspector; and
- externally supplied inspection trust, time, and limits.

The owner protects credentials, journal storage, signing material, and inspection trust. Kubernetes
RBAC should limit the configured credential to the intended target, but Kapsel's concrete
adapter—not RBAC—owns the image-only patch. Collusion, compromised credentials, compromised host
administration, or bypass of the gateway removes independence. Receipts must not imply otherwise.

## Surviving claims

| Event                | What Kapsel can establish                                                                | What remains unproven                                                      |
| -------------------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Authorized request   | An owner-trusted key signed the exact fixed-purpose operation grant.                     | RBAC permission, legal authority, or a human decision.                     |
| `NOT_ATTEMPTED`      | A permanent target rejection finished before a mutation attempt was recorded.            | A receiver result, receiver failure, or Kubernetes write outcome.          |
| `apply_started`      | Target identity and attempt marker committed before the Kubernetes attempt.              | That Kubernetes received, applied, or rejected the request.                |
| Receiver observation | Kubernetes reported the disclosed classifier inputs at the observation point.            | Causation, complete cluster state, or absence of another writer.           |
| Signed receipt       | The signing key authenticated frozen classifier bytes; inspection recomputed the result. | Truth, authority beyond the grant, causation, or completeness.             |
| `INSPECTED`          | Signature, trust, bounds, and classifier consistency passed under supplied data.         | Kubernetes truth, causation, complete capture, compliance, or `VERIFIED`.  |
| `UNKNOWN`            | Bounded reconciliation established neither defined receiver result.                      | Failure, success, no effect, safety, harmlessness, or permission to retry. |

## Principal threats and controls

### Ambiguous provider attempt and recovery

Permanent missing or invalid targets become terminal `NOT_ATTEMPTED` before the mutation marker;
transient reads defer fairly. Neither disposition becomes a receiver result.

The process can fail after Kubernetes receives a request but before Kapsel records the response.
Kapsel safely validates the target, atomically records target identity with `apply_started`, and
only then attempts the conditional patch. Recovery from ambiguity observes the same target and
requested image. It never blindly applies again.

Request acceptance, transport completion, process exit, and command success establish no rollout
result. A timeout or evidence that satisfies neither exact classifier is `UNKNOWN`, not `SUCCEEDED`
or `FAILED`.

### Authorization mismatch or excessive authority

A caller may request broader or destructive behavior or supply self-asserted authorization. Kapsel
accepts one exact namespace, Deployment, container, and immutable digest-bound image under a grant
signed by the configured owner key. The operator supplies grant, trust, Kubernetes client, receipt
key, journal, and paths outside the request. Trust never comes from caller or grant contents.

This narrows caller authority but does not replace Kubernetes RBAC or prevent someone who
independently holds credentials from bypassing Kapsel. A receipt covers one Kapsel operation, not
every cluster change.

### MCP confusion and hostile input

A local MCP client can send malformed, duplicated, oversized, out-of-order, unknown, or wrong-tool
messages and can try to place operator authority in arguments. The fixed stdio adapter bounds frames
before JSON allocation, rejects duplicate and extra fields, exposes one five-field tool, loads
operator configuration at startup, and returns bounded protocol or typed application vocabulary.
Standard output is protocol-only.

Cancellation, disconnect, late messages, or transport completion cannot establish that an operation
was unattempted, failed, rolled back, or safe. Restart uses ordinary application reconciliation.

### Demonstration control misuse

The bundled harness stops a process at two fixed crash windows without adding lifecycle control to
caller input. Ordinary builds contain no pause behavior. The separately built executable accepts
only fixed environment-selected seams and an owner-private control directory; malformed, symlinked,
partial, or repeated controls fail closed.

The harness is evaluator tooling, not a production binary or authorization boundary. Anyone able to
replace its executable or process environment already controls that local process. Markers and its
apply counter do not prove Kubernetes truth or exactly-once real-world effects.

### False or changing receiver state

Kubernetes observations may be stale, incomplete, deceptive, or overwritten by another actor. Kapsel
records bounded facts including target identity and generation and classifies only those facts. It
does not claim Kubernetes truth, workload correctness, causal attribution, or complete cluster
health.

### Receipt substitution and malicious inspection input

Receipt bytes may be malformed, oversized, self-trusting, reordered, or substituted. Parsing and
reports are bounded. Inspection takes trust, evaluation time, and limits explicitly, recomputes the
result from every signed classifier input, and performs no network or ambient lookup.

Receipt signing authenticates frozen Kapsel evidence under the named key. It does not witness the
effect, prove existence time, prevent omission, or make disclosed receiver facts true. Immutable
publication protects the selected frozen bytes and path; it is not generic durable storage or
backup.

### Secret and metadata disclosure

Caller input, SQLite, reports, receipts, errors, and logs must not contain Kubernetes credentials,
signing keys, private trust decisions, or unbounded provider response bodies. Private paths are
validated before use. Receipts still disclose identifiers, image digests, timing, receiver facts,
key identities, and operational relationships. [Privacy](PRIVACY.md) owns the disclosure checklist.

### Release substitution and provenance overclaim

An archive or checksum can be replaced, built from another tree, or mislabeled for another target.
Assembly records source, tree, lockfile, target, builder, and binary identities; normalizes output;
and checks final digests before extraction. Publisher authentication covers the signed digest
manifest and named bytes.

Checksums alone do not authenticate a publisher. Reproducibility and Sigstore identity do not prove
source review, workflow or builder integrity, dependency safety, current non-withdrawal, production
fitness, or another platform. [Release artifacts](RELEASE.md) owns exact controls and limits.

## Unpublished service boundary

The service adds a local admission and lifetime boundary but does not change gateway semantics. The
locked service identity owns exact mode-`0700` configuration and state roots and mode-`0600`
authority and state files. Callers can traverse only the mode-`0750` runtime directory and use its
mode-`0660` group-owned socket; Linux peer credentials must report the exact caller-group effective
GID before any frame is read. Supplementary membership alone is not authentication.

Startup opens fixed configuration, state, receipt, and runtime roots descriptor-relatively, rejects
symlinks, consumes validated regular single-link authority files, and reconciles before admission.
It leaves every unexpected leaf unchanged and removes only an exact inactive service-owned stale
socket. Systemd owns process lifecycle, failed-start runtime cleanup, health, and diagnostics, with
no automatic restart. One in-flight submission is a bound, not a queue. `ACCEPTED` means only that
the process owns execution; it is never `SUCCEEDED`.

The exact Role allows namespaced `get` and `patch` on one Deployment. Because RBAC cannot constrain
patch fields, the concrete adapter remains the field-level authority owner. Host root, kernel,
service identity, and already authenticated caller processes remain trusted. Membership revocation
does not change credentials cached by an existing process, so the operator must stop relevant
service and client processes.

One disposable Debian 12 qualification lane supplies bounded service evidence for accounts, systemd,
short-lived credentials, namespaced RBAC, clean installation, revocation, retained data, and
cleanup. It does not establish production safety or support for another environment.

Service and installer code in repository HEAD is unpublished and absent from v0.2.0. Installer tests
currently cross only bounded operator input, clean-install preflight, durable transaction recovery,
and two fixed group mutations; they do not establish a runnable installation. The exact authority,
filesystem, recovery, qualification, and unsupported boundaries are owned by
[Kapsel service](KAPSEL_SERVICE.md).

## Non-claims

Kapsel does not establish:

- exactly-once real-world mutation;
- Kubernetes truth, workload correctness, or complete cluster health;
- authorization legality, policy compliance, or complete capture;
- causation between a Kapsel request and a receiver state;
- complete history, non-omission, or absence of gateway bypass;
- independent witnessing, trusted existence time, or `VERIFIED`;
- confidentiality, anonymity, fairness, or hard tenant isolation; or
- production readiness, availability, remediation, backup, high availability, or another platform.

## Assumptions

- The operator protects Kubernetes credentials, journal storage, receipt signing keys, and private
  paths.
- Kubernetes RBAC limits the configured credential to the intended experiment scope.
- Demonstration `kind` clusters are disposable and controlled by the evaluator.
- The Kubernetes Deployment controller exposes the receiver facts required by the classifier.
- Inspection trust, time, and limits are reviewed separately from receipt contents.
- For the unpublished service, host root, kernel, systemd, and the service identity are trusted.
