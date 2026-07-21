# Review

Status: active procedure.

Kind: design. Authority: review procedure.

Owns: Contract-first review workflow and review result shape.

Does not own: Contract truth, build commands, test philosophy, or task status.

## Commit subjects

Use a plain domain-oriented subject:

```text
<domain>: <imperative result>
```

Examples:

```text
k8s: preserve receiver generation across recovery
docs: tighten the active capability contract
```

## Loop

1. State the contract changed and name its owner.
2. Check dependency direction and whether a new seam is real.
3. Check bounds before allocation, I/O, or diagnostics.
4. Check durable transition ordering and crash recovery.
5. Check assertions versus typed operating/adversarial errors.
6. Check deterministic inputs and ambient authority.
7. Check comments for non-local context rather than syntax narration.
8. Run the narrowest meaningful proof from [Build](BUILD.md).
9. Review the diff for duplicated truth and stale status.
10. Update the owner, rationale, guide, or task according to its job.

## Active KAP-0038 questions

- Does agent input remain one exact bounded operation without credentials, shell, manifest, patch,
  tag, or wildcard?
- Did the request receive authority from operator-controlled input, or from its own contents?
- Does a permanent target rejection become terminal `not_attempted` before the mutation marker, and
  does transient retry deferral avoid head-of-line blocking?
- Is the durable mutation marker committed before the mutation and interpreted no more broadly than
  the owner allows?
- Can any timeout, crash, provider response, or retry become a false receiver outcome?
- Does recovery issue a second mutation, or only bounded observation?
- Are target identity, request acceptance, and receiver facts still distinct?
- Are `SUCCEEDED`, `FAILED`, and `UNKNOWN` classified only from owner-defined frozen facts?
- Are receipt bytes built only from frozen authorization, target, strategy, and receiver facts, and
  is the result recomputed from every signed classifier input?
- Can hostile receipt, trust, path, SQLite, or Kubernetes input allocate, block, follow a symlink,
  panic, or disclose an unbounded value before rejection?
- Does offline inspection receive trust, time, and limits explicitly and perform no network or
  ambient lookup?
- Did a prototype receipt, adapter, or test seam become a generic public interface without a second
  real use?
- Is planned MCP/application behavior still labeled planned?

## Public sandbox questions

- Does the caller choose only `healthy` or `unavailable-image` plus a bounded idempotency key?
- Is durable admission still distinct from scheduler work, Kapsel submission, receiver outcome,
  receipt availability, and cleanup?
- Can timeout, disconnect, HTTP status, lease loss, storage failure, or cleanup populate or alter a
  KAP-0038 result?
- Does replay remain contiguous, bounded, retained, and independent of internal journal/fault
  states?
- Are raw receipt bytes unchanged, with trust appointed separately and synthetic disclosure
  explicit?
- Are run IDs unguessable bearer locators without becoming authentication or anonymity claims?
- Do global stop and saturation fail before admission while retained reads/recovery/cleanup
  continue?
- Is every run policy-complete before dispatch, and does cleanup delete only recorded UIDs?
- Are private runner/store/control-plane identifiers, paths, credentials, uncontrolled logs, raw
  journal rows, and fault controls absent from every public field and fixture?
- Did a contract choice accidentally select a provider, framework, store, generic protocol package,
  production interface, or second capability?

## Documentation review

- Current owners state what they own and refuse to own.
- Scope, experiment, architecture, threat, guide, task, and decision jobs are not mixed.
- Guides describe commands that exist; planned commands are explicit.
- Status appears only where the document's audience can act on it.
- Strong claims name trust, evidence, causality, completeness, and witnessing limits.
- Local links and heading anchors resolve.
- Deleting a new document would spread current knowledge; otherwise merge it.

## Result shape

```text
Contract:
Owner:
Surface:
Gate:
Good:
Findings:
Risk:
Next action:
```

A clean review says what was checked and what remains unproved.
