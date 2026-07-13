# Testing

Status: active experiment strategy.

Kind: design. Authority: proof strategy for current work.

Owns: Test placement, deterministic inputs, hostile-input coverage, and recovery proof expectations.

Does not own: Build commands, technical scope, or exact receipt bytes.

## Short answer

The active Kubernetes experiment must be tested through its one deep interface: authorized
`kubernetes.set_deployment_image` request in, durable state and inspected receipt out. Internal
tests may exist for parsers and pure state transitions, but the important proof is crash recovery
across provider-attempt windows.

## Required proof stack for KAP-0038

| Layer                | Required proof                                                                                           |
| -------------------- | -------------------------------------------------------------------------------------------------------- |
| Request validation   | Namespace, deployment, container, digest, authorization, and operation identity bounds.                  |
| Authorization        | Signed grant parsing, application-configured trust, exact tuple, and pre-persistence rejection.          |
| Journal transition   | Every durable state has a deterministic fault-injection test.                                            |
| Target disposition   | Missing/invalid target becomes terminal `not_attempted`; transient reads defer fairly without blocking.  |
| Provider attempt     | Safe target GET precedes atomic target identity plus `apply_started`; mutation follows that commit.      |
| Recovery             | Reopen after every injected window and real process kill reconciles without a blind second apply.        |
| Receiver observation | Request acceptance and rollout outcome remain distinct.                                                  |
| Receipt/inspection   | Canonical vectors carry all classifier inputs; inspection recomputes result under explicit trust/limits. |
| Publication          | Exact bytes/path/digest/key ID freeze before publication; no-follow paths, fsync, kill recovery.         |
| Migration            | Legacy self-asserted authorization fails closed rather than being promoted to trusted provenance.        |
| Hostile input        | Malformed, oversized, duplicate, reordered, unknown, and trailing grant/receipt records fail closed.     |
| Disclosure           | Secrets and unbounded provider bodies do not enter SQLite, receipts, reports, errors, or logs.           |

## Determinism

Default semantic tests do not depend on wall-clock time, random keys, live cloud services, ambient
trust, locale, or filesystem ordering. Use fixed keys, explicit evaluation time, temporary private
directories, seeded inputs, and sorted output. Subprocess kill tests may use a bounded monotonic
coordination deadline and marker-file polling; result semantics must not depend on the polling
schedule. Use deterministic `kind` setup where a test actually crosses Kubernetes.

A live `kind` demonstration is allowed only when its setup and cleanup are explicit. It does not
replace fault-injection tests around the journal. Process-kill tests must cross both the ambiguous
mutation seam and the receipt-publication seam. They must prove that recovery does not issue a
second mutation and does not re-sign or relocate already prepared receipt bytes.

## Review record

Meaningful changes report:

```text
Contract: <owner document>
Surface: <validation | journal | recovery | receipt | demo | docs>
Gate: <narrowest command run>
Risk: <what remains unproved>
```
