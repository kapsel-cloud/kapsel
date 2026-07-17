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

## Placement and ownership

Tests live at the lowest layer whose interface states the behavior under test. Moving a test outward
must not require widening a production seam, and crossing a deeper interface must add a distinct
contract assertion rather than repeat the same implementation matrix.

| Location                                 | Owns                                                                                             |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Implementation-local `#[cfg(test)]`      | Pure parsing, classification, SQL and filesystem invariants, and private adapter or fault seams. |
| Root package `tests/application_*.rs`    | The exported `Application` interface with the product package compiled without `cfg(test)`.      |
| Root package `tests/e2e_*.rs`            | Black-box production binaries, machine output, exit classes, restart, and operator workflows.    |
| `crates/<crate>/tests/`                  | Exported interfaces of independently meaningful workspace packages.                              |
| `fuzz/`                                  | Hostile-byte entry points reached only through production interfaces.                            |
| Ignored long-simulation targets          | Seeded lifecycle schedules, repeated recovery, and invariant checks.                             |
| Explicit live-kind script and root tests | Disposable-cluster behavior and real process termination where required by the release packet.   |

The repository root is also the `kapsel` product package. Its `tests/` directory therefore contains
both package integration tests and true binary end-to-end tests; the `application_` and `e2e_`
prefixes keep those lanes explicit. A test-support crate is justified only after fixtures are shared
by multiple real package interfaces. The private Kubernetes adapter seam remains private while only
one production adapter exists.

Pure implementation rules are asserted exhaustively once at their owner. Higher-layer tests assert
composition, authority separation, durable outcomes, observable output, and non-disclosure; they do
not repeat every parser or classifier mutation. Tests use several precise assertions when different
facts matter, rather than hiding contract failures behind one snapshot or compound predicate.

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

## Suite shape and robustness lanes

The default deterministic suite stays small and runs implementation-local unit tests, package
integration tests, binary tests that need no external service, and documentation tests. Every test
names one contract behavior, but may use many assertions to prove all facts owned by that behavior.
Table-driven cases are preferred when the setup and expected invariant are identical.

Fuzz targets are separate from the default gate. They call production hostile-input interfaces,
start from canonical corpus vectors when available, never depend on network or ambient authority,
and retain minimized regressions. A reported failure must include the target, seed or artifact, and
exact replay command.

Long simulations are also separate from the default gate. They use an explicit seed to generate
bounded lifecycle schedules, injected crash windows, retry deferrals, and reopen operations. Each
step checks durable-state, provider-call-count, terminal-state, and frozen-receipt invariants. The
seed is always printed on failure and accepted as input for exact replay. Simulation duration or
case count may vary by lane; semantics and generated schedules may not depend on wall-clock timing.

The live-kind lane remains explicit and environment-owning. It is not called a fuzz test or
simulation and is never used as evidence that a deterministic invariant holds for every crash
window.

## Review record

Meaningful changes report:

```text
Contract: <owner document>
Surface: <validation | journal | recovery | receipt | demo | docs>
Gate: <narrowest command run>
Risk: <what remains unproved>
```
