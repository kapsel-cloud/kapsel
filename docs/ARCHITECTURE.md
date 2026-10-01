# Architecture

This page maps code responsibilities and compile-time dependencies. The
[effect-gateway contract](EFFECT_GATEWAY.md) owns authorization, lifecycle, recovery, results, and
receipts. [Technical scope](SCOPE.md) owns capability and release limits.

## Root product package

The repository root is the `kapsel` product package and workspace root. Its direct CLI and MCP paths
support one Kubernetes Deployment image change:

```text
local operate command or fixed stdio MCP adapter
  -> Application
       -> private Gateway
            -> exact grant authorization
            -> SQLite journal
            -> concrete Kubernetes adapter
            -> receiver-fact classification
            -> receipt signing and terminal completion in SQLite
            -> optional filesystem export

kapsel inspect
  -> offline receipt inspector
       <- receipt bytes + explicit trust + evaluation time + limits
```

`Application` separates caller requests from operator configuration. `OperatorConfiguration`
supplies the signed grant, grant trust, Kubernetes client, receipt-signing material, journal path,
and optional export directory. The caller supplies only `AgentRequest`, an alias for
`SetDeploymentImageRequest`. It cannot select authority, trust, credentials, paths, signing
material, or lifecycle controls.

`Application::execute` submits a request, then calls `Gateway::reconcile`. `Application::reconcile`
uses that same gateway entry point for an existing operation. Both project public reports and errors
without interpreting durable phases. Submission and snapshot helpers remain private so callers
cannot sequence those phases themselves.

The private `Gateway` owns validation, authorization, journaling, conditional mutation,
observation-only recovery, classification, and receipt construction. SQLite commits the signed
receipt and terminal state together. Filesystem export is separate. The offline inspector opens
neither an application, a journal, nor a receiver client.

The journal owns rows, snapshots, worker locking, capacity, and guarded transitions. Its private
children have distinct responsibilities:

- `schema`: format-6 layout and version rejection.
- `opening`: safe SQLite access and private pathname identity.
- `capacity`: fixed completion accounting.

### Reconciliation and locking

`Gateway::reconcile` advances an existing configured operation until it is blocked or terminal. It
rechecks original authority, completes authorization, executes or recovers, and commits receipts
from frozen observations. It does not submit an absent operation. There is no queue or scheduler.

The execution helper reloads state under the worker lock before choosing fresh dispatch or
observation-only recovery. It holds that lock through target, mutation, and receiver I/O. Receipt
completion separately holds the lock through signing and the conditional SQLite commit. Submission
and report reads use journal transactions without worker exclusion. Private execution and receipt
helpers provide test points for crash windows.

A contending worker returns the latest authorized snapshot without waiting or calling Kubernetes. An
absent operation produces no report. A blocked operation produces its current report. Terminal
retrieval neither observes nor re-signs. Submission rejection is distinct from advancement failure.
Cancellation releases the worker lock and preserves the last committed state. Recovery after the
attempt marker never resends. Export is independent of completion.

### Git service composition

The service resolves retained original authority before selecting the effect. Git uses a concrete
receiver, a typed journal table, and a receipt codec with a separate signing purpose.

Git advancement and Kubernetes share `Gateway::admit_service_operation`. This helper owns terminal
reselection, worker contention, capacity refusal, and post-commit acknowledgement. It returns the
held lease for advancement. Each effect rechecks original identity under worker exclusion and
commits its initial state: Kubernetes `requested`, Git `authorized`.

Receiver transitions, journal rows, and evidence remain effect-specific. Only a fresh Git attempt
commit can produce dispatch permission. Loaded attempts observe without sending. Frozen evidence can
finalize without receiver material. Service reads expose the Git tuple, acknowledgement, and
observation without reinterpreting Kubernetes columns. The
[Git contract](EFFECT_GATEWAY.md#git-transition-boundary) owns exact semantics.

## Kubernetes adapter

The adapter performs safe target reads, one conditional strategic merge patch, and bounded rollout
observation. It keeps receiver facts separate from transport and request-acceptance facts.

`Journal::begin_attempt` issues private one-use dispatch permission only after a fresh transaction
commits. The adapter consumes the permission's bound request and target. Loading an attempted row
cannot restore permission. The
[fresh dispatch contract](EFFECT_GATEWAY.md#fresh-dispatch-permission) owns client-retry obligations
and limits.

A private adapter interface supports deterministic call-count and crash-recovery tests. It is not a
public provider interface or a general Kubernetes abstraction.

## CLI and MCP adapters

`src/lib.rs` maps workspace-visible interfaces. The executable layers have these responsibilities:

- `transport_support`: load bounded operator files and project application reports and errors.
- `command`: decode fixed CLI input and produce deterministic envelopes and exit classes.
- `mcp`: enforce bounded stdio framing and protocol lifecycle.
- `main.rs`: handle process arguments, streams, and exits.

The direct CLI and fixed-schema MCP adapter call `Application`. Neither sequences private durable
states. MCP exposes request fields; operator configuration stays separate. [Commands](COMMANDS.md)
and [MCP](MCP.md) own the external contracts. The ID-only service MCP bridge uses the resident
service instead of this direct-execution path.

## Receipts and export

The receipt module owns canonical bytes, signatures, bounded parsing, and classifier recomputation.
Trust, evaluation time, and limits are explicit inputs. Git and Kubernetes share private envelope
signing, framing, and signature/trust checks. Statement parsing, version checks, and classifiers
remain separate. Authentication uses original statement bytes, not a re-encoded statement.

Inspection is offline. SQLite atomically commits receipt bytes, digest, signer identity, and
terminal state. The export module installs frozen bytes through Unix descriptor-relative operations.
It requires owner-private custody and refuses collisions. Neither module supplies ambient trust or
proves receiver truth, causation, or complete capture.

## Workspace and release

```text
kapsel (root product)
  -> kapsel-authority

kapseld (resident service)
  -> kapsel
  -> kapsel-authority
```

`kapsel-authority` owns grant and receipt-trust codecs, their combined consistency check, and the
bounded [request grammar](EFFECT_GATEWAY.md#one-capability). Gateway and service share pure grammar
checks but retain their own error projection and rejection-before-effect boundaries. `Application`
also exposes the combined operator-input check, covered by its contract tests.

This package is not an installed process, public SDK, generic validation library, or supported Rust
interface. The excluded `fuzz` package contains hostile-input test targets.

Release assembly packages the product for one target. The preview's `kapsel`, `kapseld`, and
`kapsel-service-client` binaries have no optional features enabled. Source-only and older-beta demos
are separate from this archive. Checksums, metadata, SBOM, and smoke automation add no runtime
plugins, trust sources, or result vocabulary. [Release artifacts](RELEASE.md) owns the archive.

## Resident service

```text
bounded local service client
  -> authenticated Linux Unix socket
       -> kapseld
            -> ServiceApplication
                 -> sole SQLite effect journal
```

`kapseld` keeps execution alive independently of the caller. Across a separate OS identity, it
provides an authenticated catalog, history, status, and original receipt retrieval. Startup is
read-first: it does not reconcile operations automatically.

The process accepts fixed operator and socket arguments. It validates roots descriptor-relatively
and retains their directory handles. Journal and socket I/O use verified Linux `/proc/self/fd` paths
beneath those handles. Missing or inconsistent procfs stops startup before journal or socket
effects. If the database moves, SQLite refuses later writes instead of reopening a replaced root.
Startup removes only an exact inactive service-owned stale socket.

Systemd owns process lifecycle, runtime-directory cleanup, health, and diagnostics. Static assets
define the service identity and namespaced Kubernetes RBAC.

The `kapsel-daemon` package produces the `kapseld` binary. Private modules in
`crates/kapsel-daemon/src` separate the mechanisms:

- `server/protocol.rs`: JSON decoding, shared request validation, response rendering, and byte
  limits. It performs no I/O or ambient-authority lookup.
- `server/runtime.rs`: peer checks, framing, deadlines, connection and submission admission, locks,
  task lifetime, and shutdown. It does not interpret durable states or receiver results.
- `server.rs`: startup and the bridge to `ServiceApplication` reads and selection.
- `server/harness.rs`: feature-gated tests of the same runtime, without a public harness interface.

The adapter calls `ServiceApplication::select` and authenticated catalog, history, status, and
receipt reads. It does not query SQLite directly, sequence lifecycle states, duplicate export rules,
or add a store or queue. [Kapsel service](KAPSEL_SERVICE.md) owns protocol and installation rules.

`ServiceApplication` resolves selectable or retained original authority. The gateway owns admission,
reconciliation, and blocked outcomes. The journal owns conditional rows, capacity, and receipt
commitment. These responsibilities stay below the transport, without a generic registry or
scheduler.

## Dependency rule

Transport adapters depend on application interfaces. Those interfaces depend on the private gateway
and concrete implementations. Share authority codecs only through the fixed-purpose package.

Add a package or public interface only for a demonstrated deployment or dependency boundary with
real consumers. [Architecture decisions](decisions/README.md) explain rationale; they do not
override current contracts.
