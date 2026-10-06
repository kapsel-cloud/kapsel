# Architecture

This page maps code responsibilities and compile-time dependencies.
[Effect gateway](EFFECT_GATEWAY.md) owns authority, lifecycle, recovery, results and receipts.
[Scope](SCOPE.md) owns capability and release boundaries.

## Root product package

The root is the `kapsel` product package and workspace root. Its executable provisions operator
approval and inspects detached receipts. It does not execute caller requests. Both maintained
effects execute through the resident service:

```text
fixed ID-only service client or MCP bridge
  -> authenticated Linux Unix socket
       -> kapseld
            -> ServiceApplication
                 -> private Gateway
                      -> purpose-specific exact grant authorization
                      -> SQLite journal and worker lease
                      -> concrete Kubernetes or Git receiver
                      -> effect-specific classification
                      -> original signed receipt and terminal state

kapsel inspect
  -> offline inspector
       <- receipt bytes + explicit trust + evaluation time + limits
```

`ServiceApplication` resolves catalog or retained original authority. Caller action IDs cannot
choose trust, credentials, paths, signing material or lifecycle controls. The gateway owns
admission, advancement and bounded blocked outcomes. The journal owns conditional rows, snapshots,
capacity, worker exclusion and receipt commitment. Transport does not sequence those phases.

The journal's private children separate `schema` (format-6 layout/version rejection), `opening`
(SQLite/pathname custody) and `capacity` (completion accounting). SQLite commits signed receipt
bytes and terminal state atomically. Caller export is separate. Inspection opens neither a journal
nor a receiver client.

### Reconciliation and locking

The gateway reloads original authority under the worker lease before choosing fresh dispatch or
observation-only recovery. It holds exclusion through target reads, mutation, observations, signing
and completion. Admission and stored reads use journal transactions without waiting for that worker.
There is one worker, no scheduler and no implicit startup reconciliation.

Only a fresh confirmed attempt commit issues private one-use dispatch permission. Loading attempted
history never reconstructs permission. Recovery after the attempt marker only observes. Terminal
retrieval neither observes nor re-signs. Cancellation preserves committed state; the daemon retains
physical job ownership until the work actually retires. Export cannot change completion.

### Git service composition

Git and Kubernetes share `Gateway::admit_service_operation` for terminal reselection, worker
contention, capacity refusal and durable acknowledgement. Each effect rechecks original identity
under the returned lease. Kubernetes initially records `requested`; Git records `authorized`.

Receiver transitions, journal rows, result rules and receipt purposes remain effect-specific. Git
uses exact-lease receiver semantics, not Kubernetes classifiers. Frozen evidence can complete
without receiver material. Service reads expose Git tuple, acknowledgement and observation without
reinterpreting Kubernetes columns. [Git contract](EFFECT_GATEWAY.md#git-transition-boundary) owns
exact semantics.

## Kubernetes adapter

The adapter performs safe reads, one conditional strategic merge patch and bounded rollout
observation. `Journal::begin_attempt` supplies receiver-bound one-use permission only after its
fresh transaction commits. The adapter consumes that permission. The shared explicit-kubeconfig
client disables server-response mutation retries and caps responses before collection/parsing.
[Fresh dispatch](EFFECT_GATEWAY.md#fresh-dispatch-permission) owns retry obligations and limits.

Private adapter/fault seams support deterministic checks. They are not a public provider interface
or generic Kubernetes framework. Service process checkpoint controls remain feature-gated because
the Linux recovery lane consumes them; production artifacts do not contain them.

## CLI and MCP adapters

`src/lib.rs` maps service, operator provisioning and offline inspection interfaces. There is no
direct `Application` execution composition or legacy execution operator document.

- `command`: fixed provisioning/inspection grammar, envelopes and exit classes.
- `transport_support`: purpose-specific offline target projection, with no runtime or authority.
- `main.rs`: process arguments, streams and exits.
- `kapsel-service-client`: fixed socket requests and collision-refusing caller export.
- `kapsel-service-mcp`: bounded stdio lifecycle and ID-only socket composition.

[Commands](COMMANDS.md), [MCP](MCP.md) and [service](KAPSEL_SERVICE.md) own these external
contracts.

## Receipts and export

Receipt codecs own canonical bytes, signatures, bounded parsing and classifier recomputation. Git
and Kubernetes share envelope/signature mechanisms but retain their own statements and purposes.
Authentication uses original bytes, not re-encoding. Trust, evaluation time and limits are explicit.

The service retrieves original committed bytes. The fixed client owns caller export and refuses an
existing destination. It cannot reopen the action on export failure. No exporter supplies ambient
trust or proves receiver truth, causation or complete capture. Legacy purposes remain inspectable.

## Workspace and release

```text
kapsel (product library and operator/inspection CLI)
  -> kapsel-authority

kapsel-daemon (resident service, fixed client and MCP bridge)
  -> kapsel
  -> kapsel-authority
```

`kapsel-authority` owns grant/trust codecs, their combined consistency check and bounded tuple
validation. The root retains operator provisioning and service composition, not a supported public
SDK. The excluded fuzz workspace enters maintained hostile decoders through production interfaces.

Release assembly packages four executables and operating assets for one target, without test/demo
features. No source-only crash demo is assembled or maintained at HEAD. Published tags retain their
old bytes and contracts. [Release](RELEASE.md) owns archive and exact-byte qualification.

## Resident service

`kapseld` survives caller loss and exposes catalog, history, status and original receipt retrieval
across separate OS identities. Startup is read-first. Fixed operator/socket arguments and retained
directory handles keep journal/socket I/O under verified roots through Linux `/proc/self/fd`.
Missing or inconsistent procfs stops startup before effects. A moved database refuses later writes;
startup removes only an exact inactive owned socket. Systemd owns process lifecycle and diagnostics.

Private daemon owners remain:

- `server/protocol.rs`: bounded JSON grammar and response projection without I/O.
- `server/runtime.rs`: peer checks, frames, deadlines, admission, physical jobs and shutdown.
- `server.rs`: service application reads and selection.
- `server/harness.rs`: feature-gated checks of that same runtime.

The daemon never interprets journal phases, queries SQLite directly, fabricates receiver results or
adds a store/queue. [Service](KAPSEL_SERVICE.md) owns installation and protocol rules.

## Dependency rule

Transport depends on application interfaces; application depends on the private gateway and concrete
effects. Share authority codecs through their fixed-purpose package. Add a package or public
interface only for a demonstrated boundary with real consumers. [Decisions](decisions/README.md)
explain rationale; they do not override contracts.
