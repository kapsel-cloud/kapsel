# Architecture

A caller asks to run an approved ID. By the time it gets a receipt, Kapsel has checked authority,
recorded an attempt, contacted a receiver, classified evidence, and committed signed bytes. Those
steps must still fit together when the caller disconnects or the service crashes.

This page explains where those responsibilities meet and where to change them. Read the
[tour](../tour.md) for the operation's story, then use the code map below. The
[effect contracts](../reference/effect_gateway.md) define exact behaviour. [Scope](../scope.md)
defines supported capabilities and platforms.

## Execution path

```text
fixed ID-only client or MCP bridge
  -> authenticated Linux Unix socket
       -> kapseld
            -> ServiceApplication
                 -> private Gateway
                      -> exact grant authorization
                      -> SQLite journal and worker lease
                      -> Kubernetes or Git receiver
                      -> effect-specific classification
                      -> original signed receipt + terminal state
```

### Transport carries an ID, not a plan

The fixed client and MCP bridge cannot assemble an execution request with credentials, trust, paths,
signing material, or lifecycle controls. They carry an ID to the service. `ServiceApplication` first
looks for retained history under its original authority, then consults the current catalog only for
a new ID. Otherwise replacing the catalog could quietly reapprove an unfinished operation.

The application turns stored facts into status and execution guidance. Transport formats the
response. It does not decide which journal phase comes next.

### The gateway controls the next step

The private gateway coordinates authorization, journal transitions, and the concrete receiver. One
worker lease spans receiver reads, mutation, observation, signing, and completion. Stored reads and
admission checks use separate transactions without waiting for that worker.

The adapter cannot send a patch just because it has found an approved request. First, the journal
must confirm a fresh attempt commit. It then returns a one-use dispatch permission for that exact
operation. The adapter consumes the permission when it sends.

Loading attempted history returns no permission. Recovery can only observe. Once evidence freezes,
recovery can only complete that evidence without new observations. The gateway enforces these rules
so each caller interface does not have to get them right independently.

### Kubernetes and Git answer different questions

Git and Kubernetes share admission, identity namespace, worker exclusion, and completion capacity.
They do not share a definition of success. Kubernetes checks rollout observations. Git requires an
original per-ref acknowledgement. Their journal rows, classifications, and signing purposes stay
separate. Kubernetes starts at `requested`. Git starts at `authorized`.

A generic “execute and retry” interface would hide the very facts recovery needs. For each receiver,
Kapsel needs to know what authorizes a change, what a lost response means, and what evidence can
establish a result. Shared code follows from those concrete rules, not the other way around. See the
[Kubernetes](../reference/kubernetes_effect.md) and [Git](../reference/git_effect.md) contracts for
the current rules.

## Code owners

| Owner                            | Responsibility                                                                                        |
| -------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `src/application/service/`       | Catalog, original-authority resolution, status, and execution guidance                                |
| `src/gateway/`                   | Private lifecycle and concrete effect orchestration                                                   |
| `src/gateway/journal/`           | Schema, custody, capacity, conditional transitions, worker exclusion, receipt commitment              |
| `src/gateway/kubernetes/`        | Bounded reads, one conditional patch, rollout observations                                            |
| `src/gateway/git.rs`             | Fixed Git executable/configuration, preflight, exact-lease send, acknowledgement and ref observations |
| `src/gateway/receipt/`           | Canonical evidence, signatures, bounded parsing, classifier recomputation                             |
| `src/command/` and `src/main.rs` | Operator provisioning and offline inspection CLI                                                      |
| `crates/kapsel-authority/`       | Grant/trust codecs, consistency checks, bounded tuple grammar                                         |
| `crates/kapsel-daemon/`          | Resident service, fixed client, and MCP bridge                                                        |

The workspace dependency direction is `kapsel-daemon -> kapsel -> kapsel-authority`. The daemon also
depends on authority codecs. The root package owns the product library and operator CLI, not a
supported public Rust SDK.

## Service lifetime and custody

There are two lifetimes to track: how long the caller waits, and how long work actually runs. A
two-second response deadline can expire while a storage commit is still blocked. Freeing its permit
at that point would allow overlapping work or a false refusal of admission.

The daemon's protocol module parses bounded frames and renders responses. Its runtime checks peers
and retains physical jobs through disconnect and deadlines. Shutdown drains them before releasing
applications and lifecycle exclusion. [Runtime ownership](service_runtime.md) walks through the
admission race and shutdown order.

Systemd controls process lifecycle and diagnostics. Startup reads history without selecting work.
There is no scheduler or queue: resumption is an explicit request for the same unfinished ID.

Retained directory handles anchor private journal and socket access through Linux `/proc/self/fd`.
Missing or inconsistent procfs refuses startup before effects. The
[service reference](../reference/service.md) defines exact custody, process ownership, and shutdown
requirements. Private feature-gated checkpoints support process tests. Production artifacts contain
no caller-selectable fault controls.

## Evidence and offline inspection

Completion belongs to SQLite, not to a receipt file. The journal commits original signed bytes and
terminal state atomically. If a caller cannot write its export, the operation is still complete and
the same bytes remain retrievable. Export refuses an existing destination. Retrieval neither
re-signs nor observes the receiver.

```text
kapsel inspect
  <- original receipt + explicit trust + evaluation time + limits
  -> bounded inspection report
```

The inspector deliberately knows less than the executor. It opens no journal or receiver client. It
checks original bytes under explicit trust and evaluation time, then recomputes the result from the
signed facts. It cannot go looking for a healthier rollout or appoint a key carried in the receipt.
[Evidence formats](../reference/evidence_formats.md) defines the wire and trust rules.
[Storage](../reference/storage.md) defines journal completion and capacity bounds.

Transport depends on application interfaces. The application depends on the private gateway and
concrete effects. Add packages or public interfaces only for demonstrated boundaries with real
consumers. [Engineering conventions](../../CONTRIBUTING.md#engineering-conventions) and
[decisions](../decisions/README.md) explain the design criterion. [Build](build.md),
[Testing](testing.md), and [Qualification](qualification.md) cover contributor workflows.
