# Kapsel service

This contract defines service composition, authenticated local protocol, fixed filesystem roots,
process lifecycle, static assets, and precautions for existing host state. The
[effect-gateway contract](effect_gateway.md) defines authorization, action lifecycle, recovery,
results, and receipts. [Technical scope](../scope.md) defines capability and support limits.

## Boundary

```text
bounded local caller
  -> /run/kapsel/kapseld.sock
       -> kapseld under a separate OS identity
            -> kapsel::ServiceApplication
                 -> sole SQLite effect journal
                 -> concrete Kubernetes or Git receiver
```

The service gives execution a lifetime independent of a caller connection. A reconnecting caller can
read the same action's status and original receipt without gaining credentials or permission to
resend a mutation. This local service is not a hosting or installation-support commitment.

For `kubernetes.set_deployment_image`, service execution requires an exact-snapshot v2 grant,
binding the operation tuple and independently acquired Deployment UID and resourceVersion. The
multi-action application may authenticate retained v1 history for status and original receipt reads,
but rejects v1 selection before acknowledgement or advancement. Existing handles cannot acquire
replacement authority. Retained grants keep their original meaning. Older journal formats are
rejected unchanged. [Exact-snapshot approval](kubernetes_effect.md#exact-snapshot-approval) explains
which grants can be read or used for execution. The service calls `ServiceApplication`, never
gateway internals.

`git.transition_ref` shares the ID-only commands but uses separately purposed grants and evidence.
Kubernetes tuple, authority and receipt semantics do not change. Git entries identify their effect
and repository/ref/A/B tuple. Git status separates attempt, acknowledgement and present-ref
observation. See the [Git contract](git_effect.md) and
[operator example](../guides/git_transition.md). The version-1 wire request names retain their
historical `set_deployment_image` spelling. The application resolves the effect from the selected
ID's authenticated authority, not caller-supplied fields.

Callers can submit approved IDs and read retained history through the version-1 socket or fixed
client. Startup serves stored reads without advancing work. Operators replace configuration only
after old work retires. Journal capacity limits how many operations the service can retain.

## Multi-action application boundary

`kapsel::ServiceApplication` uses one bounded catalog and one gateway journal. It is not a map of
single-action execution adapters. The operator supplies at most 32 signed snapshot approvals, at
most 4 KiB each, with printable ASCII labels of at most 128 bytes. Decoded grant/label data and the
eventual encoded operator document each have a 160-KiB ceiling. Labels are display-only. Up to 128
unique, separately appointed historical grant keys are accepted. Malformed global appointments or
duplicate selectable IDs fail before journal opening. Operator provisioning, not target-name
comparison or caller cooperation, determines action independence.

Catalog listing returns at most eight handles after an exact optional identity cursor. It neither
inserts nor observes. Selection supplies only an ID. Retained history resolves under its original
grant even after catalog removal. Current catalog membership cannot replace retained authority.
Stored status and exact receipt reads require neither Kubernetes configuration, receipt seeds nor
export access. Missing historical trust is an authority error, not absence.

History pages contain at most eight retained IDs in bytewise ascending order, after an optional
bounded identity cursor. A continuation cursor is returned only when another ID was found. Each ID
has either an authenticated status/target projection or a bounded access error with no action facts.
Missing one key does not suppress other entries. Listing IDs is not authentication, admission or
proof of non-admission. Pages and per-ID reads are separate snapshots. Concurrent admissions can
require restarting pagination to see new IDs ordered before an already-consumed cursor.

The gateway performs
[durable admission](effect_gateway.md#service-admission-and-historical-authority) and holds its
single worker lease through commitment, acknowledgement and advancement. The application passes
typed admission decisions to the runtime. It does not create background tasks. Receiver
configuration and receipt signing material are optional execution inputs, never caller input. Their
absence can block advancement but cannot hide authenticated stored history.

The runtime keeps selected work alive after a response deadline or caller disconnect. The socket
grammar and shutdown rules are defined below. Native installation needs its separate qualification
lane.

### Action independence

Before exposing an approval, the operator must assess it against both selectable actions and
unresolved action history. Different Deployment names do not prove independence. Containers in one
Deployment share a snapshot. Neither a free worker nor terminal `UNKNOWN` clears a conflict or
authorizes a conflicting follow-on action. Keep that approval unavailable until the operator has
resolved the conflict. Removing an earlier action from the catalog does not clear its history.

This is an operator-enforced provisioning rule. The service does not infer application dependencies
or classify conflicts. A cooperative caller withholding an already selectable approval is
insufficient. Use [cold publication and retirement](#cold-publication-and-graceful-retirement) to
replace the complete catalog after old tasks retire, so a stale process cannot admit a withdrawn
action. The service validates publication and excludes it while old work survives. The operator must
still assess the catalog's meaning and control how the service is launched. Withdrawal cannot undo
an action already admitted. There is no dependency engine or automatic conflict-resolution policy.

## Versioned operator document

The multi-action application parser accepts one UTF-8 JSON document of at most 160 KiB. Its required
fields are `service_configuration_version` (integer `1`), `authorization_keys`, `approvals`, and
`receipt_signing_key_id`. Unknown, duplicate, missing or wrong-typed fields fail closed. This
grammar is the sole execution startup document.

`authorization_keys` contains at most 128 objects with exactly `key_id` and `public_key_hex`. Public
keys are exactly 64 lowercase hexadecimal characters. `approvals` contains at most 32 objects with
exactly `label` and `signed_grant_hex`. Grant hex is nonempty, lowercase, even-length and decodes to
at most 4 KiB. Labels retain the printable ASCII/128-byte limit. Count overflow is rejected before
deserializing the extra element. The whole-document byte limit precedes JSON parsing.

There are no configurable private paths in this service document. The host retains the fixed
journal, Kubernetes configuration and receipt-seed paths. Git material uses the optional fixed
`/etc/kapsel/git-receiver.json` file, with the bounded operator-only shape in the
[Git guide](../guides/git_transition.md#operator-preparation). `receipt_signing_key_id` is a bounded
public identity, not signing material. The parser checks structure and bounds. Opening the
application verifies grants, external key appointments and consistency with retained identities.

Missing, unreadable, unsafe or malformed execution material does not prevent authenticated stored
reads. Startup snapshots only safely bounded bytes from the fixed files. Invalid inputs disable that
execution material rather than triggering ambient fallback. The selected job constructs the receiver
client from the snapshot only when needed. If construction fails, the receiver stays unavailable.
Receipt signing can be unavailable independently. An admitted operation may therefore remain
unfinished without a receiver outcome. There is no hot reload, generated replacement key or
automatic retry. Invalid authority, operator documents, retained roots and journals still fail
closed normally. Cold replacement must validate the complete document before publication under
lifecycle exclusion.

## Cold publication and graceful retirement

The operator-only invocation is exactly `/usr/libexec/kapsel/kapseld --replace-operator-config`,
under the existing service UID and effective GID. Ordinary daemon argv is unchanged. No
socket/client maintenance request, alternate path, privilege transition or staged startup document
exists. Stdin must contain one complete candidate. The read limit is 160 KiB plus one byte to detect
overflow, and EOF is required within that bound.

Both entrypoints acquire an exclusive nonwaiting `flock` on the fixed
`/var/lib/kapsel/kapseld.lifecycle.lock` before consuming authority (including candidate stdin). The
lock is a zero-length regular file, mode `0600`, service UID/effective GID, one link, opened without
following symlinks and close-on-exec. Creation is exclusive. The acquired descriptor must still
identify the named inode. Never unlink or replace this lock. Retained private directory descriptors
anchor subsequent access. Exclusion ends only after physical jobs, application handles and retained
roots retire. Stable roots and cooperative launches are host assumptions: replacement of the state
root or old binaries ignoring the lock defeats exclusion.

Publication validates all appointments and approvals, then retained identity, schema, integrity and
capacity through the shared application/gateway verification in one read-only, no-create journal
snapshot. It refuses recovery requiring writes, never uses SQLite immutable mode, and never admits,
reconciles, signs or contacts Kubernetes. A genuinely absent journal permits pure configuration
validation only. Leftover journal sidecars or worker-lock artifacts are not fresh history. Missing
trust still blocks only the affected historical ID, not removal of unrelated catalog appointments.
Validation handles close before publication. The publisher creates an exclusive private temporary
file in the retained configuration directory, writes the exact validated bytes, syncs the file,
rechecks destination custody, renames over fixed `operator.json`, then syncs the directory. It
removes a temporary inode only when it can confirm that this invocation created it. It does not
adopt stale temporary files.

Stdout is exactly one ASCII status line, at most 14 bytes including LF. Stderr is empty. If stdout
cannot be written, the publisher exits `5`. A missing or truncated line does not prove what
happened.

| Status line     | Exit | Meaning                                                              |
| --------------- | ---- | -------------------------------------------------------------------- |
| `PUBLISHED`     | 0    | Rename and directory synchronization completed.                      |
| `NOT_PUBLISHED` | 4    | Refusal before rename. The candidate was not published.              |
| `INDETERMINATE` | 5    | Publication was attempted but its result or durability is uncertain. |

A rename syscall error is conservatively `INDETERMINATE`, not proof that the destination is
unchanged. No automatic rollback follows a rename attempt. Lost responses and process crashes
require operator inspection. They never imply non-publication.

The daemon registers SIGTERM before blocking startup or authority loading. A stop during startup is
retained: started blocking work finishes without cancellation, then no listener is bound. Serving
gives a ready stop priority over accept, closes its listener, drains admitted handlers and physical
jobs while driving the current-thread reactor, then retires applications and roots before the lease.
`TimeoutStopSec=infinity` deliberately means hung storage leaves stop incomplete and publication
excluded indefinitely. Manual SIGKILL is crash recovery, not graceful retirement or proof that an
attempted publication did not occur. Startup never automatically reconciles.

## Runtime inventory

| Item                   | Boundary                                                                                                                 |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Packages               | Root `kapsel` and resident `kapseld -> kapsel`                                                                           |
| Executables            | `/usr/bin/kapsel`, `/usr/libexec/kapsel/kapseld`, `/usr/bin/kapsel-service-client`, `/usr/bin/kapsel-service-mcp`        |
| Caller interface       | One length-prefixed JSON request and response per Unix-socket connection                                                 |
| Authentication         | Parent `0750`, socket `0660`, service UID and `kapsel-service-callers` GID; exact effective caller-group peer credential |
| Connection resources   | At most eight admitted connections; two-second read/write deadlines; no queue                                            |
| Durable store          | Format-6 SQLite effect journal only                                                                                      |
| Configuration          | Fixed `/etc/kapsel/operator.json`; private authority beneath `/etc/kapsel`                                               |
| OS ownership           | Locked service identity, `0700` private roots and `0600` private files                                                   |
| Caller identity        | Locked `kapsel-service-caller`, primary/effective group `kapsel-service-callers`                                         |
| Kubernetes authority   | Namespaced `get` and `patch` on exact Deployment `demo/agent-api`                                                        |
| Runtime dependencies   | Rust executables, Linux Unix sockets, systemd, existing SQLite/Kubernetes stack                                          |
| Tested failure domains | Caller disconnect, process loss, same-host restart, attempt and receipt-commit seams, bounded receiver ambiguity         |

## Authority and filesystem

The operator provisions approvals and external public-key appointments in the service document.
Execution material uses these fixed paths:

```text
/etc/kapsel/operator.json
/etc/kapsel/kubeconfig.yaml
/etc/kapsel/git-receiver.json
/etc/kapsel/receipt.seed
/var/lib/kapsel/journal.sqlite3
```

Configuration and state roots are service-owned mode `0700`. Operator files are stable regular,
single-link, service-owned mode `0600`. The caller group receives no read or traversal permission.
The journal and worker lock may be absent before first use and have exact private file checks when
present. Credentials and signing material never enter caller input or service responses.

Startup opens `/etc/kapsel`, `/var/lib/kapsel`, and `/run/kapsel` descriptor-relatively and
validates owners, modes, types, link counts, path components and stable consumed bytes. It retains
those roots. `/var/lib/kapsel/receipts` is not opened or required. The service document has no
`receipt_directory` field. The fixed client exports to the caller-selected path.

Journal/SQLite sidecar access and socket preparation/bind resolve through Linux `/proc/self/fd/<fd>`
paths for retained handles. Each procfs path must resolve to the same device, inode, owner, group,
type and mode. Unavailable or inconsistent procfs fails before journal creation, reconciliation or
bind. Rename/replacement cannot redirect journal or socket effects into the substituted root. If the
state root moves after SQLite opens, its file-move defense rejects later writes with
`SQLITE_READONLY_DBMOVED` rather than reopening the replacement. A renamed runtime root can make the
fixed client pathname unreachable until restart. Startup validates a substituted fixed root anew.
Host root, procfs, kernel and service identity remain trusted.

## SQLite-owned receipt storage

`receiver_observed` freezes the historical statement before signing. Exact signed bytes, digest,
signer identity and terminal `finalized` state commit together. There is no durable receipt path or
filesystem-publication phase. Journal versions older than format 6, including format 5, are rejected
before reconciliation and binding, without migration.

Receipt requests read committed bytes through `ServiceApplication`. Callers receive no journal
access. Retrieval never re-signs or contacts Kubernetes. The service-client receipt command exports
a copy separately. Export failure cannot change terminal status or block later retrieval. Database
availability is required for retrieval. Consistent backups must preserve action history and receipt
bytes together. There is no automatic backup or host-loss continuity promise.

## Version-1 socket contract

Every request is a named JSON object with integer `version: 1`. Version is mandatory on every
variant. Unversioned input, other versions, positional arrays, duplicate/unknown fields and trailing
values fail before application access.

```json
{"version":1,"request":"list_approved_actions","after":null}
{"version":1,"request":"list_operation_history","after":null}
{"version":1,"request":"get_set_deployment_image_status","operation_id":"operation-id"}
{"version":1,"request":"get_set_deployment_image_receipt","operation_id":"operation-id"}
{"version":1,"request":"submit_set_deployment_image","operation_id":"operation-id"}
```

List requests require `after`, either null or a bounded identity. Catalog cursors must name a
current selectable entry. History cursors are bytewise lower bounds. Submission has no tuple, grant,
key, path, budget or lifecycle fields. The application resolves original authority.

Every response includes `version: 1`. Selection returns one of:

- `status: "ADMITTED"` and the confirmed durable `phase`, using the gateway's lowercase state names.
  This includes an identical existing identity. It does not claim a live worker or receiver success.
- `status: "NOT_ADMITTED"` and `reason: "BUSY"` or `"CAPACITY"` for a definite refusal of new work.
- `status: "INDETERMINATE"` when commitment has not settled before the decision deadline.
- `status: "ERROR"` with `error_class: "invalid_request"`, `"authority_unavailable"` or
  `"operation_failure"`. An operation error or lost response is not proof of non-admission.

The service records an operation before acknowledging admission. If submission loses its response,
read the same operation ID. `NOT_FOUND` alone does not prove submission failed: a selected job may
still commit after the read.

The admission decision deadline is two seconds after complete frame read. The runtime retains the
selected ID, task and permits through unsettled commitment. Existing admitted identities resolve
before busy refusal without creating another execution task. The read-only admission lookup uses the
same selection authorization checks. It cannot settle another task's pending commit. Contention must
not turn an absence snapshot into definite non-admission while matching work may still commit.
[Runtime ownership](../contributing/service_runtime.md#admission-under-contention) explains the how
ownership pins keep this check safe when jobs finish during a read.

Catalog/history responses contain `status: "READY"`, at most eight `entries` and `next_cursor` as
null or the last returned identity when more entries exist. Every catalog entry has `operation_id`,
`effect` and `label`. Kubernetes entries use `effect: "kubernetes.set_deployment_image"` and contain
`namespace`, `deployment`, `container`, `immutable_image_digest` and `approved_target`. Git entries
use `effect: "git.transition_ref"` and contain `repository_id`, `reference`, `old_commit` and
`new_commit`. Authenticated status/history projections carry the same effect tag. Git facts are in
`git`, while Kubernetes retains its separate target fields. `NOT_FOUND` and access errors have no
effect or receiver facts. History entries contain `operation_id` and an authenticated status/target
projection, or only `operation_id`, `status: "ERROR"` and a bounded access error. No error entry
contains action facts.

The fixed client's grammar is `list [after-id]`, `history [after-id]`, `submit <id>`, `status <id>`
and `receipt <id> <new-output-file>`. It must reject responses without version 1 and enforce the
bounds and exclusive receipt-export behavior below.

## Protocol

Each connection carries a four-byte unsigned big-endian length, one UTF-8 JSON body, required client
write-half-close, one framed response, and close. Request length is 1–16 KiB. Ordinary responses are
at most 16 KiB and receipt responses at most 40 KiB. Aggregate frame-read and response-write
deadlines are two seconds. Saturation closes immediately without reading a body or creating work.

The five version-1 commands above are the entire socket grammar. The separate
[ID-only MCP bridge](mcp.md#resident-service-bridge) projects these commands without adding service
methods or owning execution. Input key order is insignificant. Duplicate, unknown, missing, null,
wrong-typed, trailing, cross-request, malformed UTF-8, oversized, timed-out and out-of-grammar
fields fail closed without lifecycle effect.

Status returns `NOT_FOUND`, `IN_PROGRESS`, `NOT_ATTEMPTED` with its required `target_rejection`,
`SUCCEEDED`, `FAILED`, or `UNKNOWN`, without Kubernetes access. It projects `approved_target`,
`observed_target` and `attempt_target` as null or bounded objects with `uid` and `resource_version`.
Missing observed members are null. `NOT_FOUND` carries no target facts.

Receipt responses are `{"version":1,"status":"NOT_FOUND"}`, `{"version":1,"status":"NOT_READY"}`, or
a ready record containing only `version:1`, `status:"READY"`, `receipt_hex` and `receipt_sha256`.
Hex and digest are lowercase and identify the exact journal-frozen bytes. A pre-attempt rejection
has no effect receipt.

Selection returns only the durable admission decisions defined above. Disconnect or response failure
does not cancel surviving execution. Completion is observed through status and receipt reads. A
contended selection authenticates retained admission before deciding whether new work was refused.
No queue is created. Peer denial, framing failure, read timeout, saturation and over-limit responses
close without a response.

## Actionable execution status

Version-1 status and authenticated history entries contain an `execution` object with exactly
`disposition`, `condition` (a fixed token or null), `next_action` and `action_owner`. It describes
execution guidance, not receiver evidence. Receipt and admission responses carry no execution
guidance. Access errors contain no execution or action facts.

| Disposition             | Condition                                                                                   | Next action                | Owner    |
| ----------------------- | ------------------------------------------------------------------------------------------- | -------------------------- | -------- |
| `active`                | null                                                                                        | `wait`                     | caller   |
| `waiting_for_worker`    | null                                                                                        | `wait_then_select_same_id` | caller   |
| `resume_required`       | null, `preflight_unavailable`, or `worker_contention`                                       | `select_same_id`           | caller   |
| `operator_required`     | `receiver_unavailable`, `signing_unavailable`, `completion_blocked`, or `operation_blocked` | `contact_operator`         | operator |
| `complete`              | null                                                                                        | `inspect_result`           | caller   |
| `admission_unconfirmed` | null                                                                                        | `read_same_id`             | caller   |

`NOT_FOUND` with `admission_unconfirmed` means this read snapshot cannot confirm admission. A
selected job may still commit after that read. Only the submission decision `NOT_ADMITTED` confirms
a definite refusal of new work. Keep reading the same ID after uncertainty, rather than creating
another identity.

`IN_PROGRESS` means unfinished durable history, never activity by itself. `active` means the runtime
owns the scheduled or physically executing selection job, even if storage is stalled. A contention
probe retaining exclusion after that job finishes must not report active execution. Disconnect,
response timeout and supervisor cancellation do not end a surviving physical job's ownership.

The runtime remembers at most 32 most-recent selection outcomes in memory, evicting the oldest.
Starting a new selection clears that identity's old explanation before publishing task ownership.
New outcomes are recorded before physical retirement. Restart loses all explanations. Lost knowledge
is null, not `crashed`, `cancelled` or another fabricated cause. Terminal history overrides stale
diagnostics. History and ownership are separate snapshots and can change immediately after a read.
No flags or diagnostic facts are written to SQLite. External worker contention is an observed stop
condition, not continuing knowledge that the external worker is alive. Explicit selection may find
contention again, but never queues work or resets a surviving pass.

`preflight_unavailable` cannot distinguish transport, credentials, malformed response or timeout
from the adapter's bounded read failure. It does not mean the receiver permanently rejected the
operation. Retry is explicit and same-ID only. `receiver_unavailable` covers unavailable local
execution material or a typed receiver execution failure. `signing_unavailable` needs
operator-supplied signing material. `completion_blocked` means frozen evidence could not be
completed, not that the receiver failed. These conditions are process observations, not new signed
evidence.

### Operator diagnostics

The daemon emits only fixed ASCII codes prefixed `kapseld: ` on stderr, routed by the unit to the
systemd journal. Stdout remains null. No raw error, operation ID, grant, credential, signing seed,
response body, or private path is logged. The panic hook also emits only `internal_failure`.
Rendering has no diagnostic side effects. Read-access failures are reported at the application
bridge or retained-admission probe, at most once per failure class per service lifetime across all
IDs and status/history/receipt reads. Success does not reset suppression. Explicit selection failure
is reported once by its execution owner, never again by response rendering. Startup retains its own
failure boundary.

Emission is best-effort, not durable evidence. Before startup, the daemon retains a close-on-exec
stderr descriptor only when it identifies a pipe or socket, and sets its shared open-file
description to nonblocking. The host must not clear that flag or reuse this description for blocking
output. Regular files, terminals and unsupported sinks are skipped because nonblocking flags do not
bound their I/O. Each fixed line is at most 64 bytes and uses one nonblocking syscall without a
userspace stderr lock. There is no retry, buffering thread, queue, flush or shutdown drain.
Saturation, short writes, sink errors and process loss may drop or truncate diagnostics. The stop
condition is recorded before the write attempt. A stalled sink cannot hold physical execution or
service retirement.

There is no telemetry store, socket administration request or per-action diagnostic history. Journal
access remains host/operator-owned.

Startup custody/provisioning refusal emits `provisioning_unavailable`. Application opening emits
`configuration_invalid` or `storage_or_operation_blocked`. Failed original-authority access emits
`original_authority_unavailable`. Execution emits the bounded condition tokens above, or the
application failure code. Systemd's existing state/exit fields still describe process availability,
not receiver success. The [operator guide](../guides/operator.md#diagnose-and-resume) explains how
to diagnose and repair blocked work. Publication's separate bounded stdout/empty-stderr contract is
unchanged.

## Command discovery

All three executables accept `--help` and `--version` alone, without opening configuration, history
or sockets. Help prints fixed text, version prints the executable name and Cargo package version,
and both exit zero. Extra or invalid arguments exit 2 with bounded usage diagnostics. Runtime and
publication failures retain their separate meanings. `kapseld` is still Linux-only for execution.

## Fixed service client

The source client's exact grammar is:

```text
kapsel-service-client list [after-id]
kapsel-service-client history [after-id]
kapsel-service-client submit <operation-id>
kapsel-service-client status <operation-id>
kapsel-service-client receipt <operation-id> <new-output-file>
```

It has no socket, authority, retry, lifecycle or protocol configuration. It connects only to
`/run/kapsel/kapseld.sock`, sends one frame, write-half-closes, reads one bounded response and
exits. It rejects responses without integer version 1. `list`, `history`, `submit` and `status`
print the exact one-line JSON response. `receipt` accepts only `READY`, validates lowercase hex and
SHA-256, and creates a new regular mode-`0600` file without following or replacing a path. It prints
bounded JSON with status, digest and the caller-selected output pathname, not receipt bytes. Other
daemon statuses fail without creating output.

The caller-selected export path is local to the client, never daemon authority. There is no SDK or
reusable protocol package.

Local failures write one fixed diagnostic line to stderr, with no argument, path, action data or raw
error. Exit 2 means invalid usage. Exit 4 means a local connection, exchange, response, receipt
availability, export or stdout failure, identified by `connection_unavailable`,
`exchange_incomplete`, `response_invalid`, `receipt_unavailable`, `export_failed`, or
`output_unavailable`. Read the original ID after any uncertain submission. Transport completion is
not admission or receiver success. Exit 0 means a response was delivered, not that an action
succeeded. Service JSON (including ERROR or NOT_ADMITTED) remains on stdout unchanged. A failed
export may leave a partial newly created file and never changes the action.

The [source operator guide](../guides/operator.md) shows the fixed caller identity and
primary/effective group. No supplementary membership is required.

## Execution and process lifecycle

Execution and projection `ServiceApplication` handles open the same bounded catalog and journal.
They are two handles to one store, not separate lifecycle owners. Projection does not advance
lifecycle state or call Kubernetes.

Synchronous storage runs outside the current-thread reactor in at most eight registered blocking
jobs. A response deadline or supervisor cancellation cannot release connection or execution permits
while physical work survives.

On SIGTERM, finite serving completion or a recoverable accept error, the service stops accepting and
drains handlers, supervisors and physical jobs before releasing applications, retained roots or
lifecycle exclusion. A stuck fsync can block retirement indefinitely. Cold publication uses the
shared nonwaiting lifecycle lock to exclude publication until retirement finishes.
[Runtime ownership](../contributing/service_runtime.md#physical-jobs-and-retirement) explains the
registry and reactor requirements.

The exact ordinary argv is:

```text
/usr/libexec/kapsel/kapseld --operator-config /etc/kapsel/operator.json --socket /run/kapsel/kapseld.sock
```

Startup accepts no environment configuration or finite-connection input. It opens authenticated read
and execution applications without reconciliation, secures the socket and serves indefinitely.
Kubernetes configuration, receipt seed and export availability are not prerequisites for reads. Only
explicit ID selection can request a bounded advancement pass. There is no periodic retry or
automatic same-boot restart loop.

Before bind, it removes an existing socket leaf only when no listener answers and metadata shows an
exact single-link socket owned by the service UID and caller-group GID with mode `0660`. Every other
leaf remains unchanged and startup fails. Systemd may then remove the service-owned runtime
directory and leaf. After bind, exact socket type, owner, group and mode are verified again.

SIGTERM drains surviving work. Process loss or manual SIGKILL may interrupt a durable window. After
activation, callers read first and explicitly reselect the same identity when appropriate. After
`apply_started`, gateway recovery observes and never resends. Ordinary status/receipt reads cannot
acquire later observations or change a terminal `UNKNOWN`.

The gateway's [initial observation policy](kubernetes_effect.md#result-meaning) defines the fixed
per-pass time and read bounds. Explicit resumption after interruption starts a new pass, not a
durable operation-wide countdown. Reconnect and stored reads never extend the surviving pass. During
observation the single worker remains occupied, so selection of B returns `BUSY` without admission.
Status and receipt reads use the separate stored-read path. The observation bound does not bound
storage stalls or graceful retirement. No operator or caller configuration changes the budget, and
format 6 retains no timing facts. The 504 retained / 32 unfinished limits and no-pruning policy are
unchanged.

The unit uses `Type=exec`, `User=kapsel`, `Group=kapsel-service-callers`, `RuntimeDirectory=kapsel`,
`RuntimeDirectoryMode=0750`, `StateDirectory=kapsel`, `StateDirectoryMode=0700`, `UMask=0077`,
`Restart=no`, null stdout, journal stderr, disabled start-rate limiting, the fixed argv above and
`WantedBy=multi-user.target`. Boot, explicit start and explicit restart each attempt startup once.
Systemd state plus authenticated socket use is the health boundary. Process fields are
`ActiveState`, `SubState`, `Result`, `ExecMainCode`, `ExecMainStatus` and `NRestarts`, supplemented
by the fixed operator diagnostic codes above. The socket exposes no administrative or health
request.

## Kubernetes authority and installed assets

RBAC permits namespaced `get` and `patch` on the named Deployment. It is not a field policy. The
concrete adapter enforces the exact approved image operation. Safe credential bytes are snapshotted
at startup and the receiver client is constructed only on selection. The operator must issue and
renew credentials. Credential expiry cannot become a receiver result. Local reads do not need
receiver access. Startup does not reconcile operations.

| Repository input                                | Installed destination                              |
| ----------------------------------------------- | -------------------------------------------------- |
| feature-free root `kapsel`                      | `/usr/bin/kapsel`                                  |
| feature-free `kapsel-service-client`            | `/usr/bin/kapsel-service-client`                   |
| feature-free `kapsel-service-mcp`               | `/usr/bin/kapsel-service-mcp`                      |
| feature-free `kapseld`                          | `/usr/libexec/kapsel/kapseld`                      |
| `crates/kapsel-daemon/deploy/kapseld.service`   | `/usr/lib/systemd/system/kapseld.service`          |
| `crates/kapsel-daemon/deploy/kapseld.conf`      | `/usr/lib/sysusers.d/kapseld.conf`                 |
| `crates/kapsel-daemon/deploy/kapseld-rbac.yaml` | `/usr/share/kapsel/kapseld-rbac.yaml`              |
| `docs/guides/operator.md`                       | `/usr/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md` |

The static RBAC manifest contains one token-automount-disabled `ServiceAccount/demo/kapsel-service`,
one Role for `apps/deployments` `get`/`patch` with `resourceNames: ["agent-api"]`, and one
RoleBinding. It creates no credential, token Secret, Namespace, Deployment, workload or ClusterRole.
Static files alone are not an authenticated installer. Use an authenticated release archive.

## Existing host state

Fresh-host preparation requires absent service identities, installed assets and private roots.
Matching account names, paths or bytes do not establish ownership or authorize adoption or deletion.
Before changing a host that may retain actions, the operator must inventory its service accounts,
configuration, state, locks, installed assets and separately provisioned receiver resources.
Preserve ambiguous evidence and establish provenance independently. Source deletion is not
uninstall. Kapsel provides no automated cleanup or state migration.

## Qualification envelope and residual risk

Deterministic and Linux process tests cover the application/service paths, receipt
commitment/retrieval, unavailable export, roots, and socket identity.
[Testing](../contributing/testing.md) explains where these checks belong.
[Release artifacts](release.md) describes the candidate checks.

Container evidence may use host emulation and is not fresh-VM installation proof. Process-exit tests
do not prove power-loss durability. None of this establishes production safety, HA, host/disk-loss
continuity, backup automation, another platform, broad upgrade/rollback, online identity rotation,
remote callers or protection from compromised host root, kernel or service UID.

The service provides no queue, periodic controller, network MCP endpoint, SDK, generic protocol,
second store, policy engine, dashboard or hosted authority. Its two concrete effects share the
[caller lifecycle](../guides/caller.md), not receiver-result semantics.
