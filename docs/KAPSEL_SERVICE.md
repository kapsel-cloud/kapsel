# Kapsel service

Status: accepted implementation in unreleased source. Not a published or supported installation.

This page owns the `kapseld -> kapsel` composition, authenticated local protocol, fixed filesystem
roots, process lifecycle, static assets, and installer retirement. The
[effect-gateway contract](EFFECT_GATEWAY.md) owns authorization, action lifecycle, recovery,
receiver results and receipts. [Technical scope](SCOPE.md) owns the accepted product boundary.

## Boundary

```text
bounded local caller
  -> /run/kapsel/kapseld.sock
       -> kapseld under a separate OS identity
            -> kapsel::Application
                 -> sole SQLite effect journal
                 -> concrete Kubernetes adapter
```

The service gives execution a lifetime independent of a caller connection. A reconnecting caller can
read the same action's status and original receipt without gaining credentials or deciding whether
to send a mutation again. It is retained as the current bounded broker composition, not a permanent
hosting or installation commitment.

The sole capability is `kubernetes.set_deployment_image`. The service requires an exact-snapshot v2
grant at startup and restart, binding the operation tuple and independently acquired Deployment UID
and resourceVersion. Legacy grants fail before journal opening or recovery. Existing handles cannot
acquire replacement authority. Legacy CLI/MCP grants keep their original meaning, but old journal
versions cannot be opened by current source.
[Exact-snapshot approval](EFFECT_GATEWAY.md#exact-snapshot-approval-in-unpublished-head) owns those
distinctions. The service composes `Application`, never gateway internals.

## Runtime inventory

| Item                   | Current source boundary                                                                                                  |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Packages               | Root `kapsel` and unpublished `kapseld -> kapsel`                                                                        |
| Executables            | `/usr/bin/kapsel`, `/usr/libexec/kapsel/kapseld`, `/usr/bin/kapsel-service-client`                                       |
| Caller interface       | One length-prefixed JSON request and response per Unix-socket connection                                                 |
| Authentication         | Parent `0750`, socket `0660`, service UID and `kapsel-service-callers` GID; exact effective caller-group peer credential |
| Connection resources   | At most eight admitted connections; two-second read/write deadlines; no queue                                            |
| Durable store          | Existing format-4 SQLite effect journal only                                                                             |
| Configuration          | Fixed `/etc/kapsel/operator.json`; private authority beneath `/etc/kapsel`                                               |
| OS ownership           | Locked service identity, `0700` private roots and `0600` private files                                                   |
| Caller identity        | Locked `kapsel-service-caller`, primary/effective group `kapsel-service-callers`                                         |
| Kubernetes authority   | Namespaced `get` and `patch` on exact Deployment `demo/agent-api`                                                        |
| Runtime dependencies   | Rust executables, Linux Unix sockets, systemd, existing SQLite/Kubernetes stack                                          |
| Tested failure domains | Caller disconnect, process loss, same-host restart, attempt and receipt-commit seams, bounded receiver ambiguity         |

## Authority and filesystem

The operator provisions the existing operator-document grammar at these exact paths. There is no
installer in the active source tree:

```text
/etc/kapsel/operator.json
/etc/kapsel/grant.bin
/etc/kapsel/authorization.pub
/etc/kapsel/kubeconfig.yaml
/etc/kapsel/receipt.seed
/var/lib/kapsel/journal.sqlite3
```

Configuration and state roots are service-owned mode `0700`. Operator files are stable regular,
single-link, service-owned mode `0600`. The caller group receives no read or traversal permission.
The journal and worker lock may be absent before first use and have exact private file checks when
present. Credentials and signing material never enter caller input or service responses.

Startup opens `/etc/kapsel`, `/var/lib/kapsel`, and `/run/kapsel` descriptor-relatively and
validates owners, modes, types, link counts, path components and stable consumed bytes. It retains
those roots. `/var/lib/kapsel/receipts` is not opened or required. The optional operator-document
`receipt_directory` is only a CLI/MCP export destination.

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
filesystem-publication phase. Journal versions older than format 4 are rejected before
reconciliation and binding, without migration.

Receipt requests read committed bytes through `Application`; callers receive no journal access.
Retrieval never re-signs or contacts Kubernetes. The service-client receipt command exports a copy
separately. Export failure cannot change terminal status or block later retrieval. Database
availability is required for retrieval. Consistent backups must preserve action history and receipt
bytes together. There is no automatic backup or host-loss continuity promise.

## Protocol

Each connection carries a four-byte unsigned big-endian length, one UTF-8 JSON body, required client
write-half-close, one framed response, and close. Request length is 1–16 KiB. Ordinary responses are
at most 16 KiB and receipt responses at most 40 KiB. Aggregate frame-read and response-write
deadlines are two seconds. Saturation closes immediately without reading a body or creating work.

The socket accepts exactly:

```json
{"request":"get_set_deployment_image_status","operation_id":"operation-id"}
{"request":"get_set_deployment_image_receipt","operation_id":"operation-id"}
{"request":"submit_set_deployment_image","operation_id":"operation-id","namespace":"demo","deployment":"agent-api","container":"api","immutable_image_digest":"registry.example/agent-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
```

Input key order is insignificant. Duplicate, unknown, missing, null, wrong-typed, trailing,
cross-request, malformed UTF-8, oversized, timed-out and out-of-grammar fields fail closed without
lifecycle effect.

Status returns `NOT_FOUND`, `IN_PROGRESS`, `NOT_ATTEMPTED` with its required `target_rejection`,
`SUCCEEDED`, `FAILED`, or `UNKNOWN`, without Kubernetes access. It projects `approved_target`,
`observed_target` and `attempt_target` as null or bounded objects with `uid` and `resource_version`.
Missing observed members are null. `NOT_FOUND` carries no target facts.

Receipt responses are `{"status":"NOT_FOUND"}`, `{"status":"NOT_READY"}`, or a ready record
containing only `status:"READY"`, `receipt_hex` and `receipt_sha256`. Hex and digest are lowercase
and identify the exact journal-frozen bytes. A pre-attempt rejection has no effect receipt.

A submission that acquires the sole execution slot, matches the configured grant and installs the
background task returns `{"status":"ACCEPTED"}`. This means only process ownership of execution and
the slot. It may precede durable visibility and is not receiver success. Disconnect or response
failure does not cancel execution. Completion is observed through status and receipt reads.

A submission that cannot acquire the slot immediately returns `{"status":"BUSY"}`. It waits for
nothing, creates no queue, calls no `Application` method and changes no lifecycle fact. Invalid
requests return `invalid_request`; application or exact-grant failures return the non-disclosing
`operation_failure`. Peer denial, framing failure, timeout, saturation and over-limit responses
close without a response.

## Fixed service client

The source client's exact grammar is:

```text
kapsel-service-client submit <operation-id> <namespace> <deployment> <container> <immutable-image-digest>
kapsel-service-client status <operation-id>
kapsel-service-client receipt <operation-id> <new-output-file>
```

It has no socket, authority, retry, lifecycle or protocol configuration. It connects only to
`/run/kapsel/kapseld.sock`, sends one frame, write-half-closes, reads one bounded response and
exits. `submit` and `status` print the exact one-line JSON response. `receipt` accepts only `READY`,
validates lowercase hex and SHA-256, and creates a new regular mode-`0600` file without following or
replacing a path. It prints bounded JSON with status, digest and the caller-selected output
pathname, not receipt bytes. Other daemon statuses fail without creating output.

The caller-selected export path is local to the client, never daemon authority. There is no SDK or
reusable protocol package. The [source operator guide](KAPSEL_SERVICE_OPERATOR.md) shows the fixed
caller identity and primary/effective group. No supplementary membership is required.

## Execution and process lifecycle

Execution and projection `Application` handles may open the same configured operation and journal.
They are two handles to one store. Projection does not advance lifecycle state or call Kubernetes.

The exact ordinary argv is:

```text
/usr/libexec/kapsel/kapseld --operator-config /etc/kapsel/operator.json --socket /run/kapsel/kapseld.sock
```

Startup accepts no environment configuration or finite-connection input. It opens and reconciles the
execution application before binding, opens the projection application, secures the socket and
serves indefinitely. There is no periodic retry or automatic same-boot restart loop.

Before bind, it removes an existing socket leaf only when no listener answers and metadata shows an
exact single-link socket owned by the service UID and caller-group GID with mode `0660`. Every other
leaf remains unchanged and startup fails. Systemd may then remove the service-owned runtime
directory and leaf. After bind, exact socket type, owner, group and mode are verified again.

SIGTERM or process loss may interrupt a durable window. The next explicit activation uses gateway
recovery. After `apply_started`, it observes and never resends. Ordinary status/receipt reads cannot
invoke the test-only later-observation prototype or change a terminal `UNKNOWN`.

The unit uses `Type=exec`, `User=kapsel`, `Group=kapsel-service-callers`, `RuntimeDirectory=kapsel`,
`RuntimeDirectoryMode=0750`, `StateDirectory=kapsel`, `StateDirectoryMode=0700`, `UMask=0077`,
`Restart=no`, null standard streams, disabled start-rate limiting, the fixed argv above and
`WantedBy=multi-user.target`. Boot, explicit start and explicit restart each attempt startup once.
Systemd state plus authenticated socket use is the health boundary. Diagnostics are limited to
`ActiveState`, `SubState`, `Result`, `ExecMainCode`, `ExecMainStatus` and `NRestarts`. The socket
exposes no administrative or health request.

## Kubernetes authority and installed assets

RBAC permits namespaced `get` and `patch` on the named Deployment. It is not a field policy. The
concrete adapter enforces the exact approved image operation. Credentials are loaded at startup;
issuance and renewal are operator responsibilities. Credential expiry cannot become a receiver
result. Local reads remain available while the process is running, but startup reconciliation may
need receiver access for an unfinished action.

| Repository input                          | Direct-source destination                          |
| ----------------------------------------- | -------------------------------------------------- |
| feature-free root `kapsel`                | `/usr/bin/kapsel`                                  |
| feature-free `kapsel-service-client`      | `/usr/bin/kapsel-service-client`                   |
| feature-free `kapseld`                    | `/usr/libexec/kapsel/kapseld`                      |
| `crates/kapseld/deploy/kapseld.service`   | `/usr/lib/systemd/system/kapseld.service`          |
| `crates/kapseld/deploy/kapseld.conf`      | `/usr/lib/sysusers.d/kapseld.conf`                 |
| `crates/kapseld/deploy/kapseld-rbac.yaml` | `/usr/share/kapsel/kapseld-rbac.yaml`              |
| `docs/KAPSEL_SERVICE_OPERATOR.md`         | `/usr/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md` |

The static RBAC manifest contains one token-automount-disabled `ServiceAccount/demo/kapsel-service`,
one Role for `apps/deployments` `get`/`patch` with `resourceNames: ["agent-api"]`, and one
RoleBinding. It creates no credential, token Secret, Namespace, Deployment, workload or ClusterRole.
Static files are source assets, not an authenticated installer or accepted current release.

## Installer retirement

The partial, unpublished installer was removed rather than maintained around an undecided
installation model. Future installation work must start from a concrete maintainer or user workflow
and a sufficiently settled product shape. This retirement selects no replacement, migration or
upgrade path and changes no published v0.2.0 artifact or contract.

The final pre-deletion revision is `244687740d535bc4ee97e9fe51021745e8b8e30d`. At that revision,
`linux.rs::run` ends at `ImplementationIncomplete` after creating the two groups and two locked
users. `ensure_host_file` has only test callers. No working installation was delivered.

From a checkout containing that revision, inspect the removed source without restoring active code:

```sh
git show 244687740d535bc4ee97e9fe51021745e8b8e30d:crates/kapsel-installer/src/linux.rs
git ls-tree -r --name-only 244687740d535bc4ee97e9fe51021745e8b8e30d crates/kapsel-installer
git show 244687740d535bc4ee97e9fe51021745e8b8e30d:docs/KAPSEL_SERVICE.md
```

If needed, first fetch from a repository containing the revision, for example
`git fetch /path/to/owning/kapsel master`. Availability in one local checkout does not imply a
published release or remote availability. Git is the archive, not a second maintained source tree.

Removed: `crates/kapsel-installer`, its embedded-bundle build script and generated test fixtures,
the bundle and Debian identity launchers, workspace membership, installer-only CI and hook checks,
and its exclusive direct dependencies. Identity, transaction, host-file publication and recovery
tests inside that crate covered only the retired mechanism, so they were deleted, not ported.

Retained: `kapsel-authority` owns grant/trust codecs, request grammar and the combined authority
check exposed through `Application`. Its vectors and application-contract tests remain. `kapseld`,
its client, static systemd/sysusers/RBAC assets and `install_assets` tests still own the service
composition. Linux process and root-substitution tests still establish service admission, private
paths, restart and receipt retrieval. Core approval, dispatch, recovery and receipt tests remain
unchanged. The published archive assembly, authentication and smoke consumers remain separate.

Reusable lessons from the removed implementation:

- A command exit or timeout does not establish ownership. Recovery needs independent, exact
  observations and must stop on conflict or partial evidence.
- Durable pending-effect facts must precede host mutation. A lock must cover child processes too,
  not just the process that spawned them.
- Matching names or bytes do not justify adoption or deletion. Publication and recovery need exact
  inode/parent identity and explicit ownership evidence.

Source deletion is not uninstall. On any disposable host that ran a staged build, an operator must
inventory the `kapsel` and `kapsel-service-callers` groups, `kapsel` and `kapsel-service-caller`
users, `/var/lib/kapsel-installer` transaction evidence, `/run/lock/kapsel-installer.lock`, and any
separately provisioned service files or Kubernetes objects before deciding what to retain. Do not
infer installer ownership from a matching name. Preserve ambiguous evidence. No identities, host
files or Kubernetes objects are removed by this retirement, and no fleet-wide cleanup is claimed.

## Qualification envelope and residual risk

The earlier direct-source service qualification ran on one fresh x86-64 Debian 12 KVM VM with
systemd 252 and Kubernetes v1.33.12. It established separate identities, caller denial from private
state, exact-effective-GID admission, systemd lifecycle, stale-socket checks, named RBAC, a
successful image operation, reconnect and ordered revocation. That historical run predates format-4
receipts and is not fresh-native acceptance of current HEAD.

Current deterministic and Linux process tests cover the maintained application/service paths,
receipt commitment/retrieval, unavailable export, roots and socket identity. The reconnect and
later-observation reports distinguish live Kubernetes evidence from mock HTTP, process-exit and
model evidence. [Testing](TESTING.md) owns proof placement and
[action-boundary evidence](TESTING.md#action-boundary-evidence) pins source revisions.

Container evidence may use host emulation and is not fresh-VM installation proof. Process-exit tests
do not prove power-loss durability. None of this establishes production safety, HA, host/disk-loss
continuity, backup automation, another platform, broad upgrade/rollback, online identity rotation,
remote callers or protection from compromised host root, kernel or service UID.

No queue, periodic controller, HTTP/TCP/MCP server, SDK, generic protocol, second store, policy
engine, dashboard, hosted authority, second capability or new installation promise is added.
