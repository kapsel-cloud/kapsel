# Kapsel service

Status: accepted unpublished source-independent preview candidate.

Kind: product contract. Authority: service process boundary, local protocol, installed assets,
qualification envelope, unsupported behavior, and residual risk.

Owns: The `kapseld -> kapsel` composition, authenticated Unix socket, fixed filesystem roots,
systemd lifecycle, and narrow Kubernetes RBAC.

Does not own: Authorization, effect lifecycle, receiver-result, `UNKNOWN`, or receipt semantics;
those remain owned by the [effect-gateway contract](EFFECT_GATEWAY.md). Build and installation
commands are in [Build](BUILD.md), and proof requirements are in [Testing](TESTING.md).

## Boundary

```text
bounded local caller
  -> /run/kapsel/kapseld.sock
       -> kapseld under a separate OS identity
            -> kapsel::Application
                 -> sole SQLite effect journal
                 -> concrete Kubernetes adapter
```

The Kapsel service retains the sole `kubernetes.set_deployment_image` capability. The exact grant
binds one operation identity, namespace, Deployment, container, and immutable image digest.
`kapseld` composes `Application`; it does not sequence gateway internals.

The service process exists because the synchronous CLI and stdio MCP adapter do not provide
caller-independent lifetime, startup reconciliation, read-only reconnect/status, exact receipt
retrieval, or a separate installed authority identity. Wrapping either adapter would require an
unsupported status store, receipt copying, and supervision.

## Runtime inventory

| Item                        | Contract                                                                                                                                                      |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Packages                    | Existing root `kapsel`; one unpublished `kapseld -> kapsel` package                                                                                           |
| Executables                 | Existing `/usr/bin/kapsel`; `/usr/libexec/kapsel/kapseld`; fixed `/usr/bin/kapsel-service-client` caller                                                      |
| Caller interface            | `/run/kapsel/kapseld.sock`; one length-prefixed JSON request and response per connection                                                                      |
| Authentication              | Parent `0750`, socket `0660`, owner `kapsel:kapsel-service-callers`; exact effective caller-group peer credential required                                    |
| Connection resources        | At most eight admitted connections; two-second read and write deadlines; no queue                                                                             |
| Durable stores              | Existing effect-gateway SQLite journal only                                                                                                                   |
| Operator configuration      | Fixed `/etc/kapsel/operator.json`; authority beneath `/etc/kapsel`; journal and receipts beneath `/var/lib/kapsel`                                            |
| Startup path validation     | Descriptor-relative fixed roots; exact owners/modes; regular single-link files; no symlinks; stable consumed bytes                                            |
| OS ownership                | Locked non-login `kapsel`; `0700` private roots and `0600` private files                                                                                      |
| Caller identity             | Fixed locked `kapsel-service-caller`, created separately; supervisor-set effective group is distinct from supplementary membership                            |
| Kubernetes authority        | `ServiceAccount/demo/kapsel-service`; namespaced `get` and `patch` on exact Deployment `agent-api`                                                            |
| Installed assets            | Three executables, systemd unit, sysusers record, non-secret RBAC manifest, and operator guide; no socket unit, tmpfiles rule, PID file, wrapper, or workload |
| Runtime dependencies        | Rust executables, Linux Unix sockets, systemd, existing SQLite and Kubernetes stack; no Python, shell, daemon framework, RPC SDK, or new DB                   |
| Supported failure domains   | Caller disconnect, service process loss, same-host restart, mutation/publication seams, bounded Kubernetes ambiguity                                          |
| Unsupported failure domains | Host or disk loss, backup, HA, fleet, partition tolerance, production, broad upgrade/rollback, identity rotation, or another operation                        |

The service adds no scheduler, queue, controller framework, protocol framework, provider
abstraction, policy engine, SDK, or second store.

## Authority and filesystem

The Kapsel service reuses the root operator JSON grammar at these exact paths:

```text
/etc/kapsel/operator.json
/etc/kapsel/grant.bin
/etc/kapsel/authorization.pub
/etc/kapsel/kubeconfig.yaml
/etc/kapsel/receipt.seed
/var/lib/kapsel/journal.sqlite3
/var/lib/kapsel/receipts
```

Configuration and state roots are service-owned mode `0700`; operator files are regular,
single-link, service-owned mode `0600`. The caller group receives no read or traversal permission.
Journal, worker lock, and receipt files may be absent before first use; when present they remain
regular, single-link, service-owned mode `0600`.

Startup opens fixed `/etc/kapsel`, `/var/lib/kapsel`, `/var/lib/kapsel/receipts`, and `/run/kapsel`
roots descriptor-relatively. It validates exact owners, modes, file types, link counts, path
components, and stable consumed bytes. It retains handles for the configuration, state, receipt, and
runtime roots. Authority and receipt reads use validated opened inodes, and frozen receipt paths
remain beneath the fixed receipt directory. Host root, the kernel, and the service identity remain
trusted.

The locked `kapsel` identity exclusively owns operator files, Kubernetes credentials, grant trust,
receipt signing material, journal, worker lock, and receipts. The caller never selects or receives
an operator path, credential, grant/trust bytes, signing material, journal path, receipt path,
lifecycle transition, or Kubernetes patch.

## Protocol

Each connection carries one four-byte unsigned big-endian length, one UTF-8 JSON body, required
client write-half-close, one framed response, and close. Request length is 1–16 KiB. Ordinary
responses are at most 16 KiB and receipt responses at most 40 KiB. Aggregate frame-read and
response-write deadlines are two seconds. At most eight connections are admitted; saturation closes
immediately without reading a body or creating lifecycle work.

The socket accepts exactly three capability-specific requests:

```json
{"request":"get_set_deployment_image_status","operation_id":"operation-id"}
{"request":"get_set_deployment_image_receipt","operation_id":"operation-id"}
{"request":"submit_set_deployment_image","operation_id":"operation-id","namespace":"demo","deployment":"agent-api","container":"api","immutable_image_digest":"registry.example/agent-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
```

Input key order is insignificant. Duplicate, unknown, missing, null, wrong-typed, trailing,
cross-request, malformed UTF-8, oversized, timed-out, and out-of-grammar fields fail closed without
lifecycle effect.

Status returns `NOT_FOUND`, `IN_PROGRESS`, `NOT_ATTEMPTED` with its required `target_rejection`,
`SUCCEEDED`, `FAILED`, or `UNKNOWN` without Kubernetes access. Status responses contain only
`status`, except `NOT_ATTEMPTED`. Receipt responses are `{"status":"NOT_FOUND"}`,
`{"status":"NOT_READY"}`, or a ready record containing only `status:"READY"`, `receipt_hex`, and
`receipt_sha256`. The receipt is lowercase hexadecimal of exact journal-frozen bytes and retains the
journal-frozen lowercase digest.

A submission that acquires the sole execution slot, matches the configured grant, and installs the
background execution task returns `{"status":"ACCEPTED"}`. `ACCEPTED` means only that the process
owns execution and the in-flight slot. It is not a receiver result and may precede durable
visibility. Disconnect or response failure does not cancel execution. Completion is observed only
through status and receipt requests.

A submission that cannot acquire the slot immediately returns `{"status":"BUSY"}`. `BUSY` waits for
nothing, creates no queue, calls no `Application` method, and changes no lifecycle fact. Invalid
requests return `invalid_request`; application or exact-grant failures return the non-disclosing
`operation_failure`. Peer denial, framing failure, timeout, saturation, and an over-limit response
close without a response.

## Fixed service client

`/usr/bin/kapsel-service-client` is the sole service client. It has no socket, authority, path,
retry, lifecycle, or protocol configuration. Its exact grammar is:

```text
kapsel-service-client submit <operation-id> <namespace> <deployment> <container> <immutable-image-digest>
kapsel-service-client status <operation-id>
kapsel-service-client receipt <operation-id> <new-output-file>
```

It always connects to `/run/kapsel/kapseld.sock`, sends one contract-owned frame, write-half-closes,
reads one bounded response, and exits. `submit` and `status` print the exact one-line JSON response.
`receipt` accepts only `READY`, validates lowercase hexadecimal and the declared SHA-256, and
creates the output as one new regular mode-`0600` file without following or replacing a path. It
prints one bounded JSON record containing `status`, `receipt_sha256`, and the caller-selected output
pathname; it never prints receipt bytes. Other daemon statuses fail without creating an output.

The caller has no SDK or reusable protocol package. The supported operator journey invokes it as the
fixed `kapsel-service-caller` identity with effective group `kapsel-service-callers`; supplementary
membership alone remains insufficient.

## Execution and process lifecycle

One execution `Application` and one projection `Application` may open the same configured operation
and journal. They are two handles to one lifecycle store. Projection reads use application-owned
status and frozen-receipt grammar; they neither call Kubernetes nor advance lifecycle state.

The exact ordinary argv is:

```text
/usr/libexec/kapsel/kapseld --operator-config /etc/kapsel/operator.json --socket /run/kapsel/kapseld.sock
```

Ordinary startup accepts no environment configuration or finite-connection input. It opens and
reconciles the execution application once before binding, opens the projection application, secures
the socket, and serves indefinitely. There is no periodic retry or automatic same-boot restart loop.

Before bind, `kapseld` removes an existing socket leaf only when no listener answers and metadata
shows an exact single-link socket owned by the service UID and caller-group GID with mode `0660`.
Every other leaf is left unchanged and startup fails. Systemd may then remove the service-owned
runtime directory and leaf. After bind, `kapseld` verifies exact socket type, owner, group, and mode
before admission.

Caller disconnect does not cancel an accepted operation. SIGTERM or process loss may interrupt any
durable window; the next explicit activation uses effect-gateway recovery. After `apply_started`,
recovery observes and never issues a blind second mutation attempt.

The systemd unit uses `Type=exec`, `User=kapsel`, `Group=kapsel-service-callers`,
`RuntimeDirectory=kapsel`, `RuntimeDirectoryMode=0750`, `StateDirectory=kapsel`,
`StateDirectoryMode=0700`, `UMask=0077`, `Restart=no`, null standard streams, disabled start-rate
limiting, the fixed argv above, and `WantedBy=multi-user.target`. Every boot, explicit start, or
explicit restart attempts startup once.

The sysusers record creates only the locked non-login `kapsel` identity, its private group, and
`kapsel-service-callers`. It does not create the external caller. The caller's supervisor must set
effective `Group=kapsel-service-callers`; supplementary membership alone is insufficient.

Systemd state plus successful authenticated socket use is the health boundary. The socket exposes no
administration, key management, migration, purge, health, or shutdown request. Diagnostics are
limited to `ActiveState`, `SubState`, `Result`, `ExecMainCode`, `ExecMainStatus`, and `NRestarts`.

## Kubernetes authority and installed assets

Kubernetes authority is namespaced `get` and `patch` on exact Deployment `agent-api`. RBAC is not a
field policy; the concrete adapter remains responsible for the fixed conditional image patch.

| Repository input                          | Direct-install destination                         |
| ----------------------------------------- | -------------------------------------------------- |
| feature-free root `kapsel`                | `/usr/bin/kapsel`                                  |
| feature-free `kapsel-service-client`      | `/usr/bin/kapsel-service-client`                   |
| feature-free `kapseld`                    | `/usr/libexec/kapsel/kapseld`                      |
| `crates/kapseld/deploy/kapseld.service`   | `/usr/lib/systemd/system/kapseld.service`          |
| `crates/kapseld/deploy/kapseld.conf`      | `/usr/lib/sysusers.d/kapseld.conf`                 |
| `crates/kapseld/deploy/kapseld-rbac.yaml` | `/usr/share/kapsel/kapseld-rbac.yaml`              |
| `docs/KAPSEL_SERVICE_OPERATOR.md`         | `/usr/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md` |

The RBAC manifest contains one token-automount-disabled `ServiceAccount/demo/kapsel-service`, one
Role granting `apps/deployments` `get` and `patch` for `resourceNames: ["agent-api"]`, and one
RoleBinding. It creates no credential, token Secret, Namespace, Deployment, workload, ClusterRole,
wildcard, or field policy.

Removal stops and disables the service, waits for process and connection closure, removes caller
group membership, revokes Kubernetes authority, and removes all three executables, unit, sysusers
record, RBAC manifest, operator guide, and runtime socket. It retains identities, operator files,
journal, and receipts. Destructive purge is unsupported.

## Source-independent service artifact

The unpublished service preview has one strict `x86_64-unknown-linux-gnu` archive named
`kapsel-service-<40-lowercase-source-revision>-x86_64-unknown-linux-gnu.tar.gz`. It does not change
the immutable v0.2.0 archive. It has one top-level directory and exactly these regular inputs
beneath normalized directories:

```text
LICENSE
SERVICE-METADATA.json
bin/kapsel
bin/kapsel-service-client
lib/systemd/system/kapseld.service
lib/sysusers.d/kapseld.conf
libexec/kapsel/kapseld
share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md
share/kapsel/kapseld-rbac.yaml
share/kapsel/smoke-kapsel-service-artifact.py
share/kapsel/verify-kapsel-service-artifact.py
```

Directories and executables are mode `0755`; other files are mode `0644`. USTAR and gzip metadata,
entry order, owners, groups, names, and timestamps are normalized exactly as in the v0.2 release
assembler. Assembly uses the same pinned Debian 12 Rust builder, feature-free locked release builds,
source-prefix remapping, a clean exact revision and tree, bounded output, and no installed or
operator authority. Metadata binds the schema, root package version, source revision and tree,
target, builder image, Cargo lock digest, each executable digest and length, license digest, and
exact preview non-claims.

Adjacent deterministic `.sha256` and `.SHA256SUMS` files bind the archive and checksum bytes. An
unpublished candidate may additionally carry a Sigstore bundle over exact `.SHA256SUMS` bytes from
the appointed `.github/workflows/kapsel-service-candidate.yml@refs/heads/master` GitHub Actions
identity for the exact source SHA, repository, ref, and `workflow_dispatch` trigger. A checksum
alone establishes byte identity, not publisher authentication. No local assembly, package version,
archive metadata, or source checkout may be presented as authenticated publisher identity.

The bundled Python 3.11 verifier is read by exact archive member name to standard output before
execution. It and the bundled clean-container smoke driver are not installed or service runtime
dependencies. It bounds and validates the archive and sidecars before exclusive extraction, rejects
extra, missing, duplicate, reordered, absolute, traversal, link, special, permissive, oversized, or
non-normalized entries, and executes only extracted files. Deterministic smoke proves binary
identity, the caller's submit/status/exact-receipt path, daemon argv refusal, and static install
bytes without Cargo, a checkout, or repository-relative paths. A second isolated strict assembly
must be byte-identical. The separate fresh native gate must prove systemd install/start/restart,
Kubernetes execution, recovery, inspection, and ordered uninstall from those exact authenticated
bytes. The [Kapsel service operator guide](KAPSEL_SERVICE_OPERATOR.md) is the sole supported
installed journey. Installation is clean-only and refuses pre-existing identities, static
destinations, configuration/state roots, or named RBAC objects; reinstall and upgrade are
unsupported.

This unpublished service preview has no compatibility, upgrade, production, or public-release
promise. Candidate assembly and verification do not authorize publication.

## Qualification envelope

The deterministic package, application, CLI, MCP, formatting, documentation, Clippy, and default
repository gates pass. Native Linux tests cover peer credentials, saturation, framing deadlines,
process-local execution, disconnect continuity, process loss, startup roots, socket identity, and
static asset bytes.

The direct-source path passed on one fresh x86-64 Debian 12 KVM VM with systemd 252, kind 0.32.0,
kubectl 1.33.13, and Kubernetes v1.33.12. The disposable qualification established separate locked
service and caller identities; caller denial from authority and state; exact-effective-GID
admission; boot, explicit start/restart, `Restart=no`, and bounded diagnostics; process-loss and
boot recovery without a second Deployment generation; exact stale-socket handling; named Deployment
RBAC allow/deny behavior; one successful image operation preserving Deployment UID and sidecar;
exact frozen receipt retrieval, offline inspection, replay, and restart; ordered caller and
Kubernetes authority revocation; retained operator, journal, and receipt bytes; and complete cluster
and VM cleanup.

The exact candidate from source revision `5becdcba96a7969a8a88d8bc1ab172aacbb89a44` then passed the
separate authenticated downloaded-artifact journey on a fresh x86-64 Debian 12 KVM with systemd 252,
kind 0.32.0, kubectl 1.33.13, and Kubernetes v1.33.12. The operator authenticated archive SHA-256
`1caec9c621623970e752c7cdd13ab2409d734b83c9dc69eca15c6cd47c527b1e` from the
[candidate workflow](https://github.com/kapsel-cloud/kapsel/actions/runs/33116851737), extracted
only through the bundled verifier, installed without a checkout, invoked the fixed client against
one running Deployment replica, observed `SUCCEEDED`, retrieved and inspected the exact receipt,
restarted without changing the Deployment generation or frozen receipt bytes, revoked caller and
Kubernetes authority, preserved operator state, journal, lock, and receipt bytes, removed the static
assets, deleted the cluster, and destroyed the KVM. The downloaded bytes are therefore an accepted
unpublished preview candidate; they are not a release or production qualification.

The explicit live-kind gate also passed healthy, `ProgressDeadlineExceeded`, and deleted-after-patch
`UNKNOWN` cases against the pinned node image.

## Unsupported behavior

No published Kapsel service release, production use, host-loss continuity, backup, HA, fleet
management, concurrency queue, periodic controller, broad upgrade/rollback matrix, online key or
identity rotation, remote client, container package, SDK, plugin, second capability, arbitrary image
change, arbitrary provider input, hosted authority, managed coordination, or compatibility promise
is supported.

Do not add a socket-activation unit, admin interface, daemon/RPC framework, HTTP/TCP/MCP server,
client SDK, generic envelope, protocol package, second database, cache, queue, scheduler,
controller, lease, dashboard, metrics server, plugin loader, provider trait, policy engine,
container package, sandbox code, or another capability. Service status and diagnostics remain
systemd-owned.

## Residual risk

Source qualification and the accepted downloaded candidate each cover one fresh x86-64 Debian
12/systemd 252 and Kubernetes 1.33 environment. This finite evidence establishes the exact
unpublished candidate journey only. It does not establish production safety, another platform,
upgrade compatibility, backup, HA, repeated external operation, or protection from compromised host
root, kernel, or service identity.
