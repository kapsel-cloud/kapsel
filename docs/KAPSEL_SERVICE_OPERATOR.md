# Kapsel service source operator guide

Status: unreleased source workflow. No supported installer or published service artifact.

This guide describes caller use after explicit operator provisioning in a disposable environment. It
supplies no install, refresh or uninstall command. The [service contract](KAPSEL_SERVICE.md) owns
fixed paths, identities, authority and process lifecycle.

## Reproduce before provisioning

The [reconnect experiment](RECONNECTABLE_AGENT_ACTION.md) describes a disposable Linux service and
pinned Kubernetes receiver, including the operator-owned setup script. It is a research harness, not
an installation product. The [build guide](BUILD.md#kapsel-service-candidate) lists source and Linux
process checks. The [published-beta evaluation guide](EVALUATOR.md) is the separate route for the
released local CLI/MCP demonstration.

Before exposing the source service, the operator must supply its static binaries/assets, separate
service and caller identities, fixed private roots, narrow Kubernetes authority and operator
configuration. Approval must be a v2 exact-snapshot grant acquired through
`kapsel provision-snapshot-grant`, not caller-supplied UID/version facts. The service rejects legacy
grants and journal versions older than format 5, including format 4. Keep credentials, grants,
trust, signing seeds, private storage and process controls outside the caller boundary.

The fixed `/etc/kapsel/operator.json` uses the
[versioned service document](KAPSEL_SERVICE.md#versioned-operator-document), not the legacy CLI/MCP
document. It supplies bounded snapshot approvals and external historical public-key appointments.
Each approved ID and tuple is immutable. Reapproval requires an operator decision, a new grant and a
new handle. Restart must not refresh authority on an existing action. Credential provisioning and
renewal remain explicit operator work. Physical-capacity/live qualification remains outstanding.

### Replace the cold operator document

Stop the daemon gracefully, then run exactly `/usr/libexec/kapsel/kapseld --replace-operator-config`
under the existing service UID/effective GID, feeding the complete candidate on stdin (at most 160
KiB). This is trusted operator provisioning, not a caller command; it changes only fixed
`/etc/kapsel/operator.json`, never starts the daemon and never advances an action. The daemon and
publisher share a nonwaiting lifecycle lock. Do not delete that lock to bypass contention. Do not
replace private roots or launch old binaries ignoring it.

The [canonical publication contract](KAPSEL_SERVICE.md#cold-publication-and-graceful-retirement)
owns validation, custody and outcomes. `PUBLISHED` with exit `0` confirms rename and directory sync;
`NOT_PUBLISHED` with exit `4` proves refusal before rename; `INDETERMINATE` with exit `5` requires
inspection. Stdout contains just that bounded status line. A rename error, failed output, lost
response or crash is not proof of non-publication. Never automatically roll back or replay after an
uncertain result. Inspect the fixed document and journal before deciding the next operator action.

Validation is strictly read-only/no-create against retained history, including schema and capacity.
Recovery-required journals must first undergo ordinary recovery, not publication-side repair. Lost
journal history plus leftover sidecars or a worker lock is rejected rather than treated as fresh.
Catalog removal does not erase history or change original receipts. Omitting an original historical
key makes that ID inaccessible until its external trust is restored; it does not replace authority.

SIGTERM stops acceptance and drains surviving work. Systemd has `TimeoutStopSec=infinity`: hung
storage can leave stop incomplete and publication excluded indefinitely. Manual SIGKILL is a crash,
not successful retirement. After a completed publication, start normally and read history/status
first; startup does not reconcile automatically.

## Submit and inspect

With the service already provisioned and running, list the approved handles and read retained
history before selecting an ID. These example IDs are placeholders, not authority:

```sh
operation_id=service-op-1
sudo -u kapsel-service-caller -g kapsel-service-callers -- \
  /usr/bin/kapsel-service-client list
sudo -u kapsel-service-caller -g kapsel-service-callers -- \
  /usr/bin/kapsel-service-client history
sudo -u kapsel-service-caller -g kapsel-service-callers -- \
  /usr/bin/kapsel-service-client submit "$operation_id"
sudo -u kapsel-service-caller -g kapsel-service-callers -- \
  /usr/bin/kapsel-service-client status "$operation_id"
```

The caller account's primary group is `kapsel-service-callers`. The explicit `-g` supplies the
required effective GID without a supplementary membership entry. Every response has integer
`version: 1`. `ADMITTED` includes the confirmed durable phase, not worker liveness or receiver
success. `NOT_ADMITTED` with `BUSY` or `CAPACITY` is a definite refusal of new work.
`INDETERMINATE`, an error, timeout or disconnect is not proof of non-admission. Read the same ID; do
not invent a replacement action. `list` and `history` accept an optional `after-id` cursor.

| Status          | Next interpretation                                                                                                                               |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NOT_FOUND`     | No durable action is visible. This is not proof that an accepted background task cannot still start.                                              |
| `IN_PROGRESS`   | Read the same handle again. Do not invent a replacement action.                                                                                   |
| `NOT_ATTEMPTED` | Inspect `target_rejection`. `STALE_APPROVAL` requires an operator decision about new approval, not automatic refresh. There is no effect receipt. |
| `SUCCEEDED`     | Inspect application behavior. Deployment availability is not application correctness.                                                             |
| `FAILED`        | Investigate the defined receiver failure. No automatic rollback is authorized.                                                                    |
| `UNKNOWN`       | Stop dependent mutations and hand the original evidence to an operator. It is not retry permission.                                               |

For an attempted action with a ready receipt, export its exact stored bytes to a new caller-owned
file and inspect them under separately supplied trust:

```sh
receipt="/tmp/$operation_id.receipt"
sudo -u kapsel-service-caller -g kapsel-service-callers -- \
  /usr/bin/kapsel-service-client receipt "$operation_id" "$receipt"
evaluation_time_unix_s='<operator-selected Unix second within receipt trust>'
sudo /usr/bin/kapsel inspect \
  --receipt "$receipt" \
  --trust /secure/kapsel/receipt.trust \
  --evaluation-time-unix-s "$evaluation_time_unix_s"
```

The trust file and evaluation time are operator-selected. Inspection reports `INSPECTED`, never
`VERIFIED`. The service reads canonical bytes from SQLite. An unavailable output destination or
existing file fails export without changing the action. Use a new writable destination for a later
export. The service needs no receipt directory and the caller never opens its private journal.

## Disconnect, restart and uncertainty

Caller disconnect does not cancel surviving selected work. Service startup exposes authenticated
stored reads without reconciliation, Kubernetes availability, receipt seeds or export access.
Missing, invalid or unsafe execution files disable that material without disabling reads; they do
not trigger ambient configuration or replacement keys. Read status/history first after restart.
Explicit reselection of the same unfinished ID requests one bounded advancement pass. After a
durable attempt, recovery observes without another PATCH, even when loss may have preceded the
original send. A stored receipt remains byte-identical through restart and retrieval.

Ordinary status and receipt reads are offline projections. A rollout settling after terminal
`UNKNOWN` does not update the historical result. The
[later-observation prototype](LATER_OBSERVATION_EXPERIMENT.md) is useful evidence for a separately
scoped implementation decision, not a command available here.

Systemd and operator configuration own lifecycle and credentials. A stopped daemon makes the socket
unavailable. Already exported receipts remain inspectable offline. Database loss can prevent
retrieval, and losing or rolling back action history defeats continuity assumptions. No automatic
backup, HA, credential renewal, installer recovery or destructive cleanup is supplied by this guide.
