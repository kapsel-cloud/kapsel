# Kapsel service source operator guide

Status: unreleased source workflow. No supported installer or published service artifact.

The resident service is retained, but the former one-command install, refresh and uninstall journey
is withdrawn. Do not run the partial installer to obtain a working service. This guide describes
caller use only after explicit operator provisioning in a disposable environment. The
[service contract](KAPSEL_SERVICE.md) owns fixed paths, identities, authority and process lifecycle.

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
grants and journal versions older than format 4. Keep credentials, grants, trust, signing seeds,
private storage and process controls outside the caller boundary.

The configured operation ID and tuple are fixed for that service instance. Reapproval requires an
operator decision, a new grant and a new handle. Restart must not refresh authority on an existing
action. Credential provisioning/renewal remains explicit operator work. No installer refresh command
is implemented.

## Submit and inspect

With the service already provisioned and running, use the exact grant-bound values. These example
values are placeholders, not authority:

```sh
operation_id=service-op-1
image='registry.example/agent-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
sudo -u kapsel-service-caller -g kapsel-service-callers -- \
  /usr/bin/kapsel-service-client submit \
  "$operation_id" demo agent-api api "$image"
sudo -u kapsel-service-caller -g kapsel-service-callers -- \
  /usr/bin/kapsel-service-client status "$operation_id"
```

The caller account's primary group is `kapsel-service-callers`. The explicit `-g` supplies the
required effective GID without a supplementary membership entry. `ACCEPTED` means only process
ownership of execution. `BUSY`, timeout and disconnect establish no receiver outcome.

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

Caller disconnect does not cancel accepted execution. Service startup reconciles before exposing the
socket. After a durable attempt, recovery observes without another PATCH, even when loss may have
preceded the original send. A stored receipt remains byte-identical through restart and retrieval.

Ordinary status and receipt reads are offline projections. A rollout settling after terminal
`UNKNOWN` does not update the historical result. The
[later-observation prototype](LATER_OBSERVATION_EXPERIMENT.md) is useful evidence for a separately
scoped implementation decision, not a command available here.

Systemd and operator configuration own lifecycle and credentials. A stopped daemon makes the socket
unavailable. Already exported receipts remain inspectable offline. Database loss can prevent
retrieval, and losing or rolling back action history defeats continuity assumptions. No automatic
backup, HA, credential renewal, installer recovery or destructive cleanup is supplied by this guide.
