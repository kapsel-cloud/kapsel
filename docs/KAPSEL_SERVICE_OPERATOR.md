# Kapsel service operator guide

Status: unreleased preview preparation path. Native installed-artifact and live-journey
qualification remain required. No published service artifact or production support is implied.

The operator prepares exact approvals and private execution material. A separate caller can select
an approved ID and retrieve its evidence, but cannot change authority or control the service. The
[service contract](KAPSEL_SERVICE.md) owns fixed paths, identities and process lifecycle.

## Prepare the extracted artifact

Use one fresh, disposable native x86-64 Debian 12 host with systemd, Python 3.11, OpenSSL, sudo and
standard account tools. Artifact preparation additionally requires Cosign 3.1.2 and GNU `sha256sum`.
Follow [Authenticate and extract the preview](RELEASE.md#authenticate-and-extract-the-preview) using
its checksum-bound verifier companion and Python 3.11 or newer. An unsigned local test archive is
not authenticated publication. No Rust toolchain or repository checkout is needed on the operating
host.

Do not use these fresh-host commands on a machine with experimental service identities, private
roots, installer records, an existing unit or installed Kapsel binaries. Inventory those first under
[experimental-host precautions](KAPSEL_SERVICE.md#experimental-installer-hosts). A matching name is
not permission to adopt, overwrite, chown or remove an object.

In a trusted root operator shell, set `artifact` to the absolute extracted directory. Confirm the
identities and destinations below are absent, including dangling symlinks, before proceeding:

```sh
artifact=/absolute/path/to/kapsel-0.3.0-preview.1-x86_64-unknown-linux-gnu
# Inspect first. Unexpected existing entries mean stop, not automatic reuse.
getent passwd kapsel kapsel-service-caller
getent group kapsel kapsel-service-callers
ls -ld /etc/kapsel /var/lib/kapsel /run/kapsel /usr/libexec/kapsel \
  /usr/bin/kapsel /usr/bin/kapsel-service-client \
  /usr/share/kapsel /usr/share/doc/kapsel \
  /usr/lib/systemd/system/kapseld.service /usr/lib/sysusers.d/kapseld.conf
```

After confirming this is a fresh host, install the exact extracted assets:

```sh
install -d -m 0755 /usr/libexec/kapsel /usr/share/kapsel /usr/share/doc/kapsel
install -m 0755 "$artifact/bin/kapsel" /usr/bin/kapsel
install -m 0755 "$artifact/bin/kapsel-service-client" /usr/bin/kapsel-service-client
install -m 0755 "$artifact/libexec/kapsel/kapseld" /usr/libexec/kapsel/kapseld
install -m 0644 "$artifact/share/kapsel/kapseld.service" /usr/lib/systemd/system/kapseld.service
install -m 0644 "$artifact/share/kapsel/kapseld.conf" /usr/lib/sysusers.d/kapseld.conf
install -m 0644 "$artifact/share/kapsel/kapseld-rbac.yaml" /usr/share/kapsel/kapseld-rbac.yaml
install -m 0644 "$artifact/share/doc/kapsel/"*.md /usr/share/doc/kapsel/
systemd-sysusers /usr/lib/sysusers.d/kapseld.conf
useradd --system --no-create-home --gid kapsel-service-callers \
  --shell /usr/sbin/nologin kapsel-service-caller
install -d -o kapsel -g kapsel-service-callers -m 0700 /etc/kapsel /var/lib/kapsel
systemctl daemon-reload
```

The service identity and caller identity must be different. Do not grant the caller sudo, Docker,
private-file access, Kubernetes credentials, the service UID, or a way to become the operator. The
unit uses the caller group for socket access, but mode `0700` keeps private roots inaccessible.
Systemd creates `/run/kapsel` with mode `0750` on start and removes it on stop. It retains the state
directory. Do not run `systemctl clean`, delete locks or use private-state deletion as uninstall.

## Provision authority and an exact approval

The supplied RBAC asset is a concrete example for the existing `demo/agent-api` Deployment only. It
creates a token-automount-disabled ServiceAccount and namespaced `get`/`patch` authority for that
Deployment. The cluster operator must approve and apply it using their own tools. It does not create
a namespace, workload or credential. If the target differs, explicitly review the equivalent narrow
RBAC. Do not use cluster-admin credentials. Resolve desired-state ownership with any existing
reconciler before approving direct mutation. This is not a GitOps integration.

In a private operator workspace, provision these inputs using your cluster and key-management tools:

- `kubeconfig.yaml`: explicit context, endpoint and embedded CA/credential data. No exec plugin,
  credential-file reference or ambient fallback. Issue bounded credentials and record their expiry.
- `approval.seed` and `approval.pub`: the existing operator's 32-byte raw Ed25519 signing seed and
  matching 32-byte public key. Appoint the public key independently. Never derive trust from a
  grant.
- `receipt.seed`: a separate intended 32-byte raw Ed25519 receipt seed. Retain its public key and
  separately appointed receipt trust for later inspection.
- `authorization.json`: the exact intent below. Replace the example image with your approved digest
  and use a new operation ID for each genuinely new approval.

Keep this workspace mode `0700` and private inputs mode `0600`. Do not give the approval seed to the
service. The service only needs its public appointment and signed grants.

```json
{
  "authorization_id": "approval-1",
  "operation_id": "service-op-1",
  "namespace": "demo",
  "deployment": "agent-api",
  "container": "api",
  "immutable_image_digest": "registry.example/agent-api@sha256:<64-lowercase-hex>"
}
```

From that private workspace in the root operator shell:

```sh
umask 077
/usr/bin/kapsel provision-snapshot-grant \
  --authorization authorization.json --kubeconfig kubeconfig.yaml \
  --signing-seed approval.seed --signing-key-id approval-key-1 --output approval.grant
python3 - <<'PY'
import json
from pathlib import Path
public = Path("approval.pub").read_bytes()
assert len(public) == 32
candidate = {
    "service_configuration_version": 1,
    "authorization_keys": [{"key_id": "approval-key-1", "public_key_hex": public.hex()}],
    "approvals": [{"label": "Approved image for agent-api", "signed_grant_hex": Path("approval.grant").read_bytes().hex()}],
    "receipt_signing_key_id": "receipt-key-1",
}
with Path("operator.candidate.json").open("x") as output:
    json.dump(candidate, output)
    output.write("\n")
PY
install -o kapsel -g kapsel-service-callers -m 0600 kubeconfig.yaml /etc/kapsel/kubeconfig.yaml
install -o kapsel -g kapsel-service-callers -m 0600 receipt.seed /etc/kapsel/receipt.seed
runuser -u kapsel -g kapsel-service-callers -- \
  /usr/libexec/kapsel/kapseld --replace-operator-config < operator.candidate.json
```

Proceed only after `PUBLISHED` and exit `0`. Any missing or uncertain response requires inspection,
not automatic replay. The command obtains UID/resourceVersion from the receiver before signing the
snapshot grant. Caller-supplied versions cannot substitute for this read. No token or key is bundled
in the archive. The service rejects legacy grants and journals older than format 5 unchanged.

Start explicitly, then read before selecting anything:

```sh
systemctl start kapseld.service
systemctl show kapseld.service -p ActiveState -p SubState -p ExecMainStatus
sudo -u kapsel-service-caller -g kapsel-service-callers -- /usr/bin/kapsel-service-client history
```

`Type=exec` start success means execution began, not that history is ready or an action succeeded.
If the client is unavailable, inspect the unit and diagnostics below. No action is selected at
startup. The unit does not automatically restart or enable itself at boot.

Credential renewal is explicit operator work. Stop gracefully, replace only the intended credential
material under the same custody, and start to reload it. Read the original ID before explicit
resumption. Expired credentials do not justify reapproval, a new ID or a receiver outcome.

The fixed `/etc/kapsel/operator.json` uses the
[versioned service document](KAPSEL_SERVICE.md#versioned-operator-document), not the legacy CLI/MCP
document. It supplies bounded snapshot approvals and external historical public-key appointments.
Each approved ID and tuple is immutable. Reapproval requires an operator decision, a new grant and a
new handle. Restart must not refresh authority on an existing action. Credential provisioning and
renewal remain explicit operator work. Source completion-capacity qualification does not establish
installed-service or native-host acceptance.

## Stop, replace or remove executables

Run `systemctl stop kapseld.service` and wait for it to finish before replacing configuration,
credentials or executables. Confirm `ActiveState=inactive` and `MainPID=0` with `systemctl show`. A
timeout, lost shell or forced kill is not successful retirement. Preserve the history and follow the
uncertainty guidance below.

For a separately accepted compatible executable replacement, authenticate and verify the new archive
first. While stopped, replace only the installed binaries/unit/docs with their exact new bytes,
retaining the service UID/GID, roots, journal, sidecars, lifecycle lock, original grants and
historical trust. Reload the unit, start, and read history first. This is not authorization to use
an older binary or migrate a refused journal. Format 4 is refused unchanged. A fresh installation
cannot recover continuity for an old or lost journal.

For removal, stop and disable the unit. An operator may remove only the installed executables and
static assets whose provenance they have verified, then run `systemctl daemon-reload`. Retain
`/etc/kapsel`, `/var/lib/kapsel`, identities, original authority and any exported receipts under
private custody. Do not run `systemctl clean`, recursively delete roots, or recycle identities.
There is no automated cleanup, state migration or backup recovery promise. Never restore stale state
to revive execution: the host may already have sent a mutation absent from that snapshot.

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
| `IN_PROGRESS`   | Follow `execution.next_action`. Durable unfinished history does not prove a worker is running.                                                    |
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

## Diagnose and resume

An absent row is `NOT_FOUND` with `execution.disposition: "admission_unconfirmed"`. This read cannot
prove non-admission while a commit may still finish. Only a submission response of `NOT_ADMITTED`
establishes definite refusal. Continue reading the same ID after uncertainty.

For unfinished history, use `execution`, not internal phase names:

- `active`: wait. The physical job may be blocked, so this is not a progress guarantee.
- `waiting_for_worker`: wait, then explicitly submit the same ID. There is no queue.
- `resume_required`: explicitly submit the same ID. A null condition means the process does not know
  why it stopped. Do not infer a crash. A repeated `preflight_unavailable` warrants operator
  inspection.
- `operator_required`: obtain remediation below, then explicitly submit the same ID.

Any authenticated service caller may resume an original retained snapshot-approved ID. The gateway
still checks original authority and controls continuation. Reselecting after attempt cannot resend
the PATCH. Signing completion cannot acquire new observations. Do not create a replacement ID just
because execution stopped or a response was lost.

Operators can inspect the existing process fields with `systemctl show kapseld.service` and fixed
codes with `journalctl -u kapseld.service`. Keep journal access operator-only. Read failures emit at
most once per class per service lifetime, not once per poll or identity. Diagnostics may be lost
under backpressure or process loss. Missing or repeated codes are not progress evidence. The daemon
uses nonblocking pipe/socket stderr only, as supplied by the unit. Do not redirect it to a regular
file or clear its nonblocking flag. Status and process exit remain usable when diagnostics are lost.
Do not paste private configuration, grant bytes, credentials or signing seeds into diagnostics or
caller responses.

| Code                                                | Operator action                                                                                                                                                          |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `provisioning_unavailable`                          | Inspect fixed roots, file ownership/modes, lifecycle exclusion and operator document bounds. Preserve unknown artifacts.                                                 |
| `configuration_invalid`                             | Validate the version-1 operator document and separately appointed original grant keys. Use cold replacement, never caller input.                                         |
| `original_authority_unavailable`                    | Restore the original externally appointed trust key for the retained grant. Do not replace authority under the same ID.                                                  |
| `storage_or_operation_blocked`, `operation_blocked` | Inspect journal version, custody, filesystem availability and retained history using the owning binary. Do not delete, rotate or restore stale history as a retry.       |
| `preflight_unavailable`                             | Check receiver connectivity, narrow RBAC and credential validity. The code does not distinguish these from bounded/malformed response failure.                           |
| `receiver_unavailable`                              | Repair the fixed kubeconfig or receiver access. Execution snapshots are loaded at startup, so changed material needs graceful stop/start. Read before same-ID selection. |
| `signing_unavailable`                               | Restore the intended private receipt seed and valid configured signer ID. Restart to reload material, then select the same ID to complete frozen facts.                  |
| `completion_blocked`                                | Check storage capacity/custody and signing configuration. Preserve frozen observations and original receipts. Resume the same ID only after remediation.                 |
| `worker_contention`                                 | Let the current owner retire. Then select the same ID explicitly. Never remove a lock to bypass exclusion.                                                               |
| `internal_failure`                                  | Preserve history and inspect the binary/host before restart. No exception payload or secret-bearing detail is logged.                                                    |

Codes describe observations in the current process, not a durable audit trail or proof of root
cause. Status is still readable when execution material is unavailable. Unsafe or unreadable
authority and storage may prevent startup. The journal retains at most **504 identities and 32
unfinished actions**. There is no pruning. Clearing history to make room or resume would destroy the
no-resend boundary.

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
