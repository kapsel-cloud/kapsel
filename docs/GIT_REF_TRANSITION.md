# Exact Git ref transitions

Use this guide to prepare and exercise `git.transition_ref` through the resident service's ID-only
caller tools. It requires current source; the published `v0.3.0-preview.1` does not include Git. The
[effect contract](EFFECT_GATEWAY.md#git-transition-boundary) owns authority, recovery, and receipts.
The [service contract](KAPSEL_SERVICE.md) owns admission and process lifetime.

## What is authorized

One signed grant binds an operation ID, authorization ID, repository ID, `refs/heads/approved`, and
exact nonzero lowercase SHA-1 commits A and B. B must descend from A. Operator-only configuration
selects complete private bare sender and receiver repositories and an explicit Git **2.55.0**
binary. The receiver requires `receive.denyDeletes=true`, `receive.denyNonFastForwards=true` and the
matching `kapsel.repositoryId`.

The caller selects the approved ID. It cannot supply paths, Git options, a remote URL, objects, a
signing seed, credentials or a replacement tuple. Content preparation and review remain the
operator's responsibility. There is no generic Git runner or remote-provider interface.

A successful fresh per-ref acknowledgement means the exact ref transition succeeded. It does not
mean hooks completed, CI ran, or a deployment succeeded. A lost acknowledgement remains `UNKNOWN`,
even if observation finds B. Reopening attempted history only observes: A→B→A cannot authorize
another push. Frozen receipts are returned byte-for-byte without receiver or signing material.

## Runnable source example

On Linux, with the repository's Rust toolchain, Python 3, OpenSSL and an operator-selected Git
2.55.0:

```sh
cargo build --locked -p kapsel --bin kapsel
cargo build --locked -p kapsel-daemon --features test-harness
python3 tests/qualification/run_git_service.py --git /absolute/path/to/git
```

This uses disposable private directories and the compile-time fixed-root service fixture. It does
not install anything, modify systemd, or use a live repository. It drives the maintained
[`fresh_session_caller.py`](../examples/fresh_session_caller.py), the real MCP bridge, real service
startup, CLI grant preparation, Git receiver, retained receipt retrieval and detached CLI
inspection. Each caller invocation is a new process with the same caller-owned reference.

The cases cover healthy completion; service loss after sending, before receipt commit and after
receipt commit; and receiver loss in pre/post-receive hooks. Each case independently reads the
receiver ref and checks the exact tuple, acknowledgement and observation in service status and
detached inspection. It also checks one pre-receive input, separate post-receive invocation
evidence, and stable original bytes after removal of the selectable catalog, Git material and
receipt seed. These hook inputs are not packet-level evidence; the
[core receiver tests](TESTING.md#git-receiver-and-service-checks) count update packets separately.
The fixture is not installed-systemd, power-loss or production qualification. Its test overrides are
absent from ordinary builds.

## Packaged production-binary qualification

The [artifact journey](BUILD.md#git-transition-service) exercises the same Git boundary without
source-harness binaries. It uses the authenticated archive's production service and fixed caller
inside disposable Linux containers. Receiver-owned hook faults establish lost acknowledgement and
service-loss windows. Independent ref and hook-input checks accompany same-ID recovery and retained
receipt comparison. It does not establish native systemd behavior or packet-level counts.

## Operator preparation

Follow the service's fixed-root and custody rules. Provision a canonical absolute Git executable
named `git`, complete bare repositories, and reviewed commits. Keep sender and receiver files under
service-identity custody. The receiver refuses symlinks, linked object stores, shared-write paths,
shallow repositories, alternates, replace refs, and unsupported configuration. Use the service
unit's `UMask=0077` (or `umask 077` for a direct process) so newly created Git contents retain
private custody. Choose repository locations the service's filesystem restrictions permit, such as
its private state root. A system Git installation under shared-writable package-manager custody may
need a private operator-controlled copy.

The optional fixed file `/etc/kapsel/git-receiver.json` is at most 4096 bytes and accepts exactly:

```json
{
  "executable": "/var/lib/kapsel/git-bin/git",
  "sender": "/var/lib/kapsel/sender.git",
  "receiver": "/var/lib/kapsel/receiver.git",
  "repository_id": "release-repository"
}
```

This material is loaded only at startup, outside socket input and outside signed grants. It selects
one receiver for the process, not a per-request path. Missing or invalid material does not prevent
authenticated stored reads. An unfinished operation needing it stops with `receiver_unavailable`; a
frozen observation needs only the intended receipt signer. Restart to load repaired material, then
explicitly select the original identity.

Prepare `authorization.json` with these six fields, substituting the exact reviewed commit IDs:

```json
{
  "authorization_id": "release-approval-1",
  "operation_id": "release-ref-1",
  "repository_id": "release-repository",
  "reference": "refs/heads/approved",
  "old_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "new_commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
```

The illustrative hashes are not runnable object IDs. Using separately provisioned raw Ed25519
operator material, preflight and sign before preparing the service catalog:

```sh
kapsel provision-git-grant --authorization authorization.json \
  --git-receiver git-receiver.json --signing-seed approval.seed \
  --signing-key-id approval-key --output approval.grant
kapsel prepare-service-config --authorization-key approval-key approval.pub \
  --approval 'Approved release ref' approval.grant \
  --receipt-signing-key-id receipt-key --output operator.json
```

Provisioning reads the receiver but never pushes or admits an operation. Submission rechecks it; the
exact lease still rejects a competing change between preflight and sending. Service configuration
may contain both Kubernetes snapshot and Git grants under separately appointed public keys.
Operation IDs share one immutable namespace and one worker/capacity budget. Use the existing
[cold-publication procedure](KAPSEL_SERVICE.md#cold-publication-and-graceful-retirement) to replace
the catalog; do not rewrite an admitted identity or delete its original trust appointment.

## Caller and inspection

Use the existing `approved`, `history`, `start`, `read`, `resume` and `receipt` commands of the
[read-first caller](KAPSEL_SERVICE_OPERATOR.md#fresh-session-caller-current-source). Git catalog
entries carry `effect: "git.transition_ref"` and the exact repository/ref/A/B tuple. Git status and
history add the same effect tag and a `git` object with that tuple, `attempted`, `acknowledgement`
and `observed_ref`. The [shared caller guide](CALLER_GUIDE.md) exercises both effects through this
same lifecycle. An attempt marker is not proof of transmission. Acknowledgement is never inferred
from observation. Kubernetes response fields and receipt meanings remain unchanged.

Export the exact receipt bytes returned by the service and inspect them offline:

```sh
kapsel inspect --receipt receipt.bin --trust receipt.trust --evaluation-time-unix-s 50
```

Appoint the receipt public key independently, with purpose `kapsel.git-ref-transition-receipt.v1`
and an explicit validity interval containing the chosen time. The trust-record framing is shared
with existing receipts; Git statement/envelope framing and purpose are distinct. An inspection time
is not evidence of when the receiver changed. The CLI detects the Git envelope; the Rust
`inspect_git_receipt` entry point is explicit. Kubernetes inspection rejects Git envelopes. Do not
treat `INSPECTED` as a success result: separately read `result`, `acknowledgement`, `observed_ref`,
`attribution` and the fixed non-claims.

Journal format 6 is required. Older journals are refused unchanged, not migrated. Keep them with
matching binaries and original authority; a new journal is not permission to replay old work.
