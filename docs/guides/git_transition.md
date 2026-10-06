# Prepare a Git ref transition

Use this operator guide to approve one local branch transition from commit A to prepared descendant
B. Install the service using the [operator guide](operator.md#prepare-your-own-extracted-artifact)
first. You need complete private bare sender and receiver repositories and an explicitly selected
Git **2.55.0** executable. Preparation and content review belong to the operator, not the caller.

The fixed ref is `refs/heads/approved`. This is not a remote-provider integration or a generic Git
runner. [Git reference](../reference/git_effect.md) defines exact authority, acknowledgement,
recovery, and receipt rules. A lost acknowledgement remains `UNKNOWN` even if the ref later contains
B. Do not prepare a replacement approval as an automatic retry.

For a disposable source or packaged receiver exercise, use
[Git qualification](../contributing/qualification.md#git-transition-service). Those test commands
are not service installation or operator preparation.

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
authenticated stored reads. An unfinished operation needing it stops with `receiver_unavailable`. A
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

Provisioning reads the receiver but never pushes or admits an operation. Submission rechecks it. The
exact lease still rejects a competing change between preflight and sending. Service configuration
may contain both Kubernetes snapshot and Git grants under separately appointed public keys.
Operation IDs share one immutable namespace and one worker/capacity budget. Use the existing
[cold-publication procedure](../reference/service.md#cold-publication-and-graceful-retirement) to
replace the catalog. Do not rewrite an admitted identity or delete its original trust appointment.

## Caller and inspection

Use the existing `approved`, `history`, `start`, `read`, `resume` and `receipt` commands of the
[read-first caller](caller.md). Git catalog entries carry `effect: "git.transition_ref"` and the
exact repository/ref/A/B tuple. Git status and history add the same effect tag and a `git` object
with that tuple, `attempted`, `acknowledgement` and `observed_ref`. The
[shared caller guide](caller.md) exercises both effects through this same lifecycle. An attempt
marker is not proof of transmission. Acknowledgement is never inferred from observation. Kubernetes
response fields and receipt meanings remain unchanged.

Export the exact receipt bytes returned by the service and inspect them offline:

```sh
kapsel inspect --receipt receipt.bin --trust receipt.trust --evaluation-time-unix-s 50
```

Appoint the receipt public key independently, with purpose `kapsel.git-ref-transition-receipt.v1`
and an explicit validity interval containing the chosen time. The trust-record framing is shared
with existing receipts. Git statement/envelope framing and purpose are distinct. An inspection time
is not evidence of when the receiver changed. The CLI detects the Git envelope. In Rust, use the
explicit `inspect_git_receipt` entry point. Kubernetes inspection rejects Git envelopes. Do not
treat `INSPECTED` as a success result: separately read `result`, `acknowledgement`, `observed_ref`,
`attribution` and the fixed non-claims.

Journal format 6 is required. Older journals are refused unchanged, not migrated. Keep them with
matching binaries and original authority. A new journal is not permission to replay old work.
