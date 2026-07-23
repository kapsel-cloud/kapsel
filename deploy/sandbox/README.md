# KAP-0053 Gate 1 offline fixture

This provider-neutral fixture is an implementation input, not a deployment or live-proof record. It
creates no account, credential, resource, endpoint, DNS change, spend, or traffic.

The fixture locks:

- the native `kapsel-sandbox` HTTP/1.1 process and non-public `stop`/`clear-stop` commands;
- the only allowed KAP-0038 Deployment transition: one selected named-container image plus the
  required operation annotation under exact UID, owner, resource-version, current-image, and
  operation preconditions;
- one `ReadWriteOncePod` system-state volume for admission, receipts, and cleanup ownership, plus
  one separately fenced owner-private `ReadWriteOncePod` gateway-journal volume per active run, an
  exact runner Pod/identity template, and a normalized fail-closed mount-admission rule that forbids
  the API, target workload, and every other runner from mounting it; and
- a multi-volume backup-generation protocol that freezes the active journal inventory, quiesces and
  fences every exact writer, rejects incomplete or mixed generations, and leaves provider snapshot
  consistency and enforcement as a Gate 2/3 experiment.

Run the offline evidence lane with:

```sh
cargo make test-sandbox-gate1
```

The current lock intentionally leaves the correction revision and image ID null. The superseded
revision/image remain historical evidence only; a corrected commit and rebuild are required before
Gate 1 can be accepted again.

`workload-template.json` and `journal-volume-template.json` deliberately retain
`${KAPSEL_SANDBOX_IMAGE_DIGEST}`, `${GATE2_STORAGE_CLASS}`, `${GATE2_RUNTIME_CLASS}`, and the
provider-dependent runner subcommand. Gate 2 must authorize and lock those values and replace the
unimplemented runner placeholder before rendering or provisioning. The templates create no public
Service or ingress. The container image uses the already locked repository builder image; Gate 2
must review runtime size and vulnerability evidence before selection.

The raw signing boundary accepts only an exact 32-byte Ed25519 seed. The RFC 8032 seed/public-key/
signature known-answer test and a production `Application` receipt inspected through
`kapsel::inspect_receipt` prove the offline format path. They do not prove managed custody, workload
IAM, audit, outage, rotation, backup, or deletion protection.

The Gate 1 binary composes the native HTTP boundary and operator stop only. Stop and clear-stop open
only the existing private admission database and its singleton row; receipt storage, tombstone-key
availability, retention, and full service initialization are deliberately outside that emergency
path. The binary does not yet launch the provider-dependent scheduler/runner, cleanup controller, or
periodic retention loop; Gate 2 must compose those existing service operations with the selected
Kubernetes, key, and storage identities before any deployment can be accepted.

The exact patch harness evaluates normalized Kubernetes Deployment objects. Live Kubernetes
admission/audit enforcement, post-verification downgrade denial under the real runner identity,
CNI/runtime isolation, volume fencing, snapshot atomicity, restore, cleanup, rollback, cost, and
public readiness remain unproved.
