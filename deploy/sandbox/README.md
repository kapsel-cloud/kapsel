# KAP-0053 Gate 1 offline fixture

This provider-neutral fixture is an implementation input, not a deployment or live-proof record. It
creates no account, credential, resource, endpoint, DNS change, spend, or traffic.

The fixture locks:

- the native `kapsel-sandbox` HTTP/1.1 process and non-public `stop`/`clear-stop` commands;
- the only allowed KAP-0038 Deployment transition: one selected named-container image plus the
  required operation annotation under exact UID, owner, resource-version, current-image, and
  operation preconditions;
- one single-writer `ReadWriteOncePod` durable volume containing admission, receipt, per-run
  journal, and cleanup-ownership state; and
- a fenced backup/restore sequence whose provider storage and snapshot enforcement remains a Gate
  2/3 experiment.

Run the offline evidence lane with:

```sh
cargo make test-sandbox-gate1
```

`workload-template.json` deliberately retains `${KAPSEL_SANDBOX_IMAGE_DIGEST}` and
`${GATE2_STORAGE_CLASS}`. Gate 2 must authorize and lock both values before rendering or
provisioning. The template creates no public Service or ingress. The container image uses the
already locked repository builder image; Gate 2 must review runtime size and vulnerability evidence
before selection.

The raw signing boundary accepts only an exact 32-byte Ed25519 seed. The RFC 8032 seed/public-key/
signature known-answer test and a production `Application` receipt inspected through
`kapsel::inspect_receipt` prove the offline format path. They do not prove managed custody, workload
IAM, audit, outage, rotation, backup, or deletion protection.

The Gate 1 binary composes the native HTTP boundary and operator stop only. It does not yet launch
the provider-dependent scheduler/runner, cleanup controller, or periodic retention loop; Gate 2 must
compose those existing service operations with the selected Kubernetes, key, and storage identities
before any deployment can be accepted.

The exact patch harness evaluates normalized Kubernetes Deployment objects. Live Kubernetes
admission/audit enforcement, post-verification downgrade denial under the real runner identity,
CNI/runtime isolation, volume fencing, snapshot atomicity, restore, cleanup, rollback, cost, and
public readiness remain unproved.
