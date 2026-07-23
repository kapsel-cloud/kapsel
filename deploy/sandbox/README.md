# KAP-0053 Gate 1 offline fixture

This provider-neutral fixture is an implementation input, not a deployment or live-proof record. It
creates no account, credential, resource, endpoint, DNS change, spend, or traffic.

The fixture locks:

- the native `kapsel-sandbox` HTTP/1.1 process and non-public `stop`/`clear-stop` commands;
- the only allowed KAP-0038 Deployment transition: one selected named-container image plus the
  required operation annotation under exact UID, owner, resource-version, current-image, and
  operation preconditions;
- one `ReadWriteOncePod` system-state volume for admission, receipts, and cleanup ownership, plus
  one separately fenced owner-private `ReadWriteOncePod` gateway-state volume per active run; one
  canonical runner identity across mount, RoleBinding, and patch admission; explicit read-only
  controller, grant/trust, signing, composition, and receipt-handoff channels; and complete rendered
  Pod equality that rejects every undeclared field; and
- a multi-volume backup-generation protocol that freezes the active journal inventory, quiesces and
  fences every exact writer, rejects incomplete or mixed generations, and leaves provider snapshot
  consistency and enforcement as a Gate 2/3 experiment.

Run the offline evidence lane with:

```sh
cargo make test-sandbox-gate1
```

The lock preserves the two superseded revision/image records and records runner-composition revision
`bd67be9b469672b895a6214322b4dc7ff942da33` with its clean local `linux/arm64` image
`sha256:4d85515113eccf5cb56618fd5b406632111ac429a25352e385942c40733d3480`. Independent evidence
review remains required before Gate 1 can be accepted.

`workload-template.json` and `journal-volume-template.json` deliberately retain
`${KAPSEL_SANDBOX_IMAGE_DIGEST}`, `${GATE2_STORAGE_CLASS}`, `${GATE2_RUNTIME_CLASS}`,
`${GATE2_KUBERNETES_AUDIENCE}`, and the provider-dependent runner subcommand. Gate 2 must authorize
and lock those values and replace the unimplemented runner placeholder before rendering or
provisioning. The templates create no public Service or ingress. The container image uses the
already locked repository builder image; Gate 2 must review runtime size and vulnerability evidence
before selection.

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
