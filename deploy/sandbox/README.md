# KAP-0053 Authority Composition Proof (Gate 1) fixture

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
  controller, grant/trust, signing, composition, and authenticated runner-handoff channels; exact
  confined Kubernetes atomic-writer symlink consumption; owner-private `run`/receipt-outbox
  initialization on an empty gateway volume; and complete rendered Pod equality that rejects every
  undeclared field; and
- a multi-volume backup-generation protocol that freezes the active journal inventory, quiesces and
  fences every exact writer, rejects incomplete or mixed generations, and leaves provider snapshot
  consistency and enforcement to Infrastructure Enforcement and Failure Recovery Proofs (Gates 2 and
  3).

Run the offline evidence lane with:

```sh
cargo make test-sandbox-gate1
```

The lock preserves the two superseded revision/image records and records runner-composition revision
`bd67be9b469672b895a6214322b4dc7ff942da33` with its clean local `linux/arm64` image
`sha256:4d85515113eccf5cb56618fd5b406632111ac429a25352e385942c40733d3480`. Independent review of
evidence revision `e757ce0adbc79d2f36209155149f03506f93e69b` recomputed the fixture digest, reran
the focused gate, reproduced the exact clean image build, and accepted corrected Authority
Composition evidence.

`workload-template.json` and `journal-volume-template.json` deliberately retain
`${KAPSEL_SANDBOX_IMAGE_DIGEST}`, `${GATE2_STORAGE_CLASS}`, `${GATE2_RUNTIME_CLASS}`, and
`${GATE2_KUBERNETES_AUDIENCE}` while locking the exact implemented `runner` subcommand. The existing
`gate1` and `GATE2` machine identifiers remain stable compatibility names. Infrastructure
Enforcement Proof (Gate 2) must authorize and lock the remaining provider-dependent values and
compose the runner before rendering or provisioning. The templates create no public Service or
ingress.

Authority Composition's historical image uses the already locked repository builder image. The
separate `Containerfile.gate2-candidate` is pre-authorization source/config evidence for an exact
`linux/amd64` Distroless runtime and does not replace the Gate 1 lock. Run
`cargo make test-sandbox-gate2-image-candidate` to verify the runtime signature, process boundary,
64 MiB size ceiling, and a time-bound Trivy `HIGH`/`CRITICAL` scan without provider access.
`gate2-image-candidate.json` records the exact clean source revision, local image identity, tools,
and non-claims. The result is still not a registry digest, selected runtime, or Infrastructure
Enforcement authorization.

`gate2-gke-fixture.json` is the separate non-executed `europe-north1` authorization candidate,
`gate2-gke-storage-class.json` is its proposed regional Persistent Disk CSI class, and
`gate2-system-workload.json` is the incomplete, non-applicable evidence wrapper for the implemented
native API, private handoff, and periodic-retention roles. Its objects are digest-locked, but its
headless Service provides only cluster-internal discovery—not access control—and NetworkPolicy is
still absent. Run `cargo make test-sandbox-gate2-fixture` to check the exact tuple, node arithmetic,
placeholders, storage, key roles, audit/retention split, native system-role commands and authority,
inventory, command previews, teardown coverage, costs, stop conditions, and non-claims without
invoking a provider. The fixture records its reviewed source revision and digest; null registry
digest, private approval bindings, Kubernetes audience, runner subcommand, and secret versions still
keep execution blocked.

The raw signing boundary accepts only an exact 32-byte Ed25519 seed. The RFC 8032 seed/public-key/
signature known-answer test and a production `Application` receipt inspected through
`kapsel::inspect_receipt` prove the offline format path. They do not prove managed custody, workload
IAM, audit, outage, rotation, backup, or deletion protection.

The native binary composes the HTTP boundary, private handoff, runner, scheduler, operator stop, and
periodic retention modes. The concrete scheduler uses only the fixed `sandbox-policy-v2` renderer
and an in-cluster Kubernetes client, recovers active leases before new FIFO dispatch, creates or
exactly observes all eleven policy objects, and recomputes normalized policy digests before deriving
the private handoff assignment. It deliberately does not create a runner Pod yet: key staging,
lease-specific runner inputs, runner-resource UID recording, and exact RBAC/token binding remain
part of the blocked complete composition. Stop and clear-stop open only the existing private
admission database and its singleton row; receipt storage, tombstone-key availability, retention,
and full service initialization are deliberately outside that emergency path. The incomplete Gate 2
system workload renders only the API, handoff, and retention roles against one system-state volume
and explicitly omits scheduler and cleanup-controller composition. The implemented scheduler is not
added until its projected controller token, RBAC, runner/key binding, and NetworkPolicy are
complete. Infrastructure Enforcement Proof must complete those roles, runner binding, policy, key
staging, and selected Kubernetes/storage identities before any deployment can be accepted.

The exact patch harness evaluates normalized Kubernetes Deployment objects. Live Kubernetes
admission/audit enforcement, post-verification downgrade denial under the real runner identity,
CNI/runtime isolation, volume fencing, snapshot atomicity, restore, cleanup, rollback, cost, and
public readiness remain unproved.
