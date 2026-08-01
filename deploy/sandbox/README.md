# Sandbox topology-neutral preservation fixtures

This directory contains the retained Gate 0 mutation pair plus the three canonical Slice 3
provider-neutral behavior records. They describe no runnable host, cluster, provider, image,
credential, or deployment:

- `admission-fixture.json` fixes the old Deployment, exact UID/owner/resource-version/current-image
  preconditions, selected named container, immutable replacement image, and KAP-0038 operation ID;
- `operator-admission-rule.json` fixes `conditional-operation-v1`, the full runner identity,
  digest-bound old Deployment, and the only two permitted changes;
- `composition-admission-rule.json` fixes the fail-closed admission-visible provisioner generation
  and cleanup epoch behavior; and
- `cleanup-admission-rule.json` fixes UID-preconditioned, propagation-bound cleanup behavior; and
- `network-boundary-record.json` fixes ready/default-deny/metadata/API/arbitrary-egress denial with
  no fallback.

Validate the mutation fixtures and the KAP-0070 Gate 0 deletion boundary with no Docker, provider,
network, credential, or live resource:

```sh
cargo make test-sandbox-preservation
```

The validator accepts the one normalized image/operation-annotation update and rejects identity,
UID, owner, resource-version, current-image, container, metadata, or other object changes. It also
asserts that superseded controller/stager source, CLI modes, deployment/provider/image artifacts,
and Make tasks are absent while the retained public contract, service/handoff, and package boundary
remain.

These records are deterministic composition evidence only. They do not prove runtime, CNI, RBAC,
admission, metadata, or network enforcement and authorize no provider, registry, credential, image,
cluster, endpoint, DNS, or traffic.
