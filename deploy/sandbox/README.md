# Sandbox topology-neutral preservation fixtures

This directory contains only two Gate 0 fixtures. They preserve the exact conditional
`kubernetes.set_deployment_image` mutation invariant without describing a runnable host, cluster,
provider, image, credential, or deployment:

- `admission-fixture.json` fixes the old Deployment, exact UID/owner/resource-version/current-image
  preconditions, selected named container, immutable replacement image, and KAP-0038 operation ID;
- `operator-admission-rule.json` fixes the provider-neutral runner identity, required preconditions,
  and the only two permitted changes: the selected container image and required operation
  annotation.

Validate both fixtures and the KAP-0070 Gate 0 deletion boundary with no Docker, provider, network,
credential, or live resource:

```sh
cargo make test-sandbox-preservation
```

The validator accepts the one normalized image/operation-annotation update and rejects identity,
UID, owner, resource-version, current-image, container, metadata, or other object changes. It also
asserts that superseded controller/stager source, CLI modes, deployment/provider/image artifacts,
and Make tasks are absent while the retained public contract, service/handoff, and package boundary
remain.

These fixtures are preservation evidence only. They do not implement or authorize KAP-0070 Gate 1
host composition, runner identity enforcement, cluster admission, an image, or live behavior.
