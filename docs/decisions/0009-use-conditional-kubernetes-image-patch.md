# Use a conditional Kubernetes image patch

Status: accepted.

Kind: decision. Date: 2026-07-15.

Owns: Why KAP-0038 uses a UID/resource-version-guarded strategic merge patch instead of no-force
server-side apply for its one Deployment image mutation.

Does not own: The experiment lifecycle, receiver-result meaning, receipt bytes, another Kubernetes
operation, or a reusable provider seam.

## Context

Ordinary Deployments are normally managed by another actor that owns the container image field.
Server-side apply with `force=false` therefore returns `409 FieldManagerConflict` for the
experiment's central operation. Forcing apply would take field ownership from that actor, which
exceeds the experiment's bounded authority. Restricting the capability to Kapsel-owned Deployments
would hide that limitation rather than solve it.

Kubernetes strategic merge patch treats the container list as name-keyed. Kubernetes also enforces
supplied object UID and resource-version preconditions, allowing the experiment to reject deletion,
replacement, or concurrent desired-state changes without taking managed-field ownership.

## Decision

KAP-0038 uses one strategic merge patch that:

- requires the named container to exist in the target observation;
- includes the observed Deployment UID and resource version;
- changes only the exact name-keyed container image;
- writes the exact operation identity annotation; and
- treats conflict or identity replacement as a bounded provider failure that is never blindly
  retried.

The durable attempt records the fixed write-strategy identity `conditional-strategic-merge-patch`.
The receiver-observation and explicit-`UNKNOWN` rules remain unchanged.

## Consequences

- The experiment works with ordinary Deployments without transferring server-side-apply ownership.
- A concurrent Deployment change can reject the patch even when it touches another field; this is a
  conservative outcome, not a rollout failure.
- The patch remains internal construction. Agent input still cannot supply a manifest or patch.
- This decision establishes no generic Kubernetes write interface and does not authorize a second
  operation.
- The local `kind` proof must exercise precondition enforcement and confirm that an untargeted
  container remains unchanged.
