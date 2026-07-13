# Privacy

Status: active experiment design.

Kind: design. Authority: data-exposure boundary for the Kubernetes effect-gateway experiment.

Owns: Disclosure risks for requests, journals, receipts, reports, and demo artifacts.

Does not own: Legal compliance, production retention, or Kubernetes credential operations.

## Short answer

The active experiment is local and self-hosted, but its receipts and reports still disclose
operational metadata. Treat them as sensitive unless intentionally published.

Potentially revealing material includes:

- namespace, deployment, container, and image digest;
- operation identity and timing;
- Kubernetes target and receiver UIDs, image and operation marker, generations, resource versions,
  replica counts, and rollout condition;
- authorization and receipt key identifiers, signed-grant digest, and trust anchors; and
- failure classes and unknown-outcome reports.

## Rules

- Agent requests must not contain Kubernetes credentials, signing keys, arbitrary manifests, shell
  commands, prompts, or private logs.
- SQLite, receipts, reports, errors, and captured demo logs must not contain secrets or unbounded
  Kubernetes response bodies.
- The receipt includes only the fields needed to explain the exact experiment operation and result.
- Offline inspection uses externally supplied trust; receipt-carried keys or metadata do not appoint
  themselves.
- Public demos must use disposable local `kind` resources and synthetic image digests or clearly
  safe public images.

## Non-claims

Kapsel does not guarantee anonymity, unlinkability, legal compliance, production retention safety,
or absence of sensitive inference.
