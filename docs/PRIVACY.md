# Privacy

Kapsel is local and self-hosted, but its journals, receipts, reports, and demonstration artifacts
can disclose operational metadata. Treat them as sensitive unless they are intentionally published.

Potentially revealing material includes:

- namespace, Deployment, container, immutable image digest, operation identity, and timing;
- Kubernetes target and receiver UIDs, operation marker, generations, resource versions, replica
  counts, and rollout condition;
- authorization and receipt key identifiers, signed-grant digest, and trust anchors; and
- rejection, failure, and unknown-outcome classes.

## Disclosure checklist

- Keep Kubernetes credentials, signing keys, arbitrary manifests, shell commands, prompts, and
  private logs out of caller requests.
- Keep secrets and unbounded Kubernetes response bodies out of SQLite, receipts, reports, errors,
  and captured logs.
- Include only the fields required to explain the exact operation and result in a receipt.
- Supply inspection trust externally. Receipt-carried keys or metadata cannot appoint themselves.
- Use disposable local `kind` resources and synthetic digests or clearly safe public images in
  public demonstrations.
- Release artifacts may contain source revision, target, builder identity, binary digests, public
  documentation, and synthetic vectors. They must not contain evaluator grants, private trust
  decisions, credentials, seeds, kubeconfigs, journals, receipts, reports, logs, or private paths.

Kapsel does not guarantee anonymity, unlinkability, legal compliance, production retention safety,
or absence of sensitive inference. See the [threat model](THREAT_MODEL.md) for the wider security
boundary.
