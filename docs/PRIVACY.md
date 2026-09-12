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

## Source check

`scripts/check-source-privacy.py` is an independent source check in the default static gate. It
rejects known private absolute paths, private-key headers, AWS/GitHub token patterns and private
artifact suffixes. In Markdown it also rejects specific affirmative production, SLA, exactly-once,
universal Kubernetes and native-host performance claims. Diagnostics name the category and source
location, not the matched material. `scripts/test-source-checks.py` owns its rejection regressions.

The checker selects existing tracked and non-ignored untracked files under `crates/`, `src/`,
`tests/`, `vectors/`, `docs/`, `scripts/`, `fuzz/`, `.github/` and `.githooks/`, plus the root
manifests, lockfile, Rust toolchain, README, SECURITY, CONTRIBUTING and AGENTS files. Generated
build/release output and unrelated root files are not scanned. Only the checker and its
pattern-fixture test are exempt from credential/path matching, not from the private-artifact suffix
check.

These are finite patterns, not a general secret detector or a semantic review of public claims. The
disclosure checklist still requires human review. The separate
[source security scan](BUILD.md#source-privacy-and-security) checks a complete committed Git archive
with Trivy's secret scanner. [Release verification](RELEASE.md) independently constrains artifact
contents. None of these checks certifies that arbitrary logs or generated artifacts are publishable.

Kapsel does not guarantee anonymity, unlinkability, legal compliance, production retention safety,
or absence of sensitive inference. See the [threat model](THREAT_MODEL.md) for the wider security
boundary.
