# Qualify and publish a release

Maintainers qualify one clean source revision and its exact artifact bytes before publication. These
are release requirements, not a record of completed work. Consumers should use
[release authentication and extraction](../reference/release.md#authenticate-and-extract-the-release).

## Selected scope

The candidate contains the resident service, fixed ID-only client, MCP bridge, operator CLI, and
fresh-session caller continuity. Include both `kubernetes.set_deployment_image` and
`git.transition_ref` under their existing contracts. The sole release target is
`x86_64-unknown-linux-gnu`.

Do not add another effect, target, scheduler, provider interface, installer, or production-support
promise to this release. Fixes required by the selected contracts remain in scope.
[Scope](../scope.md) defines capability limits. The
[beta decision](../decisions/0012-v04-beta-quality-bar.md) distinguishes accepted scope from
proposed assurance targets.

## Compatibility boundary

There is no cross-version support commitment for v0.4.x, migration/downgrade procedure, or stable
public Rust API. Qualify the selected release's current contracts rather than maintaining an upgrade
matrix for hypothetical adopters.

Within that boundary, reconnect and restart must preserve the same operation identity, original
authority, attempted history and exact committed evidence. Removing cross-version support does not
permit recovery to resend a mutation or reinterpret signed bytes. Format 6 rejects older journals
unchanged. [Preserve operation history](../guides/journal_retention.md) explains the operating
precautions. Published tags, artifacts and signed purposes retain their original meanings.

## Graduation gates

A maintainer must accept one exact clean revision and its artifact bytes. All required lanes must
pass; missing evidence blocks release. Record commands, environment identities, outcomes, and
source/artifact digests without publishing private fixture material.

| Gate             | Required evidence                                                                                                                                                      | Procedure                                                                                                                               |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Source           | Full deterministic gate, fresh security scan, Linux process tests, receiver-recovery matrix, seeded simulation, receipt fuzz smoke, bounded ENOSPC                     | [Build](build.md), [qualification](qualification.md)                                                                                    |
| Artifact         | Two isolated assemblies with identical deterministic files, hostile-archive checks, extracted-binary smoke, exact-artifact SBOM scan                                   | [Assembly and artifact checks](../reference/release.md#deterministic-assembly), [SBOM](../reference/release.md#spdx-sbom)               |
| Native service   | Authenticated extraction and shipped systemd unit on a fresh native x86-64 Linux host                                                                                  | [Native qualification](../reference/release.md#native-installed-systemd-qualification)                                                  |
| Kubernetes       | Live receiver gate and packaged workflow: caller loss, service crash, same-ID recovery, frozen uncertainty, independent mutation counts                                | [Live gate](qualification.md#live-kubernetes-gate), [packaged workflow](qualification.md#packaged-service-live-workflow)                |
| Git              | Core recovery matrix, Linux process recovery, extracted production-artifact journey: acknowledgement loss, same-ID recovery, ref/hook observations, identical receipts | [Git qualification](qualification.md#git-transition-service)                                                                            |
| Caller           | Fresh-session identity retention through real Linux MCP bridge and one representative model-driven packaged healthy action                                             | [Process check](qualification.md#kapsel-service-candidate), [agent workflow](qualification.md#packaged-service-live-workflow)           |
| Release identity | Version agreement across binaries, MCP, archive, metadata and SBOM; current format/support limits; publisher authentication and downloaded-byte verification           | [Metadata](../reference/release.md#release-metadata), [authentication](../reference/release.md#publisher-authentication-and-provenance) |

The packaged Git journey must run separately from the source harness. Source tests alone cannot
satisfy that gate. The candidate-signing workflow does not run every native, live, Git, or agent
lane; a successful workflow run is not complete release acceptance.

## Interrupted execution

Packaged receiver journeys consume extracted production binaries with separate operator, service,
and caller identities. Keep independent receiver mutation counts. Kubernetes must exercise service
loss after mutation, observation-only same-ID recovery, receipt-commit loss before first export,
cold key rotation, and original receipt retrieval. Git separately exercises acknowledgement loss and
receiver-driven service loss. Graceful restart alone is not crash qualification.

The [crash evidence map](evidence.md#service-crash-and-retained-history-evidence) identifies process
owners. Failed-rollout and untargeted-container assertions belong to the independent live Kubernetes
lane. Legacy vectors and inspection retain their original purposes. Private checkpoint features must
remain absent from production artifacts; caller requests cannot select them.

## Qualification and publication sequence

1. Choose the package version and prepare release notes. Preserve published tags and bytes.
2. Run required checks. Identify internal builds by exact source revision and artifact digests,
   using separate output directories. Fix failures without incrementing the unpublished version.
   Re-run affected checks; shipped bytes must match the qualified revision.
3. Authenticate and publish those exact artifacts under the matching tag. Download through the
   public release route and verify identity, signature, and extraction. Update the README and scope
   to describe the published release.

Prerelease publication is not part of this process. Source revisions and artifact digests
distinguish internal qualification attempts; they are not published releases. Preserve useful
evidence, and never overwrite a published tag or artifact. This procedure does not itself authorize
publication.
