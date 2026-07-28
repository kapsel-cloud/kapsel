# Release artifacts

Status: v0.2 developer-beta artifact contract. Acceptance and publication status are external
evidence.

Kind: contract. Authority: supported release target, archive layout, assembly, SBOM,
publisher-authentication, installation, and artifact-only behavior.

Owns: The bounded v0.2 distribution format and verification route.

Does not own: Capability behavior, command or MCP semantics, receipt bytes, Kubernetes behavior,
GitHub publication approval, production support, or another target.

## Supported target and inputs

The sole v0.2 target is `x86_64-unknown-linux-gnu`. Kapsel builds and tests it in pinned x86-64
Debian 12 environments. There is no support claim for macOS, ARM, musl, Windows, another Linux
target, or older glibc environments. Adding a target requires a separately accepted native clean
artifact lane and owner update.

The build container is the Docker Official Image
`rust@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663` for Rust 1.96.1 on
Debian 12. The clean smoke container is
`python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1` for Python 3.11 on
Debian 12. Both run with `--platform linux/amd64`. Their digests are build and smoke inputs, not
claims that the builder or image contents are trustworthy.

The root `kapsel` archive is the only distributed package. The shared workspace version inherited by
unpublished `kapsel-dev` and `kapsel-sandbox` packages does not distribute or support them. v0.2
publishes no crates.io, docs.rs, `cargo install`, source-package, sandbox, image, or second-target
artifact.

## Deterministic assembly

From a clean checkout at the intended source revision, run:

```sh
python3 scripts/assemble-release-artifact.py --output-directory dist
```

Assembly refuses a dirty worktree, a non-`x86_64-unknown-linux-gnu` target, missing Docker, or
source metadata it cannot validate. It builds exactly once without features for the ordinary
executable and once with `demo-harness` for the separately named demonstration executable. Both
builds use `--release`, `--locked`, the explicit target, fixed container path `/workspace`, and
source-prefix remapping. Packaging copies those bytes and never rebuilds them.

`--allow-dirty` exists only for local script tests. Such metadata records `source_dirty: true`; its
outputs are not publishable and cannot satisfy candidate evidence.

One assembly emits exactly these deterministic files:

```text
dist/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz
dist/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz.sha256
dist/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz.spdx.json
dist/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz.SHA256SUMS
```

The adjacent checksum is one lowercase SHA-256 digest, two spaces, the archive basename, and a
newline. `SHA256SUMS` contains lexically ordered, basename-only SHA-256 lines for the archive,
adjacent checksum, and SBOM. A checksum proves byte identity only; publisher authentication starts
with the separately signed `SHA256SUMS` manifest.

The gzip header has timestamp zero and no source filename. The USTAR stream has stable lexical
ordering, owner/group `0`, empty names, timestamp zero, and fixed modes. Two clean assemblies of the
same revision and pinned inputs must produce byte-identical archives, checksums, SBOMs, and digest
manifests. This is a bounded reproducibility claim for those files, not a general Rust reproducible
build, reviewed-source, or builder-integrity guarantee.

## Exact archive

The archive has one top-level directory and exactly this layout:

```text
kapsel-<version>-x86_64-unknown-linux-gnu/
  bin/kapsel
  libexec/kapsel-demo-harness
  share/kapsel/demo-kind-crash-recovery.sh
  share/kapsel/kap0038-trust.hex
  share/doc/kapsel/COMMANDS.md
  share/doc/kapsel/EVALUATOR.md
  share/doc/kapsel/MCP.md
  share/doc/kapsel/PRIVACY.md
  share/doc/kapsel/RELEASE.md
  share/doc/kapsel/SECURITY.md
  share/doc/kapsel/UPGRADE.md
  CHANGELOG.md
  LICENSE
  RELEASE-METADATA.json
```

Directories and executables use mode `0755`; other files use `0644`. Bundled Markdown retains the
source prose while rewriting repository-local `.md` links to absolute URLs at the exact source
revision, so extracted compatibility and security documents do not contain checkout-relative broken
links. The compressed archive is at most 32 MiB, expanded regular files total at most 64 MiB, and
each regular file is at most 32 MiB. Verification rejects extra or missing entries, non-lexical
ordering, absolute paths, traversal, links, special files, unsafe modes, non-normalized
ownership/timestamps, and size excess before extraction. Extraction creates each regular file
exclusively rather than delegating path handling to `tar`.

The archive contains no credential, provider authority, grant, private trust decision, signing seed,
kubeconfig, journal, receipt, report, evaluator output, private path, sandbox asset, or customer
data. The bundled trust vector is a public deterministic demonstration fixture, not ambient trust.

## Release metadata

`RELEASE-METADATA.json` is canonical UTF-8 JSON with fixed field order and a trailing newline.
Schema `kapsel.release-artifact.v2` binds:

- package version, target, source revision, Git tree, and clean/dirty state;
- Cargo lockfile SHA-256 plus canonical reachable-package/relationship graph digest and counts;
- license identifier and digest;
- exact build and smoke image identities;
- ordinary and demonstration binary byte lengths and SHA-256 digests; and
- fixed developer-beta non-claims.

Metadata is an input to the authenticated digest manifest through the archive. It does not
self-authenticate, witness a build, prove review, or establish trusted existence time.

## SPDX SBOM

The adjacent SBOM is deterministic SPDX 2.3 JSON generated by `scripts/assemble-release-artifact.py`
under generator identity `kapsel-release-sbom/1`. It is at most 2 MiB and binds the exact archive
digest, bundled binary paths and digests, package version, source revision and tree, target, builder
image, Cargo lockfile digest, and the complete locked Rust package graph reachable from the root
package, including build and target-conditioned dependencies. Presence in that conservative graph is
dependency identity evidence, not a runtime-reachability claim. The archive package sets SPDX
`filesAnalyzed` to false and relates only the two digest-bound binary records explicitly; it does
not claim that every bundled document or asset received file analysis. Metadata independently binds
the canonical reachable package/relationship graph digest and counts, and artifact smoke rejects a
deleted or changed graph.

The SPDX document namespace includes the exact source revision and archive digest. Its `created`
field is normalized to the source commit time so isolated assemblies serialize identically. The
document comment states this normalization and the source/build identities. Packages without
owner-supplied license or download facts use SPDX `NOASSERTION`; the generator does not invent
license conclusions.

The SBOM is not a vulnerability result, dependency-safety proof, malicious-package detector, or
complete account of compiler, OS, firmware, or hosted workflow components. Candidate review records
the generator identity plus fresh cargo-audit and Trivy versions/database times. Scanner knowledge
can be incomplete or later change.

## Publisher authentication and provenance

The appointed v0.2 candidate publisher is exactly the GitHub Actions workflow identity:

```text
issuer: https://token.actions.githubusercontent.com
identity: https://github.com/kapsel-cloud/kapsel/.github/workflows/release-candidate.yml@refs/heads/master
repository: kapsel-cloud/kapsel
ref: refs/heads/master
trigger: workflow_dispatch
source SHA: exact 40-hex candidate revision
```

A maintainer manually dispatches `.github/workflows/release-candidate.yml` at the accepted candidate
revision. The workflow has only `contents: read` and `id-token: write`, installs exact Cosign
`v3.1.2` through an action pinned by commit, re-runs deterministic assembly/reproducibility, and
executes:

```sh
cosign sign-blob --yes \
  --bundle <archive>.SHA256SUMS.sigstore.json \
  <archive>.SHA256SUMS
```

The Sigstore bundle is bounded to 1 MiB and contains the signature, short-lived Fulcio certificate,
and Rekor inclusion evidence. It is intentionally nondeterministic because each release act uses a
new ephemeral key, certificate, signature, and transparency-log event. Reproducibility applies to
the signed manifest and its named files, not bundle bytes. Candidate evidence records the bundle
digest, workflow run/attempt, exact source and workflow revision, Cosign version, and trust-root
identity.

Verify the bundle before trusting manifest contents, require the exact issuer and non-regex
identity, and constrain the GitHub certificate extensions:

```sh
cosign verify-blob \
  --bundle <archive>.SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity \
    https://github.com/kapsel-cloud/kapsel/.github/workflows/release-candidate.yml@refs/heads/master \
  --certificate-github-workflow-repository kapsel-cloud/kapsel \
  --certificate-github-workflow-ref refs/heads/master \
  --certificate-github-workflow-sha <exact-candidate-revision> \
  --certificate-github-workflow-trigger workflow_dispatch \
  <archive>.SHA256SUMS
sha256sum --check --strict <archive>.SHA256SUMS
```

Connected verification refreshes Sigstore trust through its TUF distribution. A network-disabled
verification must pass `--trusted-root <captured-trusted-root.json>` and records that snapshot's
digest. The bundle supplies authenticated signing-time evidence so an expired short-lived leaf
certificate can remain historically valid. Rekor time is not a general release-approval timestamp.
Offline verification cannot discover later root rotation, compromise, candidate withdrawal, or
replacement; KAP-0063 therefore repeats connected verification before publication.

There is no long-lived Kapsel signing key to rotate. Workflow path or branch changes require a new
explicit identity rule and candidate. Suspected repository, workflow, GitHub OIDC, Fulcio, Rekor, or
candidate compromise disables candidate signing, records the exact digests/run as withdrawn, and
creates a newly named candidate from a newly accepted revision. Existing archive, manifest, and
bundle bytes are never overwritten or silently re-signed. Cryptographic validity alone does not
communicate withdrawal.

Publisher authentication proves that the appointed workflow signed exact manifest bytes. It does not
prove source review, workflow safety, builder integrity, dependency safety, reproducibility,
operational fitness, production support, or universal existence time.

## Install, upgrade, and artifact-only proof

After publisher verification and digest-manifest verification, an evaluator safely extracts the one
archive and may install `bin/kapsel` to `$HOME/.local/bin/kapsel`. Installation creates no
authority, trust, journal, or receipt. `kapsel --version`, MCP `serverInfo.version`, archive
identity, metadata, and SBOM must all report the same package version.

The separately named demo executable and assets remain outside the ordinary installed binary. From
the extracted top-level directory, the owned live path is:

```sh
./share/kapsel/demo-kind-crash-recovery.sh
```

From the repository, deterministic artifact-only smoke is:

```sh
python3 scripts/smoke-release-artifact.py \
  --archive dist/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz \
  --expected-revision <40-lowercase-hex Git revision>
```

`cargo make test-release-artifact` assembles and validates a candidate and then runs only extracted
files in the pinned clean container. It proves safe extraction, installed identity, grant
provisioning, ordinary operation/restart, offline inspection, MCP initialization/list/call/EOF,
bounded output, cleanup, demo-binary separation, and uninstall. `cargo make test-release-upgrade`
consumes the exact immutable v0.1.1 archive and candidate archive, then uses only their safely
extracted executables to prove a finalized historical journal backup, migration-only open/reopen,
retained receipt inspection, restore/re-mark, and direct exact-v0.1.1 downgrade. It complements the
complete source-fixture state/process matrix and reads no checkout or `target/` candidate binary.

The live artifact demo uses only the extracted script, feature-gated executable, and public vector
against its uniquely owned disposable `kind` cluster. The ordinary binary contains no demonstration
pause behavior.

## Result and security limits

Installation, SBOM creation, checksum agreement, signature success, process exit, MCP completion, or
demo completion cannot change receiver meaning. `NOT_ATTEMPTED` remains pre-attempt; `SUCCEEDED`,
`FAILED`, and `UNKNOWN` remain bounded receiver outcomes. Inspection remains `INSPECTED`, never
`VERIFIED`.

The release does not claim exactly-once effects, Kubernetes truth, causation, complete capture,
compliance, trusted builders, vulnerability absence, production readiness, another capability, or
another platform. Receipts and reports remain sensitive operational metadata under
[Privacy](PRIVACY.md).

## Official basis

The target and build behavior follow official Rust platform, Cargo locked-build/metadata, release
profile, and path-remapping documentation. SPDX fields follow the SPDX 2.3 specification. Keyless
blob signing and verification follow current Sigstore Cosign, Fulcio, Rekor, and trusted-root
specifications. KAP-0062 owns candidate-production evidence; KAP-0063 alone owns tag, publication,
public download verification, and website handoff.
