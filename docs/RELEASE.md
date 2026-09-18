# Release artifacts

Status: unreleased resident-service preview artifact contract. Native installed-artifact
qualification and publication remain separate, required evidence. The published v0.2.0 archive is
unchanged and remains reproducible from its tagged source, not this assembler.

Kind: contract. Authority: supported release target, archive layout, assembly, SBOM,
publisher-authentication, installation, and artifact-only behavior.

Owns: The bounded HEAD preview distribution format and verification route.

Does not own: Capability behavior, command or MCP semantics, receipt bytes, Kubernetes behavior,
GitHub publication approval, production support, or another target.

## Supported target and inputs

The sole preview target is `x86_64-unknown-linux-gnu`. Kapsel builds and tests it in pinned x86-64
Debian 12 environments. There is no support claim for macOS, ARM, musl, Windows, another Linux
target, or older glibc environments. Adding a target requires a separately accepted native clean
artifact lane and owner update.

The build container is the Docker Official Image
`rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922` for Rust 1.98.0 on
Debian 12. The clean smoke container is
`python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1` for Python 3.11 on
Debian 12. Both run with `--platform linux/amd64`. Their digests are build and smoke inputs, not
claims that the builder or image contents are trustworthy.

The root `kapsel` archive is the only selected package. The preview selects no crates.io, docs.rs,
`cargo install`, source-package, sandbox, image, or second-target artifact.

## Deterministic assembly

From a clean checkout at the intended source revision, run:

```sh
python3 scripts/assemble-release-artifact.py --output-directory dist
```

Assembly refuses a dirty worktree, a non-`x86_64-unknown-linux-gnu` target, missing Docker, or
source metadata it cannot validate. It builds the `kapsel` and `kapseld` packages together without
test/demo features. The three executables use `--release`, `--locked`, the explicit target, fixed
container path `/workspace`, and source-prefix remapping. Packaging copies those bytes and never
rebuilds them.

`--allow-dirty` exists only for local script tests. Such metadata records `source_dirty: true`; its
outputs are not publishable and cannot satisfy candidate evidence.

One assembly emits exactly these deterministic files:

```text
dist/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz
dist/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz.sha256
dist/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz.spdx.json
dist/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz.SHA256SUMS
dist/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz.verify.py
```

The adjacent checksum is one lowercase SHA-256 digest, two spaces, the archive basename, and a
newline. `SHA256SUMS` contains lexically ordered, basename-only SHA-256 lines for the archive,
adjacent checksum, SBOM, and extraction verifier. A checksum proves byte identity only; publisher
authentication starts with the separately signed `SHA256SUMS` manifest.

The gzip header has timestamp zero and no source filename. The USTAR stream has stable lexical
ordering, owner/group `0`, empty names, timestamp zero, and fixed modes.

The release proof uses exactly two strict isolated assemblies of the same clean revision and pinned
inputs. Assembly A remains outside the worktree, passes exact layout and hostile-archive
verification, and is smoke-tested only through extracted files. Independent assembly B uses a
separate target and output directory. The archive, checksum, SBOM, digest manifest and verifier from
A and B must be byte-identical. Only after smoke and comparison pass are the exact five A files
copied byte-for-byte to `dist/` for upload; B is never uploaded. Neither target directory nor
compiled output is shared between A and B. An immutable Cargo registry/download cache may be shared
because it supplies inputs rather than compiled output.

This is a bounded reproducibility claim for those files, not a general Rust reproducible build,
reviewed-source, or builder-integrity guarantee.

## Exact archive

The archive has one top-level directory and exactly this layout:

```text
kapsel-<version>-x86_64-unknown-linux-gnu/
  bin/kapsel
  bin/kapsel-service-client
  libexec/kapsel/kapseld
  share/kapsel/kapseld.service
  share/kapsel/kapseld.conf
  share/kapsel/kapseld-rbac.yaml
  share/doc/kapsel/COMMANDS.md
  share/doc/kapsel/KAPSEL_SERVICE.md
  share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md
  share/doc/kapsel/PRIVACY.md
  share/doc/kapsel/RELEASE.md
  share/doc/kapsel/SECURITY.md
  share/doc/kapsel/UPGRADE.md
  CHANGELOG.md
  LICENSE
  RELEASE-METADATA.json
```

Directories and executables use mode `0755`; other files use `0644`. Bundled Markdown retains the
source prose. Links to other bundled Markdown remain local. Other repository-local `.md` links
become absolute URLs at the exact source revision, so extracted documents do not contain broken
checkout-relative links. The operator path and service contract are available without a checkout.
The compressed archive is at most 32 MiB, expanded regular files total at most 64 MiB, and each
regular file is at most 32 MiB. Verification rejects extra or missing entries, non-lexical ordering,
absolute paths, traversal, links, special files, unsafe modes, non-normalized ownership/timestamps,
and size excess before extraction. Extraction creates each regular file exclusively rather than
delegating path handling to `tar`.

The archive contains no credential, provider authority, grant, private trust decision, signing seed,
kubeconfig, journal, receipt, report, evaluator output, private path, sandbox asset, or customer
data. No demonstration executable, test pause surface or public fixture trust is bundled.

## Release metadata

`RELEASE-METADATA.json` is canonical UTF-8 JSON with fixed field order and a trailing newline.
Schema `kapsel.release-artifact.v3` binds:

- package version, target, source revision, Git tree, and clean/dirty state;
- Cargo lockfile SHA-256 plus canonical reachable-package/relationship graph digest and counts;
- license identifier and digest;
- exact build and smoke image identities;
- CLI, service and client binary byte lengths and SHA-256 digests; and
- fixed service-preview non-claims.

Metadata is an input to the authenticated digest manifest through the archive. It does not
self-authenticate, witness a build, prove review, or establish trusted existence time.

## SPDX SBOM

The adjacent SBOM is deterministic SPDX 2.3 JSON generated by `scripts/assemble-release-artifact.py`
under generator identity `kapsel-release-sbom/1`. It is at most 2 MiB and binds the exact archive
digest, bundled binary paths and digests, package version, source revision and tree, target, builder
image, Cargo lockfile digest, and the complete locked Rust package graph reachable from the root and
service packages, including build and target-conditioned dependencies. Presence in that conservative
graph is dependency identity evidence, not a runtime-reachability claim. The archive package sets
SPDX `filesAnalyzed` to false and relates only the three digest-bound binary records explicitly; it
does not claim that every bundled document or asset received file analysis. Metadata independently
binds the canonical reachable package/relationship graph digest and counts, and artifact smoke
rejects a deleted or changed graph.

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

The appointed candidate publisher is exactly the GitHub Actions workflow identity:

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
replacement; connected verification is therefore repeated before publication.

There is no long-lived Kapsel signing key to rotate. Workflow path or branch changes require a new
explicit identity rule and candidate. Suspected repository, workflow, GitHub OIDC, Fulcio, Rekor, or
candidate compromise disables candidate signing, records the exact digests/run as withdrawn, and
creates a newly named candidate from a newly accepted revision. Existing archive, manifest, and
bundle bytes are never overwritten or silently re-signed. Cryptographic validity alone does not
communicate withdrawal.

Publisher authentication proves that the appointed workflow signed exact manifest bytes. It does not
prove source review, workflow safety, builder integrity, dependency safety, reproducibility,
operational fitness, production support, or universal existence time.

## Authenticate and extract the preview

Use Python 3.11 or newer, Cosign 3.1.2, and GNU `sha256sum` on the selected Linux host. Obtain the
exact archive and all five sidecars, including the Sigstore bundle, from the appointed publisher. No
preview has been published yet. For a local candidate, transfer the locally recorded exact bytes
through your trusted operator channel. An unsigned local candidate has no publisher authentication.

The `.verify.py` companion is a byte-for-byte copy of the existing
`scripts/smoke-release-artifact.py` verification owner, at most 64 KiB. It is covered by the signed
digest manifest. Authenticate the manifest using the exact issuer, identity and source revision
[above](#publisher-authentication-and-provenance), then check its files **before executing this
Python file**. Do not fetch a script from a moving branch or use the published-beta evaluator's
old-layout extractor.

In a private, caller-owned download directory containing only those files:

```sh
archive=kapsel-0.3.0-preview.1-x86_64-unknown-linux-gnu.tar.gz
revision='<exact accepted 40-lowercase-hex source revision>'
cosign verify-blob \
  --bundle "$archive.SHA256SUMS.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity \
    https://github.com/kapsel-cloud/kapsel/.github/workflows/release-candidate.yml@refs/heads/master \
  --certificate-github-workflow-repository kapsel-cloud/kapsel \
  --certificate-github-workflow-ref refs/heads/master \
  --certificate-github-workflow-sha "$revision" \
  --certificate-github-workflow-trigger workflow_dispatch \
  "$archive.SHA256SUMS" &&
sha256sum --check --strict "$archive.SHA256SUMS" &&
python3 "$archive.verify.py" --archive "$archive" \
  --expected-revision "$revision" --extract-to ./extracted
```

The command validates the exact bounded archive, checksum, SBOM, manifest and revision before
creating `./extracted` mode `0700`. That destination must not already exist, even as a symlink. Use
a parent directory controlled only by the operator. Extraction does not run a bundled binary,
contact Kubernetes, create system identities or touch private service state. It creates only the
verified archive tree and prints its path. On an I/O failure, a partial new destination may remain;
inspect it and use a new empty destination, never merge with or overwrite an existing tree.

The result is `./extracted/kapsel-0.3.0-preview.1-x86_64-unknown-linux-gnu/`. Use that absolute path
as `artifact` in the
[operator guide](KAPSEL_SERVICE_OPERATOR.md#prepare-your-own-extracted-artifact). Keep the archive,
sidecars, source revision and digests as the artifact identity. Installation is a separate, explicit
operator step.

## Install, upgrade, and artifact-only proof

After publisher verification and digest-manifest verification, an evaluator safely extracts the one
archive and may install `bin/kapsel` to `$HOME/.local/bin/kapsel`. Installation creates no
authority, trust, journal, or receipt. `kapsel --version`, MCP `serverInfo.version`, archive
identity, metadata, and SBOM must all report the same package version.

The preview's operator path is [service preparation and operation](KAPSEL_SERVICE_OPERATOR.md). The
CLI prepares snapshot grants and inspects receipts. The daemon owns private execution and history.
The client supplies the caller's fixed ID-only interface. The systemd unit owns process lifecycle.
No custom installer is supplied.

From the repository, deterministic artifact-only smoke is:

```sh
python3 scripts/smoke-release-artifact.py \
  --archive dist/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz \
  --expected-revision <40-lowercase-hex Git revision>
```

`scripts/test-release-artifact.py --archive <A>` validates one already assembled A and then runs
only extracted files in the pinned clean container. It proves safe extraction, installed identity,
grant provisioning, ordinary operation/restart, offline inspection, MCP
initialization/list/call/EOF, bounded output and ordinary-binary removal. Its explicit
`--service-container` lane uses fresh fixed paths and separate numeric service/caller identities
inside a disposable root Docker container. It exercises exact-snapshot provisioning, cold
publication, ID selection, caller disconnect, read-first restart and identical receipt retrieval,
with independent receiver mutation counts. It retains private state until container destruction.
This is not a systemd or native-host qualification lane. It proves successful completion followed by
graceful restart, not interrupted execution, crash ambiguity or recovery from an unfinished attempt.
The complete operator/agent journey must exercise those failures against the packaged service and
independently count mutations. Final combined-candidate qualification consumes that journey and its
exact rebuilt bytes. Removing the old demo from this archive does not discharge those recovery
requirements. Its synthetic hostile-archive matrix remains independent of the producer.
`scripts/test-release-reproducibility.py --reference-archive <A>` performs the one independent
strict assembly B and compares all five deterministic outputs byte-for-byte. Neither verifier hides
another A assembly.

HEAD qualification and candidate acceptance do not require historical migration, rollback, or
downgrade. Current format 5 rejects older journals unchanged. The published v0.1.1-to-v0.2.0
artifact and source proofs remain separate
[historical evidence](UPGRADE.md#reproduce-the-published-release-evidence), not compatibility
obligations for a newly assembled HEAD candidate.

The published-beta live demo remains at the v0.2.0 tag. It is not the preview service journey.
Native installed-systemd and live receiver exercises must consume the extracted preview bytes. An
emulated container smoke test does not establish either qualification.

## Native installed-systemd qualification

On an explicitly authorized fresh native x86-64 Debian host with systemd as PID 1, the same
checksum-bound verifier companion runs the
[canonical disposable service example](KAPSEL_SERVICE_OPERATOR.md#one-command-disposable-example)
and exercises the shipped unit. This is a **privileged test**, not an installer or production setup
command. It uses only a loopback HTTP receiver and deterministic disposable test keys. It never
consumes real cluster credentials or applies the example RBAC to a cluster. The build baseline
remains Debian 12; record the actual native host's OS and systemd version separately, including when
qualifying on a newer Debian host.

Prerequisites are Python 3.11+, root operator access, systemd/systemd-sysusers, systemd-analyze,
journalctl, useradd, GNU coreutils, and a fresh host with no Kapsel accounts, groups, unit,
overrides, enablement references, static destinations or private state. Existing dangling enablement
links are refused unchanged. First follow the
[authenticated preparation route](#authenticate-and-extract-the-preview). For an unsigned local
candidate, use separately recorded exact digests and a trusted transfer; this does not establish
publisher authentication. Dirty-source artifacts are refused for this mode.

From the private directory holding the already authenticated and checksum-verified artifact files:

```sh
archive=kapsel-0.3.0-preview.1-x86_64-unknown-linux-gnu.tar.gz
revision='<exact accepted 40-lowercase-hex source revision>'
sha256sum --check --strict "$archive.SHA256SUMS" &&
sudo python3 "$archive.verify.py" --archive "$archive" \
  --expected-revision "$revision" --service-systemd
```

The test checks fail-closed startup and the fixed journald provisioning diagnostic before approval,
then uses the installed binaries for snapshot provisioning and cold publication. The shipped unit
starts the daemon under its service identity. The separate caller is denied private configuration
access. The test checks socket custody, selects the ID, retrieves and independently inspects a
receipt, stops through systemd, replaces the cold catalog, starts again, reads retained history and
retrieves identical receipt bytes. The receiver count must remain one PATCH. No forced kill is used
to claim retirement.

Success leaves the unit **stopped**, not enabled, and retains the installed test binaries, unit,
sysusers/RBAC assets, documentation, service/caller accounts, `/etc/kapsel`, `/var/lib/kapsel`,
lifecycle lock, fixture authority, `/etc/kapsel/example-receipt.trust` and two caller-owned
`/tmp/kapsel-artifact-receipt-*` exports. Do not restart this test installation as a production
service. Failure may leave a partial installation or an incomplete stop. Preserve and inspect it, do
not rerun by deleting history or assume matching names are safe to adopt. There is no automatic host
cleanup or rollback.

Capture the command, exact artifact/source digests, OS release, systemd version, exit and output.
This gate still does not establish live Kubernetes behavior, interrupted execution or ambiguity
recovery. The complete operator/agent journey and final combined-candidate qualification own those
packaged-service exercises.

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
specifications. Candidate evidence remains immutable. Public release evidence alone establishes the
tag, publication, and downloaded verification for the accepted artifact.
