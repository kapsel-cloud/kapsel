# Release artifacts

Status: 0.1 experiment release contract. No compatibility promise.

Kind: contract. Authority: supported release target, archive layout, provenance, assembly, install,
and artifact-only smoke behavior for KAP-0044.

Owns: The bounded 0.1 distribution format and evaluator installation route.

Does not own: Capability behavior, command or MCP grammar, receipt bytes, Kubernetes semantics,
GitHub publication, a stable package format, or production support.

## Supported target

The sole 0.1 release target is `x86_64-unknown-linux-gnu`. Kapsel builds and tests it in pinned
x86-64 Debian 12 environments. The release makes no support claim for macOS, ARM, musl, Windows,
other Linux distributions, or older glibc environments. Adding a target requires a native
clean-artifact smoke lane and an owner update; it is not implied by Rust target availability.

The build container is the Docker Official Image
`rust@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663` for Rust 1.96.1 on
Debian 12. The clean smoke container is
`python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1` for Python 3.11 on
Debian 12. Both run with `--platform linux/amd64`. Digests are part of this prototype assembly
contract so moving image tags cannot silently change release evidence.

## Assembly command

From a clean checkout at the intended source revision, run:

```sh
python3 scripts/assemble-release-artifact.py --output-directory dist
```

Assembly refuses a dirty worktree, a non-`x86_64-unknown-linux-gnu` target, missing Docker, or
source metadata it cannot validate. It builds exactly once without features for the ordinary
executable and once with `demo-harness` for the separately named demonstration executable, both with
`--release`, `--locked`, and the explicit Rust target. The container always sees the checkout at
`/workspace` and uses a remapped source prefix. It copies those built bytes into staging; it never
rebuilds while packaging.

A developer may pass `--allow-dirty` only to exercise assembly before commit. The metadata then
records `source_dirty: true`; such an archive is not publishable and cannot satisfy KAP-0044 or
KAP-0045 evidence.

## Archive and checksum

Assembly emits exactly:

```text
dist/kapsel-<package-version>-x86_64-unknown-linux-gnu.tar.gz
dist/kapsel-<package-version>-x86_64-unknown-linux-gnu.tar.gz.sha256
```

The checksum file is one lowercase SHA-256 digest, two spaces, the archive basename, and a newline.
It identifies the exact downloadable archive bytes, not a workflow-artifact wrapper.

The gzip header has timestamp zero and no source filename. The tar stream uses stable lexical order,
owner/group `0`, empty owner/group names, fixed modes, and timestamp zero. Two clean assemblies of
the same revision with the pinned builder must produce identical archive and checksum bytes before
Kapsel may call assembly reproducible. This claim is limited to the release archive; it is not a
general Rust reproducible-build guarantee.

The archive has one top-level directory and exactly this layout. The demonstration script safely
resolves the fixed archive relationship between `share/kapsel`, `libexec`, and its adjacent public
trust vector, so an extracted artifact needs no internal-layout environment variables:

```text
kapsel-<package-version>-x86_64-unknown-linux-gnu/
  bin/kapsel
  libexec/kapsel-demo-harness
  share/kapsel/demo-kind-crash-recovery.sh
  share/kapsel/kap0038-trust.hex
  share/doc/kapsel/EVALUATOR.md
  CHANGELOG.md
  LICENSE
  RELEASE-METADATA.json
```

Directories and executables use mode `0755`; other files use `0644`. The compressed archive is at
most 32 MiB, the expanded regular files total at most 64 MiB, and each regular file is at most 32
MiB. Verification applies these limits before extraction. The archive contains no grant, trust
decision, credential, signing seed, kubeconfig, journal, receipt, evaluator output, private path, or
customer data. The bundled trust vector is a public deterministic demonstration fixture, not ambient
evaluator trust.

## Provenance metadata

`RELEASE-METADATA.json` is UTF-8 JSON with fixed field order and a trailing newline:

```json
{
  "artifact_schema": "kapsel.release-artifact.v1",
  "package_version": "<Cargo package version>",
  "rust_target": "x86_64-unknown-linux-gnu",
  "source_revision": "<40-lowercase-hex Git revision>",
  "source_dirty": false,
  "license": "Apache-2.0",
  "license_sha256": "<sha256>",
  "builder_image": "rust@sha256:<digest>",
  "smoke_image": "python@sha256:<digest>",
  "ordinary_binary_sha256": "<sha256>",
  "demo_binary_sha256": "<sha256>",
  "non_claims": "not-production;no-stable-cli;no-stable-receipt;no-other-targets"
}
```

The package version and SPDX license identifier come from Cargo metadata. The revision and dirty
state come from Git. License and binary digests identify the exact bundled bytes. Metadata is
release provenance, not a receipt, witness, signature, authorization statement, or claim that the
build environment was trustworthy.

## Installation and smoke

An evaluator downloads the versioned archive and adjacent checksum, verifies the checksum before
extraction, rejects unexpected archive entries, and may install `bin/kapsel` from the one top-level
directory. No install step writes credentials, trust, configuration, journals, or receipts. A
user-local installation may copy the ordinary binary to `$HOME/.local/bin/kapsel`; the demo
executable and assets remain separate. Installation is not required for the primary real-kind path.
From the safely extracted top-level directory, that path is exactly:

```sh
./share/kapsel/demo-kind-crash-recovery.sh
```

The command reports prerequisite versions before cluster inspection, elapsed phases, a bounded
lifecycle evidence summary, the temporary offline-inspection path, and ownership-safe cleanup. A
missing prerequisite or cleanup failure names a concrete corrective action and exits unsuccessfully.

From the repository, run the deterministic artifact-only smoke with:

```sh
python3 scripts/smoke-release-artifact.py \
  --archive dist/kapsel-<package-version>-x86_64-unknown-linux-gnu.tar.gz \
  --expected-revision <40-lowercase-hex Git revision>
```

`cargo make test-release-artifact` first assembles a fresh archive and drives this supplied-archive
entry point in the pinned clean container. The smoke verifies checksum, exact layout, modes,
metadata, license, target, revision, binary digests, and extraction safety before executing only
extracted files in the pinned clean container. It proves grant provisioning, operation and ordinary
restart against a deterministic local HTTP Kubernetes fixture, offline inspection, MCP
initialization/list/call/EOF, bounded output, and cleanup. It never calls Cargo, reads `target/`, or
uses a checkout binary.

The separate artifact demo gate runs the bundled script with the extracted feature-gated demo
executable and bundled public vector against its owned disposable `kind` cluster. The ordinary
binary never contains demo pause behavior. Source-build and artifact-demo modes preserve the same
prerequisite, ownership, crash, result, disclosure, and cleanup contract.

## Result and security limits

Installation does not change result meaning. `NOT_ATTEMPTED` remains a pre-attempt disposition;
`SUCCEEDED`, `FAILED`, and `UNKNOWN` remain bounded receiver outcomes. Inspection remains
`INSPECTED`, never `VERIFIED`. Artifact completion, checksum agreement, process exit, MCP transport
completion, or Kubernetes request acceptance cannot strengthen those meanings.

The archive and its checksum are unsigned prototype distribution artifacts. SHA-256 detects byte
mismatch but does not appoint a publisher, establish trusted existence time, prove source review, or
make the artifact safe for production. Evaluators must treat generated receipts and reports as the
sensitive operational metadata described by [Privacy](PRIVACY.md).

## Official build basis

The target and build behavior follow the official Rust [platform support], [GNU/Linux target],
[`cargo build`], [locked dependency], [target selection], [release profile], and [path-remapping]
documentation. The completed `0.1.0` publication evidence is owned by
[KAP-0045](../tasks/KAP-0045.md); the completed `0.1.1` release and its publication evidence are
owned by [KAP-0049](../tasks/KAP-0049.md).

[platform support]: https://doc.rust-lang.org/rustc/platform-support.html
[GNU/Linux target]: https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-linux-gnu.html
[`cargo build`]: https://doc.rust-lang.org/cargo/commands/cargo-build.html
[locked dependency]: https://doc.rust-lang.org/cargo/commands/cargo-build.html#manifest-options
[target selection]: https://doc.rust-lang.org/cargo/commands/cargo-build.html#compilation-options
[release profile]: https://doc.rust-lang.org/cargo/reference/profiles.html#release
[path-remapping]: https://doc.rust-lang.org/rustc/codegen-options/index.html#remap-path-prefix
