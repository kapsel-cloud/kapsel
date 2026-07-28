# Evaluate Kapsel v0.2.x

This guide evaluates an authenticated v0.2.x `x86_64-unknown-linux-gnu` developer-beta artifact for
the fixed `kubernetes.set_deployment_image` operation. It is not production guidance. Use one exact
version and all named sidecars attached to the project's GitHub release; release tags and assets are
immutable.

## Limits first

Kapsel accepts one immutable Deployment image request under one exact owner-signed grant. It does
not accept shell, `kubectl`, manifests, arbitrary patches, tags, wildcards, credentials, trust,
paths, or lifecycle controls from the request. It reports bounded receiver outcomes:

- `SUCCEEDED`: the owned receiver facts meet the defined available-rollout condition;
- `FAILED`: the owned receiver facts contain the defined `ProgressDeadlineExceeded` condition;
- `UNKNOWN`: bounded reconciliation cannot establish either outcome; and
- `NOT_ATTEMPTED`: a local target rejection occurred before the mutation marker, so there is no
  receiver outcome.

A receipt inspected as `INSPECTED` is authenticated under supplied prototype trust. It is never
`VERIFIED` and does not prove Kubernetes truth, causation, exactly-once effects, complete capture,
compliance, or production readiness.

```text
verified release archive
  -> ordinary bin/kapsel
       -> local command or fixed MCP adapter
            -> one Application composition
                 -> owner-configured exact grant, trust, Kubernetes authority, journal, receipts
  -> separate libexec/kapsel-demo-harness
       -> owned disposable-kind crash demonstration only
```

## Short real-kind path

With Docker, kind 0.32 or newer, kubectl 1.30 or newer, Python 3.11 or newer, and `curl` on x86-64
GNU/Linux, the primary path is:

1. download the exact archive, checksum, SBOM, digest manifest, and Sigstore bundle;
2. authenticate, verify, and safely extract them with the next section; then
3. run one command from the extracted top-level directory:

```sh
./share/kapsel/demo-kind-crash-recovery.sh
```

Expect roughly two to five minutes with ordinary network access; the first kind node-image download
is usually the longest step. The command refuses to begin when it cannot establish prerequisites or
exclusive ownership, reports elapsed phases, and ends with the lifecycle evidence and cleanup
summary described below. Ten minutes without a receipt is a failed evaluation, not evidence of a
receiver result.

## Verify and install

The sole release target is x86-64 GNU/Linux, validated in Debian 12. Download one exact version and
all its sidecars from the public GitHub release. With Cosign v3.1.2, authenticate the exact
publisher workflow and source revision before checking the signed digest manifest:

```sh
umask 077
download_directory=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-download.XXXXXXXX")
cd "$download_directory"
version="${KAPSEL_VERSION:?set KAPSEL_VERSION to an exact attached 0.2.x version}"
revision="${KAPSEL_REVISION:?set KAPSEL_REVISION to the release's exact 40-hex source revision}"
base="https://github.com/kapsel-cloud/kapsel/releases/download/v$version"
archive="kapsel-$version-x86_64-unknown-linux-gnu.tar.gz"
for suffix in '' .sha256 .spdx.json .SHA256SUMS .SHA256SUMS.sigstore.json; do
  curl -fLO "$base/$archive$suffix"
done
cosign verify-blob \
  --bundle "$archive.SHA256SUMS.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity \
    https://github.com/kapsel-cloud/kapsel/.github/workflows/release-candidate.yml@refs/heads/master \
  --certificate-github-workflow-repository kapsel-cloud/kapsel \
  --certificate-github-workflow-ref refs/heads/master \
  --certificate-github-workflow-sha "$revision" \
  --certificate-github-workflow-trigger workflow_dispatch \
  "$archive.SHA256SUMS"
sha256sum --check --strict "$archive.SHA256SUMS"
sha256sum --check --strict "$archive.sha256"
python3 - "$archive" <<'PY'
import gzip, io, pathlib, shutil, sys, tarfile
archive = pathlib.Path(sys.argv[1])
if not archive.is_file() or archive.is_symlink() or archive.stat().st_size > 32 * 1024 * 1024:
    raise RuntimeError("release archive is not a bounded regular file")
archive_bytes = archive.read_bytes()
basename = archive.name.removesuffix(".tar.gz")
if pathlib.Path(basename).exists():
    raise RuntimeError("release extraction destination already exists")
expected = {
    f"{basename}/", f"{basename}/bin/", f"{basename}/bin/kapsel",
    f"{basename}/libexec/", f"{basename}/libexec/kapsel-demo-harness",
    f"{basename}/share/", f"{basename}/share/kapsel/",
    f"{basename}/share/kapsel/demo-kind-crash-recovery.sh",
    f"{basename}/share/kapsel/kap0038-trust.hex", f"{basename}/share/doc/",
    f"{basename}/share/doc/kapsel/", f"{basename}/share/doc/kapsel/COMMANDS.md",
    f"{basename}/share/doc/kapsel/EVALUATOR.md", f"{basename}/share/doc/kapsel/MCP.md",
    f"{basename}/share/doc/kapsel/PRIVACY.md", f"{basename}/share/doc/kapsel/RELEASE.md",
    f"{basename}/share/doc/kapsel/SECURITY.md", f"{basename}/share/doc/kapsel/UPGRADE.md",
    f"{basename}/CHANGELOG.md", f"{basename}/LICENSE",
    f"{basename}/RELEASE-METADATA.json",
}
with gzip.GzipFile(fileobj=io.BytesIO(archive_bytes), mode="rb") as compressed:
    tar_bytes = compressed.read(64 * 1024 * 1024 + 64 * 1024 + 1)
if len(tar_bytes) > 64 * 1024 * 1024 + 64 * 1024:
    raise RuntimeError("release tar stream exceeds its decompressed bound")
offset = entries = zero_blocks = 0
while offset + 512 <= len(tar_bytes):
    header = tar_bytes[offset:offset + 512]
    if header == bytes(512):
        zero_blocks += 1
        offset += 512
        if zero_blocks == 2:
            break
        continue
    if zero_blocks or header[257:263] != b"ustar\0" or header[156:157] not in {b"\0", b"0", b"5"}:
        raise RuntimeError("release tar is not exact extension-free USTAR")
    size_field = header[124:136].rstrip(b"\0 ")
    if any(character not in b"01234567" for character in size_field):
        raise RuntimeError("release tar size is not canonical octal")
    size = int(size_field or b"0", 8)
    entries += 1
    offset += 512 + ((size + 511) // 512) * 512
    if entries > len(expected) or offset > len(tar_bytes):
        raise RuntimeError("release tar framing exceeds its bound")
if entries != len(expected) or zero_blocks != 2 or any(tar_bytes[offset:]):
    raise RuntimeError("release tar framing or padding is not canonical")
with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as release:
    members = release.getmembers()
    ordered_names = [member.name + ("/" if member.isdir() else "") for member in members]
    if set(ordered_names) != expected or len(ordered_names) != len(expected) or ordered_names != sorted(expected):
        raise RuntimeError("unexpected release archive layout or ordering")
    if sum(member.size for member in members if member.isfile()) > 64 * 1024 * 1024:
        raise RuntimeError("release archive exceeds its expanded bound")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise RuntimeError("unsafe archive path")
        if not (member.isdir() or member.isfile()) or member.size > 32 * 1024 * 1024:
            raise RuntimeError("links, special entries, or oversized files are forbidden")
        if (member.uid, member.gid, member.uname, member.gname, member.mtime) != (0, 0, "", "", 0):
            raise RuntimeError("release archive metadata is not normalized")
        expected_mode = 0o755 if member.isdir() or member.name.endswith(
            ("/kapsel", "/kapsel-demo-harness", ".sh")
        ) else 0o644
        if member.mode != expected_mode:
            raise RuntimeError("unexpected release archive mode")
    root = pathlib.Path(basename)
    root.mkdir(mode=0o700)
    try:
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            target = pathlib.Path(*path.parts)
            if target == root:
                continue
            if member.isdir():
                target.mkdir(mode=member.mode)
            else:
                source = release.extractfile(member)
                if source is None:
                    raise RuntimeError("release file could not be read")
                with target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(member.mode)
        root.chmod(0o755)
    except BaseException:
        shutil.rmtree(root)
        raise
PY
cd "$(basename "$archive" .tar.gz)"
python3 -m json.tool RELEASE-METADATA.json
install -d "$HOME/.local/bin"
install -m 0755 bin/kapsel "$HOME/.local/bin/kapsel"
export PATH="$HOME/.local/bin:$PATH"
command -v kapsel
kapsel --version
```

Confirm that `package_version`, `rust_target`, `source_revision`, `source_tree`, and `source_dirty`
identify the intended release. A publishable artifact has `source_dirty: false`. Confirm
`kapsel --version` reports the same package version. SHA-256 detects changed bytes; the successful
Sigstore verification appoints the exact publisher workflow but does not prove builder integrity,
source review, dependency safety, or production fitness.

The ordinary binary contains no demonstration pause behavior. The separate
`libexec/kapsel-demo-harness` executable is only for the owned disposable-cluster demonstration.

## Operator and request separation

All file paths below must be absolute, regular, non-symlink files. Required directories must be
absolute, pre-existing, owner-private, and non-symlinked. JSON inputs are bounded and reject
unknown, duplicate, missing, wrong-typed, or trailing fields.

The request-only caller supplies exactly:

```json
{
  "operation_id": "op-001",
  "namespace": "demo",
  "deployment": "agent-api",
  "container": "api",
  "immutable_image_digest": "registry.example/agent-api@sha256:<64-lowercase-hex>"
}
```

The operator separately supplies one exact authorization intent:

```json
{
  "authorization_id": "auth-001",
  "operation_id": "op-001",
  "namespace": "demo",
  "deployment": "agent-api",
  "container": "api",
  "immutable_image_digest": "registry.example/agent-api@sha256:<64-lowercase-hex>"
}
```

Provision its fixed-purpose grant with operator-controlled Ed25519 material:

```sh
kapsel provision-grant \
  --authorization /absolute/authorization.json \
  --signing-seed /absolute/owner.seed \
  --signing-key-id owner-key \
  --output /absolute/grant.bin
```

Expected stdout:

```json
{ "command": "provision-grant", "status": "PROVISIONED" }
```

The operator configuration names the exact authority and private durable locations. Kubeconfig
certificate, key, and token data must be embedded; path references, exec plugins, auth-provider
plugins, ambient kubeconfig, and environment defaults are rejected.

```json
{
  "signed_authorization_grant": "/absolute/grant.bin",
  "authorization_key_id": "owner-key",
  "authorization_public_key": "/absolute/owner.pub",
  "kubeconfig": "/absolute/kubeconfig.yaml",
  "journal": "/absolute/private/journal.sqlite3",
  "receipt_directory": "/absolute/private/receipts",
  "receipt_signing_seed": "/absolute/receipt.seed",
  "receipt_signing_key_id": "receipt-key"
}
```

Run or ordinarily restart the operation with the same request and operator configuration:

```sh
kapsel operate \
  --request /absolute/request.json \
  --operator-config /absolute/operator.json
```

A finalized receiver report has this bounded shape:

```json
{
  "command": "operate",
  "operation_id": "op-001",
  "state": "FINALIZED",
  "result": "SUCCEEDED",
  "target_rejection": null,
  "receipt_file": "kap0038-op-001-<sha256>.receipt",
  "receipt_sha256": "<sha256>"
}
```

Starting the same command again is ordinary recovery. After `apply_started`, recovery observes and
does not blindly issue a second mutation.

## Offline inspection

Inspection requires explicit receipt trust and evaluation time. It performs no network, ambient
clock, Kubernetes, filesystem-discovery, or trust lookup:

```sh
KUBECONFIG=/unavailable HTTPS_PROXY=http://127.0.0.1:1 \
  kapsel inspect \
    --receipt /absolute/private/receipts/result.receipt \
    --trust /absolute/receipt.trust \
    --evaluation-time-unix-s 150
```

Expected trusted prototype status is `INSPECTED`, followed by every signed classifier input, the
recomputed `SUCCEEDED`, `FAILED`, or `UNKNOWN` result, and the fixed non-claims. Structural,
signature, and external-trust failures remain distinct as `STRUCTURE_REJECTED`,
`SIGNATURE_REJECTED`, and `UNTRUSTED_SIGNER`.

## MCP

Start the fixed MCP `2025-11-25` newline-delimited stdio adapter with the same out-of-band operator
configuration. A conventional generic stdio client entry is copyable as:

```json
{
  "mcpServers": {
    "kapsel": {
      "command": "/absolute/kapsel/bin/kapsel",
      "args": ["mcp", "--operator-config", "/absolute/operator.json"]
    }
  }
}
```

Client wrapper field names may vary; the process command and arguments do not. After MCP
initialization, one complete request is:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "kubernetes.set_deployment_image",
    "arguments": {
      "operation_id": "op-001",
      "namespace": "demo",
      "deployment": "agent-api",
      "container": "api",
      "immutable_image_digest": "registry.example/agent-api@sha256:1111111111111111111111111111111111111111111111111111111111111111"
    }
  }
}
```

It advertises exactly `kubernetes.set_deployment_image`. Operator authority, trust, signing
material, credentials, paths, and lifecycle controls never enter tool arguments. MCP completion,
cancellation, or disconnect does not establish receiver success, failure, or that no mutation was
attempted; restart with the same configuration and operation request.

## Owned disposable-kind demonstration

Prerequisites are Docker, `kind` 0.32 or newer, `kubectl` 1.30 or newer, and Python 3.11 or newer.
The demonstration refuses any pre-existing `kind` cluster, creates one uniquely named cluster, and
removes only its own cluster and host workspace.

From the extracted top-level directory:

```sh
./share/kapsel/demo-kind-crash-recovery.sh
```

The final summary distinguishes:

- `apply_started` durably recorded before the provider mutation;
- exact process termination after the returned mutation and after frozen receipt publication;
- restart-only reconciliation with a harness apply count of exactly one;
- `FAILED` only from observed `ProgressDeadlineExceeded` receiver facts;
- finalization from frozen receipt bytes despite rotated receipt settings;
- the temporary receipt path used by offline `INSPECTED` classification; and
- the limit that incomplete or ambiguous bounded observation remains `UNKNOWN`.

The command deletes its unique owned cluster before offline inspection, then removes its private
host workspace on exit. Successful cleanup is explicit. A failed cluster cleanup names the exact
`kind delete cluster --name <owned-name>` retry; a failed workspace cleanup names only the uniquely
created path. The receipt path is intentionally temporary, so copy the receipt during a modified
private run if it must be retained. The demo does not prove exactly-once real-world effects.

## Failure classes and cleanup

Local command failures use fixed exit classes:

| Exit | Class                    | Meaning                                                      |
| ---- | ------------------------ | ------------------------------------------------------------ |
| 2    | `command_input`          | Invalid command grammar, JSON, bounds, or request intent.    |
| 3    | `operator_configuration` | Unsafe or invalid authority, kubeconfig, signing, or paths.  |
| 4    | `operation_failure`      | Durable, Kubernetes, reconciliation, or publication failure. |

Errors never print configured secrets or unbounded provider bodies. `UNKNOWN` is a completed bounded
receiver outcome, not exit class 4.

After evaluation, remove only paths and cluster resources you created:

```sh
rm -f "$HOME/.local/bin/kapsel"
rm -rf /absolute/private/evaluation-directory
kind delete cluster --name <owned-name>  # only if output says its owned cluster remains
```

Receipts and reports may disclose namespaces, Deployment/container names, image digests, operation
identities, Kubernetes UIDs and versions, rollout facts, and key identifiers. Treat them as
sensitive unless intentionally published.
