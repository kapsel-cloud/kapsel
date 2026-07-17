# Evaluate Kapsel 0.1.0

This guide evaluates the stable `0.1.0` `x86_64-unknown-linux-gnu` artifact for the fixed
`kubernetes.set_deployment_image` experiment. It is not production guidance or a compatibility
promise.

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

## Verify and install

The sole release target is x86-64 GNU/Linux, validated in Debian 12. From the directory containing
the archive and adjacent checksum:

```sh
archive=kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz
sha256sum --check "$archive.sha256"
python3 - "$archive" <<'PY'
import pathlib, shutil, sys, tarfile
archive = pathlib.Path(sys.argv[1])
if not archive.is_file() or archive.stat().st_size > 32 * 1024 * 1024:
    raise RuntimeError("release archive exceeds its compressed bound")
basename = archive.name.removesuffix(".tar.gz")
if pathlib.Path(basename).exists():
    raise RuntimeError("release extraction destination already exists")
expected = {
    f"{basename}/", f"{basename}/bin/", f"{basename}/bin/kapsel",
    f"{basename}/libexec/", f"{basename}/libexec/kapsel-demo-harness",
    f"{basename}/share/", f"{basename}/share/kapsel/",
    f"{basename}/share/kapsel/demo-kind-crash-recovery.sh",
    f"{basename}/share/kapsel/kap0038-trust.hex", f"{basename}/share/doc/",
    f"{basename}/share/doc/kapsel/", f"{basename}/share/doc/kapsel/EVALUATOR.md",
    f"{basename}/CHANGELOG.md", f"{basename}/LICENSE",
    f"{basename}/RELEASE-METADATA.json",
}
with tarfile.open(archive, "r:gz") as release:
    members = release.getmembers()
    names = {member.name + ("/" if member.isdir() else "") for member in members}
    if names != expected:
        raise RuntimeError("unexpected release archive layout")
    if sum(member.size for member in members if member.isfile()) > 64 * 1024 * 1024:
        raise RuntimeError("release archive exceeds its expanded bound")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise RuntimeError("unsafe archive path")
        if not (member.isdir() or member.isfile()) or member.size > 32 * 1024 * 1024:
            raise RuntimeError("links, special entries, or oversized files are forbidden")
        expected_mode = 0o755 if member.isdir() or member.name.endswith(
            ("/kapsel", "/kapsel-demo-harness", ".sh")
        ) else 0o644
        if member.mode != expected_mode:
            raise RuntimeError("unexpected release archive mode")
        target = pathlib.Path(*path.parts)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            source = release.extractfile(member)
            if source is None:
                raise RuntimeError("release file could not be read")
            with target.open("xb") as output:
                shutil.copyfileobj(source, output)
        target.chmod(member.mode)
PY
cd "$(basename "$archive" .tar.gz)"
python3 -m json.tool RELEASE-METADATA.json
install -d "$HOME/.local/bin"
install -m 0755 bin/kapsel "$HOME/.local/bin/kapsel"
export PATH="$HOME/.local/bin:$PATH"
command -v kapsel
```

Confirm that `package_version`, `rust_target`, `source_revision`, and `source_dirty` identify the
intended release. A publishable artifact has `source_dirty: false`. SHA-256 detects changed bytes;
it does not authenticate a publisher.

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
configuration:

```sh
kapsel mcp --operator-config /absolute/operator.json
```

It advertises exactly `kubernetes.set_deployment_image`. Tool input is the same five-field request
object above. Operator authority never enters the tool schema. MCP completion, cancellation, or
disconnect does not establish receiver success, failure, or that no mutation was attempted; restart
with the same configuration and operation request.

## Owned disposable-kind demonstration

Prerequisites are Docker, `kind` 0.32 or newer, `kubectl` 1.30 or newer, and Python 3.11 or newer.
The demonstration refuses any pre-existing `kind` cluster, creates one uniquely named cluster, and
removes only its own cluster and host workspace.

From the extracted top-level directory:

```sh
KAPSEL_DEMO_EXECUTABLE="$PWD/libexec/kapsel-demo-harness" \
KAPSEL_DEMO_ASSET_DIRECTORY="$PWD/share/kapsel" \
  "$PWD/share/kapsel/demo-kind-crash-recovery.sh"
```

The demo proves a healthy `SUCCEEDED` rollout, one failed-image mutation request, process
termination at both owned crash seams, restart without a blind second mutation, `FAILED` only from
`ProgressDeadlineExceeded`, frozen receipt bytes under rotated settings, offline `INSPECTED`
classification, and ownership-safe cleanup. It does not prove exactly-once real-world effects.

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
kind delete cluster --name <owned-name>  # only if your interrupted demo left its named cluster
```

Receipts and reports may disclose namespaces, Deployment/container names, image digests, operation
identities, Kubernetes UIDs and versions, rollout facts, and key identifiers. Treat them as
sensitive unless intentionally published.
