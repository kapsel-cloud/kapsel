# Operator and inspection commands

This contract defines the operator provisioning and offline inspection CLI. Execution uses the
resident service and its fixed ID-only client/MCP bridge. [Service](service.md), [MCP](mcp.md) and
[effect gateway](effect_gateway.md) own those interfaces and their semantics. [Release](release.md)
owns packaging.

## Command grammar

The Unix executable accepts exactly:

```text
kapsel --help
kapsel --version
kapsel provision-grant --authorization <file> --signing-seed <file> --signing-key-id <id> --output <file>
kapsel provision-snapshot-grant --authorization <file> --kubeconfig <file> --signing-seed <file> --signing-key-id <id> --output <file>
kapsel provision-git-grant --authorization <file> --git-receiver <file> --signing-seed <file> --signing-key-id <id> --output <file>
kapsel inspect --receipt <file> --trust <file> --evaluation-time-unix-s <i64>
               [--receipt-bytes-max <usize>] [--statement-bytes-max <usize>]
               [--trust-bytes-max <usize>] [--text-bytes-max <usize>]
```

`provision-grant` retains legacy canonical grant provisioning; it does not authorize legacy service
execution. `provision-snapshot-grant` reads target UID/resourceVersion through the explicit
kubeconfig before signing grant v2. It does not mutate the receiver. Kubernetes service approval
requires a snapshot grant. Changed intent or target requires another operator decision and identity,
not hidden refresh. See
[operator preparation](../guides/operator.md#provision-authority-and-an-exact-approval).

`provision-git-grant` accepts the six-field Git authorization and bounded receiver material from
[Git preparation](../guides/git_transition.md#operator-preparation). It checks fixed objects and
ancestry before signing, without pushing or admitting work. Git and Kubernetes use separate
purposes.

Help and version accept no additional arguments, read no configuration and contact no service.
Version prints `kapsel <Cargo package version>` and one newline, with no diagnostic, and exits zero.
It identifies the binary, not its qualification or production readiness.

Options appear in any order, exactly once. Unknown or duplicate options, positional values, missing
values and additional arguments are input failures. No environment or ambient defaults are used.
Named inputs must be regular non-symlink files. Their owned limits are checked before reading:
operator intent and kubeconfig at most 16 KiB, service document at most 160 KiB, seeds/public keys
exactly 32 raw bytes, grants at most 4 KiB, receipts at most 16 KiB and trust at most 1 KiB. Output
grants are created owner-only and never replace an existing path.

## Prepare and validate service configuration

These operator-only commands write or validate the existing version-1 service document. They do not
appoint trust from a grant, provision credentials, publish configuration or open history.

```text
kapsel prepare-service-config --authorization-key <id> <raw-public-key-file>
    --approval <label> <signed-grant-file> --receipt-signing-key-id <id> --output <new-file>
kapsel validate-service-config --operator-config <file>
```

Repeat `--authorization-key` for up to 128 appointed keys and `--approval` for up to 32 snapshot
grants. Both may be omitted for an empty catalog. Signer and output options are required once.
Labels use printable ASCII with a 128-byte bound. Preparation authenticates the complete document
before writing a new private file. Validation applies the same parser/approval/trust checks.

Success reports `PREPARED` or `VALIDATED_STATIC`. Static validation is not filesystem custody,
retained-identity compatibility, credentials, receiver availability or execution readiness. Cold
publication still performs read-only history/custody checks under lifecycle exclusion. An I/O
failure can leave an incomplete new preparation output; inspect it and choose a new destination.

## Fixed JSON inputs

Intent is a UTF-8 object with exactly these string fields. Unknown, duplicate, missing, wrong-type
and trailing content is rejected. The [gateway grammar](kubernetes_effect.md#authorized-input)
bounds values.

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

Kubeconfig must name its selected current context and embed credentials and certificate data.
Credential-file references, auth-provider and exec plugins are rejected. No environment lookup
supplies kubeconfig, context, credentials or proxy. The shared provisioning/service client disables
server-response mutation retries and bounds HTTP bodies to 2 MiB before collection or parsing,
including content-length, chunked and close-delimited responses. Authority and seeds never enter
caller input, history, receipts or diagnostics.

## Output and diagnostics

Each invocation writes one newline-terminated JSON object and at most one bounded diagnostic.
Provisioning stdout and stderr are at most 4 KiB; classifier-complete inspection stdout is at most
64 KiB. There are no input bytes, credentials, seeds, provider bodies or ambient values in errors.

Provisioning success is `{"command":"provision-grant","status":"PROVISIONED"}` (with the selected
provisioning command name). Inspection retains its existing purpose-specific projection: operation
and authorization identities, signer and grant digest, approved tuple, attempt/observed targets,
receiver facts, classifier result and non-claims. Kubernetes retains UID/resourceVersion,
image/marker, generations, replicas and rollout-condition fields. Git retains commits, ref,
acknowledgement, observed ref and attribution. Optional values remain JSON null.

`STRUCTURE_REJECTED` and `SIGNATURE_REJECTED` expose no statement. `UNTRUSTED_SIGNER` exposes
authenticated statement facts without appointing trust. `INSPECTED` is not `VERIFIED`. Inspection
uses named bytes, explicit purpose-separated trust, evaluation time and limits. It constructs no
receiver client and performs no discovery or network I/O.

A failed invocation reports the selected command, or `kapsel` for an unidentified/retired command:

```text
{"command":"inspect","status":"ERROR","error_class":"command_input"}
Kapsel command failure: command_input
```

## Exit classes

| Exit | Class                    | Meaning                                                              |
| ---- | ------------------------ | -------------------------------------------------------------------- |
| 0    | completed                | Provisioning, static validation or any bounded inspection status.    |
| 2    | `command_input`          | Invalid grammar, JSON, numeric value, bound or authorization intent. |
| 3    | `operator_configuration` | Missing/unsafe operator input, signing material or output path.      |
| 4    | `operation_failure`      | Inspection/output serialization failure.                             |

An exit status is not receiver evidence. [Scope](../scope.md) defines support limits.
