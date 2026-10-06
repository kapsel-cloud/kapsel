# Signed evidence and inspection

This reference defines Kubernetes grant/receipt encodings, trust, and offline inspection. Snapshot
extensions are defined in [Kubernetes approval](kubernetes_effect.md#exact-snapshot-approval). Git
uses separate [grant and receipt statements](git_effect.md#signed-grant-and-receipt-versions) with
the same ordered-record and signature mechanisms.

## Kubernetes authorization encoding

Kapsel accepts only a canonical signed grant for the exact operation parameters. Grant v1 uses the
fixed purpose `kapsel.kap0038.kubernetes-set-deployment-image-grant.v1`. The gateway verifies it
against an application-configured key identity and Ed25519 verifying key. Trust is supplied out of
band; caller input cannot choose it. Grant parsing is bounded and canonical. Wrong purpose, key
identity, signature, tuple, or grammar fails before request persistence or Kubernetes calls.

| Document        | Magic                                     |
| --------------- | ----------------------------------------- |
| Grant statement | `KAPSEL-KAP0038-K8S-GRANT-STATEMENT-V1\0` |
| Signed grant    | `KAPSEL-KAP0038-K8S-GRANT-V1\0`           |

The grant statement contains exactly the authorization identity, operation identity, namespace,
Deployment, container, and immutable image digest in that order. The signed grant contains exactly
the fixed purpose, signing-key identity, statement bytes, and Ed25519 signature. The signing input
is the exact byte string `purpose`, one zero byte, then the statement bytes.

The canonical grant-v1 known answer is
[`vectors/effect-gateway-grant.hex`](../../vectors/effect-gateway-grant.hex). Its fixed
authorization, seed and signer identity belong to the owner test. Retained v1 grants keep their
original meaning; they appoint no trust and add no expiry or revocation semantics. Service execution
requires the [snapshot v2 grant](kubernetes_effect.md#exact-snapshot-approval), not v1.

## Receipt and inspection

Kapsel writes one signed, portable receipt and supports offline inspection under separately provided
trust, explicit evaluation time, and explicit resource limits. Formats are capability-specific.
Inspection preserves original bytes and cannot appoint receipt-carried trust. A later format must
use a new identifier and explicit migration/inspection policy rather than reuse or rename these
bytes. The canonical receipt-v2, statement-v2 and trust-v2 known answers are
[`vectors/effect-gateway-receipt.hex`](../../vectors/effect-gateway-receipt.hex),
[`vectors/effect-gateway-statement.hex`](../../vectors/effect-gateway-statement.hex), and
[`vectors/effect-gateway-trust.hex`](../../vectors/effect-gateway-trust.hex).

The following tables define legacy Kubernetes receipt v2. Snapshot receipt v3 retains fields 1–27
and adds approved UID/version as fields 28–29, with distinct magic and purpose as specified in the
[Kubernetes contract](kubernetes_effect.md#exact-snapshot-approval).

The receipt bytes are fixed-order length-delimited records with these magic prefixes:

| Document  | Magic                               |
| --------- | ----------------------------------- |
| Statement | `KAPSEL-KAP0038-K8S-STATEMENT-V2\0` |
| Receipt   | `KAPSEL-KAP0038-K8S-RECEIPT-V2\0`   |
| Trust     | `KAPSEL-KAP0038-K8S-TRUST-V2\0`     |

A record is encoded as a one-byte field number, a four-byte big-endian length, and that many value
bytes. Fields must appear exactly once in strictly increasing field-number order. Unknown,
duplicate, missing, reordered, trailing, or truncated records fail closed. Text is UTF-8 ASCII in
the grammar and length stated here. Integers are signed or unsigned big-endian fixed-width values as
owned by the durable facts. Canonical receipt bytes are the original parsed bytes; inspection never
re-encodes and verifies a different representation.

The statement is built only from already frozen durable facts and contains exactly:

| Field | Meaning                                                             |
| ----- | ------------------------------------------------------------------- |
| 1     | operation identity                                                  |
| 2     | authorization identity                                              |
| 3     | authorization grant signing-key identity                            |
| 4     | SHA-256 digest of the exact signed authorization grant bytes        |
| 5     | Kubernetes namespace                                                |
| 6     | Deployment name                                                     |
| 7     | container name                                                      |
| 8     | requested immutable image digest                                    |
| 9     | stored write strategy identity, `conditional-strategic-merge-patch` |
| 10    | target Deployment UID                                               |
| 11    | target resource version                                             |
| 12    | receiver Deployment UID, or empty when not observed                 |
| 13    | observed image digest, or empty when not observed                   |
| 14    | observed operation marker, or empty when not observed               |
| 15    | current generation, or `-1` when not observed                       |
| 16    | requested generation, or `-1` when not established                  |
| 17    | observed generation, or `-1` when not observed                      |
| 18    | observed resource version, or empty when not observed               |
| 19    | desired replica count, or `-1` when not observed                    |
| 20    | updated replica count, or `-1` when not observed                    |
| 21    | available replica count, or `-1` when not observed                  |
| 22    | unavailable replica count, or `-1` when not observed                |
| 23    | rollout condition type, or empty when not observed                  |
| 24    | rollout condition status, or empty when not observed                |
| 25    | rollout condition reason, or empty when not observed                |
| 26    | result, one of `SUCCEEDED`, `FAILED`, or `UNKNOWN`                  |
| 27    | non-claims token list                                               |

The inspector reconstructs the bounded request, apply identity, and receiver observation from these
fields and runs the same pure classifier. A signed statement is structurally rejected when its
stated result differs from the recomputed result. `INSPECTED` therefore authenticates both the
classifier inputs and their deterministic effect-gateway classification; it still does not establish
that Kubernetes reported truthful facts.

The non-claims field is the exact ASCII token list
`no-exactly-once;no-causation;no-kubernetes-truth;no-complete-capture;no-witnessing;not-production`.
It is a signed statement field so report consumers see the implementation's limits even when the
report is separated from the owner document. The statement has no timestamps, no Kubernetes response
body, no secret, no policy, no package identifier, no verifier profile, and no generic capability
field.

A receipt contains exactly:

| Field | Meaning                                                        |
| ----- | -------------------------------------------------------------- |
| 1     | signing purpose, `kapsel.kap0038.kubernetes-effect-receipt.v2` |
| 2     | signing key identifier                                         |
| 3     | statement bytes as encoded above                               |
| 4     | Ed25519 signature over the receipt signing input               |

The receipt signing input is the exact byte string `purpose`, then one zero byte, then the statement
bytes.

The key identifier is 1–128 ASCII bytes containing only letters, digits, `.`, `_`, `:`, or `-`.
Signing uses Ed25519 with a 32-byte verifying key supplied by external trust. The receipt does not
carry trust anchors, fetch keys, appoint authority, or define an issuer policy.

A trust document contains exactly:

| Field | Meaning                                            |
| ----- | -------------------------------------------------- |
| 1     | trusted signing key identifier                     |
| 2     | 32-byte Ed25519 verifying key                      |
| 3     | accepted signing purpose                           |
| 4     | inclusive not-before evaluation time, Unix seconds |
| 5     | exclusive not-after evaluation time, Unix seconds  |

Inspection takes receipt bytes, trust bytes, explicit evaluation time, and explicit limits. It
performs no network, filesystem discovery, ambient clock read, environment lookup, or trust lookup.
Evaluation time must be within the trust interval, the trust purpose must equal the receipt purpose,
and the trust key identifier must equal the receipt key identifier before the signature result can
be reported as trusted. Weak or malformed keys, bad signatures, wrong purpose, wrong key, and time
window failures all produce bounded reports or typed failures without panics.

Resource limits are part of the public inspection contract: receipt bytes are at most 16 KiB,
statement bytes are at most 8 KiB, trust bytes are at most 1 KiB, and any text field is at most 512
bytes unless an earlier grammar bound is smaller. The implementation may accept lower
caller-supplied limits but must not exceed these maxima.

Offline inspection reports an aggregate status using only this vocabulary:

| Status               | Meaning                                                                                              |
| -------------------- | ---------------------------------------------------------------------------------------------------- |
| `STRUCTURE_REJECTED` | Receipt, statement, or trust bytes did not parse within the limits.                                  |
| `SIGNATURE_REJECTED` | Structure parsed, but signature bytes did not authenticate.                                          |
| `UNTRUSTED_SIGNER`   | Signature authenticated, but external trust did not accept the key, purpose, or time.                |
| `INSPECTED`          | Structure, signature, and supplied trust matched; the report states the frozen facts and non-claims. |

Inspected and authenticated-but-untrusted reports disclose the signed fixed non-claims with the
parsed statement. Inspection must never report `VERIFIED`. `INSPECTED` means only that the disclosed
bytes were signed by a supplied trusted key for this purpose at the explicit evaluation time. It
does not mean the receiver facts were true, causal, complete, witnessed, policy-authorized, or safe.

The fixed client exports to an explicit caller-selected new file and rejects an existing path. The
[service contract](service.md#fixed-service-client) defines export custody. The service MCP bridge
returns original bytes without choosing or exporting a filename. The stored receipt digest is the
SHA-256 of the exact SQLite-committed receipt bytes, whether exported or not, rather than decoded
facts or report text. Export is separate from
[receipt completion](effect_gateway.md#sqlite-owned-receipt-completion).
