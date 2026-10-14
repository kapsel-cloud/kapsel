# Signed known answers

These fixed bytes test the [evidence formats](../docs/reference/evidence_formats.md) and
[snapshot extensions](../docs/reference/kubernetes_effect.md#snapshot-grant-and-receipt-encoding).
Tests check both directions: fixed bytes to literal fields, and specified fields to fixed bytes.
Encoder/decoder agreement alone is not the oracle. Do not automatically replace these files after an
encoder change.

## Snapshot grant v2 and receipt v3

`snapshot-grant-v2.hex`, `snapshot-statement-v3.hex`, `snapshot-receipt-v3.hex`, and
`snapshot-trust-v3.hex` were assembled independently from the published ordered-field tables.
OpenSSL 4.0.3 supplied Ed25519 signatures, not Kapsel's encoder or signer. The synthetic grant seed
contains 32 bytes of `07`; the receipt seed contains 32 bytes of `09`. These are test keys, not
operator material.

The authority and receipt owner tests specify every expected field. The grant binds
`snapshot-auth-17` and `snapshot-op-23` to `approved-uid-31` and the opaque version `opaque:0047`.
The receipt retains that approval and attempt pair, but reports version `observed:0067`.
Current/requested/observed generations are 53/59/61; desired/updated/available/unavailable replicas
are 3/5/7/11. Condition fields are explicitly absent. The expected result is `UNKNOWN`, not a
classification computed by the fixture builder. Trust appoints only the v3 purpose during
`[101, 211)`; the tests exercise both time edges and legacy-purpose rejection.

The grant SHA-256 is `de65cf5b10d5f4ed0477f15b4d4d6a31f829fb31d9deb689493734784b863fa5`.
`snapshot-receipt-v3.sha256` pins the digest of the complete signed receipt bytes.
