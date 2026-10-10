//! Deterministic public-wire fixtures, not production signing or decoder interfaces.

use ed25519_dalek::{Signer, SigningKey};
use kapsel::{ApprovedTarget, ExactAuthorization, ReceiptTrust, GIT_RECEIPT_PURPOSE};
use kapsel_authority::{sign_authorization_grant, sign_git_ref_grant, GitRefAuthorization};

fn record(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

/// Assembles fixed-order fixture records without production acceptance checks.
///
/// # Panics
///
/// Panics if a fixture length exceeds u32 or its record count exceeds u8.
pub fn records(magic: &[u8], values: &[&[u8]]) -> Vec<u8> {
    let mut bytes = magic.to_vec();
    for (index, value) in values.iter().enumerate() {
        bytes.extend(record(u8::try_from(index + 1).unwrap(), value));
    }
    bytes
}

fn envelope(magic: &[u8], purpose: &[u8], statement: &[u8]) -> Vec<u8> {
    let mut signature_message = purpose.to_vec();
    signature_message.push(0);
    signature_message.extend_from_slice(statement);
    let signature = SigningKey::from_bytes(&[7; 32])
        .sign(&signature_message)
        .to_bytes();

    records(magic, &[purpose, b"signer", statement, &signature])
}

/// Borrows at most 40 framed fixture values from at most 16 KiB, or returns None.
///
/// This reader does not validate tags or purpose and is not an acceptance oracle.
pub fn fields(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    if bytes.len() > 16 * 1024 {
        return None;
    }

    let mut offset = bytes.iter().position(|byte| *byte == 0)? + 1;
    let mut values = Vec::new();
    while offset < bytes.len() && values.len() < 40 {
        let header = bytes.get(offset..offset.checked_add(5)?)?;
        let value_bytes_len = u32::from_be_bytes(header[1..].try_into().ok()?) as usize;
        offset += 5;
        let value_end = offset.checked_add(value_bytes_len)?;
        values.push(bytes.get(offset..value_end)?);
        offset = value_end;
    }

    (offset == bytes.len()).then_some(values)
}

/// Re-signs one bounded four-record fixture envelope under the synthetic key.
///
/// Returns None if fixture framing cannot locate a 64-byte signature.
pub fn reauthenticate(bytes: &[u8]) -> Option<Vec<u8>> {
    let values = fields(bytes)?;
    if values.len() != 4 || values[3].len() != 64 {
        return None;
    }

    let mut signature_message = values[0].to_vec();
    signature_message.push(0);
    signature_message.extend_from_slice(values[2]);
    let signature = SigningKey::from_bytes(&[7; 32])
        .sign(&signature_message)
        .to_bytes();

    let signature_start = bytes.len().checked_sub(64)?;
    let mut reauthenticated = bytes.to_vec();
    reauthenticated[signature_start..].copy_from_slice(&signature);
    Some(reauthenticated)
}

/// Encodes the maintained receipt/trust split fixture.
///
/// # Panics
///
/// Panics if the receipt length exceeds u32.
pub fn pair(receipt: &[u8], trust: &[u8]) -> Vec<u8> {
    let mut input = u32::try_from(receipt.len()).unwrap().to_be_bytes().to_vec();
    input.extend_from_slice(receipt);
    input.extend_from_slice(trust);
    input
}

fn decode_fixture_hex(text: &str) -> Vec<u8> {
    let (pairs, remainder) = text.trim().as_bytes().as_chunks::<2>();
    assert!(
        remainder.is_empty(),
        "maintained hex fixture has complete bytes"
    );
    pairs
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("maintained hex fixture is ASCII");
            u8::from_str_radix(text, 16).expect("maintained hex fixture contains hex digits")
        })
        .collect()
}

/// Signs a fixture with unknown acknowledgement and the supplied result token.
///
/// # Panics
///
/// Panics if the supplied fixture result exceeds the u32 record-length range.
pub fn git_receipt(result: &[u8]) -> Vec<u8> {
    let statement = records(
        b"KAPSEL-GIT-REF-STATEMENT-V1\0",
        &[
            b"operation",
            b"approval",
            b"owner",
            &[b'c'; 64],
            b"repository",
            b"refs/heads/approved",
            &[b'a'; 40],
            &[b'b'; 40],
            b"git-exact-lease",
            b"unknown",
            b"commit",
            &[b'b'; 40],
            b"not_established",
            result,
            concat!(
                "no-hook-delivery;no-ci;no-deployment;",
                "no-complete-capture;no-witnessing;not-production",
            )
            .as_bytes(),
        ],
    );
    envelope(
        b"KAPSEL-GIT-REF-RECEIPT-V1\0",
        GIT_RECEIPT_PURPOSE.as_bytes(),
        &statement,
    )
}

/// Encodes valid synthetic Git receipt trust for the interval [100, 200).
pub fn git_trust() -> Vec<u8> {
    ReceiptTrust {
        key_id: "signer".into(),
        public_key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        accepted_purpose: GIT_RECEIPT_PURPOSE.into(),
        not_before_unix_s: 100,
        not_after_unix_s: 200,
    }
    .encode()
    .unwrap()
}

/// Builds deterministic valid and invalid seeds for one maintained target.
///
/// # Panics
///
/// Panics on an unknown target or an invalid maintained fixture.
pub fn seeds(target: &str) -> Vec<(String, Vec<u8>)> {
    let legacy_receipt =
        decode_fixture_hex(include_str!("../../vectors/effect-gateway-receipt.hex"));
    let legacy_trust = decode_fixture_hex(include_str!("../../vectors/effect-gateway-trust.hex"));
    let git_receipt = git_receipt(b"UNKNOWN");
    let git_trust = git_trust();
    let mut seeds = Vec::new();
    match target {
        "inspect_receipt" | "inspect_git_receipt" => {
            let (receipt, trust) = if target == "inspect_receipt" {
                (legacy_receipt.clone(), legacy_trust.clone())
            } else {
                (git_receipt.clone(), git_trust.clone())
            };
            seeds.push(("canonical-receipt-and-trust".into(), pair(&receipt, &trust)));
            seeds.push((
                "cross-purpose".into(),
                if target == "inspect_receipt" {
                    pair(&git_receipt, &git_trust)
                } else {
                    pair(&legacy_receipt, &legacy_trust)
                },
            ));
            if target == "inspect_git_receipt" {
                seeds.push((
                    "signed-inconsistent-result".into(),
                    pair(&self::git_receipt(b"SUCCEEDED"), &trust),
                ));
            } else {
                let statement =
                    decode_fixture_hex(include_str!("../../vectors/effect-gateway-statement.hex"));
                let mut values = fields(&statement).unwrap();
                values[25] = b"SUCCEEDED";
                let inconsistent = records(b"KAPSEL-KAP0038-K8S-STATEMENT-V2\0", &values);
                let purpose = "kapsel.kap0038.kubernetes-effect-receipt.v2";
                let signed = envelope(
                    b"KAPSEL-KAP0038-K8S-RECEIPT-V2\0",
                    purpose.as_bytes(),
                    &inconsistent,
                );
                let mut trusted = ReceiptTrust {
                    key_id: "signer".into(),
                    public_key: crate::fixture_trust().public_key,
                    accepted_purpose: purpose.into(),
                    not_before_unix_s: 100,
                    not_after_unix_s: 200,
                };
                seeds.push((
                    "signed-inconsistent-result".into(),
                    pair(&signed, &trusted.encode().unwrap()),
                ));

                let mut snapshot_fields = fields(&statement).unwrap();
                let approved = [snapshot_fields[9], snapshot_fields[10]];
                snapshot_fields.extend(approved);
                let snapshot_statement =
                    records(b"KAPSEL-KAP0038-K8S-STATEMENT-V3\0", &snapshot_fields);
                trusted.accepted_purpose = "kapsel.kap0038.kubernetes-effect-receipt.v3".into();
                let signed_snapshot = envelope(
                    b"KAPSEL-KAP0038-K8S-RECEIPT-V3\0",
                    trusted.accepted_purpose.as_bytes(),
                    &snapshot_statement,
                );
                seeds.push((
                    "canonical-snapshot".into(),
                    pair(&signed_snapshot, &trusted.encode().unwrap()),
                ));
            }
            let original = fields(&receipt).unwrap();
            let purpose = std::str::from_utf8(original[0]).unwrap();
            let signed_trust = ReceiptTrust {
                key_id: "signer".into(),
                public_key: crate::fixture_trust().public_key,
                accepted_purpose: purpose.into(),
                not_before_unix_s: 100,
                not_after_unix_s: 200,
            }
            .encode()
            .unwrap();
            let magic_end = receipt.iter().position(|byte| *byte == 0).unwrap() + 1;
            for (name, changed) in binary_mutations(original[2]) {
                let signed = envelope(&receipt[..magic_end], original[0], &changed);
                seeds.push((
                    format!("signed-statement-{name}"),
                    pair(&signed, &signed_trust),
                ));
            }
            let mut damaged_signature = receipt.clone();
            *damaged_signature.last_mut().unwrap() ^= 1;
            seeds.push(("damaged-signature".into(), pair(&damaged_signature, &trust)));
            for (name, changed) in binary_mutations(&receipt) {
                seeds.push((name, pair(&changed, &trust)));
            }
            seeds.push(("receipt-over-limit".into(), pair(&vec![0; 16385], &trust)));
            seeds.push(("trust-over-limit".into(), pair(&receipt, &vec![0; 1025])));
        },
        "verify_kubernetes_grant" | "verify_git_grant" => {
            let authorization = ExactAuthorization {
                approved_target: None,
                authorization_id: "approval".into(),
                operation_id: "operation".into(),
                namespace: "default".into(),
                deployment: "web".into(),
                container: "app".into(),
                immutable_image_digest: format!("registry.example/app@sha256:{}", "a".repeat(64)),
            };
            let legacy = sign_authorization_grant(&authorization, &[7; 32], "owner").unwrap();

            let mut snapshot_authorization = authorization;
            snapshot_authorization.approved_target = Some(ApprovedTarget {
                uid: "uid-1".into(),
                resource_version: "opaque:1".into(),
            });
            let snapshot_grant =
                sign_authorization_grant(&snapshot_authorization, &[7; 32], "owner").unwrap();
            let git = sign_git_ref_grant(
                &GitRefAuthorization {
                    authorization_id: "approval".into(),
                    operation_id: "operation".into(),
                    repository_id: "repository".into(),
                    reference: "refs/heads/approved".into(),
                    old_commit: "a".repeat(40),
                    new_commit: "b".repeat(40),
                },
                &[7; 32],
                "owner",
            )
            .unwrap();
            let canonical = if target == "verify_git_grant" {
                git.clone()
            } else {
                snapshot_grant.clone()
            };
            seeds.push(("canonical".into(), canonical.clone()));
            seeds.push(("legacy-kubernetes".into(), legacy));
            seeds.push(("snapshot-kubernetes".into(), snapshot_grant));
            seeds.push(("git-purpose".into(), git));
            let original = fields(&canonical).unwrap();
            let magic_end = canonical.iter().position(|byte| *byte == 0).unwrap() + 1;
            for (name, changed) in binary_mutations(original[2]) {
                let unsigned = records(
                    &canonical[..magic_end],
                    &[original[0], b"owner", &changed, &[0; 64]],
                );
                seeds.push((
                    format!("signed-statement-{name}"),
                    reauthenticate(&unsigned).unwrap(),
                ));
            }
            seeds.extend(binary_mutations(&canonical));
            seeds.push(("over-limit".into(), vec![0; 4097]));
            seeds.push((
                "exact-legacy-vector".into(),
                decode_fixture_hex(include_str!("../../vectors/effect-gateway-grant.hex")),
            ));
        },
        "service_document" => {
            let canonical = concat!(
                r#"{"service_configuration_version":1,"authorization_keys":[],"#,
                r#""approvals":[],"receipt_signing_key_id":"signer"}"#,
            )
            .as_bytes()
            .to_vec();
            seeds.push(("canonical".into(), canonical.clone()));
            let mut at_limit = canonical.clone();
            at_limit.resize(160 * 1024, b' ');
            seeds.push(("canonical-byte-limit".into(), at_limit));
            let text = std::str::from_utf8(&canonical).unwrap();
            let approval = r#"{"label":"fixture","signed_grant_hex":"00"}"#;
            let public_key = crate::fixture_trust()
                .public_key
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let key = format!(r#"{{"key_id":"owner","public_key_hex":"{public_key}"}}"#);
            let legal_counts = text
                .replace(
                    "\"approvals\":[]",
                    &format!("\"approvals\":[{}]", [approval; 32].join(",")),
                )
                .replace(
                    "\"authorization_keys\":[]",
                    &format!(
                        "\"authorization_keys\":[{}]",
                        vec![key.clone(); 128].join(",")
                    ),
                );
            seeds.push(("canonical-count-limits".into(), legal_counts.into_bytes()));
            for (name, changed) in [
                (
                    "duplicate",
                    text.replace(
                        "\"service_configuration_version\":1",
                        "\"service_configuration_version\":1,\"service_configuration_version\":1",
                    ),
                ),
                (
                    "unknown",
                    text.replace("\"approvals\":[]", "\"unknown\":0,\"approvals\":[]"),
                ),
                (
                    "approval-over-count",
                    text.replace(
                        "\"approvals\":[]",
                        &format!("\"approvals\":[{}]", [approval; 33].join(",")),
                    ),
                ),
                (
                    "key-over-count",
                    text.replace(
                        "\"authorization_keys\":[]",
                        &format!("\"authorization_keys\":[{}]", vec![key; 129].join(",")),
                    ),
                ),
                (
                    "uppercase-hex",
                    text.replace(
                        "\"approvals\":[]",
                        r#""approvals":[{"label":"fixture","signed_grant_hex":"FF"}]"#,
                    ),
                ),
                ("positional", "[1,[],[],\"signer\"]".into()),
            ] {
                seeds.push((name.into(), changed.into_bytes()));
            }
            let mut over = canonical.clone();
            over.resize(160 * 1024 + 1, b' ');
            seeds.push(("over-limit".into(), over));
            let mut invalid_utf8 = canonical.clone();
            invalid_utf8[5] = 255;
            seeds.push(("invalid-utf8".into(), invalid_utf8));
            seeds.push((
                "truncated".into(),
                canonical[..canonical.len() - 1].to_vec(),
            ));
            let mut trailing = canonical;
            trailing.push(b'x');
            seeds.push(("trailing".into(), trailing));
        },
        _ => panic!("unknown fixture target"),
    }
    seeds
}

fn binary_mutations(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let first_record_start = bytes.iter().position(|byte| *byte == 0).unwrap() + 1;
    let first_value_bytes_len = u32::from_be_bytes(
        bytes[first_record_start + 1..first_record_start + 5]
            .try_into()
            .unwrap(),
    ) as usize;
    let first_record_end = first_record_start + 5 + first_value_bytes_len;

    let mut trailing = bytes.to_vec();
    trailing.push(0);
    let mut duplicate = bytes[..first_record_end].to_vec();
    duplicate.extend_from_slice(&bytes[first_record_start..]);
    let mut unknown = bytes.to_vec();
    unknown[first_record_start] = 255;
    let mut reordered = bytes.to_vec();
    reordered[first_record_start] = 2;
    let mut overflowing_length = bytes.to_vec();
    overflowing_length[first_record_start + 1..first_record_start + 5].fill(255);
    let mut invalid_utf8 = bytes.to_vec();
    invalid_utf8[first_record_start + 5] = 255;

    vec![
        ("trailing".into(), trailing),
        ("duplicate".into(), duplicate),
        ("unknown".into(), unknown),
        ("reordered".into(), reordered),
        ("length-overflow".into(), overflowing_length),
        ("invalid-utf8".into(), invalid_utf8),
        ("truncated".into(), bytes[..bytes.len() - 1].to_vec()),
    ]
}
