//! Offline hostile-input drivers; no production authority or execution seams.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use kapsel::{
    inspect_git_receipt, inspect_receipt, parse_service_operator_document, InspectionLimits,
    InspectionStatus, ReceiptTrust,
};
use kapsel_authority::{
    sign_authorization_grant, sign_git_ref_grant, verify_authorization_grant, verify_git_ref_grant,
    AuthorizationTrust,
};

/// Deterministic synthetic inputs shared by targets, corpus tests and examples.
pub mod fixtures;

/// Names of the maintained production-decoder targets.
pub const TARGETS: [&str; 5] = [
    "inspect_receipt",
    "inspect_git_receipt",
    "verify_kubernetes_grant",
    "verify_git_grant",
    "service_document",
];

/// Appoints the synthetic grant signer explicitly, without ambient key discovery.
pub fn fixture_trust() -> AuthorizationTrust {
    AuthorizationTrust {
        key_id: "owner".into(),
        public_key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    }
}

/// Splits at most 17 KiB plus framing/sentinel bytes into receipt and trust slices.
///
/// Returns None for absent framing or an oversized input. The original split encoding is retained.
pub fn receipt_documents(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.len() > 17 * 1024 + 5 {
        return None;
    }

    let selector: [u8; 4] = input.get(..4)?.try_into().ok()?;
    let documents = &input[4..];
    let split = u32::from_be_bytes(selector) as usize % (documents.len() + 1);
    Some(documents.split_at(split))
}

/// Exercises one receipt inspector with explicit trust, time and bounds, without I/O.
///
/// # Panics
///
/// Panics when inspection violates a checked contract or an inspected fixture cannot be decoded.
pub fn receipt(input: &[u8], git: bool) {
    let Some((bytes, trust)) = receipt_documents(input) else {
        return;
    };
    check_receipt(bytes, trust, git);
    if let Some(signed) = fixtures::reauthenticate(bytes) {
        check_receipt(&signed, trust, git);
    }
}

fn check_receipt(bytes: &[u8], trust: &[u8], git: bool) {
    let inspect = |bytes: &[u8], trust: &[u8], time, limits| {
        if git {
            inspect_git_receipt(bytes, trust, time, limits).status()
        } else {
            inspect_receipt(bytes, trust, time, limits).status()
        }
    };
    let limits = InspectionLimits::default();
    let status = inspect(bytes, trust, 150, limits);

    let receipt_byte_limit = InspectionLimits {
        receipt_bytes_max: bytes.len().saturating_sub(1).clamp(1, 16 * 1024),
        ..limits
    };
    if bytes.len() > receipt_byte_limit.receipt_bytes_max {
        assert_eq!(
            inspect(bytes, trust, 150, receipt_byte_limit),
            InspectionStatus::StructureRejected,
            "receipt byte limit"
        );
    }

    let trust_byte_limit = InspectionLimits {
        trust_bytes_max: trust.len().saturating_sub(1).clamp(1, 1024),
        ..limits
    };
    if trust.len() > trust_byte_limit.trust_bytes_max {
        assert_eq!(
            inspect(bytes, trust, 150, trust_byte_limit),
            InspectionStatus::StructureRejected,
            "trust byte limit"
        );
    }

    // Independent explicit time/limit exploration, including legal lower text/statement ceilings.
    let _ = inspect(bytes, trust, i64::MIN, limits);
    let _ = inspect(bytes, trust, i64::MAX, limits);
    let _ = inspect(
        bytes,
        trust,
        150,
        InspectionLimits {
            statement_bytes_max: 1,
            text_bytes_max: 1,
            ..limits
        },
    );
    if status != InspectionStatus::Inspected {
        return;
    }

    let mut damaged_signature = bytes.to_vec();
    *damaged_signature
        .last_mut()
        .expect("inspected signature bytes") ^= 1;
    assert_eq!(
        inspect(&damaged_signature, trust, 150, limits),
        InspectionStatus::SignatureRejected,
        "damaged receipt signature"
    );

    if git {
        let envelope = fixtures::fields(bytes).expect("inspected envelope");
        let statement = fixtures::fields(envelope[2]).expect("inspected statement");
        let expected_result_token: &[u8] = match statement[9] {
            b"updated" => b"SUCCEEDED",
            b"rejected_before_send" | b"receiver_rejected" => b"FAILED",
            b"unknown" => b"UNKNOWN",
            _ => panic!("inspected acknowledgement grammar"),
        };
        assert_eq!(
            statement[13], expected_result_token,
            "inconsistent signed statement"
        );
    }

    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert_eq!(
        inspect(&trailing, trust, 150, limits),
        InspectionStatus::StructureRejected,
        "trailing receipt record"
    );
    let mut trailing_trust = trust.to_vec();
    trailing_trust.push(0);
    assert_eq!(
        inspect(bytes, &trailing_trust, 150, limits),
        InspectionStatus::StructureRejected,
        "trailing trust record"
    );

    // Once inspected, externally supplied trust must still own time, key and purpose.
    let parsed = kapsel_authority::parse_receipt_trust(
        trust,
        kapsel_authority::ReceiptTrustLimits::default(),
    )
    .expect("inspected trust parses");
    for time in [
        parsed.not_before_unix_s.saturating_sub(1),
        parsed.not_after_unix_s,
    ] {
        if time < parsed.not_before_unix_s || time >= parsed.not_after_unix_s {
            assert_eq!(
                inspect(bytes, trust, time, limits),
                InspectionStatus::UntrustedSigner,
                "trust time window"
            );
        }
    }
    let wrong_key_id = if parsed.key_id == "not-the-signer" {
        "another-signer"
    } else {
        "not-the-signer"
    };
    for (key_id, purpose) in [
        (wrong_key_id, parsed.accepted_purpose.as_str()),
        (parsed.key_id.as_str(), "not-the-purpose"),
    ] {
        let wrong = ReceiptTrust {
            key_id: key_id.into(),
            public_key: parsed.public_key,
            accepted_purpose: purpose.into(),
            not_before_unix_s: parsed.not_before_unix_s,
            not_after_unix_s: parsed.not_after_unix_s,
        }
        .encode()
        .expect("valid fixture trust");
        assert_eq!(
            inspect(bytes, &wrong, 150, limits),
            InspectionStatus::UntrustedSigner,
            "external signer appointment"
        );
    }
    if git {
        assert_eq!(
            inspect_receipt(bytes, trust, 150, limits).status(),
            InspectionStatus::StructureRejected,
            "cross-purpose receipt"
        );
    } else {
        assert_eq!(
            inspect_git_receipt(bytes, trust, 150, limits).status(),
            InspectionStatus::StructureRejected,
            "cross-purpose receipt"
        );
    }
}

/// Exercises bounded grant verification under synthetic external trust, without I/O.
///
/// # Panics
///
/// Panics when verification violates a checked contract or authenticated bytes are noncanonical.
pub fn grant(input: &[u8], git: bool) {
    if input.len() > 4097 {
        return;
    }
    check_grant(input, git);
    if let Some(signed) = fixtures::reauthenticate(input) {
        check_grant(&signed, git);
    }
}

fn check_grant(input: &[u8], git: bool) {
    let trust = fixture_trust();
    let accepts = |bytes: &[u8], trust: &AuthorizationTrust| {
        if git {
            verify_git_ref_grant(bytes, trust).is_ok()
        } else {
            verify_authorization_grant(bytes, trust).is_ok()
        }
    };
    let grant_is_accepted = accepts(input, &trust);
    if input.len() > 4096 {
        assert!(!grant_is_accepted, "grant byte limit");
    }
    if !grant_is_accepted {
        return;
    }

    let mut trailing = input.to_vec();
    trailing.push(0);
    assert!(!accepts(&trailing, &trust), "trailing grant record");

    let mut wrong_signer_trust = trust.clone();
    wrong_signer_trust.key_id = "another-owner".into();
    assert!(
        !accepts(input, &wrong_signer_trust),
        "external grant signer identity"
    );
    wrong_signer_trust = trust.clone();
    wrong_signer_trust.public_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    assert!(
        !accepts(input, &wrong_signer_trust),
        "external grant signer key"
    );

    if git {
        let (authorization, signer, _) = verify_git_ref_grant(input, &trust).unwrap().into_parts();
        assert_eq!(
            sign_git_ref_grant(&authorization, &[7; 32], &signer).unwrap(),
            input,
            "canonical Git grant"
        );
        assert!(
            verify_authorization_grant(input, &trust).is_err(),
            "cross-purpose grant"
        );
    } else {
        let (authorization, signer, _) = verify_authorization_grant(input, &trust)
            .unwrap()
            .into_parts();
        assert_eq!(
            sign_authorization_grant(&authorization, &[7; 32], &signer).unwrap(),
            input,
            "canonical Kubernetes grant"
        );
        assert!(
            verify_git_ref_grant(input, &trust).is_err(),
            "cross-purpose grant"
        );
    }
}

/// Exercises bounded service JSON parsing with an inert operator-owned path, without I/O.
///
/// # Panics
///
/// Panics when parsing violates a checked byte/count, path or trailing-input contract.
pub fn service_document(input: &[u8]) {
    if input.len() > 160 * 1024 + 1 {
        return;
    }

    let path = PathBuf::from("/fixture/operator-owned-journal.sqlite");
    let parsed = parse_service_operator_document(input, path.clone());
    if input.len() > 160 * 1024 {
        assert!(parsed.is_err(), "service byte limit");
    }

    if let Ok(document) = parsed {
        assert_eq!(
            document.configuration.journal_path, path,
            "operator-owned path"
        );
        assert!(
            document.configuration.authorization_trust.len() <= 128,
            "key count limit"
        );
        assert!(
            document.configuration.approvals.len() <= 32,
            "approval count limit"
        );
        let mut trailing = input.to_vec();
        trailing.push(b'x');
        assert!(
            parse_service_operator_document(&trailing, path).is_err(),
            "trailing JSON"
        );
    }
}

/// Replays one input through a named maintained driver.
///
/// # Panics
///
/// Panics for an unknown target or a checked decoder contract violation.
pub fn run(target: &str, input: &[u8]) {
    match target {
        "inspect_receipt" => receipt(input, false),
        "inspect_git_receipt" => receipt(input, true),
        "verify_kubernetes_grant" => grant(input, false),
        "verify_git_grant" => grant(input, true),
        "service_document" => service_document(input),
        _ => panic!("unknown fixture target"),
    }
}
