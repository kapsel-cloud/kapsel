use kapsel::{inspect_git_receipt, inspect_receipt, InspectionLimits, InspectionStatus};
use kapsel_authority::{verify_authorization_grant, verify_git_ref_grant};
use kapsel_fuzz::{fixture_trust, fixtures, receipt_documents, run, TARGETS};

#[test]
fn canonical_and_negative_seeds_cross_production_interfaces() {
    for target in TARGETS {
        for (name, bytes) in fixtures::seeds(target) {
            run(target, &bytes);
            let accepted = match target {
                "inspect_receipt" | "inspect_git_receipt" => {
                    let (receipt, trust) = receipt_documents(&bytes).unwrap();
                    let status = if target == "inspect_receipt" {
                        inspect_receipt(receipt, trust, 150, InspectionLimits::default()).status()
                    } else {
                        inspect_git_receipt(receipt, trust, 150, InspectionLimits::default())
                            .status()
                    };
                    status == InspectionStatus::Inspected
                },
                "verify_kubernetes_grant" => {
                    verify_authorization_grant(&bytes, &fixture_trust()).is_ok()
                },
                "verify_git_grant" => verify_git_ref_grant(&bytes, &fixture_trust()).is_ok(),
                "service_document" => kapsel::parse_service_operator_document(
                    &bytes,
                    "/fixture/operator-owned-journal.sqlite".into(),
                )
                .is_ok(),
                _ => unreachable!(),
            };
            let expected = match target {
                "inspect_receipt" | "inspect_git_receipt" => matches!(
                    name.as_str(),
                    "canonical-receipt-and-trust" | "canonical-snapshot"
                ),
                "verify_kubernetes_grant" => matches!(
                    name.as_str(),
                    "canonical" | "legacy-kubernetes" | "snapshot-kubernetes"
                ),
                "verify_git_grant" => matches!(name.as_str(), "canonical" | "git-purpose"),
                "service_document" => name.starts_with("canonical"),
                _ => unreachable!(),
            };
            assert_eq!(accepted, expected, "{target}/{name}: seed acceptance");
        }
    }
}

#[test]
fn damaged_signatures_are_rejected_for_both_receipt_purposes() {
    for target in ["inspect_receipt", "inspect_git_receipt"] {
        for (name, input) in fixtures::seeds(target) {
            if !name.starts_with("canonical") {
                continue;
            }
            let (receipt, trust) = receipt_documents(&input).unwrap();
            let mut damaged = receipt.to_vec();
            *damaged.last_mut().unwrap() ^= 1;
            let status = if target == "inspect_receipt" {
                inspect_receipt(&damaged, trust, 150, InspectionLimits::default()).status()
            } else {
                inspect_git_receipt(&damaged, trust, 150, InspectionLimits::default()).status()
            };
            assert_eq!(
                status,
                InspectionStatus::SignatureRejected,
                "{target}/{name}"
            );
            run(target, &input);
            run(target, &fixtures::pair(&damaged, trust));
        }
    }
}

#[test]
fn externally_appointed_signer_cannot_collide_with_the_wrong_signer_probe() {
    let bytes = fixtures::git_receipt(b"UNKNOWN");
    let mut values = fixtures::fields(&bytes).unwrap();
    values[1] = b"not-the-signer";
    let bytes = fixtures::records(b"KAPSEL-GIT-REF-RECEIPT-V1\0", &values);
    let trust = kapsel::ReceiptTrust {
        key_id: "not-the-signer".into(),
        public_key: fixture_trust().public_key,
        accepted_purpose: kapsel::GIT_RECEIPT_PURPOSE.into(),
        not_before_unix_s: 100,
        not_after_unix_s: 200,
    }
    .encode()
    .unwrap();
    run("inspect_git_receipt", &fixtures::pair(&bytes, &trust));
}

#[test]
fn git_fixture_discloses_unknown_and_rejects_inconsistent_signed_result() {
    // The production owner freezes SHA-256 separately; this test asserts disclosed facts.
    let bytes = fixtures::git_receipt(b"UNKNOWN");
    let trust = fixtures::git_trust();
    let report = inspect_git_receipt(&bytes, &trust, 150, InspectionLimits::default());
    assert_eq!(report.status(), InspectionStatus::Inspected);
    assert_eq!(
        report.statement().unwrap().result(),
        kapsel::OperationResult::Unknown
    );
    assert_eq!(report.statement().unwrap().attribution(), "not_established");
    let forged = fixtures::git_receipt(b"SUCCEEDED");
    assert_eq!(
        inspect_git_receipt(&forged, &trust, 150, InspectionLimits::default()).status(),
        InspectionStatus::StructureRejected,
        "inconsistent signed statement"
    );
}
