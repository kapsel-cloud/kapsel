use std::{fs, path::Path};

use kapsel::{inspect_git_receipt, inspect_receipt, InspectionLimits, InspectionStatus};
use kapsel_authority::{verify_authorization_grant, verify_git_ref_grant};
use kapsel_fuzz::{fixture_trust, fixtures, receipt_documents, run, TARGETS};

#[test]
fn canonical_and_negative_seeds_cross_production_interfaces() {
    for target in TARGETS {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(target);
        let mut entries: Vec<_> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        assert!(!entries.is_empty(), "{target}: nonempty committed corpus");
        for path in entries {
            let name = path.file_name().unwrap().to_str().unwrap();
            let bytes = fs::read(&path).unwrap();
            run(target, &bytes);

            let decoder_accepted = match target {
                "inspect_receipt" | "inspect_git_receipt" => {
                    let status = receipt_status(target, &bytes);
                    let expected = match name {
                        "canonical-receipt-and-trust" | "canonical-snapshot" => {
                            InspectionStatus::Inspected
                        },
                        "damaged-signature" => InspectionStatus::SignatureRejected,
                        _ => InspectionStatus::StructureRejected,
                    };
                    assert_eq!(status, expected, "{target}/{name}: exact status");
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

            let seed_should_be_accepted = match target {
                "inspect_receipt" | "inspect_git_receipt" => {
                    matches!(name, "canonical-receipt-and-trust" | "canonical-snapshot")
                },
                "verify_kubernetes_grant" => matches!(
                    name,
                    "canonical" | "legacy-kubernetes" | "snapshot-kubernetes"
                ),
                "verify_git_grant" => matches!(name, "canonical" | "git-purpose"),
                "service_document" => name.starts_with("canonical"),
                _ => unreachable!(),
            };
            assert_eq!(
                decoder_accepted, seed_should_be_accepted,
                "{target}/{name}: seed acceptance"
            );
        }
    }
}

fn receipt_status(target: &str, bytes: &[u8]) -> InspectionStatus {
    let Some((receipt, trust)) = receipt_documents(bytes) else {
        return InspectionStatus::StructureRejected;
    };
    if target == "inspect_receipt" {
        inspect_receipt(receipt, trust, 150, InspectionLimits::default()).status()
    } else {
        inspect_git_receipt(receipt, trust, 150, InspectionLimits::default()).status()
    }
}

#[test]
fn reviewed_regression_bytes_run_the_semantic_driver_and_check_expected_status() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("regressions");
    let mut selected = Vec::new();
    for directory in fs::read_dir(root).unwrap() {
        let directory = directory.unwrap().path();
        let target = directory.file_name().unwrap().to_str().unwrap();
        assert!(
            TARGETS.contains(&target),
            "unknown regression target {target}"
        );
        for entry in fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap();
            let expected = match (target, name) {
                ("inspect_git_receipt", "signer-probe-collision") => InspectionStatus::Inspected,
                _ => panic!("regression {target}/{name} needs a reviewed semantic expectation"),
            };
            let bytes = fs::read(&path).unwrap();
            run(target, &bytes);
            assert_eq!(receipt_status(target, &bytes), expected, "{target}/{name}");
            selected.push(format!("{target}/{name}"));
        }
    }
    selected.sort();
    assert_eq!(selected, ["inspect_git_receipt/signer-probe-collision"]);
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
