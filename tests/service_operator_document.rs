//! Hostile operator documents cross the production parser, without a journal or receiver.
#![allow(clippy::unwrap_used, reason = "bounded fixture construction")]
use std::path::PathBuf;

use kapsel::{
    parse_service_operator_document, provision_exact_grant, ApprovedTarget, AuthorizationTrust,
    ExactAuthorization, GrantProvisioning, ServiceApplication, ServiceApproval,
    ServiceConfiguration,
};
use serde_json::{json, Value};

fn parse(bytes: &[u8]) -> bool {
    parse_service_operator_document(bytes, PathBuf::from("/not-opened/journal")).is_ok()
}

#[test]
fn named_bounded_objects_never_accept_caller_authority_or_ambiguous_fields() {
    let valid = json!({
        "service_configuration_version": 1, "receipt_signing_key_id": "receipt-key",
        "authorization_keys": [{"key_id":"authority", "public_key_hex":"00".repeat(32)}],
        "approvals": [{"label":"approval", "signed_grant_hex":"00"}],
    });
    let bytes = serde_json::to_vec(&valid).unwrap();
    assert!(parse(&bytes));
    for (field, value) in [
        ("service_configuration_version", json!(0)),
        ("service_configuration_version", Value::Null),
        ("receipt_signing_key_id", json!("bad\n")),
        ("approvals", Value::Null),
        ("authorization_keys", json!([null])),
        ("journal_path", json!("/caller-selected")),
    ] {
        let mut document = valid.clone();
        document[field] = value;
        assert!(!parse(&serde_json::to_vec(&document).unwrap()), "{field}");
    }
    for (array, field, value) in [
        ("approvals", "signed_grant_hex", "FF".into()),
        ("approvals", "signed_grant_hex", "0".into()),
        ("approvals", "signed_grant_hex", "00".repeat(4097)),
        ("approvals", "label", "x".repeat(129)),
        ("approvals", "label", "line\nbreak".into()),
        ("authorization_keys", "public_key_hex", "00".into()),
    ] {
        let mut document = valid.clone();
        document[array][0][field] = json!(value);
        assert!(
            !parse(&serde_json::to_vec(&document).unwrap()),
            "{array}/{field}"
        );
    }
    for (array, maximum) in [("approvals", 32), ("authorization_keys", 128)] {
        let mut document = valid.clone();
        document[array] = json!(vec![valid[array][0].clone(); maximum]);
        assert!(parse(&serde_json::to_vec(&document).unwrap()));
        document[array]
            .as_array_mut()
            .unwrap()
            .push(valid[array][0].clone());
        assert!(!parse(&serde_json::to_vec(&document).unwrap()));
    }
    for document in [
        json!([1, [], [], "receipt-key"]),
        {
            let mut document = valid.clone();
            document["approvals"] = json!([["label", "00"]]);
            document
        },
        {
            let mut document = valid.clone();
            document["authorization_keys"] = json!([["authority", "00".repeat(32)]]);
            document
        },
    ] {
        assert!(!parse(&serde_json::to_vec(&document).unwrap()));
    }
    let text = serde_json::to_string(&valid).unwrap();
    assert!(!parse(
        text.replacen('{', "{\"service_configuration_version\":1,", 1)
            .as_bytes()
    ));
    assert!(!parse(&vec![b' '; 160 * 1024 + 1]));
}

#[test]
fn static_approval_validation_requires_independent_trust_and_unique_snapshot_ids() {
    let seed = [41; 32];
    let mut authorization = ExactAuthorization {
        authorization_id: "auth-1".into(),
        operation_id: "op-1".into(),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: format!("registry.example/api@sha256:{}", "a".repeat(64)),
        approved_target: Some(ApprovedTarget {
            uid: "uid-1".into(),
            resource_version: "1".into(),
        }),
    };
    let sign = |authorization: &ExactAuthorization| {
        provision_exact_grant(&GrantProvisioning {
            authorization,
            signing_seed: &seed,
            signing_key_id: "key-1",
        })
        .unwrap()
    };
    let valid = ServiceConfiguration {
        journal_path: PathBuf::from("/not-created/journal"),
        authorization_trust: vec![AuthorizationTrust {
            key_id: "key-1".into(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        }],
        approvals: vec![ServiceApproval {
            label: "Approved".into(),
            signed_grant: sign(&authorization),
        }],
    };
    assert!(ServiceApplication::validate_static_configuration(&valid).is_ok());
    authorization.approved_target = None;
    for defect in 0..5 {
        let mut configuration = valid.clone();
        match defect {
            0 => configuration.authorization_trust.clear(),
            1 => configuration
                .authorization_trust
                .push(configuration.authorization_trust[0].clone()),
            2 => configuration
                .approvals
                .push(configuration.approvals[0].clone()),
            3 => configuration.approvals[0].signed_grant = sign(&authorization),
            _ => {
                configuration.authorization_trust[0].public_key =
                    ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                        .verifying_key()
                        .to_bytes();
            },
        }
        assert!(ServiceApplication::validate_static_configuration(&configuration).is_err());
    }
}
