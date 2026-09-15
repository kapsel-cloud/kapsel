//! Cold publisher refusal, exact bytes and owned temporary-file fault evidence.
#![allow(
    clippy::panic,
    reason = "authority consumption must fail the contention fixture"
)]
use std::{fs, os::unix::fs::PermissionsExt as _};

use super::*;
use crate::startup::{tests::valid_root, InstallationInputs};

#[test]
fn invalid_candidate_leaves_operator_and_journal_exactly_unchanged() {
    let root = valid_root("publisher-invalid");
    let inputs = InstallationInputs::open_at(&root).unwrap();
    let mut execution = inputs.open_execution().unwrap();
    let action = execution
        .application
        .approved_actions(None)
        .unwrap()
        .remove(0);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(execution.application.select(
            "service-op",
            kapsel::ServiceExecution {
                kubernetes_client: None,
                receipt_signing: None,
            },
            |_| {},
        ))
        .unwrap();
    drop(execution);
    drop(inputs);
    let path = root.join("etc/kapsel/operator.json");
    let original = fs::read(&path).unwrap();
    let journal = root.join("var/lib/kapsel/journal.sqlite3");
    let history = fs::read(&journal).unwrap();
    let conflicting_grant = kapsel::provision_exact_grant(&kapsel::GrantProvisioning {
        authorization: &kapsel::ExactAuthorization {
            authorization_id: "different-authority".into(),
            operation_id: action.request.operation_id,
            namespace: action.request.namespace,
            deployment: action.request.deployment,
            container: action.request.container,
            immutable_image_digest: action.request.immutable_image_digest,
            approved_target: Some(action.approved_target),
        },
        signing_seed: &[101; 32],
        signing_key_id: "service-owner-key",
    })
    .unwrap();
    let mut conflict: serde_json::Value = serde_json::from_slice(&original).unwrap();
    conflict["approvals"][0]["signed_grant_hex"] =
        crate::startup::tests::hex(&conflicting_grant).into();
    for bytes in [
        b"invalid".to_vec(),
        vec![b' '; OPERATOR_DOCUMENT_BYTES_MAX + 1],
        serde_json::to_vec(&conflict).unwrap(),
    ] {
        assert_eq!(replace(&root, &mut bytes.as_slice()), Outcome::NotPublished);
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read(&journal).unwrap(), history);
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn publication_faults_have_honest_outcomes_and_only_remove_owned_temporary() {
    for fault in [
        Fault::None,
        Fault::Write,
        Fault::FileSync,
        Fault::BeforeRename,
        Fault::Rename,
        Fault::DirectorySync,
    ] {
        let root = valid_root(&format!("publisher-fault-{fault:?}"));
        let roots = InstallationRoots::open_at(&root).unwrap();
        let path = root.join("etc/kapsel/operator.json");
        let original = fs::read(&path).unwrap();
        let mut candidate = original.clone();
        candidate.extend_from_slice(b" \n");
        let stale = root.join("etc/kapsel/.operator-stale.tmp");
        fs::write(&stale, b"not ours").unwrap();
        let result = publish_candidate(&roots.configuration, &candidate, fault);
        let renamed = matches!(fault, Fault::None | Fault::DirectorySync);
        assert_eq!(
            result,
            match fault {
                Fault::None => Outcome::Published,
                Fault::Rename | Fault::DirectorySync => Outcome::Indeterminate,
                _ => Outcome::NotPublished,
            }
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            if renamed { candidate } else { original }
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(fs::read(&stale).unwrap(), b"not ours");
        assert_eq!(
            fs::read_dir(root.join("etc/kapsel"))
                .unwrap()
                .filter(|entry| entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
                .count(),
            1
        );
        drop(roots);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn publication_stays_on_retained_configuration_directory() {
    let root = valid_root("publisher-retained-root");
    let roots = InstallationRoots::open_at(&root).unwrap();
    let configuration = root.join("etc/kapsel");
    let retained = root.join("etc/kapsel.retained");
    let mut candidate = fs::read(configuration.join("operator.json")).unwrap();
    candidate.push(b'\n');
    fs::rename(&configuration, &retained).unwrap();
    fs::create_dir(&configuration).unwrap();
    fs::set_permissions(&configuration, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(configuration.join("operator.json"), b"foreign root").unwrap();
    assert_eq!(
        validate(&roots, &mut candidate.as_slice()).unwrap(),
        candidate
    );
    assert_eq!(
        publish(&roots.configuration, &candidate),
        Outcome::Published
    );
    assert_eq!(fs::read(retained.join("operator.json")).unwrap(), candidate);
    assert_eq!(
        fs::read(configuration.join("operator.json")).unwrap(),
        b"foreign root"
    );
    drop(roots);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn publication_does_not_unlink_a_substituted_temporary_inode() {
    let root = valid_root("publisher-temp-substitution");
    let roots = InstallationRoots::open_at(&root).unwrap();
    let temp = Temporary::create(&roots.configuration).unwrap();
    let path = root.join("etc/kapsel").join(&temp.name);
    fs::rename(&path, path.with_extension("retained")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    drop(temp);
    assert_eq!(fs::read(&path).unwrap(), b"replacement");
    drop(roots);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn lifecycle_contention_precedes_candidate_consumption_and_exact_publication() {
    struct Unread;
    impl io::Read for Unread {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("contending publisher consumed authority");
        }
    }
    let root = valid_root("publisher-contention");
    let inputs = InstallationInputs::open_at(&root).unwrap();
    assert_eq!(replace(&root, &mut Unread), Outcome::NotPublished);
    assert!(InstallationInputs::open_at(&root).is_err());
    drop(inputs);
    let path = root.join("etc/kapsel/operator.json");
    let mut bytes = fs::read(&path).unwrap();
    bytes.extend_from_slice(b"\n \t");
    assert_eq!(replace(&root, &mut bytes.as_slice()), Outcome::Published);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(!root.join("var/lib/kapsel/journal.sqlite3").exists());
    fs::remove_dir_all(root).unwrap();
}
