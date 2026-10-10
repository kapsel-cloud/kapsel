//! Mixed-effect catalog and retained-ID routing without receiver credentials.
use super::*;

pub(super) fn git_approval(id: &str) -> ServiceApproval {
    let authorization = kapsel_authority::GitRefAuthorization {
        operation_id: id.into(),
        authorization_id: format!("git-{id}"),
        repository_id: "repository-1".into(),
        reference: kapsel_authority::APPROVED_GIT_REF.into(),
        old_commit: "a".repeat(40),
        new_commit: "b".repeat(40),
    };
    ServiceApproval {
        label: "Exact Git transition".into(),
        signed_grant: kapsel_authority::sign_git_ref_grant(&authorization, &[41; 32], "a").unwrap(),
    }
}

#[tokio::test]
async fn mixed_catalog_admits_git_and_reconnects_by_original_identity_without_material() {
    let root = root("mixed-git");
    let mut config = configuration(&root);
    config.approvals[0] = git_approval("a");
    let mut application = ServiceApplication::open(config.clone()).unwrap();
    assert!(matches!(
        application.approved_actions(None).unwrap()[0],
        kapsel::ApprovedAction::Git { .. }
    ));
    let stopped = application
        .select("a", offline(), |admission| {
            assert_eq!(
                admission,
                ServiceAdmission::Admitted(OperationState::Authorized)
            );
        })
        .await
        .unwrap();
    assert_eq!(
        stopped,
        kapsel::ServiceStop::Blocked(kapsel::ExecutionCondition::ReceiverUnavailable)
    );
    application.select("b", offline(), |_| {}).await.unwrap();
    let entries = application.history(None).unwrap().entries;
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.operation_id.as_str())
            .collect::<Vec<_>>(),
        ["a", "b"]
    );

    let original_git_targets = application.status("a").unwrap().1.git.unwrap();
    assert!(!original_git_targets.attempted);
    assert!(original_git_targets.acknowledgement.is_none());
    assert!(original_git_targets.observed_ref.is_none());
    assert_eq!(
        application.receipt("a").unwrap(),
        OperationReceipt::NotReady
    );
    drop(application);

    config.approvals.clear();
    let mut reopened = ServiceApplication::open(config).unwrap();
    assert!(reopened.approved_actions(None).unwrap().is_empty());
    assert_eq!(
        reopened.admitted_state("a").unwrap(),
        Some(OperationState::Authorized)
    );
    assert_eq!(
        reopened.select("a", offline(), |_| {}).await.unwrap(),
        stopped
    );
    assert_eq!(
        reopened.status("a").unwrap().1.git.unwrap(),
        original_git_targets
    );
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn replacement_cannot_rebind_an_identity_across_effect_types() {
    for git_first in [false, true] {
        let root = root(if git_first {
            "git-to-kubernetes"
        } else {
            "kubernetes-to-git"
        });
        let mut config = configuration(&root);
        if git_first {
            config.approvals[0] = git_approval("a");
        }
        let mut application = ServiceApplication::open(config.clone()).unwrap();
        application.select("a", offline(), |_| {}).await.unwrap();
        let original = application.status("a").unwrap();
        drop(application);

        config.approvals[0] = if git_first {
            approval("a", 41)
        } else {
            git_approval("a")
        };
        assert!(ServiceApplication::validate_replacement(&config).is_err());
        assert!(ServiceApplication::open(config.clone()).is_err());

        config.approvals.clear();
        let reopened = ServiceApplication::open(config).unwrap();
        assert_eq!(reopened.status("a").unwrap(), original);
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn git_material_is_bounded_object_only_and_does_not_open_paths_when_decoded() {
    let material = br#" {
        "executable":"/absent/git", "sender":"/absent/sender.git",
        "receiver":"/absent/receiver.git", "repository_id":"repository-1"
    }"#;
    assert!(kapsel::GitReceiverConfiguration::from_document(material).is_some());
    assert!(kapsel::GitReceiverConfiguration::from_document(
        br#"["/git","/sender","/receiver","id"]"#
    )
    .is_none());
    assert!(kapsel::GitReceiverConfiguration::from_document(&[b' '; 4097]).is_none());
    assert!(kapsel::GitReceiverConfiguration::from_document(
        br#"{
        "executable":"/git", "executable":"/git", "sender":"/s",
        "receiver":"/r", "repository_id":"id"
    }"#
    )
    .is_none());
}
