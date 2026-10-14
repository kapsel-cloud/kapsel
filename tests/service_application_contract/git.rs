//! Git document parsing and cross-effect namespace collisions.
use super::*;

pub(super) fn git_approval(id: &str) -> ServiceApproval {
    git_approval_with_key(id, "a")
}

pub(super) fn git_approval_with_key(id: &str, key_id: &str) -> ServiceApproval {
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
        signed_grant: kapsel_authority::sign_git_ref_grant(&authorization, &[41; 32], key_id)
            .unwrap(),
    }
}

#[tokio::test]
async fn one_identity_cannot_change_effect_type() {
    for git_first in [false, true] {
        let root = root(&format!("effect-collision-{git_first}"));
        let mut config = configuration(&root);
        if git_first {
            config.approvals[0] = git_approval("a");
        }
        let mut app = ServiceApplication::open(config.clone()).unwrap();
        app.select("a", offline(), |_| {}).await.unwrap();
        let original = app.status("a").unwrap();
        drop(app);
        config.approvals[0] = if git_first {
            approval("a", 41)
        } else {
            git_approval("a")
        };
        assert!(ServiceApplication::validate_replacement(&config).is_err());
        assert!(ServiceApplication::open(config.clone()).is_err());
        config.approvals.clear();
        let app = ServiceApplication::open(config).unwrap();
        assert_eq!(app.status("a").unwrap(), original);
        drop(app);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn git_material_is_bounded_object_only_and_does_not_open_paths_when_decoded() {
    let material = br#"{
        "executable":"/absent/git", "sender":"/absent/sender.git",
        "receiver":"/absent/receiver.git", "repository_id":"repository-1"
    }"#;
    assert!(kapsel::GitReceiverConfiguration::from_document(material).is_some());
    for bytes in [
        br#"["/git","/sender","/receiver","id"]"#.to_vec(),
        vec![b' '; 4097],
        br#"{"executable":"/git", "executable":"/git", "sender":"/s",
            "receiver":"/r", "repository_id":"id"}"#
            .to_vec(),
    ] {
        assert!(kapsel::GitReceiverConfiguration::from_document(&bytes).is_none());
    }
}
