//! Independently pinned version-1 wire contracts shared by renderer and decoder checks.
//! These examples define observable fields, not authority or lifecycle outcomes.

pub(super) const COMMANDS: [(&str, &str, &str); 5] = [
    (
        "kapsel.list_approved_actions",
        "list_approved_actions",
        "after",
    ),
    (
        "kapsel.list_operation_history",
        "list_operation_history",
        "after",
    ),
    (
        "kapsel.get_status",
        "get_set_deployment_image_status",
        "operation_id",
    ),
    (
        "kapsel.get_receipt",
        "get_set_deployment_image_receipt",
        "operation_id",
    ),
    (
        "kapsel.submit",
        "submit_set_deployment_image",
        "operation_id",
    ),
];

pub(super) const GUIDANCE: [(&str, Option<&str>, &str, &str); 11] = [
    ("active", None, "wait", "caller"),
    (
        "waiting_for_worker",
        None,
        "wait_then_select_same_id",
        "caller",
    ),
    ("resume_required", None, "select_same_id", "caller"),
    (
        "resume_required",
        Some("preflight_unavailable"),
        "select_same_id",
        "caller",
    ),
    (
        "resume_required",
        Some("worker_contention"),
        "select_same_id",
        "caller",
    ),
    (
        "operator_required",
        Some("receiver_unavailable"),
        "contact_operator",
        "operator",
    ),
    (
        "operator_required",
        Some("signing_unavailable"),
        "contact_operator",
        "operator",
    ),
    (
        "operator_required",
        Some("completion_blocked"),
        "contact_operator",
        "operator",
    ),
    (
        "operator_required",
        Some("operation_blocked"),
        "contact_operator",
        "operator",
    ),
    ("complete", None, "inspect_result", "caller"),
    ("admission_unconfirmed", None, "read_same_id", "caller"),
];

// SHA-256's published "abc" vector, not a digest calculated by either renderer or decoder.
pub(super) const RECEIPT: &str = concat!(
    r#"{"version":1,"status":"READY","receipt_hex":"616263","receipt_sha256":""#,
    r#"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}"#,
);

pub(super) const HISTORY: &str = r#"{
    "version":1,"status":"READY","next_cursor":"kube-op","entries":[
        {"operation_id":"git-op","status":"UNKNOWN","effect":"git.transition_ref",
         "git":{"repository_id":"repo-1","reference":"refs/heads/approved",
                "old_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "new_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "attempted":true,"acknowledgement":"unknown",
                "observed_ref":{"kind":"commit",
                                "commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
         "execution":{"disposition":"complete","condition":null,
                      "next_action":"inspect_result","action_owner":"caller"}},
        {"operation_id":"inaccessible","status":"ERROR","error_class":"authority_unavailable"},
        {"operation_id":"kube-op","status":"IN_PROGRESS","effect":"kubernetes.set_deployment_image",
         "approved_target":{"uid":"approved-uid","resource_version":"7"},
         "attempt_target":{"uid":"approved-uid","resource_version":"9"},
         "observed_target":{"uid":null,"resource_version":"11"},
         "execution":{"disposition":"resume_required","condition":null,
                      "next_action":"select_same_id","action_owner":"caller"}}
    ]
}"#;
