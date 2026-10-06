//! Offline inspection projection shared by the purpose-specific receipt renderers.

pub(crate) fn target_fields(targets: &kapsel::OperationTargets) -> String {
    let exact = |target: Option<&kapsel::ApprovedTarget>| {
        target.map(|target| {
            serde_json::json!({"uid": target.uid, "resource_version": target.resource_version})
        })
    };
    serde_json::json!({
        "approved_target": exact(targets.approved_target.as_ref()),
        "attempt_target": exact(targets.attempt_target.as_ref()),
        "observed_target": targets.observed_target.as_ref().map(|target| serde_json::json!({
            "uid": target.uid, "resource_version": target.resource_version,
        })),
    })
    .to_string()
}
