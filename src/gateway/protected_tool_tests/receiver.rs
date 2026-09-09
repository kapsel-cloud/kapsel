//! Independent receiver facts and HTTP request accounting. Imports neither implementation.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use http_body_util::BodyExt;
use kube::Client;
use serde_json::{json, Value};
use tower_test::mock;

pub(super) const IMAGE: &str = concat!(
    "example/api@sha256:",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
);
pub(super) const OTHER: &str = concat!(
    "example/api@sha256:",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
);

pub(super) fn read(root: &Path) -> Value {
    serde_json::from_slice(&fs::read(root.join("receiver.json")).unwrap()).unwrap()
}
pub(super) fn save(root: &Path, evidence: &Value) {
    let bytes = serde_json::to_vec(evidence).unwrap();
    assert!(bytes.len() <= 128 * 1024);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(root.join("receiver.json"))
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}

pub(super) fn initialize(root: &Path, case: &str) {
    let mut object = json!({"apiVersion":"apps/v1", "kind":"Deployment", "metadata": {
        "name":"api", "namespace":"demo", "uid":"uid-1", "resourceVersion":"opaque-1",
        "generation":1,"annotations":{}}, "spec":{"replicas":1,
        "selector":{"matchLabels":{"app":"api"}},
        "template":{"spec":{"containers":[{"name":"api","image":OTHER}]} }},
        "status":{"observedGeneration":1,"updatedReplicas":1,"availableReplicas":1,
            "unavailableReplicas":0,"conditions":[{"type":"Available","status":"True",
                "reason":"MinimumReplicasAvailable"}]}});
    if case == "healthy" {
        object["status"]
            .as_object_mut()
            .unwrap()
            .remove("unavailableReplicas");
    }
    if case.starts_with("stale-") {
        object["metadata"]["resourceVersion"] = json!("opaque-churn");
        match case {
            "stale-status" => object["status"]["replicas"] = json!(2),
            "stale-annotation" => object["metadata"]["annotations"]["unrelated"] = json!("changed"),
            "stale-identity" => object["metadata"]["uid"] = json!("replacement"),
            _ => panic!("unknown stale case"),
        }
    }
    save(
        root,
        &json!({"object":object,"requests":[],"persisted_patches":0,
        "writer_changes":usize::from(case.starts_with("stale-"))}),
    );
}

pub(super) fn intervene(root: &Path, case: &str) {
    let mut evidence = read(root);
    let object = &mut evidence["object"];
    match case {
        "target-replacement" => object["metadata"]["uid"] = json!("replacement"),
        "intervening-writer" => {
            object["spec"]["template"]["spec"]["containers"][0]["image"] = json!(OTHER);
        },
        "retained-marker" => object["metadata"]["generation"] = json!(3),
        "slow-rollout" => {
            object["status"]["observedGeneration"] = json!(2);
            object["status"]["updatedReplicas"] = json!(1);
            object["status"]["availableReplicas"] = json!(1);
            object["status"]["unavailableReplicas"] = json!(0);
        },
        _ => panic!("unknown intervention"),
    }
    if case == "retained-marker" {
        object["status"]["observedGeneration"] = json!(3);
    }
    object["metadata"]["resourceVersion"] = json!("opaque-writer");
    evidence["writer_changes"] = json!(evidence["writer_changes"].as_u64().unwrap() + 1);
    save(root, &evidence);
}

pub(super) fn client(
    root: &Path,
    case: &str,
    lose_response: bool,
) -> (Client, tokio::task::JoinHandle<()>) {
    let (service, mut handle) =
        mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
    let client = Client::new(service, "demo");
    let root = root.to_owned();
    let case = case.to_owned();
    let task = tokio::spawn(async move {
        while let Some((request, send)) = handle.next_request().await {
            assert_eq!(
                request.uri().path(),
                "/apis/apps/v1/namespaces/demo/deployments/api"
            );
            let method = request.method().to_string();
            let content_type = request.headers().get("content-type").cloned();
            let bytes = request.into_body().collect().await.unwrap().to_bytes();
            assert!(bytes.len() <= 16 * 1024);
            let patch: Value = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            let mut evidence = read(&root);
            let requests = evidence["requests"].as_array_mut().unwrap();
            requests.push(json!({"method":method,"body":patch}));
            assert!(requests.len() <= 64);
            let mut status = 200;
            if method == "PATCH" {
                assert_eq!(
                    content_type.unwrap(),
                    "application/strategic-merge-patch+json"
                );
                assert_eq!(
                    patch,
                    json!({"apiVersion":"apps/v1","kind":"Deployment",
                    "metadata":{"name":"api","namespace":"demo", "uid":"uid-1",
                        "resourceVersion":"opaque-1", "annotations":{
                            "kapsel.dev/kap0038-operation-id":"comparison-op"}},
                    "spec":{"template":{"spec":{"containers":[{"name":"api","image":IMAGE}]}}}})
                );
                if case == "preflight-race" {
                    evidence["object"]["metadata"]["resourceVersion"] = json!("race-writer");
                    evidence["writer_changes"] = json!(1);
                }
                if evidence["object"]["metadata"]["uid"] != patch["metadata"]["uid"]
                    || evidence["object"]["metadata"]["resourceVersion"]
                        != patch["metadata"]["resourceVersion"]
                {
                    status = 409;
                } else {
                    let object = &mut evidence["object"];
                    object["metadata"]["resourceVersion"] = json!("opaque-2");
                    object["metadata"]["generation"] = json!(2);
                    object["metadata"]["annotations"] = patch["metadata"]["annotations"].clone();
                    object["spec"]["template"]["spec"]["containers"][0]["image"] = json!(IMAGE);
                    object["status"]["observedGeneration"] = json!(2);
                    if case == "slow-rollout" {
                        object["status"]["observedGeneration"] = json!(1);
                        object["status"]["updatedReplicas"] = json!(0);
                        object["status"]["availableReplicas"] = json!(0);
                        object["status"]["unavailableReplicas"] = json!(1);
                    }
                    if case == "failed" {
                        object["status"]["conditions"] = json!([{"type":"Progressing",
                            "status":"False", "reason":"ProgressDeadlineExceeded"}]);
                    }
                    evidence["persisted_patches"] =
                        json!(evidence["persisted_patches"].as_u64().unwrap() + 1);
                }
            } else {
                assert_eq!(method, "GET");
            }
            save(&root, &evidence);
            if method == "PATCH" && lose_response {
                send.send_error(std::io::Error::other("accepted response discarded"));
            } else {
                let body = if status == 200 {
                    evidence["object"].clone()
                } else {
                    json!({"apiVersion":"v1","kind":"Status","status":"Failure",
                        "reason":"Conflict","message":"fixture conflict","code":status})
                };
                send.send_response(
                    http::Response::builder()
                        .status(status)
                        .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                );
            }
        }
    });
    (client, task)
}
