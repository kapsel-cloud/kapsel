//! Service A/B selection against receiver-owned objects and actual loopback HTTP requests.

use std::sync::{Arc, Mutex};

use kapsel::{
    AuthorizationTrust, ServiceAdmission, ServiceApplication, ServiceApproval,
    ServiceConfiguration, ServiceExecution, SetDeploymentImageStatus, TargetRejection,
};

use super::*;

#[tokio::test(start_paused = true)]
#[allow(
    clippy::too_many_lines,
    reason = "ordered observation, reconnect and frozen-history proof"
)]
async fn observation_pass_holds_worker_but_not_stored_reads() {
    use http::{Method, Request, Response};
    use kube::{client::Body, Client};
    use tower_test::mock;

    for settle_after in [60, 181, 361] {
        let root = std::env::temp_dir().join(format!(
            "kapsel-service-observation-{}-{settle_after}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let mut worker = ServiceApplication::open(configuration(&root, false)).unwrap();
        let mut connected = ServiceApplication::open(configuration(&root, false)).unwrap();
        let (mock_service, mut handle) = mock::pair::<Request<Body>, Response<Body>>();
        let client = Client::new(mock_service, "default");
        let evidence = Arc::new(Mutex::new(Vec::new()));
        let recorded = evidence.clone();
        let start = tokio::time::Instant::now();
        let responder = tokio::spawn(async move {
            while let Some((request, send)) = handle.next_request().await {
                let method = request.method().clone();
                let mut observed = recorded.lock().unwrap();
                observed.push(method.clone());
                let initial = observed.len() == 1;
                drop(observed);
                let mut object = deployment(false);
                if !initial {
                    object["spec"]["template"]["spec"]["containers"][0]["image"] = json!(IMAGE);
                    object["metadata"]["generation"] = json!(2);
                    object["metadata"]["resourceVersion"] = json!("2");
                    object["metadata"]["annotations"] =
                        json!({"kapsel.dev/kap0038-operation-id":"a"});
                    object["status"]["observedGeneration"] = json!(2);
                    if start.elapsed() < Duration::from_secs(settle_after) {
                        object["status"]["unavailableReplicas"] = json!(1);
                    }
                }
                send.send_response(Response::new(Body::from(
                    serde_json::to_vec(&object).unwrap(),
                )));
            }
        });
        if settle_after == 361 {
            drop(worker);
            for _ in 0..2 {
                interrupt_service_observation(&root, &client, &evidence).await;
            }
            worker = ServiceApplication::open(configuration(&root, false)).unwrap();
        }
        let previous_requests = evidence.lock().unwrap().len();
        let pass_started = tokio::time::Instant::now();
        let mut pass = Box::pin(worker.select(
            "a",
            ServiceExecution {
                kubernetes_client: Some(client.clone()),
                receipt_signing: Some(([42; 32], "receipt-key".into())),
            },
            |admission| {
                assert_eq!(
                    admission,
                    ServiceAdmission::Admitted(if settle_after == 361 {
                        OperationState::ApplyStarted
                    } else {
                        OperationState::Requested
                    })
                );
            },
        ));
        tokio::select! {
            result = &mut pass => panic!("provisional availability stopped early: {result:?}"),
            () = tokio::time::sleep(Duration::from_secs(35)) => {},
        }
        // Disconnect/reconnect only replaces the read application, never the surviving worker.
        drop(connected);
        connected = ServiceApplication::open(configuration(&root, false)).unwrap();
        let before_reads = evidence.lock().unwrap().len();
        for _ in 0..3 {
            assert_eq!(
                connected.status("a").unwrap().0,
                SetDeploymentImageStatus::InProgress
            );
            assert_eq!(
                connected.receipt("a").unwrap(),
                SetDeploymentImageReceipt::NotReady
            );
        }
        connected
            .select(
                "b",
                ServiceExecution {
                    kubernetes_client: Some(client.clone()),
                    receipt_signing: None,
                },
                |admission| assert_eq!(admission, ServiceAdmission::Busy),
            )
            .await
            .unwrap();
        assert_eq!(connected.admitted_state("b").unwrap(), None);
        assert_eq!(evidence.lock().unwrap().len(), before_reads);
        pass.await.unwrap();
        assert_eq!(pass_started.elapsed().as_secs(), settle_after.min(179));
        if settle_after == 361 {
            assert!(start.elapsed() > Duration::from_secs(180));
        }
        let expected = if settle_after == 60 {
            SetDeploymentImageStatus::Succeeded
        } else {
            SetDeploymentImageStatus::Unknown
        };
        assert_eq!(connected.status("a").unwrap().0, expected);
        let frozen = connected.receipt("a").unwrap();
        let before_reselect = evidence.lock().unwrap().len();
        connected
            .select(
                "a",
                ServiceExecution {
                    kubernetes_client: Some(client.clone()),
                    receipt_signing: None,
                },
                |admission| {
                    assert_eq!(
                        admission,
                        ServiceAdmission::Admitted(OperationState::Finalized)
                    );
                },
            )
            .await
            .unwrap();
        assert_eq!(connected.receipt("a").unwrap(), frozen);
        assert_eq!(evidence.lock().unwrap().len(), before_reselect);
        let requests = evidence.lock().unwrap().clone();
        assert_eq!(
            requests
                .iter()
                .filter(|method| **method == Method::PATCH)
                .count(),
            1
        );
        assert_eq!(
            requests.len() - previous_requests,
            (settle_after + 1).min(180) as usize + usize::from(previous_requests == 0) * 2
        );
        drop(client);
        responder.await.unwrap();
        drop(connected);
        drop(worker);
        fs::remove_dir_all(root).unwrap();
    }
}

async fn interrupt_service_observation(
    root: &Path,
    client: &kube::Client,
    evidence: &Mutex<Vec<http::Method>>,
) {
    let mut worker = ServiceApplication::open(configuration(root, false)).unwrap();
    assert!(tokio::time::timeout(
        Duration::from_secs(60),
        worker.select(
            "a",
            ServiceExecution {
                kubernetes_client: Some(client.clone()),
                receipt_signing: Some(([42; 32], "receipt-key".into())),
            },
            |_| {},
        ),
    )
    .await
    .is_err());
    drop(worker);
    let read_first = ServiceApplication::open(configuration(root, false)).unwrap();
    assert_eq!(
        read_first.admitted_state("a").unwrap(),
        Some(OperationState::ApplyStarted)
    );
    assert_eq!(
        read_first.status("a").unwrap().0,
        SetDeploymentImageStatus::InProgress
    );
    let before = evidence.lock().unwrap().len();
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert_eq!(evidence.lock().unwrap().len(), before);
}

struct Receiver {
    fixture: Fixture,
    requests: Arc<Mutex<Vec<WireRequest>>>,
    patch_received: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl Receiver {
    fn new(same_target: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "kapsel-service-selection-{}-{same_target}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (stop, stopped) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        let (patch_received, barrier) = tokio::sync::oneshot::channel();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let evidence = Arc::clone(&requests);
        let server = thread::spawn(move || {
            serve_selection(&listener, &stopped, &resumed, patch_received, &evidence);
            evidence.lock().unwrap().clone()
        });
        let kubeconfig = format!(
            concat!(
                "apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n",
                "  cluster:\n    server: http://{address}\ncontexts:\n- name: fixture\n",
                "  context:\n    cluster: fixture\n    user: fixture\n",
                "current-context: fixture\nusers:\n- name: fixture\n  user: {{}}\n"
            ),
            address = address
        )
        .into_bytes();
        Self {
            fixture: Fixture {
                root,
                kubeconfig,
                stop,
                server: Some(server),
                paused: mpsc::channel().1,
                resume,
            },
            requests,
            patch_received: Some(barrier),
        }
    }

    fn requests(&self) -> Vec<WireRequest> {
        self.requests.lock().unwrap().clone()
    }

    fn execution(
        &self,
        signing: bool,
    ) -> impl std::future::Future<Output = ServiceExecution> + Send + '_ {
        ServiceExecution::from_operator_snapshots(
            Some(&self.fixture.kubeconfig),
            signing.then_some(&[42; 32]),
            "receipt-key",
        )
    }
}

// The receiver owns object versions, persisted changes and request counts; no gateway counters.
fn serve_selection(
    listener: &TcpListener,
    stopped: &mpsc::Receiver<()>,
    resumed: &mpsc::Receiver<()>,
    patch_received: tokio::sync::oneshot::Sender<()>,
    requests: &Mutex<Vec<WireRequest>>,
) {
    let mut objects = [deployment(false), deployment(false)];
    objects[1]["metadata"]["name"] = json!("other");
    objects[1]["metadata"]["uid"] = json!("uid-other");
    let mut barrier = Some(patch_received);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if stopped.try_recv().is_ok() {
                    return;
                }
                assert!(Instant::now() < deadline, "service receiver timed out");
                thread::sleep(Duration::from_millis(1));
                continue;
            },
            Err(error) => panic!("receiver accept: {error}"),
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let request = read_request(&mut stream);
        let index = match request.path.trim_end_matches('?') {
            "/apis/apps/v1/namespaces/demo/deployments/api" => 0,
            "/apis/apps/v1/namespaces/demo/deployments/other" => 1,
            path => panic!("unexpected target: {path}"),
        };
        {
            let mut evidence = requests.lock().unwrap();
            evidence.push(request.clone());
            assert!(evidence.len() <= 8);
            drop(evidence);
        }
        let object = &mut objects[index];
        match request.method.as_str() {
            "GET" => assert!(request.body.is_empty()),
            "PATCH" => {
                let patch: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(patch["metadata"]["uid"], object["metadata"]["uid"]);
                assert_eq!(
                    patch["metadata"]["resourceVersion"],
                    object["metadata"]["resourceVersion"]
                );
                let id = if index == 0 { "a" } else { "b" };
                assert_eq!(
                    patch,
                    json!({"apiVersion":"apps/v1", "kind":"Deployment",
                        "metadata":{"name":object["metadata"]["name"], "namespace":"demo",
                            "uid":object["metadata"]["uid"], "resourceVersion":"1",
                            "annotations":{"kapsel.dev/kap0038-operation-id":id}},
                        "spec":{"template":{"spec":{"containers":[{"name":"api","image":IMAGE}]}}}
                    })
                );
                object["metadata"]["resourceVersion"] = json!("2");
                object["metadata"]["generation"] = json!(2);
                object["metadata"]["annotations"] = patch["metadata"]["annotations"].clone();
                object["spec"]["template"]["spec"]["containers"][0]["image"] = json!(IMAGE);
                object["status"]["observedGeneration"] = json!(2);
                if let Some(barrier) = barrier.take() {
                    barrier.send(()).unwrap();
                    resumed.recv_timeout(Duration::from_secs(5)).unwrap();
                }
            },
            method => panic!("unexpected method: {method}"),
        }
        let body = serde_json::to_vec(object).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
            content-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
    }
}

fn configuration(root: &Path, same_target: bool) -> ServiceConfiguration {
    ServiceConfiguration {
        journal_path: root.join("journal.sqlite3"),
        authorization_trust: vec![AuthorizationTrust {
            key_id: "authority".into(),
            public_key: SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes(),
        }],
        approvals: ["a", "b"]
            .into_iter()
            .map(|id| {
                let other = id == "b" && !same_target;
                ServiceApproval {
                    label: format!("Action {id}"),
                    signed_grant: provision_exact_grant(&GrantProvisioning {
                        authorization: &ExactAuthorization {
                            authorization_id: format!("approval-{id}"),
                            operation_id: id.into(),
                            namespace: "demo".into(),
                            deployment: if other { "other" } else { "api" }.into(),
                            container: "api".into(),
                            immutable_image_digest: IMAGE.into(),
                            approved_target: Some(ApprovedTarget {
                                uid: if other { "uid-other" } else { "uid-1" }.into(),
                                resource_version: "1".into(),
                            }),
                        },
                        signing_seed: &[41; 32],
                        signing_key_id: "authority",
                    })
                    .unwrap(),
                }
            })
            .collect(),
    }
}

fn retained_row(root: &Path, id: &str) -> Vec<rusqlite::types::Value> {
    let connection = rusqlite::Connection::open(root.join("journal.sqlite3")).unwrap();
    let mut query = connection
        .prepare("SELECT * FROM kubernetes_image_operations WHERE operation_id = ?1")
        .unwrap();
    let columns = query.column_count();
    query
        .query_row([id], |row| {
            (0..columns).map(|index| row.get(index)).collect()
        })
        .unwrap()
}

#[allow(
    clippy::too_many_lines,
    reason = "ordered A/B ownership and evidence checkpoints"
)]
async fn selected_b_advances_while_a_awaits_signing(same_target: bool) {
    let mut receiver = Receiver::new(same_target);
    let root = &receiver.fixture.root;
    let config = configuration(root, same_target);
    let original_grant = config.approvals[0].signed_grant.clone();
    let mut a = ServiceApplication::open(config).unwrap();
    let mut b = ServiceApplication::open(configuration(root, same_target)).unwrap();
    let execution = receiver.execution(false).await;
    assert!(execution.kubernetes_client.is_some());
    let mut selection = Box::pin(a.select("a", execution, |decision| {
        assert_eq!(
            decision,
            ServiceAdmission::Admitted(OperationState::Requested)
        );
    }));
    let barrier = receiver.patch_received.take().unwrap();
    tokio::select! {
        result = &mut selection => panic!("A must hold its PATCH response: {result:?}"),
        result = tokio::time::timeout(Duration::from_secs(5), barrier) => {
            result.unwrap().unwrap();
        }
    }
    assert_eq!(
        b.admitted_state("a").unwrap(),
        Some(OperationState::ApplyStarted)
    );
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("journal.sqlite3.kap0038-worker.lock"))
        .unwrap();
    assert!(matches!(lock.try_lock(), Err(fs::TryLockError::WouldBlock)));
    let before_busy = receiver.requests();
    assert_eq!(before_busy.len(), 2);
    b.select("b", receiver.execution(true).await, |decision| {
        assert_eq!(decision, ServiceAdmission::Busy);
    })
    .await
    .unwrap();
    assert_eq!(b.admitted_state("b").unwrap(), None);
    assert_eq!(b.status("b").unwrap().0, SetDeploymentImageStatus::NotFound);
    assert_eq!(b.history(None).unwrap().entries.len(), 1);
    assert_eq!(receiver.requests(), before_busy);
    receiver.fixture.resume.send(()).unwrap();
    let stopped = tokio::time::timeout(Duration::from_secs(5), &mut selection)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stopped,
        kapsel::ServiceStop::Blocked(kapsel::ExecutionCondition::SigningUnavailable)
    );
    drop(selection);
    lock.try_lock().unwrap();
    lock.unlock().unwrap();
    assert_eq!(
        a.admitted_state("a").unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(
        a.status("a").unwrap().0,
        SetDeploymentImageStatus::InProgress
    );
    assert_eq!(a.receipt("a").unwrap(), SetDeploymentImageReceipt::NotReady);
    let frozen_a = retained_row(root, "a");
    assert!(frozen_a.contains(&rusqlite::types::Value::Blob(original_grant)));
    let before_b = receiver.requests();
    assert_eq!(before_b.len(), 3);
    assert_eq!(
        a.execution_status("a", kapsel::ServiceStop::observation(Ok(stopped)))
            .unwrap()
            .2,
        kapsel::ExecutionDisposition::OperatorRequired(
            kapsel::ExecutionCondition::SigningUnavailable
        )
    );
    assert_eq!(receiver.requests(), before_b);
    b.select("b", receiver.execution(true).await, |decision| {
        assert_eq!(
            decision,
            ServiceAdmission::Admitted(OperationState::Requested)
        );
    })
    .await
    .unwrap();
    let b_status = b.status("b").unwrap();
    if same_target {
        assert_eq!(
            b_status.0,
            SetDeploymentImageStatus::NotAttempted(TargetRejection::StaleApproval)
        );
        assert_eq!(
            b.admitted_state("b").unwrap(),
            Some(OperationState::NotAttempted)
        );
        assert!(b_status.1.attempt_target.is_none());
        assert_eq!(b_status.1.approved_target.unwrap().resource_version, "1");
        assert_eq!(
            b_status
                .1
                .observed_target
                .unwrap()
                .resource_version
                .as_deref(),
            Some("2")
        );
        assert_eq!(b.receipt("b").unwrap(), SetDeploymentImageReceipt::NotReady);
    } else {
        assert_eq!(b_status.0, SetDeploymentImageStatus::Succeeded);
        assert_eq!(
            b.admitted_state("b").unwrap(),
            Some(OperationState::Finalized)
        );
        assert!(matches!(
            b.receipt("b").unwrap(),
            SetDeploymentImageReceipt::Ready { .. }
        ));
    }
    assert_eq!(retained_row(root, "a"), frozen_a);
    assert_eq!(
        a.admitted_state("a").unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    let after_b = receiver.requests();
    let b_requests = &after_b[before_b.len()..];
    assert_eq!(b_requests.len(), if same_target { 1 } else { 3 });
    assert_eq!(b_requests[0].method, "GET");
    // Remove catalog access: explicit resume must use retained authority and frozen observations.
    drop(a);
    drop(b);
    let mut history = configuration(root, same_target);
    history.approvals.clear();
    let mut a = ServiceApplication::open(history).unwrap();
    assert_eq!(
        a.execution_status("a", kapsel::ExecutionObservation::Unknown)
            .unwrap()
            .2,
        kapsel::ExecutionDisposition::ResumeRequired(None)
    );
    assert_eq!(retained_row(root, "a"), frozen_a);
    a.select("a", receiver.execution(true).await, |decision| {
        assert_eq!(
            decision,
            ServiceAdmission::Admitted(OperationState::ReceiverObserved)
        );
    })
    .await
    .unwrap();
    assert_eq!(
        a.status("a").unwrap().0,
        SetDeploymentImageStatus::Succeeded
    );
    assert_eq!(
        a.execution_status("a", kapsel::ServiceStop::observation(Ok(stopped)))
            .unwrap()
            .2,
        kapsel::ExecutionDisposition::Complete
    );
    let original_receipt = a.receipt("a").unwrap();
    assert!(matches!(
        original_receipt,
        SetDeploymentImageReceipt::Ready { .. }
    ));
    let b_receipt = a.receipt("b").unwrap();
    assert_eq!(receiver.requests(), after_b);
    drop(a);
    let mut a = ServiceApplication::open(configuration(root, same_target)).unwrap();
    for id in ["b", "a"] {
        let mut execution = receiver.execution(true).await;
        execution.receipt_signing = Some(([99; 32], "replacement-key".into()));
        a.select(id, execution, |_| {}).await.unwrap();
    }
    assert_eq!(a.receipt("a").unwrap(), original_receipt);
    assert_eq!(a.receipt("b").unwrap(), b_receipt);
    assert_eq!(receiver.requests(), after_b);
    drop(a);
    let requests = receiver.fixture.finish();
    for (id, target, expected) in [("a", "api", 1), ("b", "other", usize::from(!same_target))] {
        let patches: Vec<_> = requests
            .iter()
            .filter(|request| {
                request.method == "PATCH"
                    && serde_json::from_slice::<Value>(&request.body).unwrap()["metadata"]
                        ["annotations"]["kapsel.dev/kap0038-operation-id"]
                        == id
            })
            .collect();
        assert_eq!(patches.len(), expected, "operation {id}");
        for patch in patches {
            assert!(patch
                .path
                .trim_end_matches('?')
                .ends_with(&format!("/deployments/{target}")));
        }
    }
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        if same_target { 3 } else { 4 }
    );
}

#[tokio::test]
async fn independent_target_b_executes_while_a_remains_unfinished() {
    selected_b_advances_while_a_awaits_signing(false).await;
}

#[tokio::test]
async fn same_target_b_advances_to_stale_approval_while_a_remains_unfinished() {
    selected_b_advances_while_a_awaits_signing(true).await;
}
