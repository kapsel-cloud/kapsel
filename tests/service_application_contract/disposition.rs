use kapsel::{ExecutionCondition, ExecutionDisposition, ExecutionObservation, ServiceStop};

#[tokio::test]
async fn preflight_failure_requires_explicit_selection_and_never_patches() {
    use http::{Method, Request, Response, StatusCode};
    use kube::{client::Body, Client};
    let root = root("preflight-disposition");
    let mut application = ServiceApplication::open(configuration(&root)).unwrap();
    let (service, mut handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
    let client = Client::new(service, "demo");
    let responder = tokio::spawn(async move {
        let mut requests = 0;
        for code in [StatusCode::SERVICE_UNAVAILABLE, StatusCode::NOT_FOUND] {
            let (request, send) = handle.next_request().await.unwrap();
            assert_eq!(request.method(), Method::GET);
            requests += 1;
            send.send_response(
                Response::builder()
                    .status(code)
                    .body(Body::empty())
                    .unwrap(),
            );
        }
        requests
    });
    let execution = || ServiceExecution {
        kubernetes_client: Some(client.clone()),
        receipt_signing: None,
    };
    let stopped = application.select("a", execution(), |_| {}).await.unwrap();
    assert_eq!(
        stopped,
        ServiceStop::Blocked(ExecutionCondition::PreflightUnavailable)
    );
    for _ in 0..3 {
        assert_eq!(
            application
                .execution_status("a", ServiceStop::observation(Ok(stopped)))
                .unwrap()
                .2,
            ExecutionDisposition::ResumeRequired(Some(ExecutionCondition::PreflightUnavailable))
        );
        assert_eq!(
            application.receipt("a").unwrap(),
            SetDeploymentImageReceipt::NotReady
        );
    }
    assert_eq!(
        application.select("a", execution(), |_| {}).await.unwrap(),
        ServiceStop::Finished
    );
    assert_eq!(responder.await.unwrap(), 2);
    assert_eq!(
        application
            .execution_status("a", ServiceStop::observation(Ok(stopped)))
            .unwrap()
            .2,
        ExecutionDisposition::Complete
    );
    drop(application);
    fs::remove_dir_all(root).unwrap();
}

use super::*;

#[tokio::test]
async fn unavailable_material_is_admitted_readable_and_not_a_historical_crash_cause() {
    let root = root("disposition");
    let mut application = ServiceApplication::open(configuration(&root)).unwrap();
    let stopped = application
        .select("a", offline(), |decision| {
            assert_eq!(
                decision,
                ServiceAdmission::Admitted(OperationState::Requested)
            );
        })
        .await
        .unwrap();
    assert_eq!(
        stopped,
        ServiceStop::Blocked(ExecutionCondition::ReceiverUnavailable)
    );
    let observation = ServiceStop::observation(Ok(stopped));
    assert_eq!(
        application.execution_status("a", observation).unwrap().2,
        ExecutionDisposition::OperatorRequired(ExecutionCondition::ReceiverUnavailable)
    );
    let frozen = fs::read(root.join("journal.sqlite3")).unwrap();
    for _ in 0..3 {
        assert_eq!(
            application.execution_status("a", observation).unwrap().0,
            SetDeploymentImageStatus::InProgress
        );
        assert_eq!(
            application.receipt("a").unwrap(),
            SetDeploymentImageReceipt::NotReady
        );
        assert_eq!(application.history(None).unwrap().entries.len(), 1);
    }
    assert_eq!(fs::read(root.join("journal.sqlite3")).unwrap(), frozen);
    drop(application);
    let application = ServiceApplication::open(configuration(&root)).unwrap();
    assert_eq!(
        application
            .execution_status("a", ExecutionObservation::Unknown)
            .unwrap()
            .2,
        ExecutionDisposition::ResumeRequired(None)
    );
    assert_eq!(fs::read(root.join("journal.sqlite3")).unwrap(), frozen);
    drop(application);
    let mut no_authority = configuration(&root);
    no_authority.approvals.clear();
    no_authority.authorization_trust.clear();
    let application = ServiceApplication::open(no_authority).unwrap();
    assert_eq!(
        application.execution_status("a", observation),
        Err(ServiceError::AuthorityUnavailable)
    );
    let entry = application.history(None).unwrap().entries.remove(0);
    assert_eq!(
        entry.execution_status(observation),
        Err(ServiceError::AuthorityUnavailable)
    );
    drop(application);
    fs::remove_dir_all(root).unwrap();
}
