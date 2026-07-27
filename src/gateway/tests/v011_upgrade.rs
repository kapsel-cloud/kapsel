use std::{
    collections::BTreeSet,
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use rusqlite::OptionalExtension;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const TAG_OBJECT: &str = "9085414ad329edfa5afe49577afd1d1409a30a5d";
const SOURCE_COMMIT: &str = "ad799b39112ccd6ef06e1ec954c615b6635650f6";
const FIXTURE_FORMAT: &str = "kapsel.kap0060.v011-fixture-manifest.v1";
const MATRIX_FORMAT: &str = "kapsel.kap0060.v011-upgrade-matrix.v1";
const OPERATION_ID: &str = "op-001";
const RECEIPT_KEY_ID: &str = "kap0060-v011-receipt-key";
const MATRIX_BYTES: &[u8] =
    include_bytes!("../../../tests/fixtures/kap0060-v011-upgrade-matrix.json");

struct FixtureCase {
    name: &'static str,
    state: &'static str,
    crash_point: &'static str,
    provider_call_count: usize,
    receipt_identity: &'static str,
}

const FIXTURE_CASES: &[FixtureCase] = &[
    FixtureCase {
        name: "requested",
        state: "requested",
        crash_point: "after_requested_commit",
        provider_call_count: 0,
        receipt_identity: "absent",
    },
    FixtureCase {
        name: "authorized",
        state: "authorized",
        crash_point: "after_authorized_commit",
        provider_call_count: 0,
        receipt_identity: "absent",
    },
    FixtureCase {
        name: "not_attempted",
        state: "not_attempted",
        crash_point: "after_target_rejected_commit",
        provider_call_count: 0,
        receipt_identity: "absent",
    },
    FixtureCase {
        name: "apply_started_before_call",
        state: "apply_started",
        crash_point: "after_apply_started_commit_before_provider_call",
        provider_call_count: 0,
        receipt_identity: "absent",
    },
    FixtureCase {
        name: "apply_started_after_side_effect",
        state: "apply_started",
        crash_point: "process_loss_after_one_provider_side_effect_before_response",
        provider_call_count: 1,
        receipt_identity: "absent",
    },
    FixtureCase {
        name: "receiver_observed",
        state: "receiver_observed",
        crash_point: "after_receiver_observed_commit",
        provider_call_count: 1,
        receipt_identity: "absent",
    },
    FixtureCase {
        name: "receipt_prepared",
        state: "receipt_prepared",
        crash_point: "after_receipt_prepared_commit_before_publication",
        provider_call_count: 1,
        receipt_identity: "frozen_in_journal_not_published",
    },
    FixtureCase {
        name: "receipt_written",
        state: "receipt_written",
        crash_point: "after_receipt_written_commit",
        provider_call_count: 1,
        receipt_identity: "frozen_and_published",
    },
    FixtureCase {
        name: "finalized",
        state: "finalized",
        crash_point: "after_finalized_commit",
        provider_call_count: 1,
        receipt_identity: "frozen_and_published",
    },
];

struct SideEffectAdapter {
    ready_path: PathBuf,
    call_count_path: PathBuf,
}

struct MutationChild {
    child: Option<Child>,
}

impl MutationChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.as_mut().unwrap().try_wait()
    }

    fn terminate_and_wait(&mut self) -> io::Result<ExitStatus> {
        let status = {
            let child = self.child.as_mut().unwrap();
            if child.try_wait()?.is_none() {
                if let Err(kill_error) = child.kill() {
                    if child.try_wait()?.is_none() {
                        return Err(kill_error);
                    }
                }
            }
            child.wait()?
        };
        self.child = None;
        Ok(status)
    }
}

impl Drop for MutationChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

impl DeploymentImageAdapter for SideEffectAdapter {
    async fn identify(
        &mut self,
        _: &SetDeploymentImageRequest,
    ) -> Result<TargetIdentity, TargetReadError> {
        Ok(TargetIdentity {
            deployment_uid: "deployment-uid-1".into(),
            resource_version: "resource-version-0".into(),
        })
    }

    async fn apply(
        &mut self,
        _: &SetDeploymentImageRequest,
        _: &TargetIdentity,
    ) -> Result<ApplyOutcome, ()> {
        fs::write(&self.call_count_path, b"1").map_err(|_| ())?;
        fs::write(&self.ready_path, b"provider-side-effect-complete").map_err(|_| ())?;
        std::future::pending::<Result<ApplyOutcome, ()>>().await
    }

    async fn observe(
        &mut self,
        _: &SetDeploymentImageRequest,
    ) -> Result<ReceiverObservation, ()> {
        Err(())
    }
}

#[test]
fn v011_upgrade_matrix_names_every_historical_state_and_ambiguity() {
    let matrix: Value = serde_json::from_slice(MATRIX_BYTES).unwrap();
    assert_eq!(required_str(&matrix, "format"), MATRIX_FORMAT);
    let old_binary = format!(
        "v0.1.1 lifecycle test binary built from tagged source {SOURCE_COMMIT} with the recorded \
         test-only harness overlay"
    );
    let new_binary = "v0.2.0 Slice 2 candidate binary (not implemented in Slice 1)";
    assert_eq!(required_str(&matrix, "old_binary"), old_binary);
    assert_eq!(required_str(&matrix, "new_binary"), new_binary);
    let cases = matrix["cases"].as_array().unwrap();
    assert_eq!(cases.len(), FIXTURE_CASES.len());
    let mut names = BTreeSet::new();
    for (actual, expected) in cases.iter().zip(FIXTURE_CASES) {
        assert!(names.insert(required_str(actual, "name")));
        assert_eq!(required_str(actual, "name"), expected.name);
        assert_eq!(required_str(actual, "initial_state"), expected.state);
        assert_eq!(required_str(actual, "crash_point"), expected.crash_point);
        assert_eq!(required_str(actual, "expected_state"), expected.state);
        assert_eq!(required_str(actual, "old_binary"), old_binary);
        assert_eq!(required_str(actual, "new_binary"), new_binary);
        assert_eq!(
            actual["provider_call_count"].as_u64().unwrap(),
            expected.provider_call_count as u64
        );
        assert_eq!(
            required_str(actual, "receipt_identity"),
            expected.receipt_identity
        );
        assert_eq!(
            required_str(actual, "backup_fact"),
            "required_before_upgrade_but_not_implemented_in_slice_1"
        );
        assert_eq!(
            required_str(actual, "permitted_operator_action"),
            "fixture_verification_only_until_slice_2_contract"
        );
    }
}

#[test]
#[ignore = "invoked by the pinned-tag KAP-0060 fixture generation script"]
fn v011_fixture_mutation_child() {
    if std::env::var_os("KAPSEL_KAP0060_MUTATION_CHILD").is_none() {
        return;
    }
    let database = PathBuf::from(std::env::var_os("KAPSEL_KAP0060_DATABASE").unwrap());
    let ready_path = PathBuf::from(std::env::var_os("KAPSEL_KAP0060_READY").unwrap());
    let call_count_path =
        PathBuf::from(std::env::var_os("KAPSEL_KAP0060_CALL_COUNT").unwrap());
    let mut gateway = Gateway::open_for_test(database).unwrap();
    let mut adapter = SideEffectAdapter {
        ready_path,
        call_count_path,
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(gateway.run_once_with_adapter(&mut adapter, None))
        .unwrap();
    unreachable!("the fixture parent must stop this process after the side effect");
}

#[tokio::test]
#[ignore = "invoked only in an overlaid, detached v0.1.1 source worktree"]
async fn v011_fixture_generation() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.1");
    let output = PathBuf::from(std::env::var_os("KAPSEL_KAP0060_FIXTURES").unwrap());
    assert!(!output.exists(), "fixture output must not already exist");
    create_private_directory(&output);
    let output = fs::canonicalize(output).unwrap();
    for case in FIXTURE_CASES {
        generate_fixture(&output, case).await;
    }
}

#[test]
#[ignore = "invoked against freshly generated v0.1.1 fixtures"]
fn v011_fixture_verification() {
    let output = PathBuf::from(std::env::var_os("KAPSEL_KAP0060_FIXTURES").unwrap());
    let output = fs::canonicalize(output).unwrap();
    let harness_sha256 = std::env::var("KAPSEL_KAP0060_HARNESS_SHA256").unwrap();
    let matrix_path = PathBuf::from(std::env::var_os("KAPSEL_KAP0060_MATRIX").unwrap());
    assert_eq!(fs::read(&matrix_path).unwrap(), MATRIX_BYTES);
    for case in FIXTURE_CASES {
        verify_fixture(&output, case, &harness_sha256);
    }
}

async fn generate_fixture(output: &Path, case: &FixtureCase) {
    let fixture = output.join(case.name);
    create_private_directory(&fixture);
    let receipts = fixture.join("receipts");
    create_private_directory(&receipts);
    let receipts = fs::canonicalize(receipts).unwrap();
    let database = fixture.join("journal.sqlite3");
    let operation = request();
    assert_eq!(operation.operation_id, OPERATION_ID);

    let provider_call_count = match case.name {
        "requested" => {
            let gateway = Gateway::open_for_test(&database).unwrap();
            assert!(matches!(
                gateway.submit_exact_with_fault_for_test(
                    &operation,
                    &authorization(&operation),
                    Some(FaultPoint::RequestedCommitted),
                ),
                Err(GatewayError::InjectedFault)
            ));
            0
        },
        "authorized" => {
            let gateway = Gateway::open_for_test(&database).unwrap();
            assert!(matches!(
                gateway.submit_exact_with_fault_for_test(
                    &operation,
                    &authorization(&operation),
                    Some(FaultPoint::AuthorizedCommitted),
                ),
                Err(GatewayError::InjectedFault)
            ));
            0
        },
        "not_attempted" => {
            let mut gateway = submitted_gateway(&database, &operation);
            let mut adapter = TargetRoutingAdapter::permanent(
                OPERATION_ID,
                TargetRejection::ContainerNotFound,
            );
            assert!(matches!(
                gateway
                    .run_once_with_adapter(
                        &mut adapter,
                        Some(FaultPoint::TargetRejectedCommitted),
                    )
                    .await,
                Err(GatewayError::InjectedFault)
            ));
            adapter.apply_order.len()
        },
        "apply_started_before_call" => {
            let mut gateway = submitted_gateway(&database, &operation);
            let mut adapter = failed_adapter(&database, &operation);
            assert!(matches!(
                gateway
                    .run_once_with_adapter(
                        &mut adapter,
                        Some(FaultPoint::ApplyStartedCommitted),
                    )
                    .await,
                Err(GatewayError::InjectedFault)
            ));
            adapter.apply_calls
        },
        "apply_started_after_side_effect" => {
            let gateway = submitted_gateway(&database, &operation);
            drop(gateway);
            generate_ambiguous_side_effect(&database, &fixture);
            1
        },
        "receiver_observed" | "receipt_prepared" | "receipt_written" | "finalized" => {
            generate_receiver_or_receipt_fixture(case.name, &database, &receipts, &operation).await
        },
        _ => unreachable!("the static fixture matrix contains only known cases"),
    };
    assert_eq!(provider_call_count, case.provider_call_count);
    write_private_file(
        &fixture.join("provider-call-count.txt"),
        provider_call_count.to_string().as_bytes(),
    );
    write_manifest(&fixture, case);
}

fn submitted_gateway(database: &Path, operation: &SetDeploymentImageRequest) -> Gateway {
    let gateway = Gateway::open_for_test(database).unwrap();
    gateway
        .submit_exact_for_test(operation, &authorization(operation))
        .unwrap();
    gateway
}

async fn generate_receiver_or_receipt_fixture(
    name: &str,
    database: &Path,
    receipts: &Path,
    operation: &SetDeploymentImageRequest,
) -> usize {
    let mut gateway = submitted_gateway(database, operation);
    let mut adapter = failed_adapter(database, operation);
    let receiver_fault =
        (name == "receiver_observed").then_some(FaultPoint::ReceiverObservedCommitted);
    let result = gateway
        .run_once_with_adapter(&mut adapter, receiver_fault)
        .await;
    if receiver_fault.is_some() {
        assert!(matches!(result, Err(GatewayError::InjectedFault)));
    } else {
        assert_eq!(result.unwrap(), Some(OperationState::ReceiverObserved));
    }
    if name == "receiver_observed" {
        return adapter.apply_calls;
    }

    let settings = ReceiptSettings {
        signing_seed: &[41_u8; 32],
        key_id: RECEIPT_KEY_ID,
        output_directory: receipts,
    };
    let fault = match name {
        "receipt_prepared" => FaultPoint::ReceiptPreparedCommitted,
        "receipt_written" => FaultPoint::ReceiptWrittenCommitted,
        "finalized" => FaultPoint::FinalizedCommitted,
        _ => unreachable!("receipt generation receives a receipt fixture name"),
    };
    assert!(matches!(
        gateway.finalize_receipt_once_with_fault(&settings, Some(fault)),
        Err(GatewayError::InjectedFault)
    ));
    adapter.apply_calls
}

fn generate_ambiguous_side_effect(database: &Path, fixture: &Path) {
    let ready = fixture.join("provider-side-effect-complete");
    let call_count = fixture.join("provider-call-count.txt");
    let mut child = spawn_mutation_child(database, &ready, &call_count);
    wait_for_mutation_side_effect(&mut child, &ready).unwrap();
    let status = child.terminate_and_wait().unwrap();
    assert!(!status.success());
    assert_eq!(fs::read_to_string(&call_count).unwrap(), "1");
    set_private_file_mode(&ready);
    set_private_file_mode(&call_count);
}

fn wait_for_mutation_side_effect(child: &mut MutationChild, ready: &Path) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if ready.exists() {
            return Ok(());
        }
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Err(format!(
                "historical mutation child exited before its side effect: {status}"
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("historical mutation child did not reach its side effect".into())
}

fn spawn_mutation_child(database: &Path, ready: &Path, call_count: &Path) -> MutationChild {
    MutationChild::new(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "gateway::tests::v011_upgrade::v011_fixture_mutation_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KAPSEL_KAP0060_MUTATION_CHILD", "1")
            .env("KAPSEL_KAP0060_DATABASE", database)
            .env("KAPSEL_KAP0060_READY", ready)
            .env("KAPSEL_KAP0060_CALL_COUNT", call_count)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

#[test]
fn mutation_child_guard_reaps_a_pending_child_when_the_parent_path_fails() {
    let database = database_path("mutation-child-guard-failure");
    let operation = request();
    let gateway = submitted_gateway(&database, &operation);
    drop(gateway);
    let fixture = database.parent().unwrap();
    let ready = fixture.join("guard-provider-side-effect-complete");
    let call_count = fixture.join("guard-provider-call-count.txt");
    let child_id;
    let forced_failure: Result<(), &str> = {
        let mut child = spawn_mutation_child(&database, &ready, &call_count);
        child_id = child.id();
        wait_for_mutation_side_effect(&mut child, &ready).unwrap();
        Err("forced parent failure after child readiness")
    };
    assert_eq!(
        forced_failure,
        Err("forced parent failure after child readiness")
    );
    let raw_pid = i32::try_from(child_id).unwrap();
    let pid = rustix::process::Pid::from_raw(raw_pid).unwrap();
    assert_eq!(
        rustix::process::test_kill_process(pid),
        Err(rustix::io::Errno::SRCH)
    );
    fs::remove_dir_all(fixture).unwrap();
}

fn write_manifest(fixture: &Path, case: &FixtureCase) {
    let database = fixture.join("journal.sqlite3");
    let worker_lock = fixture.join("journal.sqlite3.kap0038-worker.lock");
    assert!(worker_lock.is_file());
    let receipt = receipt_facts(&database);
    let receipt_value = if let Some((path, digest, bytes, key_id)) = receipt {
        let receipt_path = PathBuf::from(&path);
        let published = receipt_path.is_file();
        assert_eq!(published, case.receipt_identity == "frozen_and_published");
        assert_eq!(sha256_bytes(&bytes), digest);
        let relative_path = receipt_path.strip_prefix(fixture).unwrap();
        json!({
            "identity": case.receipt_identity,
            "frozen_absolute_path": path,
            "relative_path": relative_path,
            "digest": digest,
            "bytes_sha256": sha256_bytes(&bytes),
            "key_id": key_id,
            "published": published,
        })
    } else {
        assert_eq!(case.receipt_identity, "absent");
        json!({ "identity": "absent" })
    };
    let manifest = json!({
        "format": FIXTURE_FORMAT,
        "tag_object": TAG_OBJECT,
        "source_commit": SOURCE_COMMIT,
        "cargo_package_version": env!("CARGO_PKG_VERSION"),
        "test_harness_sha256": std::env::var("KAPSEL_KAP0060_HARNESS_SHA256").unwrap(),
        "case": case.name,
        "durable_state": case.state,
        "crash_point": case.crash_point,
        "provider_call_count": case.provider_call_count,
        "database": {
            "relative_path": "journal.sqlite3",
            "sha256": sha256_file(&database),
        },
        "worker_lock_relative_path": "journal.sqlite3.kap0038-worker.lock",
        "receipt": receipt_value,
        "receipt_path_portability":
            "absolute_final_fixture_path; verify_in_place_only; do_not_copy_or_relocate",
    });
    let mut bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    bytes.push(b'\n');
    write_private_file(&fixture.join("manifest.json"), &bytes);
}

fn verify_fixture(output: &Path, case: &FixtureCase, harness_sha256: &str) {
    let fixture = output.join(case.name);
    assert_private_directory(&fixture);
    assert_private_directory(&fixture.join("receipts"));
    let manifest_bytes = fs::read(fixture.join("manifest.json")).unwrap();
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(required_str(&manifest, "format"), FIXTURE_FORMAT);
    assert_eq!(required_str(&manifest, "tag_object"), TAG_OBJECT);
    assert_eq!(required_str(&manifest, "source_commit"), SOURCE_COMMIT);
    assert_eq!(required_str(&manifest, "cargo_package_version"), "0.1.1");
    assert_eq!(
        required_str(&manifest, "test_harness_sha256"),
        harness_sha256
    );
    assert_eq!(required_str(&manifest, "case"), case.name);
    assert_eq!(required_str(&manifest, "durable_state"), case.state);
    assert_eq!(required_str(&manifest, "crash_point"), case.crash_point);
    assert_eq!(
        manifest["provider_call_count"].as_u64().unwrap(),
        case.provider_call_count as u64
    );
    assert_eq!(
        required_str(&manifest, "receipt_path_portability"),
        "absolute_final_fixture_path; verify_in_place_only; do_not_copy_or_relocate"
    );

    let database = fixture.join("journal.sqlite3");
    let lock = fixture.join("journal.sqlite3.kap0038-worker.lock");
    assert_private_file(&database);
    assert_private_file(&lock);
    let before_sha256 = sha256_file(&database);
    assert_eq!(required_str(&manifest["database"], "sha256"), before_sha256);
    let gateway = Gateway::open_for_test(&database).unwrap();
    assert_eq!(
        gateway.get(OPERATION_ID).unwrap(),
        Some(operation_state(case.state))
    );
    drop(gateway);
    assert_eq!(sha256_file(&database), before_sha256);
    assert_eq!(
        fs::read_to_string(fixture.join("provider-call-count.txt")).unwrap(),
        case.provider_call_count.to_string()
    );

    let receipt = receipt_facts(&database);
    if case.receipt_identity == "absent" {
        assert!(receipt.is_none());
        assert_eq!(required_str(&manifest["receipt"], "identity"), "absent");
        assert_eq!(fs::read_dir(fixture.join("receipts")).unwrap().count(), 0);
    } else {
        let (path, digest, bytes, key_id) = receipt.unwrap();
        assert_eq!(
            required_str(&manifest["receipt"], "identity"),
            case.receipt_identity
        );
        assert_eq!(required_str(&manifest["receipt"], "frozen_absolute_path"), path);
        assert_eq!(required_str(&manifest["receipt"], "digest"), digest);
        assert_eq!(required_str(&manifest["receipt"], "bytes_sha256"), digest);
        assert_eq!(required_str(&manifest["receipt"], "key_id"), key_id);
        assert_eq!(key_id, RECEIPT_KEY_ID);
        assert_eq!(sha256_bytes(&bytes), digest);
        let path = PathBuf::from(path);
        assert_eq!(path.parent().unwrap(), fixture.join("receipts"));
        let should_be_published = case.receipt_identity == "frozen_and_published";
        assert_eq!(path.is_file(), should_be_published);
        assert_eq!(manifest["receipt"]["published"].as_bool().unwrap(), should_be_published);
        if should_be_published {
            assert_private_file(&path);
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
    assert!(!fixture.join("backup").exists());
}

fn receipt_facts(database: &Path) -> Option<(String, String, Vec<u8>, String)> {
    let connection = Connection::open(database).unwrap();
    connection
        .query_row(
            "SELECT receipt_path, receipt_digest, receipt_bytes, receipt_key_id
             FROM kubernetes_image_operations
             WHERE operation_id = ?1
                   AND receipt_path IS NOT NULL
                   AND receipt_digest IS NOT NULL
                   AND receipt_bytes IS NOT NULL
                   AND receipt_key_id IS NOT NULL",
            [OPERATION_ID],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .unwrap()
}

fn operation_state(state: &str) -> OperationState {
    match state {
        "requested" => OperationState::Requested,
        "authorized" => OperationState::Authorized,
        "not_attempted" => OperationState::NotAttempted,
        "apply_started" => OperationState::ApplyStarted,
        "receiver_observed" => OperationState::ReceiverObserved,
        "receipt_prepared" => OperationState::ReceiptPrepared,
        "receipt_written" => OperationState::ReceiptWritten,
        "finalized" => OperationState::Finalized,
        _ => unreachable!("the static fixture matrix contains only durable states"),
    }
}

fn required_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}

fn sha256_file(path: &Path) -> String {
    sha256_bytes(&fs::read(path).unwrap())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        })
}

fn create_private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    set_private_file_mode(path);
}

fn set_private_file_mode(path: &Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn assert_private_directory(path: &Path) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

fn assert_private_file(path: &Path) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}
