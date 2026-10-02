//! Replayable long lifecycle simulations over the private deterministic adapter seam.

use std::{
    error::Error,
    fs, io,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::{
    ApplyOutcome, DeploymentImageAdapter, ExactAuthorization, FaultPoint, Gateway, GatewayError,
    OperationResult, OperationState, ReceiptSettings, ReceiverObservation,
    SetDeploymentImageRequest, TargetIdentity, TargetReadError,
};

const DEFAULT_SEED: u64 = 0x004b_4150_3030_3338;
const DEFAULT_CASES: usize = 10_000;
// Lifecycle simulation is separate from capacity qualification. Keep each independent
// fixture history below the journal's retained-identity ceiling without pruning old history.
const CASES_PER_JOURNAL: usize = 100;

struct SimulationScratch(PathBuf);

impl Drop for SimulationScratch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let _ = fs::write(self.0.join("status"), "FINDING\n");
        }
    }
}

struct Generator(u64);

impl Generator {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn index(&mut self, length: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(length).unwrap()).unwrap()
    }
}

type SimulationResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy)]
struct CaseSchedule {
    target_deferrals: usize,
    receiver_reopens: usize,
    apply_fault: FaultPoint,
    publication_fault: FaultPoint,
}

#[derive(Clone, Copy)]
struct SimulationPaths<'a> {
    journal: &'a Path,
}

struct SimulationAdapter {
    transient_reads_remaining: usize,
    apply_calls: usize,
    observation: ReceiverObservation,
}

#[allow(
    clippy::unused_async_trait_impl,
    reason = "the simulation adapter mirrors the production async provider seam"
)]
impl DeploymentImageAdapter for SimulationAdapter {
    async fn identify(
        &mut self,
        _: &SetDeploymentImageRequest,
    ) -> Result<TargetIdentity, TargetReadError> {
        if self.transient_reads_remaining > 0 {
            self.transient_reads_remaining -= 1;
            Err(TargetReadError::Transient)
        } else {
            Ok(TargetIdentity {
                deployment_uid: "simulation-deployment-uid".into(),
                resource_version: "simulation-resource-version-1".into(),
            })
        }
    }

    async fn apply(
        &mut self,
        permission: crate::gateway::DispatchPermission,
    ) -> Result<ApplyOutcome, ()> {
        let (request, target) = permission.into_payload();
        assert_eq!(target.deployment_uid, "simulation-deployment-uid");
        assert_eq!(target.resource_version, "simulation-resource-version-1");
        assert_eq!(Some(request.immutable_image_digest), self.observation.image);
        assert_eq!(
            Some(request.operation_id),
            self.observation.operation_marker
        );
        self.apply_calls += 1;
        Ok(ApplyOutcome {
            accepted: true,
            requested_generation: Some(2),
            deployment_uid: Some("simulation-deployment-uid".into()),
            resource_version: Some("simulation-resource-version-2".into()),
        })
    }

    async fn observe(
        &mut self,
        _: &SetDeploymentImageRequest,
        _: &ApplyOutcome,
    ) -> Result<ReceiverObservation, ()> {
        Ok(self.observation.clone())
    }
}

#[tokio::test]
#[ignore = "long replayable lane; run through tests/qualification/run-simulation.sh"]
async fn seeded_lifecycle_crash_simulation_preserves_invariants() {
    let seed = environment_number("KAPSEL_SIMULATION_SEED", DEFAULT_SEED);
    let cases = usize::try_from(environment_number(
        "KAPSEL_SIMULATION_CASES",
        u64::try_from(DEFAULT_CASES).unwrap(),
    ))
    .unwrap();
    assert!(cases > 0, "seed={seed} requires at least one case");

    let shard_count = usize::try_from(environment_number("KAPSEL_SIMULATION_SHARDS", 1)).unwrap();
    let shard_index =
        usize::try_from(environment_number("KAPSEL_SIMULATION_SHARD_INDEX", 0)).unwrap();
    assert!(
        shard_count > 0 && shard_count <= 128 && shard_index < shard_count,
        "seed={seed} invalid shard {shard_index}/{shard_count}"
    );

    assert!(
        std::env::var_os("KAPSEL_SIMULATION_SCRATCH_ROOT").is_some(),
        "select an owned KAPSEL_SIMULATION_SCRATCH_ROOT for the long lane"
    );
    assert!(
        seed != 0 && shard_count <= cases,
        "nonzero seed and nonempty shards required"
    );
    let result = run_simulation(seed, cases, shard_index, shard_count).await;
    assert!(
        result.is_ok(),
        "seed={seed} shard={shard_index}/{shard_count} result={result:?}"
    );
}

#[tokio::test]
async fn simulation_uses_independent_bounded_histories() {
    let journals = run_simulation(DEFAULT_SEED ^ 1, CASES_PER_JOURNAL + 1, 0, 1)
        .await
        .unwrap();
    assert_eq!(journals, 2);
}

#[tokio::test]
async fn simulation_preserves_preexisting_scratch() {
    let seed = DEFAULT_SEED ^ 2;
    let parent = std::env::var_os("KAPSEL_SIMULATION_SCRATCH_ROOT")
        .map_or_else(std::env::temp_dir, PathBuf::from);
    let earlier = parent.join(format!(
        "kapsel-lifecycle-simulation-{}-{seed}-0",
        std::process::id()
    ));
    // Exclusive fixture creation gives this test ownership; never adopt an earlier directory.
    private_directory(&earlier).unwrap();
    fs::write(earlier.join("preserve"), b"earlier replay evidence").unwrap();
    run_simulation(seed, 1, 0, 1).await.unwrap();
    assert_eq!(
        fs::read(earlier.join("preserve")).unwrap(),
        b"earlier replay evidence"
    );
    fs::remove_dir_all(earlier).unwrap();
}

async fn run_simulation(
    seed: u64,
    cases: usize,
    shard_index: usize,
    shard_count: usize,
) -> SimulationResult<usize> {
    // Only the small deterministic regression may fall back to the host temporary directory.
    let parent = std::env::var_os("KAPSEL_SIMULATION_SCRATCH_ROOT")
        .map_or_else(std::env::temp_dir, std::path::PathBuf::from);
    let metadata = fs::symlink_metadata(&parent)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("simulation scratch root must be a real directory".into());
    }
    let externally_selected = std::env::var_os("KAPSEL_SIMULATION_SCRATCH_ROOT").is_some();
    if externally_selected {
        if !parent.is_absolute() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("selected simulation root must be absolute and private".into());
        }
        for ancestor in parent.ancestors() {
            if fs::symlink_metadata(ancestor)?.file_type().is_symlink() {
                return Err("selected simulation root has a symlink component".into());
            }
        }
    }
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let root = parent.join(format!(
        "kapsel-lifecycle-simulation-{}-{seed}-{shard_index}-{nonce}",
        std::process::id()
    ));
    // Exclusive creation: never remove a directory from an earlier process or invocation.
    private_directory(&root)?;
    let _scratch = SimulationScratch(root.clone());
    let root_identity = fs::symlink_metadata(&root)?;
    if externally_selected && root_identity.uid() != metadata.uid() {
        return Err("selected simulation root must be owned by the test user".into());
    }
    fs::write(root.join("status"), "RUNNING\n")?;
    eprintln!("KAPSEL_SIMULATION_SCRATCH {}", root.display());
    let mut executed = 0;
    let mut generator = Generator(seed);
    let apply_faults = [
        FaultPoint::TargetObserved,
        FaultPoint::ApplyStartedCommitted,
        FaultPoint::AttemptCommitAcknowledgementLost,
        FaultPoint::ApplyReturned,
        FaultPoint::ApplyOutcomeCommitted,
        FaultPoint::ReceiverRead,
        FaultPoint::ReceiverObservedCommitted,
    ];
    let publication_faults = [
        FaultPoint::BeforeReceiptCommit,
        FaultPoint::ReceiptCommitAcknowledgementLost,
        FaultPoint::FinalizedCommitted,
    ];

    for case in 0..cases {
        let schedule = CaseSchedule {
            target_deferrals: generator.index(4),
            receiver_reopens: generator.index(4),
            apply_fault: apply_faults[generator.index(apply_faults.len())],
            publication_fault: publication_faults[generator.index(publication_faults.len())],
        };
        if case % shard_count == shard_index {
            let batch = (case / shard_count) / CASES_PER_JOURNAL;
            let journal_path = root.join(format!("journal-{batch}.sqlite3"));
            let paths = SimulationPaths {
                journal: &journal_path,
            };
            fs::write(
                root.join("replay"),
                format!("seed={seed} case={case} shard={shard_index}/{shard_count}\n"),
            )?;
            if let Err(error) = run_case(seed, case, paths, schedule).await {
                fs::write(root.join("status"), "FINDING\n")?;
                return Err(error);
            }
            executed += 1;
        }
    }

    let journals = fs::read_dir(&root)?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "sqlite3")
        })
        .count();
    let current = fs::symlink_metadata(&root)?;
    if !current.is_dir()
        || current.dev() != root_identity.dev()
        || current.ino() != root_identity.ino()
    {
        return Err("simulation scratch identity changed; refusing cleanup".into());
    }
    fs::remove_dir_all(&root)?;
    println!(
        "KAPSEL_SIMULATION_COMPLETED seed={seed} shard={shard_index}/{shard_count} cases={executed}"
    );
    Ok(journals)
}

async fn run_case(
    seed: u64,
    case: usize,
    paths: SimulationPaths<'_>,
    schedule: CaseSchedule,
) -> SimulationResult {
    let request = request(case);
    let authorization = authorization(&request, case);
    let mut adapter = failed_adapter(&request, schedule.target_deferrals);
    let gateway = Gateway::open_for_test(paths.journal)?;
    gateway.submit_exact_for_test(&request, &authorization)?;
    drop(gateway);

    for deferral in 0..schedule.target_deferrals {
        let mut gateway = Gateway::open_for_test(paths.journal)?;
        let result = gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await;
        assert!(
            matches!(result, Err(GatewayError::KubernetesTargetObservation)),
            "seed={seed} case={case} deferral={deferral} result={result:?}"
        );
        assert_eq!(
            gateway.get(&request.operation_id)?,
            Some(OperationState::Authorized),
            "seed={seed} case={case} deferral={deferral}"
        );
        assert_eq!(adapter.apply_calls, 0, "seed={seed} case={case}");
    }

    let mut gateway = Gateway::open_for_test(paths.journal)?;
    let result = gateway
        .run_operation_once_with_adapter_and_fault(
            &request.operation_id,
            &mut adapter,
            Some(schedule.apply_fault),
        )
        .await;
    assert!(
        matches!(result, Err(GatewayError::InjectedFault)),
        "seed={seed} case={case} apply_fault={:?} result={result:?}",
        schedule.apply_fault
    );
    drop(gateway);

    let mut gateway = recover_receiver(seed, case, paths.journal, &request, &mut adapter).await?;
    for reopen in 0..schedule.receiver_reopens {
        drop(gateway);
        gateway = Gateway::open_for_test(paths.journal)?;
        assert_eq!(
            gateway
                .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
                .await?,
            None,
            "seed={seed} case={case} receiver_reopen={reopen}"
        );
        assert_eq!(
            gateway.get(&request.operation_id)?,
            Some(OperationState::ReceiverObserved),
            "seed={seed} case={case} receiver_reopen={reopen}"
        );
    }

    let expected_apply_calls = usize::from(!matches!(
        schedule.apply_fault,
        FaultPoint::ApplyStartedCommitted | FaultPoint::AttemptCommitAcknowledgementLost
    ));
    assert_eq!(
        adapter.apply_calls, expected_apply_calls,
        "seed={seed} case={case} apply_fault={:?}",
        schedule.apply_fault
    );
    assert_eq!(
        gateway.result(&request.operation_id)?,
        Some(OperationResult::Failed),
        "seed={seed} case={case}"
    );
    recover_receipt(seed, case, paths, schedule, gateway, &request)
}

async fn recover_receiver(
    seed: u64,
    case: usize,
    journal_path: &Path,
    request: &SetDeploymentImageRequest,
    adapter: &mut SimulationAdapter,
) -> SimulationResult<Gateway> {
    let mut gateway = Gateway::open_for_test(journal_path)?;
    let state = gateway
        .get(&request.operation_id)?
        .ok_or_else(|| io::Error::other("simulation operation disappeared"))?;
    if matches!(
        state,
        OperationState::Authorized | OperationState::ApplyStarted
    ) {
        assert_eq!(
            gateway
                .run_operation_once_with_adapter(&request.operation_id, adapter)
                .await?,
            Some(OperationState::ReceiverObserved),
            "seed={seed} case={case}"
        );
    } else {
        assert_eq!(state, OperationState::ReceiverObserved);
    }
    Ok(gateway)
}

fn recover_receipt(
    seed: u64,
    case: usize,
    paths: SimulationPaths<'_>,
    schedule: CaseSchedule,
    gateway: Gateway,
    request: &SetDeploymentImageRequest,
) -> SimulationResult {
    let settings = ReceiptSettings {
        signing_seed: &[13_u8; 32],
        key_id: "simulation-receipt-key",
    };
    let result = gateway.finalize_operation_receipt_once_with_fault(
        &request.operation_id,
        &settings,
        Some(schedule.publication_fault),
    );
    assert!(
        matches!(result, Err(GatewayError::InjectedFault)),
        "seed={seed} case={case} publication_fault={:?} result={result:?}",
        schedule.publication_fault
    );
    drop(gateway);

    let gateway = Gateway::open_for_test(paths.journal)?;
    if gateway.get(&request.operation_id)? != Some(OperationState::Finalized) {
        assert_eq!(
            gateway.finalize_operation_receipt_once(
                &request.operation_id,
                &ReceiptSettings {
                    signing_seed: &[99_u8; 32],
                    key_id: "rotated-simulation-key",
                }
            )?,
            Some(OperationState::Finalized),
            "seed={seed} case={case} publication_fault={:?}",
            schedule.publication_fault
        );
    }
    assert_eq!(
        gateway.get(&request.operation_id)?,
        Some(OperationState::Finalized),
        "seed={seed} case={case}"
    );
    let receipt = gateway
        .receipt_reference(&request.operation_id)?
        .ok_or_else(|| io::Error::other("simulation receipt disappeared"))?;
    let (bytes, digest) =
        Gateway::read_loaded_receipt(gateway.loaded_for_test(&request.operation_id)?.unwrap())?;
    assert_eq!(digest, receipt.digest, "seed={seed} case={case}");
    assert!(!bytes.is_empty());
    Ok(())
}

fn environment_number(name: &str, default: u64) -> u64 {
    std::env::var(name).map_or(default, |value| value.parse().unwrap())
}

fn private_directory(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)
}

fn request(case: usize) -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: format!("simulation-op-{case}"),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .into(),
    }
}

fn authorization(request: &SetDeploymentImageRequest, case: usize) -> ExactAuthorization {
    ExactAuthorization {
        approved_target: case.is_multiple_of(2).then(|| crate::ApprovedTarget {
            uid: "simulation-deployment-uid".into(),
            resource_version: "simulation-resource-version-1".into(),
        }),
        authorization_id: format!("simulation-auth-{case}"),
        operation_id: request.operation_id.clone(),
        namespace: request.namespace.clone(),
        deployment: request.deployment.clone(),
        container: request.container.clone(),
        immutable_image_digest: request.immutable_image_digest.clone(),
    }
}

fn failed_adapter(
    request: &SetDeploymentImageRequest,
    transient_reads_remaining: usize,
) -> SimulationAdapter {
    SimulationAdapter {
        transient_reads_remaining,
        apply_calls: 0,
        observation: ReceiverObservation {
            deployment_uid: Some("simulation-deployment-uid".into()),
            resource_version: Some("simulation-resource-version-3".into()),
            current_generation: Some(2),
            observed_generation: Some(2),
            image: Some(request.immutable_image_digest.clone()),
            operation_marker: Some(request.operation_id.clone()),
            desired_replicas: Some(1),
            updated_replicas: Some(0),
            available_replicas: Some(0),
            unavailable_replicas: Some(1),
            rollout_condition_type: Some("Progressing".into()),
            rollout_condition_status: Some("False".into()),
            rollout_condition_reason: Some("ProgressDeadlineExceeded".into()),
        },
    }
}
