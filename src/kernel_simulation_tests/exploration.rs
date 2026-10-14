//! Reduce concrete histories and retain exact inputs before execution, including unknown crashes.

use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use super::{
    generation::{self, Generation},
    run::{generate, replay},
    trace::*,
    world::hex,
};
use crate::gateway::{Defect, Delivery, StorageWrite};

pub(super) fn source_identity() -> String {
    use std::process::Command;
    let output = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()
        .unwrap();
    assert!(output.status.success() && output.stdout.len() < 1024 * 1024);
    let mut files = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    files.sort_unstable();
    files.dedup();
    let mut hash = Sha256::new();
    let mut source_bytes_total = 0;
    for path in files {
        let text = std::str::from_utf8(path).unwrap();
        if !Path::new(text).try_exists().unwrap() {
            continue;
        }
        let bytes = fs::read(text).unwrap();
        source_bytes_total += bytes.len();
        assert!(source_bytes_total <= 64 * 1024 * 1024);
        hash.update(u64::try_from(path.len()).unwrap().to_le_bytes());
        hash.update(path);
        hash.update(u64::try_from(bytes.len()).unwrap().to_le_bytes());
        hash.update(bytes);
    }
    hex(&hash.finalize())
}

pub(super) fn select(
    commit: Option<(StorageWrite, Delivery)>,
    cut: Cut,
    lose_response: bool,
    sign: bool,
) -> Action {
    Action::Select(Selection {
        commit,
        cut,
        lose_response,
        sign,
    })
}

pub(super) fn trace(seed: u64, mut prefix: Vec<Action>) -> Trace {
    prefix.extend([
        Action::Restore,
        select(None, Cut::None, false, true),
        Action::Reopen { catalog: false },
        select(None, Cut::None, false, true),
    ]);
    Trace {
        seed,
        peers: 1,
        effects: vec![],
        actions: prefix,
        defect: None,
        require_progress: true,
        requested_steps: 0,
        meaningful_decisions: 0,
        source_sha256: String::new(),
        executable_sha256: String::new(),
    }
}

pub(super) fn multi_trace(seed: u64, peers: usize, prefix: Vec<Action>) -> Trace {
    let mut input = trace(seed, vec![]);
    input.peers = peers;
    input.actions = prefix;
    input.actions.push(Action::Restore);
    for peer in 0..peers {
        input
            .actions
            .extend([Action::Peer(peer), select(None, Cut::None, false, true)]);
    }
    input
}

pub(super) fn without_peer(input: &Trace, removed: usize) -> Trace {
    let mut candidate = input.clone();
    candidate.peers -= 1;
    if !candidate.effects.is_empty() {
        candidate.effects.remove(removed);
    }
    let mut selected = 0;
    candidate.actions = input
        .actions
        .iter()
        .filter_map(|action| {
            if let Action::Peer(peer) = *action {
                selected = peer;
                return (peer != removed).then(|| Action::Peer(peer - usize::from(peer > removed)));
            }
            match *action {
                Action::Restore
                | Action::Trust(_)
                | Action::Reopen { .. }
                | Action::Writes(_)
                | Action::ReplaceCatalog => Some(action.clone()),
                Action::CancelAtIo { point, contender }
                    if selected != removed && contender != removed =>
                {
                    Some(Action::CancelAtIo {
                        point,
                        contender: contender - usize::from(contender > removed),
                    })
                },
                Action::CancelAtIo { .. } => None,
                _ => (selected != removed).then(|| action.clone()),
            }
        })
        .collect();
    candidate
}

pub(super) async fn same_finding(input: &Trace, law: &'static str) -> bool {
    replay(input, true).await.err().is_some_and(|finding| {
        finding.law == law
            && input
                .defect
                .is_none_or(|defect| finding.defect_reached.contains(&defect))
    })
}

pub(super) async fn minimize(mut input: Trace, law: &'static str) -> Trace {
    input.require_progress = law == "healthy_progress";
    let mut peer = input.peers;
    while peer > 0 && input.peers > 1 {
        peer -= 1;
        let candidate = without_peer(&input, peer);
        if same_finding(&candidate, law).await {
            input = candidate;
        }
    }
    let mut index = 0;
    while index < input.actions.len() {
        if input.require_progress && matches!(input.actions[index], Action::Restore) {
            index += 1;
            continue;
        }
        let mut candidate = input.clone();
        candidate.actions.remove(index);
        if same_finding(&candidate, law).await {
            input = candidate;
        } else {
            index += 1;
        }
    }
    for index in 0..input.actions.len() {
        let simpler = match input.actions[index] {
            Action::Select(_) => Some(select(None, Cut::None, false, true)),
            Action::Receiver(_) => Some(Action::Receiver(Receiver::Healthy)),
            Action::Signer(_) => Some(Action::Signer(Signer::Original)),
            Action::CancelAtIo { contender, .. } => Some(Action::CancelAtIo {
                point: IoPoint::Preflight,
                contender,
            }),
            _ => None,
        };
        if let Some(action) = simpler {
            let mut candidate = input.clone();
            candidate.actions[index] = action;
            if same_finding(&candidate, law).await {
                input = candidate;
            }
        }
    }
    input
}

pub(super) fn defect_inputs() -> Vec<Trace> {
    let cases = [
        (
            Defect::CustodyIgnored,
            Effect::Git,
            vec![Action::CustodyDuringIo(IoPoint::Mutation)],
        ),
        (
            Defect::StaleTrust,
            Effect::Kubernetes,
            vec![
                select(None, Cut::BeforeAttempt, false, false),
                Action::SubstituteTrustKey,
            ],
        ),
        (
            Defect::CatalogConflictAccepted,
            Effect::Git,
            vec![
                select(None, Cut::BeforeAttempt, false, false),
                Action::ReplaceCatalog,
            ],
        ),
        (
            Defect::GitInferredAcknowledgement,
            Effect::Git,
            vec![
                select(None, Cut::Unsent, false, false),
                Action::GitRef { new: true },
                select(None, Cut::Frozen, false, false),
            ],
        ),
        (
            Defect::GitObservationSubstitution,
            Effect::Git,
            vec![select(None, Cut::Frozen, false, false)],
        ),
        (
            Defect::ReceiptRewrite,
            Effect::Git,
            vec![select(None, Cut::None, false, true), Action::Trust(false)],
        ),
        (
            Defect::Remint,
            Effect::Kubernetes,
            vec![select(None, Cut::Unsent, false, false)],
        ),
        (
            Defect::InitialUnknown,
            Effect::Kubernetes,
            vec![select(None, Cut::Frozen, false, false)],
        ),
        (
            Defect::NoOp,
            Effect::Kubernetes,
            vec![select(None, Cut::None, false, true), Action::AssertProgress],
        ),
        (
            Defect::NoOp,
            Effect::Git,
            vec![select(None, Cut::None, false, true), Action::AssertProgress],
        ),
        (
            Defect::WrongPeerRead,
            Effect::Kubernetes,
            vec![
                select(None, Cut::BeforeAttempt, false, false),
                Action::Peer(1),
                select(None, Cut::BeforeAttempt, false, false),
            ],
        ),
        (
            Defect::WrongSigner,
            Effect::Git,
            vec![
                select(None, Cut::Frozen, false, false),
                Action::Reopen { catalog: false },
                Action::Signer(Signer::Rotated),
                select(None, Cut::None, false, true),
            ],
        ),
    ];
    cases
        .into_iter()
        .map(|(defect, effect, actions)| {
            let mut input = multi_trace(3, 2, actions);
            input.effects = vec![effect, Effect::Kubernetes];
            input.defect = Some(defect);
            input
        })
        .collect()
}

pub(super) fn defect_law(defect: Defect) -> &'static str {
    match defect {
        Defect::Remint => "dispatch_provenance",
        Defect::InitialUnknown => "initial_result",
        Defect::NoOp => "healthy_progress",
        Defect::UnconditionalWrite => "conditional_binding",
        Defect::GitObservationSubstitution => "frozen_io_binding",
        Defect::ReceiptRewrite => "original_receipt_bytes",
        Defect::WrongSigner => "original_signer",
        Defect::WrongPeerRead => "original_intent",
        Defect::GitInferredAcknowledgement => "git_acknowledgement_binding",
        Defect::CatalogConflictAccepted => "catalog_identity_conflict",
        Defect::StaleTrust => "original_trust_disclosure",
        Defect::CustodyIgnored => "custody_after_io",
    }
}

pub(super) fn check_replay_result(input: &Trace, result: Checked) {
    if let Some(defect) = input.defect {
        let finding = result.unwrap_err();
        assert_eq!(finding.law, defect_law(defect));
        assert!(finding.defect_reached.contains(&defect));
    } else {
        assert_eq!(result, Ok(()));
    }
}

pub(super) fn durable_writes(effect: Effect) -> Vec<StorageWrite> {
    let mut writes = vec![StorageWrite::Admission];
    if effect == Effect::Kubernetes {
        writes.push(StorageWrite::Authorization);
    }
    writes.extend([
        StorageWrite::Rejection,
        StorageWrite::Attempt,
        StorageWrite::Response,
        StorageWrite::Observation,
        StorageWrite::Receipt,
    ]);
    writes
}

pub(super) fn delivery_inputs() -> Vec<Trace> {
    [Effect::Kubernetes, Effect::Git]
        .into_iter()
        .flat_map(|effect| {
            durable_writes(effect).into_iter().flat_map(move |write| {
                [
                    Delivery::Confirmed,
                    Delivery::NoCommit,
                    Delivery::LostAcknowledgement,
                ]
                .into_iter()
                .map(move |delivery| {
                    let mut actions = match write {
                        StorageWrite::Admission => vec![],
                        StorageWrite::Authorization => vec![select(
                            Some((StorageWrite::Admission, Delivery::LostAcknowledgement)),
                            Cut::None,
                            false,
                            false,
                        )],
                        StorageWrite::Rejection
                        | StorageWrite::Attempt
                        | StorageWrite::Response => {
                            vec![select(None, Cut::BeforeAttempt, false, false)]
                        },
                        StorageWrite::Observation => {
                            vec![select(None, Cut::ResponseRecorded, false, false)]
                        },
                        StorageWrite::Receipt => vec![select(None, Cut::Frozen, false, false)],
                    };
                    if write == StorageWrite::Rejection {
                        actions.push(Action::Receiver(Receiver::StaleVersion));
                    }
                    actions.extend([
                        select(Some((write, delivery)), Cut::None, false, true),
                        Action::Receiver(Receiver::Healthy),
                        select(None, Cut::None, false, true),
                        Action::AssertProgress,
                    ]);
                    let mut input = trace(0, actions);
                    input.effects = vec![effect];
                    input
                })
            })
        })
        .collect()
}

pub(super) async fn generated(seed: u64, steps: usize) -> (Trace, Checked, RunReport) {
    let mut input = generation::input(seed, steps);
    let (result, report) = generate(&mut input, &mut Generation::new(seed, steps, None)).await;
    (input, result, report)
}

pub(super) fn read_trace(path: &Path) -> Trace {
    use std::io::Read;
    assert!(path.is_absolute() && fs::symlink_metadata(path).unwrap().is_file());
    let mut bytes = Vec::new();
    fs::File::open(path)
        .unwrap()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 64 * 1024);
    let input: Trace = serde_json::from_slice(&bytes).unwrap();
    assert!(input.actions.len() <= 256 && (1..=4).contains(&input.peers));
    assert!(input.effects.is_empty() || input.effects.len() == input.peers);
    input
}

fn persist_document(path: &Path, bytes: &[u8]) {
    assert!(bytes.len() <= 64 * 1024);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

pub(super) fn persist_trace(path: &Path, input: &Trace) {
    let temporary = path.with_extension("pending");
    persist_document(&temporary, &serde_json::to_vec(input).unwrap());
    fs::rename(temporary, path).unwrap();
    fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

fn check_job_result(result: &Checked) {
    if let Err(finding) = result {
        println!(
            "KAPSEL_KERNEL_FINDING {}",
            serde_json::to_string(finding).unwrap()
        );
    }
    assert_eq!(result, &Ok(()), "bounded job found a law violation");
}

async fn retain_finding(
    directory: &Path,
    case: usize,
    input: &Trace,
    finding: &Finding,
    reached: &RunReport,
) {
    let minimized = minimize(input.clone(), finding.law).await;
    persist_document(
        &directory.join(format!("finding-{case}.json")),
        &serde_json::to_vec(&minimized).unwrap(),
    );
    let reduced = replay(&minimized, true).await.unwrap_err();
    assert_eq!(reduced.law, finding.law, "minimization changed the finding");
    let report = serde_json::json!({
        "case": case, "finding": finding, "minimized_finding": reduced, "reached": reached,
        "require_progress": input.require_progress,
        "replay": format!("KAPSEL_KERNEL_REPLAY={} {} {} --ignored --exact --nocapture",
            directory.join(format!("case-{case}.json")).display(),
            std::env::current_exe().unwrap().display(),
            "kernel_simulation_tests::kernel_trace_exploration_or_replay"),
    });
    persist_document(
        &directory.join("failure.json"),
        &serde_json::to_vec(&report).unwrap(),
    );
}

pub(super) async fn explore_or_replay() {
    if let Ok(path) = std::env::var("KAPSEL_KERNEL_REPLAY") {
        let input = read_trace(&PathBuf::from(path));
        let result = replay(&input, true).await;
        if std::env::var_os("KAPSEL_KERNEL_JOB").is_some() {
            check_job_result(&result);
        } else {
            check_replay_result(&input, result);
        }
        println!("KAPSEL_KERNEL_REPLAYED cases=1");
        return;
    }
    let requested = PathBuf::from(std::env::var("KAPSEL_KERNEL_EVIDENCE").unwrap());
    assert!(requested.is_absolute() && fs::symlink_metadata(&requested).unwrap().is_dir());
    let directory = fs::canonicalize(requested).unwrap();
    crate::gateway::validate_private_directory(&directory).unwrap();
    let source = source_identity();
    let executable = fs::read(std::env::current_exe().unwrap()).unwrap();
    let executable_digest = hex(&Sha256::digest(&executable));
    let number = |name: &str, default: u64| {
        std::env::var(name).map_or(default, |value| value.parse::<u64>().unwrap())
    };
    let seed = number("KAPSEL_KERNEL_SEED", 0);
    let cases = usize::try_from(number("KAPSEL_KERNEL_CASES", 32)).unwrap();
    let steps = usize::try_from(number("KAPSEL_KERNEL_STEPS", 32)).unwrap();
    let shards = usize::try_from(number("KAPSEL_KERNEL_SHARDS", 1)).unwrap();
    let shard = usize::try_from(number("KAPSEL_KERNEL_SHARD_INDEX", 0)).unwrap();
    let duration = number("KAPSEL_KERNEL_DURATION_MS", 0);
    assert!((1..=10_000).contains(&cases) && (8..=32).contains(&steps));
    assert!((1..=128).contains(&shards) && shards <= cases && shard < shards);
    let started = Instant::now();

    let mut completed = 0;
    let mut reached = RunReport::default();
    let mut case = shard;
    loop {
        if duration == 0 && case >= cases {
            break;
        }
        assert!(
            completed < 10_000,
            "history retention ceiling reached before duration expiry"
        );
        let case_seed = seed.wrapping_add(u64::try_from(case).unwrap());
        let mut input = generation::input(case_seed, steps);
        input.source_sha256.clone_from(&source);
        input.executable_sha256.clone_from(&executable_digest);
        let path = directory.join(format!("case-{case}.json"));
        persist_document(&path, &serde_json::to_vec(&input).unwrap());
        let (result, report) = generate(
            &mut input,
            &mut Generation::new(case_seed, steps, Some(path)),
        )
        .await;
        if let Err(finding) = &result {
            report.print();
            retain_finding(&directory, case, &input, finding, &report).await;
        }
        reached.merge(report);
        if std::env::var_os("KAPSEL_KERNEL_JOB").is_some() {
            check_job_result(&result);
        } else {
            check_replay_result(&input, result);
        }
        completed += 1;
        case += shards;
        // Real monotonic time: paused Tokio time must not turn duration into a count shortcut.
        if duration > 0 && started.elapsed() >= Duration::from_millis(duration) {
            break;
        }
    }
    reached.print();
    if duration > 0 {
        println!(
            "KAPSEL_KERNEL_DURATION_COMPLETED seed={seed} shard={shard}/{shards} \
            cases={completed} steps={steps} duration_ms={duration} elapsed_ms={}",
            started.elapsed().as_millis()
        );
    } else {
        println!(
            "KAPSEL_KERNEL_COMPLETED seed={seed} shard={shard}/{shards} \
            cases={completed} steps={steps}"
        );
    }
    println!("KAPSEL_KERNEL_EVIDENCE source={source} executable={executable_digest}");
}
