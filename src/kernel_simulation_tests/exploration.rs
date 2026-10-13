//! Generate and reduce action inputs, retain exact documents, and replay through the same laws.

use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{
    cases::{assignments, FRESH_CUTS},
    run::replay,
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
        // Cached names include unstaged deletions; the digest describes the current source bytes.
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
        input.actions.push(Action::Peer(peer));
        input.actions.push(select(None, Cut::None, false, true));
    }
    input.actions.push(Action::Reopen { catalog: false });
    for peer in (0..peers).rev() {
        input.actions.push(Action::Peer(peer));
        input.actions.push(select(None, Cut::None, false, true));
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

pub(super) fn deliberate_inputs() -> Vec<Trace> {
    let joins = [
        (Cut::BeforeAttempt, Receiver::Failed),
        (Cut::Unsent, Receiver::Pending),
        (Cut::AttemptAcknowledgementLost, Receiver::Replaced),
        (Cut::ResponseLost, Receiver::Unavailable),
        (Cut::ResponseRecorded, Receiver::WrongGeneration),
        (Cut::ObservationLost, Receiver::Pending),
        (Cut::Frozen, Receiver::Replaced),
        (Cut::None, Receiver::StaleVersion),
    ];
    assignments(2)
        .into_iter()
        .flat_map(|effects| {
            joins
                .into_iter()
                .enumerate()
                .map(move |(index, (cut, receiver))| {
                    let mut input = multi_trace(
                        u64::try_from(index).unwrap(),
                        2,
                        vec![
                            Action::Peer(1),
                            Action::CancelAtIo {
                                point: [
                                    IoPoint::Preflight,
                                    IoPoint::Mutation,
                                    IoPoint::Observation,
                                ][index % 3],
                                contender: 0,
                            },
                            Action::Peer(0),
                            Action::ReplaceCatalog,
                            Action::Receiver(Receiver::Unavailable),
                            select(None, Cut::None, false, false),
                            Action::Receiver(Receiver::Healthy),
                            select(None, cut, false, false),
                            Action::Trust(false),
                            select(None, Cut::None, false, false),
                            Action::Trust(true),
                            Action::ReplaceCatalog,
                            Action::Reopen { catalog: false },
                            Action::Receiver(receiver),
                            select(None, Cut::ObservationLost, false, false),
                            select(None, Cut::None, false, false),
                            Action::Receiver(Receiver::Failed),
                            select(None, Cut::Frozen, false, false),
                            select(
                                Some((StorageWrite::Receipt, Delivery::NoCommit)),
                                Cut::None,
                                false,
                                true,
                            ),
                            Action::Reopen { catalog: false },
                            Action::Signer(Signer::Rotated),
                            select(
                                Some((StorageWrite::Receipt, Delivery::LostAcknowledgement)),
                                Cut::None,
                                false,
                                true,
                            ),
                            Action::Signer(Signer::Original),
                            select(None, Cut::None, false, true),
                        ],
                    );
                    input.effects = effects.clone();
                    if index == 1 && matches!(effects[0], Effect::Git) {
                        let pending = input
                            .actions
                            .iter()
                            .position(|action| {
                                matches!(action, Action::Receiver(Receiver::Pending))
                            })
                            .unwrap();
                        input
                            .actions
                            .insert(pending + 1, Action::GitRef { new: true });
                    }
                    input
                })
        })
        .collect()
}

#[allow(
    clippy::too_many_lines,
    reason = "keep each seeded defect with its intended law and reached input"
)]
pub(super) fn defect_cases() -> Vec<(Defect, &'static str, Vec<Action>)> {
    vec![
        (
            Defect::CustodyIgnored,
            "custody_after_io",
            vec![Action::CustodyDuringIo(IoPoint::Mutation)],
        ),
        (
            Defect::StaleTrust,
            "original_trust_disclosure",
            vec![
                select(None, Cut::BeforeAttempt, false, false),
                Action::SubstituteTrustKey,
            ],
        ),
        (
            Defect::CatalogConflictAccepted,
            "catalog_identity_conflict",
            vec![
                select(None, Cut::BeforeAttempt, false, false),
                Action::ReplaceCatalog,
            ],
        ),
        (
            Defect::GitInferredAcknowledgement,
            "git_acknowledgement_binding",
            vec![
                select(None, Cut::Unsent, false, false),
                Action::GitRef { new: true },
                select(None, Cut::Frozen, false, false),
            ],
        ),
        (
            Defect::GitObservationSubstitution,
            "frozen_io_binding",
            vec![select(None, Cut::Frozen, false, false)],
        ),
        (
            Defect::ReceiptRewrite,
            "original_receipt_bytes",
            vec![
                select(None, Cut::None, false, true),
                Action::Peer(1),
                Action::Trust(false),
            ],
        ),
        (
            Defect::Remint,
            "dispatch_provenance",
            vec![select(None, Cut::Unsent, false, false)],
        ),
        (
            Defect::Remint,
            "dispatch_provenance",
            vec![Action::CancelAtIo {
                point: IoPoint::Mutation,
                contender: 1,
            }],
        ),
        (
            Defect::InitialUnknown,
            "initial_result",
            vec![select(None, Cut::Frozen, false, false)],
        ),
        (Defect::NoOp, "healthy_progress", vec![]),
        (
            Defect::StatusProjectionSwap,
            "stored_read_projection",
            vec![select(None, Cut::Frozen, false, false)],
        ),
        (
            Defect::DispositionProjectionSwap,
            "execution_disposition_projection",
            vec![select(None, Cut::BeforeAttempt, false, false)],
        ),
        (
            Defect::TargetProjectionSwap,
            "stored_read_projection",
            vec![select(None, Cut::BeforeAttempt, false, false)],
        ),
        (
            Defect::WrongPeerRead,
            "original_intent",
            vec![
                select(None, Cut::BeforeAttempt, false, false),
                Action::Peer(1),
                select(None, Cut::BeforeAttempt, false, false),
            ],
        ),
        (
            Defect::WrongSigner,
            "original_signer",
            vec![
                select(None, Cut::Frozen, false, false),
                Action::ReplaceCatalog,
                Action::Reopen { catalog: false },
                Action::Signer(Signer::Rotated),
                select(None, Cut::None, false, true),
            ],
        ),
        (
            Defect::ReceiptProjectionSwap,
            "receipt_binding",
            vec![
                Action::Receiver(Receiver::Pending),
                select(None, Cut::Frozen, false, false),
            ],
        ),
        (
            Defect::ReplicaSwap,
            "frozen_io_binding",
            vec![
                Action::Receiver(Receiver::Pending),
                select(None, Cut::Frozen, false, false),
            ],
        ),
    ]
}

pub(super) fn defect_inputs() -> Vec<Trace> {
    defect_cases()
        .into_iter()
        .flat_map(|(defect, _, prefix)| {
            let assignments = match defect {
                Defect::GitInferredAcknowledgement | Defect::GitObservationSubstitution => {
                    vec![vec![Effect::Git; 2]]
                },
                Defect::ReceiptRewrite => {
                    vec![vec![Effect::Git; 2], vec![Effect::Git, Effect::Kubernetes]]
                },
                Defect::WrongSigner
                | Defect::StatusProjectionSwap
                | Defect::TargetProjectionSwap
                | Defect::DispositionProjectionSwap
                | Defect::CatalogConflictAccepted
                | Defect::StaleTrust
                | Defect::CustodyIgnored => vec![
                    vec![Effect::Kubernetes; 2],
                    vec![Effect::Git; 2],
                    vec![Effect::Kubernetes, Effect::Git],
                ],
                _ => vec![vec![Effect::Kubernetes; 2]],
            };
            assignments.into_iter().map(move |effects| {
                let mut input = multi_trace(3, 2, prefix.clone());
                input.effects = effects;
                if matches!(
                    defect,
                    Defect::WrongSigner
                        | Defect::StatusProjectionSwap
                        | Defect::TargetProjectionSwap
                        | Defect::DispositionProjectionSwap
                        | Defect::CatalogConflictAccepted
                        | Defect::StaleTrust
                        | Defect::CustodyIgnored
                ) && matches!(input.effects[1], Effect::Git)
                {
                    input.actions.insert(0, Action::Peer(1));
                }
                input.defect = Some(defect);
                input
            })
        })
        .collect()
}

pub(super) fn defect_law(defect: Defect) -> &'static str {
    match defect {
        Defect::Remint => "dispatch_provenance",
        Defect::InitialUnknown => "initial_result",
        Defect::NoOp => "healthy_progress",
        Defect::UnconditionalWrite => "conditional_binding",
        Defect::ReplicaSwap | Defect::GitObservationSubstitution => "frozen_io_binding",
        Defect::ReceiptRewrite => "original_receipt_bytes",
        Defect::StatusProjectionSwap | Defect::TargetProjectionSwap => "stored_read_projection",
        Defect::DispositionProjectionSwap => "execution_disposition_projection",
        Defect::WrongSigner => "original_signer",
        Defect::WrongPeerRead => "original_intent",
        Defect::ReceiptProjectionSwap => "receipt_binding",
        Defect::GitInferredAcknowledgement => "git_acknowledgement_binding",
        Defect::CatalogConflictAccepted => "catalog_identity_conflict",
        Defect::StaleTrust => "original_trust_disclosure",
        Defect::CustodyIgnored => "custody_after_io",
    }
}

pub(super) fn check_replay_result(input: &Trace, result: Checked) {
    if let Some(defect) = input.defect {
        let finding = result.unwrap_err();
        assert_eq!(
            finding.law,
            defect_law(defect),
            "unrelated failure is not defect detection"
        );
        assert!(
            finding.defect_reached.contains(&defect),
            "defect branch was not reached"
        );
    } else {
        assert_eq!(result, Ok(()));
    }
}

pub(super) fn generated(seed: u64, steps: usize) -> Trace {
    let writes = [
        StorageWrite::Admission,
        StorageWrite::Authorization,
        StorageWrite::Attempt,
        StorageWrite::Response,
        StorageWrite::Observation,
        StorageWrite::Receipt,
    ];
    let delivery = if seed & 1 == 0 {
        Delivery::NoCommit
    } else {
        Delivery::LostAcknowledgement
    };
    let effects = match seed % 3 {
        0 => vec![Effect::Kubernetes; 3],
        1 => vec![Effect::Git; 3],
        _ => vec![Effect::Kubernetes, Effect::Git, Effect::Git],
    };
    let mut write = writes[usize::try_from((seed / 2) % 6).unwrap()];
    if matches!(effects[0], Effect::Git) && write == StorageWrite::Authorization {
        write = StorageWrite::Admission;
    }
    let point = match (seed / 3) % 3 {
        0 => IoPoint::Preflight,
        1 => IoPoint::Mutation,
        _ => IoPoint::Observation,
    };
    let mut actions = vec![
        Action::Peer(1),
        Action::CustodyDuringIo(point),
        Action::Peer(2),
        Action::CancelAtIo {
            point,
            contender: 0,
        },
        Action::Peer(0),
        select(Some((write, delivery)), Cut::None, false, true),
    ];
    let mut random = seed.wrapping_add(1);
    for _ in 0..steps {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        actions.push(Action::Peer(usize::try_from((random / 8) % 3).unwrap()));
        actions.push(match random % 11 {
            0 => Action::Receiver(Receiver::Unavailable),
            1 => Action::Receiver(Receiver::Pending),
            2 => Action::Receiver(Receiver::Failed),
            3 => Action::Receiver(Receiver::Healthy),
            4 => Action::Reopen {
                catalog: random & 8 == 0,
            },
            5 => Action::Trust(false),
            6 => Action::Trust(true),
            7 => Action::ReplaceCatalog,
            8 => Action::SubstituteTrustKey,
            9 => Action::Signer(if random & 16 == 0 {
                Signer::Rotated
            } else {
                Signer::Original
            }),
            _ => select(
                None,
                FRESH_CUTS[usize::try_from((random / 11) % 7).unwrap()],
                false,
                random & 8 == 0,
            ),
        });
    }
    let mut input = multi_trace(seed, 3, actions);
    input.effects = effects;
    input
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

fn check_job_result(result: &Checked) {
    if let Err(finding) = result {
        println!(
            "KAPSEL_KERNEL_FINDING {}",
            serde_json::to_string(finding).unwrap()
        );
    }
    assert_eq!(result, &Ok(()), "bounded job found a law violation");
}

async fn retain_finding(directory: &Path, case: usize, input: &Trace, finding: &Finding) {
    let minimized = minimize(input.clone(), finding.law).await;
    persist_document(
        &directory.join(format!("finding-{case}.json")),
        &serde_json::to_vec(&minimized).unwrap(),
    );
    let reduced = replay(&minimized, true).await;
    if std::env::var_os("KAPSEL_KERNEL_JOB").is_some() {
        let reduced = reduced.unwrap_err();
        assert_eq!(reduced.law, finding.law, "minimization changed the finding");
        let report = serde_json::json!({
            "case": case, "finding": finding, "minimized_finding": reduced,
        });
        persist_document(
            &directory.join("failure.json"),
            &serde_json::to_vec(&report).unwrap(),
        );
    } else {
        check_replay_result(&minimized, reduced);
    }
}

pub(super) async fn explore_or_replay() {
    if let Ok(directory) = std::env::var("KAPSEL_KERNEL_REPLAY_DIRECTORY") {
        let directory = PathBuf::from(directory);
        assert!(directory.is_absolute() && fs::symlink_metadata(&directory).unwrap().is_dir());
        let mut paths = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert!((1..=10_000).contains(&paths.len()));
        paths.sort();
        for path in &paths {
            let input = read_trace(path);
            assert!(input.defect.is_none() && input.require_progress);
            check_replay_result(&input, replay(&input, true).await);
        }
        println!("KAPSEL_KERNEL_REPLAYED cases={}", paths.len());
        return;
    }
    if let Ok(path) = std::env::var("KAPSEL_KERNEL_REPLAY") {
        let path = PathBuf::from(path);
        let input = read_trace(&path);
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
    let steps = usize::try_from(number("KAPSEL_KERNEL_STEPS", 12)).unwrap();
    let shards = usize::try_from(number("KAPSEL_KERNEL_SHARDS", 1)).unwrap();
    let shard = usize::try_from(number("KAPSEL_KERNEL_SHARD_INDEX", 0)).unwrap();
    assert!((1..=10_000).contains(&cases) && (8..=48).contains(&steps));
    assert!((1..=128).contains(&shards) && shards <= cases && shard < shards);
    let inputs = if std::env::var_os("KAPSEL_KERNEL_DEFECTS").is_some() {
        defect_inputs()
    } else if std::env::var_os("KAPSEL_KERNEL_DELIBERATE").is_some() {
        deliberate_inputs()
    } else {
        (0..cases)
            .map(|case| generated(seed.wrapping_add(u64::try_from(case).unwrap()), steps))
            .collect::<Vec<_>>()
    };
    let mut completed = 0;
    for (case, mut input) in inputs.into_iter().enumerate() {
        if case % shards != shard {
            continue;
        }
        input.source_sha256.clone_from(&source);
        input.executable_sha256.clone_from(&executable_digest);
        persist_document(
            &directory.join(format!("case-{case}.json")),
            &serde_json::to_vec(&input).unwrap(),
        );
        let result = replay(&input, true).await;
        if let Err(finding) = &result {
            retain_finding(&directory, case, &input, finding).await;
        }
        if std::env::var_os("KAPSEL_KERNEL_JOB").is_some() {
            check_job_result(&result);
        } else {
            check_replay_result(&input, result);
        }
        completed += 1;
    }
    println!(
        "KAPSEL_KERNEL_COMPLETED seed={seed} shard={shard}/{shards} \
         cases={completed} steps={steps}"
    );
    println!("KAPSEL_KERNEL_EVIDENCE source={source} executable={executable_digest}");
}
