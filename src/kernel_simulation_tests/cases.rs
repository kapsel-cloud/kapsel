//! Boundary witnesses and reached controls; each retained trace adds an independent observation.

use std::sync::{Arc, Mutex};

use super::{
    exploration::*,
    laws::Checker,
    run::{open, replay, replay_report},
    trace::*,
    world::{text, Adapter, Intent, Observations, Store},
};
use crate::{
    application::ServiceConfiguration,
    gateway::{Defect, Delivery, StorageControl, StorageWrite},
    test_scratch::Scratch,
};

async fn check_stores(input: &Trace) {
    for virtualized in [true, false] {
        assert_eq!(
            replay(input, virtualized).await,
            Ok(()),
            "{input:?}/{virtualized}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn every_durable_write_reaches_each_delivery_on_both_stores() {
    for effect in [Effect::Kubernetes, Effect::Git] {
        for virtualized in [true, false] {
            let mut reached = RunReport::default();
            for input in delivery_inputs()
                .into_iter()
                .filter(|input| input.effects[0] == effect)
            {
                let (result, report) = replay_report(&input, virtualized).await;
                assert_eq!(result, Ok(()), "{input:?}/{virtualized}");
                assert_eq!(report.requested_deliveries, report.consumed_deliveries());
                reached.merge(report);
            }
            println!("delivery matrix {effect:?} virtual={virtualized}");
            reached.print();
            for write in durable_writes(effect) {
                for delivery in [
                    Delivery::Confirmed,
                    Delivery::NoCommit,
                    Delivery::LostAcknowledgement,
                ] {
                    assert!(
                        reached.writes.iter().any(|event| {
                            event.write == write && event.delivery == delivery && event.consumed
                        }),
                        "missing {effect:?}/{write:?}/{delivery:?}"
                    );
                }
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_missed_or_shadowed_delivery_is_incomplete_not_a_passing_witness() {
    for prefix in [
        vec![],
        vec![Action::Writes(false)],
        vec![
            select(None, Cut::BeforeAttempt, false, false),
            Action::Receiver(Receiver::StaleVersion),
            Action::Writes(false),
        ],
    ] {
        let mut actions = prefix;
        actions.push(select(
            Some((StorageWrite::Rejection, Delivery::NoCommit)),
            Cut::None,
            false,
            true,
        ));
        let input = trace(0, actions);
        for virtualized in [true, false] {
            let (result, report) = replay_report(&input, virtualized).await;
            assert_eq!(result.unwrap_err().law, "fault_not_reached");
            assert_eq!(report.requested_deliveries, 1);
            assert_eq!(report.consumed_deliveries(), 0);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn consumed_checkpoint_reporting_includes_recovery_without_reminting() {
    for effect in [Effect::Kubernetes, Effect::Git] {
        for (cut, consumed) in [(Cut::Frozen, 2), (Cut::ObservationLost, 1)] {
            let mut input = trace(
                0,
                vec![
                    select(None, Cut::Unsent, false, false),
                    select(None, cut, false, false),
                ],
            );
            input.effects = vec![effect];
            for virtualized in [true, false] {
                let (result, report) = replay_report(&input, virtualized).await;
                assert_eq!(result, Ok(()));
                assert_eq!(report.requested_cuts, 2);
                assert_eq!(
                    report.consumed_cuts, consumed,
                    "ReceiverRead is fresh-only; Frozen is not"
                );
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn warm_repair_and_cold_recovery_progress_without_repairing_an_unrelated_peer() {
    for effects in assignments(2) {
        for cut in [Cut::BeforeAttempt, Cut::Unsent, Cut::Frozen] {
            for cold in [false, true] {
                let mut actions = vec![
                    select(None, cut, false, false),
                    Action::Peer(1),
                    select(None, Cut::BeforeAttempt, false, false),
                    Action::Receiver(Receiver::Unavailable),
                    Action::SubstituteTrustKey,
                    Action::Peer(0),
                    Action::Writes(false),
                    select(None, Cut::None, false, true),
                    Action::Writes(true),
                    Action::Signer(Signer::Invalid),
                    select(None, Cut::None, false, true),
                    Action::Signer(Signer::Original),
                ];
                if cold {
                    actions.push(Action::Reopen { catalog: false });
                }
                actions.extend([select(None, Cut::None, false, true), Action::AssertProgress]);
                let mut input = multi_trace(0, 2, actions);
                input.effects = effects.clone();
                check_stores(&input).await;
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn concrete_old_trace_keeps_original_identities_without_regenerating_the_seed() {
    // Actual c302e2b generator output, seed 1 / 8 steps, with its original executable identity.
    let original = include_str!("../../tests/fixtures/kernel_original_trace.json");
    let input: Trace = serde_json::from_str(original).unwrap();
    assert_eq!(input.peers, 3);
    assert_eq!(input.effects, vec![Effect::Git; 3]);
    let source = input.source_sha256.clone();
    let executable = input.executable_sha256.clone();
    assert_eq!(source.len(), 64);
    assert_eq!(executable.len(), 64);
    check_stores(&input).await;
    let encoded = serde_json::to_value(&input).unwrap();
    assert_eq!(
        encoded["actions"],
        serde_json::from_str::<serde_json::Value>(original).unwrap()["actions"]
    );
    assert_ne!(
        encoded["actions"],
        serde_json::to_value(generated(input.seed, 8)).unwrap()["actions"]
    );
    assert_eq!(encoded["source_sha256"], source);
    assert_eq!(encoded["executable_sha256"], executable);
}

pub(super) const FRESH_CUTS: [Cut; 7] = [
    Cut::BeforeAttempt,
    Cut::Unsent,
    Cut::AttemptAcknowledgementLost,
    Cut::ResponseLost,
    Cut::ResponseRecorded,
    Cut::ObservationLost,
    Cut::Frozen,
];

pub(super) fn assignments(peers: usize) -> [Vec<Effect>; 3] {
    [
        vec![Effect::Kubernetes; peers],
        vec![Effect::Git; peers],
        (0..peers)
            .map(|peer| {
                if peer == 0 {
                    Effect::Kubernetes
                } else {
                    Effect::Git
                }
            })
            .collect(),
    ]
}

#[tokio::test(start_paused = true)]
async fn fresh_checkpoints_precede_cancellation_and_recover_under_original_authority() {
    for effects in assignments(2) {
        for cut in FRESH_CUTS {
            for receiver in [
                Receiver::Healthy,
                Receiver::Failed,
                Receiver::Pending,
                Receiver::Replaced,
                Receiver::StaleVersion,
                Receiver::WrongGeneration,
                Receiver::Unavailable,
            ] {
                let mut input = multi_trace(
                    0,
                    2,
                    vec![
                        Action::Receiver(receiver),
                        select(None, cut, false, false),
                        Action::Reopen { catalog: false },
                    ],
                );
                input.effects = effects.clone();
                check_stores(&input).await;
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn retained_contention_reopen_and_catalog_conflict_orders_preserve_all_peers() {
    for effects in assignments(2) {
        for owner in 0..2 {
            for point in [IoPoint::Preflight, IoPoint::Mutation, IoPoint::Observation] {
                // Cross-peer interference retains all six orders. Same-ID exclusion needs one
                // order, not another copy of the catalog/reopen permutation matrix.
                for (contender, orders) in [
                    (
                        1 - owner,
                        &[
                            [0, 1, 2],
                            [0, 2, 1],
                            [1, 0, 2],
                            [1, 2, 0],
                            [2, 0, 1],
                            [2, 1, 0],
                        ][..],
                    ),
                    (owner, &[[0, 1, 2]][..]),
                ] {
                    for order in orders {
                        let events = [
                            Action::CancelAtIo { point, contender },
                            Action::ReplaceCatalog,
                            Action::Reopen { catalog: false },
                        ];
                        let mut actions = vec![
                            Action::Peer(0),
                            select(None, Cut::BeforeAttempt, false, false),
                            Action::Peer(1),
                            select(None, Cut::BeforeAttempt, false, false),
                            Action::Peer(owner),
                        ];
                        actions.extend(order.map(|index| events[index].clone()));
                        let mut input = multi_trace(0, 2, actions);
                        input.effects = effects.clone();
                        check_stores(&input).await;
                    }
                }
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn sqlite_and_virtual_write_refusal_preserve_facts_until_same_id_repair() {
    for effects in assignments(2) {
        for prefix in [
            vec![],
            vec![select(
                Some((StorageWrite::Admission, Delivery::LostAcknowledgement)),
                Cut::None,
                false,
                false,
            )],
            vec![select(None, Cut::BeforeAttempt, false, false)],
            vec![select(None, Cut::Unsent, false, false)],
            vec![select(None, Cut::Frozen, false, false)],
            vec![select(None, Cut::None, false, true)],
            // A refused stale-preflight write must not adopt the newly observed target.
            vec![
                select(None, Cut::BeforeAttempt, false, false),
                Action::Receiver(Receiver::Replaced),
            ],
        ] {
            let mut actions = prefix;
            actions.extend([
                Action::Writes(false),
                select(None, Cut::None, false, true),
                Action::Reopen { catalog: true },
                select(None, Cut::None, false, true),
            ]);
            let mut input = multi_trace(0, 2, actions);
            input.effects = effects.clone();
            check_stores(&input).await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn deliberate_recovery_joins_use_the_same_all_peer_laws() {
    for input in deliberate_inputs() {
        check_stores(&input).await;
    }
}

#[tokio::test(start_paused = true)]
async fn kubernetes_observation_retry_distinguishes_same_result_facts_and_committed_loss() {
    for virtualized in [true, false] {
        for delivery in [Delivery::NoCommit, Delivery::LostAcknowledgement] {
            for cold_retry in [false, true] {
                let scratch = Scratch::new();
                let control = if virtualized {
                    StorageControl::virtualized()
                } else {
                    StorageControl::default()
                };
                let intent = Intent::new(0);
                let configuration = ServiceConfiguration {
                    journal_path: scratch.0.join("journal.sqlite3"),
                    authorization_trust: vec![intent.trust()],
                    approvals: vec![intent.approval()],
                };
                let signing = (intent.receipt_seed, intent.receipt_key.clone());
                let mut adapter = Adapter {
                    intent,
                    store: Store {
                        control: control.clone(),
                        path: configuration.journal_path.clone(),
                        virtualized,
                    },
                    io: Arc::new(Mutex::new(Observations::default())),
                    receiver: Receiver::Pending,
                    lose_response: false,
                    fresh: true,
                    gate: None,
                };
                let mut checker = Checker::default();
                let mut app = open(configuration.clone(), &control);
                let mut selection = Selection {
                    commit: Some((StorageWrite::Observation, delivery)),
                    cut: Cut::None,
                    lose_response: false,
                    sign: false,
                };
                selection
                    .execute(&mut app, &mut adapter, &mut checker, signing.clone(), 0)
                    .await
                    .unwrap();
                {
                    let io = adapter.io.lock().unwrap();
                    assert_eq!(io.reads, 2, "one preflight and one O1 observation");
                    assert_eq!(io.expected_result, Some("UNKNOWN"));
                }
                assert_eq!(
                    text(
                        &adapter.store.raw(&adapter.intent.request.operation_id),
                        "state"
                    ),
                    Some(if delivery == Delivery::NoCommit {
                        "apply_started"
                    } else {
                        "receiver_observed"
                    })
                );
                // O2 differs in identity, generations, replica counts and condition fields, but
                // still classifies UNKNOWN. Full first-freeze binding cannot hide behind result.
                adapter.receiver = Receiver::Replaced;
                selection.commit = None;
                if cold_retry {
                    drop(app);
                    app = open(configuration.clone(), &control);
                }
                selection
                    .execute(&mut app, &mut adapter, &mut checker, signing.clone(), 1)
                    .await
                    .unwrap();
                let expected_reads = if delivery == Delivery::NoCommit { 3 } else { 2 };
                {
                    let io = adapter.io.lock().unwrap();
                    assert_eq!(io.reads, expected_reads);
                    assert_eq!(io.sends.len(), 1);
                    assert_eq!(io.expected_result, Some("UNKNOWN"));
                    assert_eq!(
                        io.returned.as_ref().unwrap().deployment_uid.as_deref(),
                        Some(if delivery == Delivery::NoCommit {
                            "replacement-uid"
                        } else {
                            adapter.intent.uid.as_str()
                        })
                    );
                }
                let frozen = adapter.store.raw(&adapter.intent.request.operation_id);
                assert_eq!(text(&frozen, "state"), Some("receiver_observed"));
                assert_eq!(text(&frozen, "result"), Some("UNKNOWN"));
                drop(app);
                app = open(configuration, &control);
                selection
                    .execute(&mut app, &mut adapter, &mut checker, signing, 2)
                    .await
                    .unwrap();
                assert_eq!(adapter.io.lock().unwrap().reads, expected_reads);
                assert_eq!(
                    adapter.store.raw(&adapter.intent.request.operation_id),
                    frozen
                );
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn durable_git_acknowledgement_survives_an_opposite_observed_ref() {
    let mut input = trace(
        9,
        vec![
            select(
                Some((StorageWrite::Observation, Delivery::NoCommit)),
                Cut::None,
                false,
                true,
            ),
            Action::GitRef { new: false },
            select(None, Cut::None, false, true),
        ],
    );
    input.effects = vec![Effect::Git];
    check_stores(&input).await;
}

#[tokio::test(start_paused = true)]
async fn replacement_catalog_and_rotated_material_preserve_retained_history() {
    for first in [
        select(
            Some((StorageWrite::Admission, Delivery::LostAcknowledgement)),
            Cut::None,
            false,
            false,
        ),
        select(None, Cut::BeforeAttempt, false, false),
        select(None, Cut::Unsent, false, false),
        select(None, Cut::Frozen, false, false),
        select(None, Cut::None, false, true),
    ] {
        let mut actions = vec![
            Action::Peer(0),
            first,
            Action::Peer(1),
            Action::Receiver(Receiver::Failed),
            select(None, Cut::Frozen, false, false),
            Action::Peer(2),
            select(
                Some((StorageWrite::Attempt, Delivery::LostAcknowledgement)),
                Cut::None,
                false,
                true,
            ),
            Action::ReplaceCatalog,
            Action::Reopen { catalog: false },
            Action::Trust(false),
        ];
        for peer in 0..3 {
            actions.extend([Action::Peer(peer), select(None, Cut::None, false, true)]);
        }
        actions.extend([
            Action::Trust(true),
            Action::Peer(1),
            Action::Signer(Signer::Rotated),
            select(
                Some((StorageWrite::Receipt, Delivery::NoCommit)),
                Cut::None,
                false,
                true,
            ),
            select(
                Some((StorageWrite::Receipt, Delivery::LostAcknowledgement)),
                Cut::None,
                false,
                true,
            ),
        ]);
        for peer in 0..3 {
            actions.extend([Action::Peer(peer), Action::SubstituteTrustKey]);
            for selected in 0..3 {
                actions.extend([Action::Peer(selected), select(None, Cut::None, false, true)]);
            }
            actions.push(Action::Trust(true));
        }
        for peer in (0..3).rev() {
            actions.extend([
                Action::Peer(peer),
                Action::Signer(Signer::Invalid),
                select(None, Cut::None, false, true),
                Action::Signer(Signer::Rotated),
                select(None, Cut::None, false, false),
                select(None, Cut::None, false, true),
                Action::Signer(Signer::Original),
                select(None, Cut::None, false, true),
            ]);
        }
        let mut input = multi_trace(11, 3, actions);
        for effects in [
            vec![Effect::Kubernetes; 3],
            vec![Effect::Git; 3],
            vec![Effect::Kubernetes, Effect::Git, Effect::Git],
        ] {
            input.effects = effects;
            check_stores(&input).await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn suspended_io_rechecks_original_custody_before_advancing_any_peer() {
    for point in [IoPoint::Preflight, IoPoint::Mutation, IoPoint::Observation] {
        let mut input = multi_trace(
            19,
            3,
            vec![
                Action::Peer(0),
                select(None, Cut::Frozen, false, false),
                Action::Peer(1),
                select(None, Cut::None, false, true),
                Action::Peer(2),
                Action::CustodyDuringIo(point),
            ],
        );
        for effects in [
            vec![Effect::Kubernetes; 3],
            vec![Effect::Git; 3],
            vec![Effect::Kubernetes, Effect::Git, Effect::Kubernetes],
            vec![Effect::Git, Effect::Kubernetes, Effect::Git],
        ] {
            input.effects = effects;
            check_stores(&input).await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn fixed_defects_fail_intended_laws_and_correct_counterparts_pass() {
    for input in defect_inputs() {
        let defect = input.defect.unwrap();
        let law = defect_law(defect);
        let mut correct = input.clone();
        correct.defect = None;
        for virtualized in [true, false] {
            let finding = replay(&input, virtualized).await.unwrap_err();
            assert_eq!(finding.law, law);
            assert!(finding.defect_reached.contains(&defect));
            if matches!(defect, Defect::NoOp | Defect::InitialUnknown) {
                assert!(
                    input.actions[..finding.event].iter().all(|action| {
                        !matches!(action, Action::Restore | Action::Reopen { .. })
                    }),
                    "detection must precede reopen or global repair"
                );
            }
            assert_eq!(
                replay(&correct, virtualized).await,
                Ok(()),
                "{correct:?}/{virtualized}"
            );
        }
        println!(
            "KAPSEL_KERNEL_DEFECT {defect:?} {law} actions={}",
            input.actions.len()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn safety_reducer_corpus_preserves_reached_laws_and_serialized_identities() {
    for mut input in defect_inputs()
        .into_iter()
        .filter(|input| matches!(input.defect, Some(Defect::Remint)))
    {
        let defect = input.defect.unwrap();
        let law = defect_law(defect);
        input.source_sha256 = "c".repeat(64);
        input.executable_sha256 = "d".repeat(64);
        let original_actions = input.actions.len();
        let minimum_peers = if input
            .actions
            .iter()
            .any(|action| matches!(action, Action::CancelAtIo { .. }))
        {
            2 // Removing the real contender changes the reached branch.
        } else {
            1
        };
        let reduced = minimize(input, law).await;
        assert!(!reduced.require_progress);
        assert_eq!(reduced.peers, minimum_peers);
        assert!(reduced.actions.len() < original_actions);
        assert_eq!(reduced.source_sha256, "c".repeat(64));
        assert_eq!(reduced.executable_sha256, "d".repeat(64));
        let document = serde_json::to_vec(&reduced).unwrap();
        let reduced: Trace = serde_json::from_slice(&document).unwrap();
        for virtualized in [true, false] {
            check_replay_result(&reduced, replay(&reduced, virtualized).await);
            let mut correct = reduced.clone();
            correct.defect = None;
            assert_eq!(replay(&correct, virtualized).await, Ok(()));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn unrelated_or_ineligible_progress_does_not_qualify_as_defect_detection() {
    let mut input = trace(0, vec![]);
    input.actions.clear();
    input.defect = Some(Defect::Remint);
    let finding = replay(&input, true).await.unwrap_err();
    assert_eq!(finding.law, "ineligible_progress");
    assert_ne!(finding.law, defect_law(Defect::Remint));
    assert!(finding.defect_reached.is_empty());
    input.actions = vec![Action::Restore, select(None, Cut::None, false, false)];
    input.defect = Some(Defect::NoOp);
    for virtualized in [true, false] {
        let finding = replay(&input, virtualized).await.unwrap_err();
        assert_eq!(finding.law, "ineligible_progress");
        assert_ne!(finding.law, defect_law(Defect::NoOp));
        assert!(finding.defect_reached.contains(&Defect::NoOp));
    }
}

#[tokio::test(start_paused = true)]
async fn unavailable_catalog_does_not_claim_a_fresh_checkpoint() {
    for effects in assignments(2) {
        for cut in FRESH_CUTS {
            let mut input = multi_trace(
                0,
                2,
                vec![
                    Action::Reopen { catalog: false },
                    select(None, cut, false, false),
                ],
            );
            input.effects = effects.clone();
            check_stores(&input).await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn progress_reduction_requires_every_remaining_peer_and_current_prerequisites() {
    for withdrawal in [
        Action::Trust(false),
        Action::SubstituteTrustKey,
        Action::Writes(false),
        Action::Signer(Signer::Invalid),
        Action::Receiver(Receiver::Unavailable),
    ] {
        let mut input = multi_trace(0, 2, vec![]);
        input.defect = Some(Defect::NoOp);
        input.actions.push(withdrawal);
        let finding = replay(&input, true).await.unwrap_err();
        assert_eq!(finding.law, "ineligible_progress");
        assert!(finding.defect_reached.contains(&Defect::NoOp));
    }
    let mut input = multi_trace(0, 3, vec![]);
    input.actions = vec![
        Action::Restore,
        Action::Peer(0),
        select(None, Cut::None, false, true),
    ];
    assert_eq!(
        replay(&input, true).await.unwrap_err().law,
        "ineligible_progress"
    );
    input.actions.extend([
        Action::Peer(1),
        select(None, Cut::None, false, true),
        Action::Peer(2),
        select(None, Cut::None, false, true),
    ]);
    input.defect = Some(Defect::NoOp);
    input.source_sha256 = "a".repeat(64);
    input.executable_sha256 = "b".repeat(64);
    let minimized = minimize(input, "healthy_progress").await;
    assert_eq!(minimized.source_sha256, "a".repeat(64));
    assert_eq!(minimized.executable_sha256, "b".repeat(64));
    let encoded = serde_json::to_vec(&minimized).unwrap();
    let minimized: Trace = serde_json::from_slice(&encoded).unwrap();
    assert!(minimized.require_progress);
    assert!(minimized.peers < 3);
    for virtualized in [true, false] {
        assert_eq!(
            replay(&minimized, virtualized).await.unwrap_err().law,
            "healthy_progress"
        );
        let mut correct = minimized.clone();
        correct.defect = None;
        assert_eq!(replay(&correct, virtualized).await, Ok(()));
    }
}

#[tokio::test(start_paused = true)]
async fn generated_io_schedules_have_replayable_healthy_suffixes() {
    let mut virtual_report = RunReport::default();
    let mut sqlite_report = RunReport::default();
    for steps in [12, 48] {
        for seed in 0..32 {
            let input = generated(seed, steps);
            let document = serde_json::to_vec(&input).unwrap();
            let replayed = serde_json::from_slice(&document).unwrap();
            let (result, report) = replay_report(&replayed, true).await;
            assert_eq!(result, Ok(()), "seed={seed}/steps={steps}");
            assert_eq!(report.requested_deliveries, report.consumed_deliveries());
            assert!(report.progress_checks >= 3);
            virtual_report.merge(report);
            if [0, 4, 6, 7].contains(&seed) {
                let (result, report) = replay_report(&replayed, false).await;
                assert_eq!(result, Ok(()), "SQLite seed={seed}/steps={steps}");
                sqlite_report.merge(report);
            }
        }
    }
    println!("64 virtual generated scenarios");
    virtual_report.print();
    println!("8 SQLite generated scenarios");
    sqlite_report.print();
}
