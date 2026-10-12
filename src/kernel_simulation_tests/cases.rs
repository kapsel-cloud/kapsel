//! Deterministic boundary witnesses and reached defects, including minimized counterparts.

use super::{exploration::*, run::replay, trace::*};
use crate::gateway::{Defect, Delivery, StorageWrite};

#[tokio::test(start_paused = true)]
pub(super) async fn refused_preflight_commit_preserves_prior_evidence_until_repair() {
    let input = trace(
        111,
        vec![
            select(None, Cut::BeforeAttempt, false, false),
            Action::Writes(false),
            Action::Receiver(Receiver::Replaced),
            select(None, Cut::None, false, true),
        ],
    );
    for virtualized in [true, false] {
        assert_eq!(replay(&input, virtualized).await, Ok(()));
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn authorized_reopen_rejects_single_field_drift_and_keeps_rejection_terminal() {
    for receiver in [Receiver::Replaced, Receiver::StaleVersion] {
        let input = trace(
            110,
            vec![
                select(None, Cut::BeforeAttempt, false, false),
                Action::Reopen { catalog: false },
                Action::Receiver(receiver),
                select(None, Cut::None, false, true),
                Action::Reopen { catalog: true },
                select(None, Cut::None, false, true),
            ],
        );
        for virtualized in [true, false] {
            assert_eq!(replay(&input, virtualized).await, Ok(()));
        }
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn atomic_delivery_and_receiver_faults_preserve_laws_and_progress() {
    for write in [
        StorageWrite::Admission,
        StorageWrite::Authorization,
        StorageWrite::Attempt,
        StorageWrite::Response,
        StorageWrite::Observation,
        StorageWrite::Receipt,
    ] {
        for delivery in [Delivery::NoCommit, Delivery::LostAcknowledgement] {
            let input = trace(
                0,
                vec![select(Some((write, delivery)), Cut::None, false, true)],
            );
            for virtualized in [true, false] {
                assert_eq!(
                    replay(&input, virtualized).await,
                    Ok(()),
                    "{write:?}/{delivery:?}"
                );
            }
        }
    }
    for cut in [Cut::BeforeAttempt, Cut::Unsent, Cut::Frozen] {
        let input = trace(
            1,
            vec![
                select(None, cut, false, false),
                Action::Receiver(Receiver::Failed),
                Action::Reopen { catalog: false },
                select(None, Cut::None, false, true),
            ],
        );
        for virtualized in [true, false] {
            assert_eq!(replay(&input, virtualized).await, Ok(()));
        }
    }
    let input = trace(
        2,
        vec![
            select(None, Cut::None, true, true),
            Action::Receiver(Receiver::Unavailable),
            select(None, Cut::None, false, true),
            Action::Reopen { catalog: false },
        ],
    );
    for virtualized in [true, false] {
        assert_eq!(replay(&input, virtualized).await, Ok(()));
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn git_atomic_delivery_and_interruption_preserve_laws_and_progress() {
    for write in [
        StorageWrite::Admission,
        StorageWrite::Attempt,
        StorageWrite::Response,
        StorageWrite::Observation,
        StorageWrite::Receipt,
    ] {
        for delivery in [Delivery::NoCommit, Delivery::LostAcknowledgement] {
            let mut input = trace(
                0,
                vec![select(Some((write, delivery)), Cut::None, false, true)],
            );
            input.effects = vec![Effect::Git];
            for virtualized in [true, false] {
                assert_eq!(
                    replay(&input, virtualized).await,
                    Ok(()),
                    "{write:?}/{delivery:?}"
                );
            }
        }
    }
    for cut in [Cut::BeforeAttempt, Cut::Unsent, Cut::Frozen] {
        let mut input = trace(
            1,
            vec![
                select(None, cut, false, false),
                Action::Receiver(Receiver::Failed),
                Action::Reopen { catalog: false },
                select(None, Cut::None, false, true),
            ],
        );
        input.effects = vec![Effect::Git];
        for virtualized in [true, false] {
            assert_eq!(replay(&input, virtualized).await, Ok(()));
        }
    }
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
pub(super) async fn fresh_checkpoints_precede_cancellation_and_recover_under_original_authority() {
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
                for virtualized in [true, false] {
                    assert_eq!(
                        replay(&input, virtualized).await,
                        Ok(()),
                        "{effects:?}/{cut:?}/{receiver:?}/virtual={virtualized}"
                    );
                }
            }
        }
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn retained_contention_reopen_and_catalog_conflict_orders_preserve_all_peers() {
    for effects in assignments(2) {
        for owner in 0..2 {
            for point in [IoPoint::Preflight, IoPoint::Mutation, IoPoint::Observation] {
                for order in [
                    [0, 1, 2],
                    [0, 2, 1],
                    [1, 0, 2],
                    [1, 2, 0],
                    [2, 0, 1],
                    [2, 1, 0],
                ] {
                    let events = [
                        Action::CancelAtIo {
                            point,
                            contender: 1 - owner,
                        },
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
                    for virtualized in [true, false] {
                        assert_eq!(
                            replay(&input, virtualized).await,
                            Ok(()),
                            "{effects:?}/{owner}/{point:?}/{order:?}"
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn suspended_selection_excludes_same_and_other_ids_until_cancellation() {
    for effects in assignments(2) {
        for owner in 0..2 {
            for contender in 0..2 {
                for point in [IoPoint::Preflight, IoPoint::Mutation, IoPoint::Observation] {
                    let mut input = multi_trace(
                        0,
                        2,
                        vec![
                            Action::Peer(owner),
                            Action::CancelAtIo { point, contender },
                            Action::ReplaceCatalog,
                            Action::Reopen { catalog: false },
                        ],
                    );
                    input.effects = effects.clone();
                    for virtualized in [true, false] {
                        assert_eq!(
                            replay(&input, virtualized).await,
                            Ok(()),
                            "{effects:?}/owner={owner}/contender={contender}/{point:?}"
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn sqlite_and_virtual_write_refusal_preserve_facts_until_same_id_repair() {
    for effects in assignments(2) {
        for first in [
            None,
            Some(select(
                Some((StorageWrite::Admission, Delivery::LostAcknowledgement)),
                Cut::None,
                false,
                false,
            )),
            Some(select(None, Cut::BeforeAttempt, false, false)),
            Some(select(None, Cut::Unsent, false, false)),
            Some(select(None, Cut::Frozen, false, false)),
            Some(select(None, Cut::None, false, true)),
        ] {
            let mut actions = first.into_iter().collect::<Vec<_>>();
            actions.extend([
                Action::Writes(false),
                select(None, Cut::None, false, true),
                Action::Reopen { catalog: true },
                select(None, Cut::None, false, true),
            ]);
            let mut input = multi_trace(0, 2, actions);
            input.effects = effects.clone();
            for virtualized in [true, false] {
                assert_eq!(
                    replay(&input, virtualized).await,
                    Ok(()),
                    "{effects:?}/virtual={virtualized}"
                );
            }
        }
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn deliberate_recovery_joins_use_the_same_all_peer_laws() {
    for input in deliberate_inputs() {
        for virtualized in [true, false] {
            assert_eq!(
                replay(&input, virtualized).await,
                Ok(()),
                "seed={}/effects={:?}/virtual={virtualized}",
                input.seed,
                input.effects
            );
        }
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn git_results_follow_acknowledgement_not_the_present_ref() {
    for prefix in [
        vec![select(None, Cut::None, false, true)],
        vec![
            Action::Receiver(Receiver::Failed),
            select(None, Cut::None, false, true),
        ],
        vec![select(None, Cut::None, true, true)],
        vec![
            select(
                Some((StorageWrite::Observation, Delivery::NoCommit)),
                Cut::None,
                true,
                true,
            ),
            Action::GitRef { new: false },
            select(None, Cut::None, false, true),
        ],
        vec![
            select(None, Cut::Unsent, false, false),
            Action::GitRef { new: true },
            select(None, Cut::None, false, true),
        ],
    ] {
        let mut input = trace(9, prefix);
        input.effects = vec![Effect::Git];
        for virtualized in [true, false] {
            assert_eq!(replay(&input, virtualized).await, Ok(()));
        }
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn all_peers_preserve_original_authority_during_material_withdrawal() {
    for cut in [Cut::BeforeAttempt, Cut::Unsent, Cut::Frozen] {
        let mut input = multi_trace(
            4,
            3,
            vec![
                Action::Peer(0),
                select(None, cut, false, false),
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
                Action::Reopen { catalog: false },
                Action::Trust(false),
                Action::Peer(0),
                select(None, Cut::None, false, true),
                Action::Receiver(Receiver::Replaced),
                Action::Peer(1),
                select(None, Cut::None, false, true),
                Action::Peer(2),
                select(None, Cut::None, false, true),
                Action::Trust(true),
                Action::Peer(1),
                select(None, Cut::None, false, true),
            ],
        );
        for effects in [
            vec![Effect::Kubernetes; 3],
            vec![Effect::Git; 3],
            vec![Effect::Kubernetes, Effect::Git, Effect::Git],
        ] {
            input.effects = effects;
            for virtualized in [true, false] {
                assert_eq!(
                    replay(&input, virtualized).await,
                    Ok(()),
                    "{cut:?}/{virtualized}/{:?}",
                    input.effects
                );
            }
        }
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn replacement_catalog_and_rotated_material_preserve_retained_history() {
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
        select(None, Cut::None, false, true),
    ] {
        let mut actions = Vec::new();
        for peer in 0..3 {
            actions.extend([Action::Peer(peer), first.clone()]);
        }
        actions.push(Action::ReplaceCatalog);
        actions.push(Action::Reopen { catalog: false });
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
            for virtualized in [true, false] {
                assert_eq!(
                    replay(&input, virtualized).await,
                    Ok(()),
                    "{first:?}/{virtualized}"
                );
            }
        }
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn suspended_io_rechecks_original_custody_before_advancing_any_peer() {
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
            for virtualized in [true, false] {
                assert_eq!(
                    replay(&input, virtualized).await,
                    Ok(()),
                    "{point:?}/{virtualized}/{:?}",
                    input.effects
                );
            }
        }
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn seeded_defects_fail_intended_laws_and_minimized_replay_reaches_the_branch() {
    for input in defect_inputs() {
        let defect = input.defect.unwrap();
        let law = defect_law(defect);
        let mut correct = input.clone();
        correct.defect = None;
        for virtualized in [true, false] {
            let finding = replay(&input, virtualized).await.unwrap_err();
            assert_eq!(finding.law, law);
            assert!(finding.defect_reached.contains(&defect));
            assert_eq!(
                replay(&correct, virtualized).await,
                Ok(()),
                "correct SUT must pass full witness"
            );
        }
        let minimized = minimize(input, law).await;
        let document = serde_json::to_vec(&minimized).unwrap();
        let replayed: Trace = serde_json::from_slice(&document).unwrap();
        for virtualized in [true, false] {
            let finding = replay(&replayed, virtualized).await.unwrap_err();
            assert_eq!(finding.law, law);
            assert!(finding.defect_reached.contains(&defect));
        }
        let mut correct = replayed.clone();
        correct.defect = None;
        for virtualized in [true, false] {
            assert_eq!(
                replay(&correct, virtualized).await,
                Ok(()),
                "correct SUT must pass minimized witness"
            );
        }
        println!(
            "KAPSEL_KERNEL_DEFECT {defect:?} {law} actions={} input={}",
            replayed.actions.len(),
            String::from_utf8(document).unwrap()
        );
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn unrelated_or_ineligible_progress_does_not_qualify_as_defect_detection() {
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
pub(super) async fn unavailable_catalog_does_not_claim_a_fresh_checkpoint() {
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
            for virtualized in [true, false] {
                assert_eq!(replay(&input, virtualized).await, Ok(()));
            }
        }
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn progress_reduction_requires_every_remaining_peer_and_current_prerequisites() {
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
    let minimized = minimize(input, "healthy_progress").await;
    assert!(minimized.require_progress);
    assert!(minimized.peers < 3);
    for virtualized in [true, false] {
        let finding = replay(&minimized, virtualized).await.unwrap_err();
        assert_eq!(finding.law, "healthy_progress");
        let mut correct = minimized.clone();
        correct.defect = None;
        assert_eq!(replay(&correct, virtualized).await, Ok(()));
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn generated_io_schedules_have_replayable_healthy_suffixes() {
    for steps in [12, 48] {
        for seed in 0..32 {
            let input = generated(seed, steps);
            let document = serde_json::to_vec(&input).unwrap();
            let replayed = serde_json::from_slice(&document).unwrap();
            assert_eq!(
                replay(&replayed, true).await,
                Ok(()),
                "seed={seed}/steps={steps}"
            );
            if seed < 4 {
                assert_eq!(
                    replay(&replayed, false).await,
                    Ok(()),
                    "SQLite seed={seed}/steps={steps}"
                );
            }
        }
    }
}
