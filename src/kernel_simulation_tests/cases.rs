//! Compact temporal witnesses, virtual delivery coverage and fixed reached oracle calibration.

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

async fn check(input: &Trace) {
    assert_eq!(replay(input, true).await, Ok(()), "{input:?}");
}

#[tokio::test(start_paused = true)]
async fn virtual_delivery_bridge_consumes_all_39_application_continuations() {
    let inputs = delivery_inputs();
    assert_eq!(inputs.len(), 39);
    let mut reached = RunReport::default();
    for input in inputs {
        let (result, report) = replay_report(&input, true).await;
        assert_eq!(result, Ok(()), "{input:?}");
        assert_eq!(report.requested_deliveries, report.consumed_deliveries());
        assert!(report.faults.iter().all(|fault| fault.consumed));
        reached.merge(report);
    }
    for effect in [Effect::Kubernetes, Effect::Git] {
        for write in durable_writes(effect) {
            for delivery in [
                Delivery::Confirmed,
                Delivery::NoCommit,
                Delivery::LostAcknowledgement,
            ] {
                assert!(reached.writes.iter().any(|event| {
                    event.effect == format!("{effect:?}")
                        && event.write == write
                        && event.delivery == delivery
                        && event.consumed
                }));
            }
        }
    }
    reached.print();
}

#[tokio::test(start_paused = true)]
async fn application_sqlite_reopen_composition_retains_each_effect_once() {
    for effect in [Effect::Kubernetes, Effect::Git] {
        let mut input = trace(0, vec![select(None, Cut::None, false, true)]);
        input.effects = vec![effect];
        assert_eq!(replay(&input, false).await, Ok(()));
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
        let (result, report) = replay_report(&trace(0, actions), true).await;
        assert_eq!(result.unwrap_err().law, "fault_not_reached");
        assert_eq!(report.requested_deliveries, 1);
        assert_eq!(report.consumed_deliveries(), 0);
        let fault = report
            .faults
            .iter()
            .find(|fault| fault.write.is_some())
            .unwrap();
        assert!(!fault.consumed);
        assert_eq!(fault.effect, Effect::Kubernetes);
        assert_eq!(fault.write, Some(StorageWrite::Rejection));
    }
}

#[tokio::test(start_paused = true)]
async fn compact_interruptions_cover_distinct_effect_and_io_boundaries() {
    let interruptions = [
        (Effect::Kubernetes, Cut::Unsent, false),
        (Effect::Git, Cut::Unsent, false),
        (Effect::Kubernetes, Cut::ResponseLost, false),
        (Effect::Git, Cut::ResponseLost, false),
        (Effect::Kubernetes, Cut::None, true),
        (Effect::Git, Cut::None, true),
        (Effect::Kubernetes, Cut::ObservationLost, false),
        (Effect::Git, Cut::ObservationLost, false),
        (Effect::Kubernetes, Cut::Frozen, false),
        (Effect::Git, Cut::Frozen, false),
    ];
    for (effect, cut, loss) in interruptions {
        let mut input = trace(0, vec![select(None, cut, loss, false)]);
        input.effects = vec![effect];
        let (result, report) = replay_report(&input, true).await;
        assert_eq!(result, Ok(()), "{input:?}");
        assert!(report.faults.iter().all(|fault| fault.consumed));
    }
    // Every distinct suspension reaches real I/O. One mixed peer covers exclusion, not an
    // outcome × assignment × backend × order product.
    for effect in [Effect::Kubernetes, Effect::Git] {
        for point in [IoPoint::Preflight, IoPoint::Mutation, IoPoint::Observation] {
            let mut input = multi_trace(
                0,
                2,
                vec![Action::CancelAtIo {
                    point,
                    contender: 1,
                }],
            );
            input.effects = vec![
                effect,
                if effect == Effect::Git {
                    Effect::Kubernetes
                } else {
                    Effect::Git
                },
            ];
            check(&input).await;
            input.actions[0] = Action::CustodyDuringIo(point);
            check(&input).await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn warm_progress_precedes_global_repair_and_cold_progress_is_separate() {
    for (effect, cold) in [
        (Effect::Kubernetes, false),
        (Effect::Git, false),
        (Effect::Git, true),
    ] {
        let mut actions = vec![
            select(None, Cut::Unsent, false, false),
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
        input.effects = vec![effect, Effect::Kubernetes];
        check(&input).await;
    }
}

#[tokio::test(start_paused = true)]
async fn git_regressions_separate_acknowledgement_from_current_ref() {
    let prefixes = [
        // A→B→A after a consumed permission cannot dispatch again.
        vec![
            select(None, Cut::ResponseRecorded, false, false),
            Action::GitRef { new: true },
            Action::GitRef { new: false },
        ],
        // Updated survived; later ref A does not remove that acknowledgement.
        vec![
            select(
                Some((StorageWrite::Observation, Delivery::NoCommit)),
                Cut::None,
                false,
                false,
            ),
            Action::GitRef { new: false },
        ],
        // External B after an unsent attempt is not acknowledgement.
        vec![
            select(None, Cut::Unsent, false, false),
            Action::GitRef { new: true },
        ],
        // Updated returned but its Response NoCommit did not survive restart.
        vec![
            select(
                Some((StorageWrite::Response, Delivery::NoCommit)),
                Cut::None,
                false,
                false,
            ),
            Action::Reopen { catalog: false },
        ],
        // A returned-but-uncommitted Updated reply also stays unknown after a later cancellation.
        vec![
            select(
                Some((StorageWrite::Response, Delivery::NoCommit)),
                Cut::None,
                false,
                false,
            ),
            Action::CancelAtIo {
                point: IoPoint::Observation,
                contender: 0,
            },
            Action::Reopen { catalog: false },
        ],
        // A lost rejection confirmation remains terminal after repair/reopen.
        vec![
            select(None, Cut::BeforeAttempt, false, false),
            Action::Receiver(Receiver::StaleVersion),
            select(
                Some((StorageWrite::Rejection, Delivery::LostAcknowledgement)),
                Cut::None,
                false,
                true,
            ),
        ],
    ];
    for prefix in prefixes {
        let mut input = trace(9, prefix);
        input.effects = vec![Effect::Git];
        check(&input).await;
    }
}

#[tokio::test(start_paused = true)]
async fn catalog_trust_and_completion_material_do_not_replace_original_evidence() {
    let mut input = multi_trace(
        11,
        2,
        vec![
            select(None, Cut::Frozen, false, false),
            Action::Peer(1),
            select(None, Cut::BeforeAttempt, false, false),
            Action::ReplaceCatalog,
            Action::Reopen { catalog: false },
            Action::Trust(false),
            select(None, Cut::None, false, true),
            Action::Trust(true),
            Action::SubstituteTrustKey,
            select(None, Cut::None, false, true),
            Action::Trust(true),
            Action::Peer(0),
            Action::Signer(Signer::Invalid),
            select(None, Cut::None, false, true),
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
            Action::Signer(Signer::Original),
            Action::Reopen { catalog: false },
            select(None, Cut::None, false, true),
            Action::AssertProgress,
        ],
    );
    input.effects = vec![Effect::Kubernetes, Effect::Git];
    check(&input).await;
}

#[tokio::test(start_paused = true)]
#[allow(
    clippy::too_many_lines,
    reason = "keep O1 refusal, O2 freeze and stale/mixed controls on one causal timeline"
)]
async fn first_freeze_binds_complete_o2_or_retains_committed_o1_with_the_same_result() {
    let mut first = None;
    for (delivery, cold) in [
        (Delivery::LostAcknowledgement, true),
        (Delivery::NoCommit, false),
    ] {
        let scratch = Scratch::new();
        let control = StorageControl::virtualized();
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
                virtualized: true,
            },
            io: Arc::new(Mutex::new(Observations::default())),
            receiver: Receiver::Pending,
            lose_response: false,
            fresh: true,
            gate: None,
        };
        let mut app = open(configuration.clone(), &control);
        let mut checker = Checker::default();
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
        assert_eq!(adapter.io.lock().unwrap().reads, 2);
        if cold {
            drop(app);
            app = open(configuration.clone(), &control);
        }
        adapter.receiver = Receiver::Replaced;
        selection.commit = None;
        selection
            .execute(&mut app, &mut adapter, &mut checker, signing.clone(), 1)
            .await
            .unwrap();
        let frozen = adapter.store.raw(&adapter.intent.request.operation_id);
        assert_eq!(text(&frozen, "state"), Some("receiver_observed"));
        assert_eq!(text(&frozen, "result"), Some("UNKNOWN"));
        let reads = if delivery == Delivery::NoCommit { 3 } else { 2 };
        assert_eq!(adapter.io.lock().unwrap().reads, reads);
        if delivery == Delivery::LostAcknowledgement {
            first = Some(frozen.clone());
        } else {
            let o1 = first.as_ref().unwrap();
            let fields = [
                "receiver_uid",
                "receiver_resource_version",
                "receiver_image",
                "receiver_operation_marker",
                "current_generation",
                "observed_generation",
                "desired_replicas",
                "updated_replicas",
                "available_replicas",
                "unavailable_replicas",
                "rollout_condition_type",
                "rollout_condition_status",
                "rollout_condition_reason",
            ];
            // Correct O2 passes; both a full stale O1 and a single mixed O1 field must fail the
            // first-event law, not post-freeze immutability or a result-token comparison.
            for stale_fields in [fields.to_vec(), vec!["available_replicas"]] {
                for field in &stale_fields {
                    assert_ne!(frozen[*field], o1[*field], "distinguishable O1/O2 field");
                    control.set_value(
                        &adapter.intent.request.operation_id,
                        field,
                        o1[*field].clone(),
                    );
                }
                let finding = Checker::default()
                    .check(
                        &adapter.store,
                        &adapter.io.lock().unwrap(),
                        &adapter.intent,
                        1,
                    )
                    .unwrap_err();
                assert_eq!(finding.law, "frozen_io_binding");
                for field in stale_fields {
                    control.set_value(
                        &adapter.intent.request.operation_id,
                        field,
                        frozen[field].clone(),
                    );
                }
            }
        }
        drop(app);
        app = open(configuration, &control);
        selection
            .execute(&mut app, &mut adapter, &mut checker, signing, 2)
            .await
            .unwrap();
        assert_eq!(adapter.io.lock().unwrap().reads, reads);
        assert_eq!(
            adapter.store.raw(&adapter.intent.request.operation_id),
            frozen
        );
    }
    for delivery in [Delivery::NoCommit, Delivery::LostAcknowledgement] {
        let mut input = trace(
            0,
            vec![
                select(
                    Some((StorageWrite::Observation, delivery)),
                    Cut::None,
                    false,
                    false,
                ),
                Action::GitRef { new: false },
                select(None, Cut::None, false, false),
            ],
        );
        input.effects = vec![Effect::Git];
        check(&input).await;
    }
}

#[tokio::test(start_paused = true)]
async fn fixed_calibration_fails_intended_reached_laws_without_shrinking() {
    for input in defect_inputs() {
        let defect = input.defect.unwrap();
        let finding = replay(&input, true).await.unwrap_err();
        assert_eq!(finding.law, defect_law(defect), "{input:?}");
        assert!(finding.defect_reached.contains(&defect));
        if matches!(defect, Defect::NoOp | Defect::InitialUnknown) {
            assert!(input.actions[..finding.event]
                .iter()
                .all(|action| { !matches!(action, Action::Restore | Action::Reopen { .. }) }));
        }
        let mut correct = input.clone();
        correct.defect = None;
        check(&correct).await;
        println!("KAPSEL_KERNEL_DEFECT {defect:?} {}", finding.law);
    }
}

#[tokio::test(start_paused = true)]
async fn concrete_replay_and_one_bounded_reducer_preserve_actions_and_identity() {
    let original = include_str!("../../tests/fixtures/kernel_original_trace.json");
    let input: Trace = serde_json::from_str(original).unwrap();
    check(&input).await;
    assert_eq!(
        serde_json::to_value(&input).unwrap()["actions"],
        serde_json::from_str::<serde_json::Value>(original).unwrap()["actions"]
    );
    let (new, result, _) = generated(input.seed, 8).await;
    assert_eq!(result, Ok(()));
    assert_ne!(
        serde_json::to_value(new).unwrap()["actions"],
        serde_json::to_value(input).unwrap()["actions"]
    );
    let mut faulty = defect_inputs()
        .into_iter()
        .find(|input| input.defect == Some(Defect::Remint))
        .unwrap();
    faulty.source_sha256 = "c".repeat(64);
    faulty.executable_sha256 = "d".repeat(64);
    let original_len = faulty.actions.len();
    let reduced = minimize(faulty.clone(), "dispatch_provenance").await;
    assert!(reduced.actions.len() < original_len);
    assert_eq!(reduced.source_sha256, faulty.source_sha256);
    assert_eq!(reduced.executable_sha256, faulty.executable_sha256);
    for trace in [faulty, reduced] {
        let bytes = serde_json::to_vec(&trace).unwrap();
        let mut replayed: Trace = serde_json::from_slice(&bytes).unwrap();
        check_replay_result(&replayed, replay(&replayed, true).await);
        replayed.defect = None;
        check(&replayed).await;
    }
}

#[tokio::test(start_paused = true)]
async fn missing_progress_premises_never_qualify_as_a_detected_defect() {
    let mut input = trace(0, vec![]);
    input.actions = vec![Action::Restore, select(None, Cut::None, false, false)];
    input.defect = Some(Defect::NoOp);
    assert_eq!(
        replay(&input, true).await.unwrap_err().law,
        "ineligible_progress"
    );
    let mut input = multi_trace(0, 2, vec![]);
    input.actions = vec![Action::Restore, select(None, Cut::None, false, true)];
    assert_eq!(
        replay(&input, true).await.unwrap_err().law,
        "ineligible_progress"
    );
}

#[tokio::test(start_paused = true)]
async fn smoke_runs_32_short_generated_histories_with_meaningful_decisions() {
    let mut reached = RunReport::default();
    let mut decisions = 0;
    for seed in 0..32 {
        let (input, result, report) = generated(seed, 32).await;
        assert_eq!(result, Ok(()), "seed={seed}");
        assert!((2..=4).contains(&input.peers));
        assert!((input.peers..=32).contains(&input.meaningful_decisions));
        assert!(input.actions.len() <= 256);
        assert_eq!(report.requested_deliveries, report.consumed_deliveries());
        assert!(report.faults.iter().all(|fault| fault.consumed));
        assert_eq!(report.progress_checks, input.peers);
        decisions += input.meaningful_decisions;
        reached.merge(report);
    }
    let (short, result, _) = generated(0, 8).await;
    assert_eq!(result, Ok(()));
    let (long, result, _) = generated(0, 32).await;
    assert_eq!(result, Ok(()));
    assert!(long.meaningful_decisions > short.meaningful_decisions);
    println!("32 virtual generated histories meaningful_decisions={decisions}");
    reached.print();
}
