//! Drive real selections, suspended I/O, cancellation, reopen and operating faults.

use std::{
    future::Future,
    sync::{Arc, Mutex},
    task::Poll,
};

use ed25519_dalek::SigningKey;
use rusqlite::types::Value;
use tokio::sync::Notify;

use super::{
    exploration::{select, trace},
    laws::*,
    trace::*,
    world::*,
};
use crate::{
    application::{
        ExecutionCondition, ServiceAdmission, ServiceApplication, ServiceConfiguration,
        ServiceError, ServiceExecution, ServiceStop,
    },
    gateway::{
        git::{exploration::Script, Acknowledgement, ObservedRef},
        Defect, Delivery, StorageControl, StorageWrite,
    },
    test_scratch::Scratch,
};

pub(super) fn open(
    configuration: ServiceConfiguration,
    control: &StorageControl,
) -> ServiceApplication {
    ServiceApplication::open_simulated(configuration, control.clone()).unwrap()
}

pub(super) async fn replay(trace: &Trace, virtualized: bool) -> Checked {
    replay_report(trace, virtualized).await.0
}

pub(super) async fn replay_report(trace: &Trace, virtualized: bool) -> (Checked, RunReport) {
    let control = if virtualized {
        StorageControl::virtualized()
    } else {
        StorageControl::default()
    };
    let mut report = RunReport::default();
    let result = drive(trace, virtualized, control.clone(), &mut report).await;
    report.writes = control.events();
    report.consumed_cuts = control.consumed_cuts();
    (result, report)
}

pub(super) async fn replay_with_control(
    trace: &Trace,
    virtualized: bool,
    control: StorageControl,
) -> Checked {
    drive(trace, virtualized, control, &mut RunReport::default()).await
}

#[allow(
    clippy::too_many_lines,
    reason = "keep schedule execution, all-peer laws and progress prerequisites in one owner"
)]
async fn drive(
    trace: &Trace,
    virtualized: bool,
    control: StorageControl,
    report: &mut RunReport,
) -> Checked {
    let scratch = Scratch::new();
    if let Some(defect) = trace.defect {
        control.seed(defect);
    }
    let store = Store {
        control: control.clone(),
        path: scratch.0.join("journal.sqlite3"),
        virtualized,
    };
    assert!(
        (1..=4).contains(&trace.peers),
        "bounded local replay identities"
    );
    let mut peers = (0..trace.peers)
        .map(|peer| {
            let effect = trace
                .effects
                .get(peer)
                .copied()
                .unwrap_or(Effect::Kubernetes);
            let (intent, git) = match effect {
                Effect::Kubernetes => (Intent::new(peer), None),
                Effect::Git => {
                    let (intent, authorization) = Intent::git(peer);
                    let script =
                        Script::new(authorization.clone(), store.path.clone(), control.clone());
                    (
                        intent,
                        Some(GitPeer {
                            authorization,
                            script,
                            durable_ack: Mutex::new(None),
                        }),
                    )
                },
            };
            Peer {
                original_signing: (intent.receipt_seed, intent.receipt_key.clone()),
                adapter: Adapter {
                    intent,
                    store: store.clone(),
                    io: Arc::new(Mutex::new(Observations::default())),
                    receiver: Receiver::Healthy,
                    lose_response: false,
                    fresh: true,
                    gate: None,
                },
                checker: Checker::default(),
                eligible_progress: false,
                signer: Signer::Original,
                git,
            }
        })
        .collect::<Vec<_>>();
    let mut configuration = ServiceConfiguration {
        journal_path: store.path.clone(),
        authorization_trust: peers
            .iter()
            .map(|peer| peer.adapter.intent.trust())
            .collect(),
        approvals: peers
            .iter()
            .map(|peer| peer.adapter.intent.approval())
            .collect(),
    };
    let mut app = open(configuration.clone(), &control);
    let mut selected = 0;
    let mut writing = true;
    let mut trusted = vec![true; peers.len()];
    for (event, action) in trace.actions.iter().enumerate() {
        match *action {
            Action::Select(selection) => {
                report.selections += 1;
                report.requested_deliveries += usize::from(selection.commit.is_some());
                report.requested_cuts += usize::from(!matches!(selection.cut, Cut::None));
                report.requested_response_losses += usize::from(selection.lose_response);
                let peers_before = peers.iter().map(Peer::snapshot).collect::<Vec<_>>();
                let write_refused_rows_before = (!writing).then(|| {
                    peers
                        .iter()
                        .map(|peer| peer.snapshot().record)
                        .collect::<Vec<_>>()
                });
                let must_preserve_history = !trusted[selected]
                    || (selection.sign
                        && matches!(peers[selected].signer, Signer::Invalid)
                        && matches!(
                            text(&peers[selected].snapshot().record, "state"),
                            Some("receiver_observed" | "finalized")
                        ));
                let protected_history_before = must_preserve_history
                    .then(|| peers.iter().map(Peer::snapshot).collect::<Vec<_>>());

                let peer = &mut peers[selected];
                let signing = peer.signing_material();
                let adapter = &mut peer.adapter;
                // Completion chooses current material once; terminal reads retain that choice.
                let raw =
                    store.raw_effect(&adapter.intent.request.operation_id, peer.git.is_some());
                if selection.sign && raw.get("receipt_bytes").is_none_or(|v| *v == Value::Null) {
                    adapter.intent.receipt_seed = signing.0;
                    adapter.intent.receipt_key.clone_from(&signing.1);
                }
                peer.eligible_progress |= trusted[selected]
                    && writing
                    && !matches!(peer.signer, Signer::Invalid)
                    && selection.sign
                    && selection.commit.is_none()
                    && matches!(selection.cut, Cut::None)
                    && !selection.lose_response
                    && matches!(adapter.receiver, Receiver::Healthy)
                    && (!store
                        .raw_effect(&adapter.intent.request.operation_id, peer.git.is_some())
                        .is_empty()
                        || !configuration.approvals.is_empty());
                if let Some(git) = &peer.git {
                    selection
                        .execute_git(&mut app, adapter, git, signing, event)
                        .await?;
                } else {
                    selection
                        .execute(&mut app, adapter, &mut peer.checker, signing, event)
                        .await?;
                }
                let after = peers[selected].snapshot();
                report.consumed_response_losses += usize::from(
                    selection.lose_response && after.sends > peers_before[selected].sends,
                );
                report.no_op_selections += usize::from(after == peers_before[selected]);
                selection.check_committed_delivery(
                    &peers_before[selected],
                    &after,
                    peers[selected].git.is_some(),
                    &control,
                    event,
                )?;
                if peers.iter().enumerate().any(|(index, peer)| {
                    index != selected && peer.snapshot() != peers_before[index]
                }) {
                    return Err(Finding {
                        law: "nonselected_peer_immutable",
                        event,
                        defect_reached: control.defect_reached(),
                    });
                }
                if write_refused_rows_before.is_some_and(|originals| {
                    originals
                        != peers
                            .iter()
                            .map(|peer| peer.snapshot().record)
                            .collect::<Vec<_>>()
                }) {
                    return Err(Finding {
                        law: "write_refusal_preserves_history",
                        event,
                        defect_reached: control.defect_reached(),
                    });
                }
                if protected_history_before.is_some_and(|originals| {
                    originals != peers.iter().map(Peer::snapshot).collect::<Vec<_>>()
                }) {
                    return Err(Finding {
                        law: if trusted[selected] {
                            "failed_signing_preserves_history"
                        } else {
                            "withdrawn_trust"
                        },
                        event,
                        defect_reached: control.defect_reached(),
                    });
                }
            },
            Action::Peer(peer) => {
                assert!(peer < peers.len(), "bounded local replay peer index");
                selected = peer;
            },
            Action::Receiver(receiver) => {
                peers[selected].adapter.receiver = receiver;
                if let Some(git) = &peers[selected].git {
                    let mut state = git.script.state.lock().unwrap();
                    state.unavailable = matches!(receiver, Receiver::Unavailable);
                    state.stale = matches!(receiver, Receiver::Replaced | Receiver::StaleVersion);
                    state.acknowledgement = match receiver {
                        Receiver::Healthy => Acknowledgement::Updated,
                        Receiver::Failed => Acknowledgement::ReceiverRejected,
                        _ => Acknowledgement::Unknown,
                    };
                    state.observed = ObservedRef::Commit(
                        if matches!(receiver, Receiver::Healthy) && state.sends > 0 {
                            git.authorization.new_commit.clone()
                        } else {
                            git.authorization.old_commit.clone()
                        },
                    );
                }
            },
            Action::GitRef { new } => {
                let git = peers[selected]
                    .git
                    .as_ref()
                    .expect("Git-ref events select a Git peer");
                git.script.state.lock().unwrap().observed = ObservedRef::Commit(if new {
                    git.authorization.new_commit.clone()
                } else {
                    git.authorization.old_commit.clone()
                });
            },
            Action::Reopen { catalog } => {
                drop(app);
                configuration.approvals = if catalog && trusted.iter().all(|key| *key) {
                    peers
                        .iter()
                        .map(|peer| peer.adapter.intent.approval())
                        .collect()
                } else {
                    vec![]
                };
                app = open(configuration.clone(), &control);
            },
            Action::Trust(available) => {
                drop(app);
                trusted.fill(available);
                configuration.approvals.clear();
                configuration.authorization_trust = if available {
                    peers
                        .iter()
                        .map(|peer| peer.adapter.intent.trust())
                        .collect()
                } else {
                    vec![]
                };
                app = open(configuration.clone(), &control);
                if !available {
                    for peer in &peers {
                        if peer.git.is_some() {
                            let raw = peer.snapshot().record;
                            if let Some(Value::Blob(bytes)) = raw.get("receipt_bytes") {
                                if control.exercise(Defect::ReceiptRewrite) {
                                    store.replace_git_receipt(
                                        &peer.adapter.intent.request.operation_id,
                                        bytes.clone(),
                                    );
                                }
                            }
                        }
                    }
                }
            },
            Action::SubstituteTrustKey => {
                drop(app);
                trusted[selected] = false;
                configuration.approvals.clear();
                let original = &peers[selected].adapter.intent;
                if let Some(appointment) = configuration
                    .authorization_trust
                    .iter_mut()
                    .find(|key| key.key_id == original.authorization_key)
                {
                    appointment.public_key =
                        SigningKey::from_bytes(&[91; 32]).verifying_key().to_bytes();
                }
                app = open(configuration.clone(), &control);
            },
            Action::ReplaceCatalog => {
                let before = peers.iter().map(Peer::snapshot).collect::<Vec<_>>();
                let mut replacement_configuration = configuration.clone();
                replacement_configuration.approvals.clear();
                if trusted.iter().all(|key| *key) {
                    for (index, peer) in peers.iter().enumerate() {
                        if peer.snapshot().record.is_empty() {
                            replacement_configuration
                                .approvals
                                .push(peer.adapter.intent.approval());
                            continue;
                        }
                        let (approval, trust) = peer.replacement(index);
                        replacement_configuration.approvals.push(approval);
                        if !replacement_configuration
                            .authorization_trust
                            .iter()
                            .any(|key| key.key_id == trust.key_id)
                        {
                            replacement_configuration.authorization_trust.push(trust);
                        }
                    }
                }
                let expect_catalog_conflict = trusted.iter().all(|key| *key)
                    && before.iter().any(|snapshot| !snapshot.record.is_empty());
                let result =
                    ServiceApplication::open_simulated(replacement_configuration, control.clone());
                if result.is_err() != expect_catalog_conflict
                    || before != peers.iter().map(Peer::snapshot).collect::<Vec<_>>()
                {
                    return Err(Finding {
                        law: "catalog_identity_conflict",
                        event,
                        defect_reached: control.defect_reached(),
                    });
                }
                // A refused operator configuration never replaces the running application.
            },
            Action::CustodyDuringIo(point) => {
                let before = peers.iter().map(Peer::snapshot).collect::<Vec<_>>();
                peers[selected]
                    .custody_during_io(&mut app, point, event)
                    .await?;
                if peers
                    .iter()
                    .enumerate()
                    .any(|(index, peer)| index != selected && peer.snapshot() != before[index])
                {
                    return Err(Finding {
                        law: "custody_after_io",
                        event,
                        defect_reached: control.defect_reached(),
                    });
                }
            },
            Action::CancelAtIo { point, contender } => {
                cancel_at_io(
                    &mut app,
                    &configuration,
                    &mut peers,
                    selected,
                    contender,
                    point,
                    event,
                )
                .await?;
            },
            Action::Writes(enabled) => {
                writing = enabled;
            },
            Action::Signer(signer) => peers[selected].signer = signer,
            Action::AssertProgress => {
                report.progress_checks += 1;
                let peer = &mut peers[selected];
                if !eligible(peer, trusted[selected], writing) {
                    return Err(Finding {
                        law: "ineligible_progress",
                        event,
                        defect_reached: control.defect_reached(),
                    });
                }
                if let Some(git) = &peer.git {
                    peer.checker
                        .check_git(&app, &store, &peer.adapter.intent, git, event, true)?;
                } else {
                    check_terminal(
                        &app,
                        &store,
                        &peer.adapter.io.lock().unwrap(),
                        &peer.adapter.intent,
                        event,
                        true,
                    )?;
                }
            },
            Action::Restore => {
                writing = true;
                trusted.fill(true);
                drop(app);
                for peer in &mut peers {
                    peer.adapter.receiver = Receiver::Healthy;
                    peer.adapter.lose_response = false;
                    if let Some(git) = &peer.git {
                        let mut state = git.script.state.lock().unwrap();
                        state.unavailable = false;
                        state.stale = false;
                        state.acknowledgement = Acknowledgement::Updated;
                    }
                }
                configuration.authorization_trust = peers
                    .iter()
                    .map(|peer| peer.adapter.intent.trust())
                    .collect();
                configuration.approvals = peers
                    .iter()
                    .map(|peer| peer.adapter.intent.approval())
                    .collect();
                app = open(configuration.clone(), &control);
            },
        }
        control.refuse_writes(!writing);
        if !virtualized {
            app.exploration_write_failure(!writing).unwrap();
        }
        // External trust gates application disclosure, not the independent raw-history oracle.
        for peer in &mut peers {
            let adapter = &peer.adapter;
            if let Some(git) = &peer.git {
                peer.checker
                    .check_git(&app, &store, &adapter.intent, git, event, false)?;
                continue;
            }
            peer.checker
                .check(&store, &adapter.io.lock().unwrap(), &adapter.intent, event)?;
            check_terminal(
                &app,
                &store,
                &adapter.io.lock().unwrap(),
                &adapter.intent,
                event,
                false,
            )?;
        }
        check_reads(&app, &peers, &trusted, &control, event)?;
    }
    if trace.require_progress
        && peers
            .iter()
            .enumerate()
            .any(|(index, peer)| !eligible(peer, trusted[index], writing))
    {
        return Err(Finding {
            law: "ineligible_progress",
            event: trace.actions.len(),
            defect_reached: control.defect_reached(),
        });
    }
    for peer in &mut peers {
        let adapter = &peer.adapter;
        if let Some(git) = &peer.git {
            peer.checker.check_git(
                &app,
                &store,
                &adapter.intent,
                git,
                trace.actions.len(),
                trace.require_progress,
            )?;
            continue;
        }
        check_terminal(
            &app,
            &store,
            &adapter.io.lock().unwrap(),
            &adapter.intent,
            trace.actions.len(),
            trace.require_progress,
        )?;
    }
    Ok(())
}

fn eligible(peer: &Peer, trusted: bool, writing: bool) -> bool {
    peer.eligible_progress
        && trusted
        && writing
        && !matches!(peer.signer, Signer::Invalid)
        && matches!(peer.adapter.receiver, Receiver::Healthy)
}

impl Peer {
    pub(super) async fn custody_during_io(
        &mut self,
        app: &mut ServiceApplication,
        point: IoPoint,
        event: usize,
    ) -> Checked {
        let resume = Arc::new(Notify::new());
        let id = self.adapter.intent.request.operation_id.clone();
        let store = self.adapter.store.clone();
        let git = self.git.is_some();
        let initial = self.snapshot();
        let writes_before = store.control.reached().len();
        self.gate(Some(point), Some(Arc::clone(&resume)));
        let mut execution = Box::pin(app.select_with_adapters(
            &id,
            ServiceExecution {
                kubernetes_client: None,
                git_receiver: None,
                receipt_signing: None,
            },
            Some(&mut self.adapter),
            self.git.as_ref().map(|git| git.script.receiver()),
            |_| {},
            None,
        ));

        let suspended =
            std::future::poll_fn(|cx| Poll::Ready(execution.as_mut().poll(cx).is_pending())).await;
        if !suspended {
            return Err(Finding {
                law: "custody_cut_not_reached",
                event,
                defect_reached: store.control.defect_reached(),
            });
        }

        let original = store.raw_effect(&id, git);
        store.set_grant(&id, git, Value::Blob(vec![1]));
        let attacked = store.raw_effect(&id, git);

        resume.notify_one();
        let result = execution.await;
        self.gate(None, None);
        let after = self.snapshot();
        let expected_reads = initial.reads + 1 + usize::from(point == IoPoint::Observation);
        let expected_sends = initial.sends + usize::from(point != IoPoint::Preflight);
        if let Some(git) = &self.git {
            if store.control.reached()[writes_before..].contains(&StorageWrite::Response) {
                *git.durable_ack.lock().unwrap() =
                    git.script.state.lock().unwrap().returned_acknowledgement;
            }
        }
        let refused = result.is_err()
            && after.record == attacked
            && after.reads == expected_reads
            && after.sends == expected_sends;

        store.set_grant(&id, git, original["signed_authorization_grant"].clone());
        if !refused {
            return Err(Finding {
                law: "custody_after_io",
                event,
                defect_reached: store.control.defect_reached(),
            });
        }
        Ok(())
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keep pending selection, contender refusal and cancellation observations together"
)]
pub(super) async fn cancel_at_io(
    app: &mut ServiceApplication,
    configuration: &ServiceConfiguration,
    peers: &mut [Peer],
    selected: usize,
    contender: usize,
    point: IoPoint,
    event: usize,
) -> Checked {
    assert!(contender < peers.len(), "bounded contender identity");
    let control = peers[selected].adapter.store.control.clone();
    let mut second = open(configuration.clone(), &control);
    let before = peers.iter().map(Peer::snapshot).collect::<Vec<_>>();
    let mut contender_adapter = peers[contender].adapter.clone();
    // Independent views stay readable while the selected adapter is borrowed by its future.
    let views = peers
        .iter()
        .map(|peer| {
            (
                peer.adapter.clone(),
                peer.git.as_ref().map(|git| Arc::clone(&git.script.state)),
            )
        })
        .collect::<Vec<_>>();
    let snapshots = || {
        views
            .iter()
            .map(|(adapter, git)| {
                let (reads, sends) = git.as_ref().map_or_else(
                    || {
                        let io = adapter.io.lock().unwrap();
                        (io.reads, io.sends.len())
                    },
                    |state| {
                        let io = state.lock().unwrap();
                        (io.reads, io.sends)
                    },
                );
                PeerSnapshot {
                    record: adapter
                        .store
                        .raw_effect(&adapter.intent.request.operation_id, git.is_some()),
                    reads,
                    sends,
                }
            })
            .collect::<Vec<_>>()
    };

    let resume = Arc::new(Notify::new());
    peers[selected].gate(Some(point), Some(resume));
    let (owner, other) = match selected.cmp(&contender) {
        std::cmp::Ordering::Less => {
            let (left, right) = peers.split_at_mut(contender);
            (&mut left[selected], Some(&right[0]))
        },
        std::cmp::Ordering::Greater => {
            let (left, right) = peers.split_at_mut(selected);
            (&mut right[0], Some(&left[contender]))
        },
        std::cmp::Ordering::Equal => (&mut peers[selected], None),
    };
    let id = owner.adapter.intent.request.operation_id.clone();

    let mut active = Box::pin(app.select_with_adapters(
        &id,
        ServiceExecution {
            kubernetes_client: None,
            git_receiver: None,
            receipt_signing: None,
        },
        Some(&mut owner.adapter),
        owner.git.as_ref().map(|git| git.script.receiver()),
        |_| {},
        None,
    ));
    let parked =
        std::future::poll_fn(|cx| Poll::Ready(active.as_mut().poll(cx).is_pending())).await;
    if !parked {
        return Err(Finding {
            law: "cancellation_cut_not_reached",
            event,
            defect_reached: control.defect_reached(),
        });
    }

    let pending = snapshots();
    let mut acknowledgements = Vec::new();
    let contender_id = contender_adapter.intent.request.operation_id.clone();
    let expected_admission = second
        .admitted_state(&contender_id)
        .unwrap()
        .map_or(ServiceAdmission::Busy, ServiceAdmission::Admitted);
    let result = second
        .select_with_adapters(
            &contender_id,
            ServiceExecution {
                kubernetes_client: None,
                git_receiver: None,
                receipt_signing: None,
            },
            Some(&mut contender_adapter),
            other
                .and_then(|peer| peer.git.as_ref())
                .or_else(|| owner.git.as_ref().filter(|_| selected == contender))
                .map(|git| git.script.receiver()),
            |admission| acknowledgements.push(admission),
            None,
        )
        .await;
    let excluded = matches!(
        result,
        Ok(ServiceStop::Blocked(ExecutionCondition::WorkerContention))
    ) && snapshots() == pending
        && acknowledgements == [expected_admission];

    // Drop the actual service selection future, not a predicted lifecycle transition.
    drop(active);
    peers[selected].gate(None, None);
    let after = peers.iter().map(Peer::snapshot).collect::<Vec<_>>();
    let expected_reads = before[selected].reads + 1 + usize::from(point == IoPoint::Observation);
    let expected_sends = before[selected].sends + usize::from(point != IoPoint::Preflight);
    if !excluded
        || after != pending
        || after[selected].reads != expected_reads
        || after[selected].sends != expected_sends
    {
        return Err(Finding {
            law: "worker_exclusion",
            event,
            defect_reached: control.defect_reached(),
        });
    }
    if let Some(git) = &peers[selected].git {
        *git.durable_ack.lock().unwrap() =
            git.script.state.lock().unwrap().returned_acknowledgement;
    }
    Ok(())
}

impl Selection {
    pub(super) fn check_cut(
        self,
        result: Result<ServiceStop, ServiceError>,
        adapter: &Adapter,
        git: bool,
        writes_before: usize,
        io_delta: (usize, usize),
        event: usize,
    ) -> Checked {
        if self.commit.is_some() || matches!(self.cut, Cut::None) {
            return Ok(());
        }
        let control = &adapter.store.control;
        let writes = &control.reached()[writes_before..];
        let raw = adapter
            .store
            .raw_effect(&adapter.intent.request.operation_id, git);
        let (expected_state, expect_response_record, expect_observation_record) = match self.cut {
            Cut::None => return Ok(()),
            Cut::BeforeAttempt => ("authorized", false, false),
            Cut::Unsent | Cut::AttemptAcknowledgementLost | Cut::ResponseLost => {
                ("apply_started", false, false)
            },
            Cut::ResponseRecorded | Cut::ObservationLost => ("apply_started", true, false),
            Cut::Frozen => ("receiver_observed", true, true),
        };
        let expected_reads =
            1 + usize::from(matches!(self.cut, Cut::ObservationLost | Cut::Frozen));
        let expected_sends = usize::from(!matches!(
            self.cut,
            Cut::BeforeAttempt | Cut::Unsent | Cut::AttemptAcknowledgementLost
        ));
        if io_delta != (expected_reads, expected_sends)
            || result != Err(ServiceError::OperationFailure)
            || text(&raw, "state") != Some(expected_state)
            || writes.contains(&StorageWrite::Response) != expect_response_record
            || writes.contains(&StorageWrite::Observation) != expect_observation_record
            || writes.contains(&StorageWrite::Receipt)
        {
            return Err(Finding {
                law: "checkpoint_not_reached",
                event,
                defect_reached: control.defect_reached(),
            });
        }
        Ok(())
    }

    pub(super) async fn execute_git(
        &self,
        app: &mut ServiceApplication,
        adapter: &Adapter,
        git: &GitPeer,
        signing: ([u8; 32], String),
        event: usize,
    ) -> Checked {
        let control = &adapter.store.control;
        let writes_before = control.reached().len();
        if let Some((write, delivery)) = self.commit {
            control.fail_next(write, delivery);
        }
        let (reads_before, sends_before, expected_update) = {
            let mut io = git.script.state.lock().unwrap();
            io.fault = self.cut.fault();
            io.lose_response = self.lose_response;
            let before = adapter
                .store
                .raw_effect(&adapter.intent.request.operation_id, true);
            io.fresh_attempt = before.is_empty() || text(&before, "state") == Some("authorized");
            (
                io.reads,
                io.sends,
                io.acknowledgement == Acknowledgement::Updated,
            )
        };
        let mut acknowledgements = Vec::new();
        let fresh_cut = git.script.state.lock().unwrap().fresh_attempt
            && app
                .admitted_state(&adapter.intent.request.operation_id)
                .is_ok()
            && (!self.sign || signing.1 != "invalid key")
            && !matches!(
                adapter.receiver,
                Receiver::Unavailable | Receiver::Replaced | Receiver::StaleVersion
            );
        let result = app
            .select_with_adapters::<Adapter>(
                &adapter.intent.request.operation_id,
                ServiceExecution {
                    kubernetes_client: None,
                    git_receiver: None,
                    receipt_signing: self.sign.then_some(signing),
                },
                None,
                Some(git.script.receiver()),
                |admission| acknowledgements.push(admission),
                self.cut.fault(),
            )
            .await;
        if let Some(law) = git.script.state.lock().unwrap().violation {
            return Err(Finding {
                law,
                event,
                defect_reached: control.defect_reached(),
            });
        }
        if fresh_cut {
            let io = git.script.state.lock().unwrap();
            self.check_cut(
                result,
                adapter,
                true,
                writes_before,
                (io.reads - reads_before, io.sends - sends_before),
                event,
            )?;
        }
        {
            let io = git.script.state.lock().unwrap();
            if self.lose_response
                && expected_update
                && io.sends > sends_before
                && io.ref_after_send
                    != Some(ObservedRef::Commit(git.authorization.new_commit.clone()))
            {
                return Err(Finding {
                    law: "git_lost_response_preserves_update",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
        }
        let reached = control.reached();
        if reached[writes_before..].contains(&StorageWrite::Response)
            && control.last_delivery(StorageWrite::Response) != Some(Delivery::NoCommit)
        {
            *git.durable_ack.lock().unwrap() =
                git.script.state.lock().unwrap().returned_acknowledgement;
        }
        self.check_delivery(control, writes_before, !acknowledgements.is_empty(), event)
    }

    pub(super) async fn execute(
        &self,
        app: &mut ServiceApplication,
        adapter: &mut Adapter,
        checker: &mut Checker,
        signing: ([u8; 32], String),
        event: usize,
    ) -> Checked {
        let control = adapter.store.control.clone();
        let writes_before = control.reached().len();
        let (reads_before, sends_before) = {
            let io = adapter.io.lock().unwrap();
            (io.reads, io.sends.len())
        };
        if let Some((write, delivery)) = self.commit {
            control.fail_next(write, delivery);
        }
        adapter.lose_response = self.lose_response;
        let before = adapter.store.raw(&adapter.intent.request.operation_id);
        adapter.fresh = !matches!(
            text(&before, "state"),
            Some("apply_started" | "receiver_observed" | "finalized" | "not_attempted")
        );
        let fresh_cut = adapter.fresh
            && app
                .admitted_state(&adapter.intent.request.operation_id)
                .is_ok()
            && (!self.sign || signing.1 != "invalid key")
            && !matches!(
                adapter.receiver,
                Receiver::Unavailable | Receiver::Replaced | Receiver::StaleVersion
            );
        let execution = ServiceExecution {
            kubernetes_client: None,
            git_receiver: None,
            receipt_signing: self.sign.then_some(signing),
        };
        let mut acknowledgements = Vec::new();
        let result = app
            .select_with_adapter(
                &adapter.intent.request.operation_id.clone(),
                execution,
                Some(&mut *adapter),
                |admission| acknowledgements.push(admission),
                self.cut.fault(),
            )
            .await;
        checker.check(
            &adapter.store,
            &adapter.io.lock().unwrap(),
            &adapter.intent,
            event,
        )?;
        if self.lose_response && matches!(self.cut, Cut::None) {
            let io = adapter.io.lock().unwrap();
            if io.sends.len() > sends_before
                && (result
                    != Ok(ServiceStop::Blocked(
                        ExecutionCondition::ReceiverUnavailable,
                    ))
                    || io.reads != reads_before + 1
                    || text(
                        &adapter.store.raw(&adapter.intent.request.operation_id),
                        "state",
                    ) != Some("apply_started"))
            {
                return Err(Finding {
                    law: "apply_error_stops",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
        }
        if fresh_cut {
            let io = adapter.io.lock().unwrap();
            self.check_cut(
                result,
                adapter,
                false,
                writes_before,
                (io.reads - reads_before, io.sends.len() - sends_before),
                event,
            )?;
        }
        self.check_delivery(&control, writes_before, !acknowledgements.is_empty(), event)
    }

    fn check_committed_delivery(
        self,
        before: &PeerSnapshot,
        after: &PeerSnapshot,
        git: bool,
        control: &StorageControl,
        event: usize,
    ) -> Checked {
        let Some((write, delivery)) = self.commit else {
            return Ok(());
        };
        let phase = text(&before.record, "state");
        let fresh = !matches!(phase, Some("apply_started" | "receiver_observed"));
        let committed = delivery != Delivery::NoCommit;
        let expected_state = if delivery == Delivery::Confirmed {
            Some(if write == StorageWrite::Rejection {
                "not_attempted"
            } else if self.sign {
                "finalized"
            } else {
                "receiver_observed"
            })
        } else {
            match write {
                StorageWrite::Admission if !committed => None,
                StorageWrite::Admission if !git => Some("requested"),
                StorageWrite::Admission => Some("authorized"),
                StorageWrite::Authorization => {
                    Some(if committed { "authorized" } else { "requested" })
                },
                StorageWrite::Rejection => Some(if committed {
                    "not_attempted"
                } else {
                    "authorized"
                }),
                StorageWrite::Attempt => Some(if committed {
                    "apply_started"
                } else {
                    "authorized"
                }),
                StorageWrite::Response => Some("apply_started"),
                StorageWrite::Observation => Some(if committed {
                    "receiver_observed"
                } else {
                    "apply_started"
                }),
                StorageWrite::Receipt => Some(if committed {
                    "finalized"
                } else {
                    "receiver_observed"
                }),
            }
        };
        let completed_io = || match phase {
            Some("receiver_observed") => (0, 0),
            Some("apply_started") => (1, 0),
            _ => (2, 1),
        };
        let expected_io = if delivery == Delivery::Confirmed && write != StorageWrite::Rejection {
            completed_io()
        } else {
            match write {
                StorageWrite::Admission | StorageWrite::Authorization => (0, 0),
                StorageWrite::Rejection | StorageWrite::Attempt => (1, 0),
                StorageWrite::Response => (1, 1),
                StorageWrite::Observation => (1 + usize::from(fresh), usize::from(fresh)),
                StorageWrite::Receipt => completed_io(),
            }
        };
        let response_field = if git {
            "acknowledgement"
        } else {
            "apply_accepted"
        };
        let observation_field = if git { "observed_ref_kind" } else { "result" };
        let present = |field| {
            after
                .record
                .get(field)
                .is_some_and(|value| *value != Value::Null)
        };
        let delivered_fields = match write {
            StorageWrite::Response => present(response_field) == committed,
            StorageWrite::Observation => present(observation_field) == committed,
            StorageWrite::Receipt => ["receipt_bytes", "receipt_digest", "receipt_key_id"]
                .iter()
                .all(|field| present(*field) == committed),
            StorageWrite::Rejection => present("target_rejection") == committed,
            StorageWrite::Admission | StorageWrite::Authorization | StorageWrite::Attempt => true,
        };
        if text(&after.record, "state") != expected_state
            || !delivered_fields
            || (after.reads - before.reads, after.sends - before.sends) != expected_io
        {
            return Err(Finding {
                law: "committed_delivery_binding",
                event,
                defect_reached: control.defect_reached(),
            });
        }
        Ok(())
    }

    pub(super) fn check_delivery(
        self,
        control: &StorageControl,
        writes_before: usize,
        acknowledged: bool,
        event: usize,
    ) -> Checked {
        let Some((write, delivery)) = self.commit else {
            return Ok(());
        };
        let law = if !control.events()[writes_before..].iter().any(|reached| {
            reached.write == write && reached.delivery == delivery && reached.consumed
        }) {
            Some("fault_not_reached")
        } else if write == StorageWrite::Admission
            && delivery != Delivery::Confirmed
            && acknowledged
        {
            Some("unconfirmed_admission")
        } else {
            None
        };
        law.map_or(Ok(()), |law| {
            Err(Finding {
                law,
                event,
                defect_reached: control.defect_reached(),
            })
        })
    }
}

pub(crate) async fn executed_write_statements() -> Vec<(StorageWrite, String)> {
    let mut statements = Vec::new();
    for receiver in [
        Receiver::Healthy,
        Receiver::Failed,
        Receiver::Pending,
        Receiver::Replaced,
    ] {
        let control = StorageControl::default();
        let input = trace(
            0,
            vec![
                Action::Receiver(receiver),
                select(None, Cut::None, false, true),
            ],
        );
        assert_eq!(
            replay_with_control(&input, false, control.clone()).await,
            Ok(())
        );
        statements.extend(control.executed_sql());
    }
    for prefix in [
        vec![select(None, Cut::None, false, true)],
        vec![
            Action::Receiver(Receiver::Failed),
            select(None, Cut::None, false, true),
        ],
        vec![
            Action::Receiver(Receiver::Replaced),
            select(None, Cut::None, false, true),
        ],
        vec![
            select(None, Cut::Unsent, false, false),
            Action::Receiver(Receiver::Unavailable),
            select(None, Cut::Frozen, false, false),
        ],
    ] {
        let control = StorageControl::default();
        let mut input = trace(0, prefix);
        input.effects = vec![Effect::Git];
        assert_eq!(
            replay_with_control(&input, false, control.clone()).await,
            Ok(())
        );
        statements.extend(control.executed_sql());
    }
    for (table, writes) in [
        (
            "kubernetes_image_operations",
            vec![
                StorageWrite::Admission,
                StorageWrite::Authorization,
                StorageWrite::Rejection,
                StorageWrite::Attempt,
                StorageWrite::Response,
                StorageWrite::Observation,
                StorageWrite::Receipt,
            ],
        ),
        (
            "git_ref_operations",
            vec![
                StorageWrite::Admission,
                StorageWrite::Rejection,
                StorageWrite::Attempt,
                StorageWrite::Response,
                StorageWrite::Observation,
                StorageWrite::Receipt,
            ],
        ),
    ] {
        for write in writes {
            assert!(
                statements
                    .iter()
                    .any(|(point, sql)| *point == write && sql.contains(table)),
                "missing {table}/{write:?} SQL"
            );
        }
    }
    statements.sort_by(|left, right| left.1.cmp(&right.1));
    statements.dedup_by(|left, right| left.1 == right.1);
    statements
}
