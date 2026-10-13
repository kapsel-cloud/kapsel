//! Serialized actions, findings and reached-interaction reports; old inputs retain their defaults.

use serde::{Deserialize, Serialize};

use crate::gateway::{Defect, Delivery, FaultPoint, StorageWrite, WriteEvent};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) enum Receiver {
    Healthy,
    Failed,
    Pending,
    Replaced,
    StaleVersion,
    WrongGeneration,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) enum Cut {
    None,
    BeforeAttempt,
    Unsent,
    AttemptAcknowledgementLost,
    ResponseLost,
    ResponseRecorded,
    ObservationLost,
    Frozen,
}

impl Cut {
    pub(super) fn fault(self) -> Option<FaultPoint> {
        match self {
            Self::None => None,
            Self::BeforeAttempt => Some(FaultPoint::TargetObserved),
            Self::Unsent => Some(FaultPoint::ApplyStartedCommitted),
            Self::AttemptAcknowledgementLost => Some(FaultPoint::AttemptCommitAcknowledgementLost),
            Self::ResponseLost => Some(FaultPoint::ApplyReturned),
            Self::ResponseRecorded => Some(FaultPoint::ApplyOutcomeCommitted),
            Self::ObservationLost => Some(FaultPoint::ReceiverRead),
            Self::Frozen => Some(FaultPoint::ReceiverObservedCommitted),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selection {
    pub(super) commit: Option<(StorageWrite, Delivery)>,
    pub(super) cut: Cut,
    pub(super) lose_response: bool,
    pub(super) sign: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) enum Action {
    Select(Selection),
    Peer(usize),
    Receiver(Receiver),
    GitRef { new: bool },
    Reopen { catalog: bool },
    Trust(bool),
    SubstituteTrustKey,
    CustodyDuringIo(IoPoint),
    CancelAtIo { point: IoPoint, contender: usize },
    Writes(bool),
    ReplaceCatalog,
    Signer(Signer),
    AssertProgress,
    Restore,
}

#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
pub(super) enum IoPoint {
    Preflight,
    Mutation,
    Observation,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) enum Signer {
    Original,
    Rotated,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub(super) enum Effect {
    Kubernetes,
    Git,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Trace {
    pub(super) seed: u64,
    #[serde(default = "single_peer")]
    pub(super) peers: usize,
    #[serde(default)]
    pub(super) effects: Vec<Effect>,
    pub(super) actions: Vec<Action>,
    pub(super) defect: Option<Defect>,
    #[serde(default = "default_progress")]
    pub(super) require_progress: bool,
    #[serde(default)]
    pub(super) source_sha256: String,
    #[serde(default)]
    pub(super) executable_sha256: String,
}

#[derive(Debug, PartialEq, Serialize)]
pub(super) struct Finding {
    pub(super) law: &'static str,
    pub(super) event: usize,
    pub(super) defect_reached: Vec<Defect>,
}

#[derive(Default, Debug, Serialize)]
pub(super) struct RunReport {
    pub(super) requested_deliveries: usize,
    pub(super) requested_cuts: usize,
    pub(super) consumed_cuts: usize,
    pub(super) requested_response_losses: usize,
    pub(super) consumed_response_losses: usize,
    pub(super) writes: Vec<WriteEvent>,
    pub(super) selections: usize,
    pub(super) no_op_selections: usize,
    pub(super) progress_checks: usize,
}

impl RunReport {
    pub(super) fn merge(&mut self, other: Self) {
        self.requested_deliveries += other.requested_deliveries;
        self.requested_cuts += other.requested_cuts;
        self.consumed_cuts += other.consumed_cuts;
        self.requested_response_losses += other.requested_response_losses;
        self.consumed_response_losses += other.consumed_response_losses;
        self.writes.extend(other.writes);
        self.selections += other.selections;
        self.no_op_selections += other.no_op_selections;
        self.progress_checks += other.progress_checks;
    }

    pub(super) fn consumed_deliveries(&self) -> usize {
        self.writes.iter().filter(|event| event.consumed).count()
    }

    pub(super) fn print(&self) {
        let tuples = self
            .writes
            .iter()
            .map(|event| {
                format!(
                    "{}/{}/{:?}/{:?}",
                    event.effect, event.phase, event.write, event.delivery
                )
            })
            .collect::<std::collections::BTreeSet<_>>();
        println!(
            "KAPSEL_KERNEL_REACHED requested={} consumed={} writes={} tuples={} \
             selections={} no_ops={} progress_checks={} cuts={}/{} response_losses={}/{}",
            self.requested_deliveries,
            self.consumed_deliveries(),
            self.writes.len(),
            tuples.len(),
            self.selections,
            self.no_op_selections,
            self.progress_checks,
            self.consumed_cuts,
            self.requested_cuts,
            self.consumed_response_losses,
            self.requested_response_losses,
        );
        println!(
            "KAPSEL_KERNEL_INTERACTIONS {}",
            serde_json::to_string(&tuples).unwrap()
        );
    }
}

pub(super) type Checked = Result<(), Finding>;

pub(super) fn default_progress() -> bool {
    true
}

pub(super) fn single_peer() -> usize {
    1
}
