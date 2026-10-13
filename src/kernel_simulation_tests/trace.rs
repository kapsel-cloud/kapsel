//! Serialized actions and findings; retained trace schema and defaults are unchanged.

use serde::{Deserialize, Serialize};

use crate::gateway::{Defect, Delivery, FaultPoint, StorageWrite};

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

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
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

pub(super) type Checked = Result<(), Finding>;

pub(super) fn default_progress() -> bool {
    true
}

pub(super) fn single_peer() -> usize {
    1
}
