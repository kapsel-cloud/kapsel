//! Choose short action batches from reached unfinished records, not predicted lifecycle states.

use std::path::PathBuf;

use super::{
    exploration::{persist_trace, select},
    trace::*,
    world::{text, PeerSnapshot},
};
use crate::gateway::{Delivery, StorageWrite};

pub(super) struct Generation {
    random: u64,
    steps: usize,
    positioned: usize,
    finished: bool,
    pub(super) retained: Option<PathBuf>,
}

impl Generation {
    pub(super) fn new(seed: u64, steps: usize, retained: Option<PathBuf>) -> Self {
        Self {
            random: seed.wrapping_add(1),
            steps,
            positioned: 0,
            finished: false,
            retained,
        }
    }

    fn choose(&mut self, count: usize) -> usize {
        self.random ^= self.random << 13;
        self.random ^= self.random >> 7;
        self.random ^= self.random << 17;
        usize::try_from(self.random % u64::try_from(count).unwrap()).unwrap()
    }

    pub(super) fn extend(&mut self, input: &mut Trace, snapshots: &[PeerSnapshot]) -> bool {
        if self.finished {
            return false;
        }
        if self.positioned < input.peers {
            let peer = self.positioned;
            self.positioned += 1;
            let cut = [
                Cut::BeforeAttempt,
                Cut::Unsent,
                Cut::ResponseRecorded,
                Cut::Frozen,
            ][self.choose(4)];
            input
                .actions
                .extend([Action::Peer(peer), select(None, cut, false, false)]);
            input.meaningful_decisions += 1;
        } else {
            let unfinished = snapshots
                .iter()
                .enumerate()
                .filter(|(_, snapshot)| {
                    !matches!(
                        text(&snapshot.record, "state"),
                        Some("finalized" | "not_attempted")
                    )
                })
                .map(|(peer, _)| peer)
                .collect::<Vec<_>>();
            if input.meaningful_decisions >= self.steps || unfinished.is_empty() {
                // Temporary faults are repaired in their batches. Prove warm progress before any
                // global Restore/reopen; terminal peers are selected only for this explicit check.
                for peer in 0..input.peers {
                    input.actions.extend([
                        Action::Peer(peer),
                        Action::Receiver(Receiver::Healthy),
                        Action::Signer(Signer::Original),
                        select(None, Cut::None, false, true),
                        Action::AssertProgress,
                    ]);
                }
                self.finished = true;
            } else {
                let peer = unfinished[self.choose(unfinished.len())];
                let phase = text(&snapshots[peer].record, "state").unwrap();
                input.actions.push(Action::Peer(peer));
                let choice = self.choose(8);
                let batch = match choice {
                    0 => vec![select(None, Cut::None, false, true)],
                    1 => vec![Action::Reopen { catalog: false }],
                    2 => vec![Action::ReplaceCatalog],
                    3 => vec![
                        Action::SubstituteTrustKey,
                        select(None, Cut::None, false, true),
                        Action::Trust(true),
                    ],
                    4 => vec![
                        Action::Signer(Signer::Invalid),
                        select(None, Cut::None, false, true),
                        Action::Signer(Signer::Original),
                    ],
                    5 => vec![
                        Action::Writes(false),
                        select(None, Cut::None, false, true),
                        Action::Writes(true),
                    ],
                    6 if phase != "receiver_observed" => vec![
                        Action::Receiver(Receiver::Unavailable),
                        select(None, Cut::None, false, false),
                        Action::Receiver(Receiver::Healthy),
                    ],
                    _ => {
                        // Actual reached rows appoint the narrow refused-write recipe. The driver
                        // still requires consumption; this does not calculate a next phase/result.
                        let write = match phase {
                            "receiver_observed" => StorageWrite::Receipt,
                            "apply_started" => StorageWrite::Observation,
                            "authorized" => StorageWrite::Attempt,
                            _ => unreachable!("positioning must retain an eligible boundary"),
                        };
                        vec![
                            Action::Signer(Signer::Rotated),
                            select(Some((write, Delivery::NoCommit)), Cut::None, false, true),
                            Action::Signer(Signer::Original),
                        ]
                    },
                };
                input.actions.extend(batch);
                input.meaningful_decisions += 1;
            }
        }
        if let Some(path) = &self.retained {
            // Keep exact actions before executing each batch, including unknown panic inputs.
            persist_trace(path, input);
        }
        true
    }
}

pub(super) fn input(seed: u64, steps: usize) -> Trace {
    let peers = 2 + usize::try_from(seed % 3).unwrap();
    Trace {
        seed,
        peers,
        effects: (0..peers)
            .map(|peer| {
                if (seed / 3 + u64::try_from(peer).unwrap()).is_multiple_of(2) {
                    Effect::Kubernetes
                } else {
                    Effect::Git
                }
            })
            .collect(),
        actions: vec![],
        defect: None,
        require_progress: true,
        requested_steps: steps,
        meaningful_decisions: 0,
        source_sha256: String::new(),
        executable_sha256: String::new(),
    }
}
