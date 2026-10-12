//! Concrete receiver scripts, original material and independent record-store observations.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use ed25519_dalek::SigningKey;
use kapsel_authority::GitRefAuthorization;
use rusqlite::{types::Value, Connection};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use super::{laws::Checker, trace::*};
use crate::{
    application::ServiceApproval,
    gateway::{
        git::{
            exploration::{Barrier, Script},
            Acknowledgement,
        },
        ApprovedTarget, AuthorizationTrust, Delivery, DeploymentImageAdapter, DispatchPermission,
        ExactAuthorization, SetDeploymentImageRequest, StorageControl, StorageWrite,
        TargetReadError, TestApplyOutcome as ApplyOutcome,
        TestReceiverObservation as ReceiverObservation, TestTargetIdentity as TargetIdentity,
    },
};

pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").unwrap();
        output
    })
}

pub(super) const ID: &str = "kernel-kubernetes";
pub(super) const UID: &str = "original-uid";
pub(super) const VERSION: &str = "approved-version";
pub(super) const IMAGE: &str = concat!(
    "registry.example/api@sha256:",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
);
#[derive(Clone)]
pub(super) struct Store {
    pub(super) control: StorageControl,
    pub(super) path: PathBuf,
    pub(super) virtualized: bool,
}

impl Store {
    pub(super) fn replace_git_receipt(&self, id: &str, mut bytes: Vec<u8>) {
        bytes.push(b' ');
        let digest = hex(&Sha256::digest(&bytes));
        if self.virtualized {
            self.control
                .set_value(id, "receipt_bytes", Value::Blob(bytes));
            self.control
                .set_value(id, "receipt_digest", Value::Text(digest));
        } else {
            Connection::open(&self.path)
                .unwrap()
                .execute(
                    "UPDATE git_ref_operations SET receipt_bytes = ?1, receipt_digest = ?2
                 WHERE operation_id = ?3",
                    rusqlite::params![bytes, digest, id],
                )
                .unwrap();
        }
    }

    pub(super) fn set_grant(&self, id: &str, git: bool, value: Value) {
        if self.virtualized {
            self.control
                .set_value(id, "signed_authorization_grant", value);
        } else {
            let table = if git {
                "git_ref_operations"
            } else {
                "kubernetes_image_operations"
            };
            Connection::open(&self.path)
                .unwrap()
                .execute(
                    &format!(
                        "UPDATE {table} SET signed_authorization_grant = ?1
                     WHERE operation_id = ?2"
                    ),
                    rusqlite::params![value, id],
                )
                .unwrap();
        }
    }

    pub(super) fn raw(&self, id: &str) -> BTreeMap<String, Value> {
        self.raw_effect(id, false)
    }

    pub(super) fn raw_effect(&self, id: &str, git: bool) -> BTreeMap<String, Value> {
        let fields = if git { GIT_FIELDS } else { KUBERNETES_FIELDS };
        let table = if git {
            "git_ref_operations"
        } else {
            "kubernetes_image_operations"
        };
        if self.virtualized {
            // Named fields are intentionally independent of the production decoder's projection.
            fields
                .iter()
                .filter_map(|field| {
                    self.control
                        .value(id, field)
                        .map(|value| ((*field).to_owned(), value))
                })
                .collect()
        } else {
            let connection = Connection::open(&self.path).unwrap();
            let mut statement = connection
                .prepare(&format!("SELECT * FROM {table} WHERE operation_id = ?1"))
                .unwrap();
            let names = statement
                .column_names()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let mut rows = statement.query([id]).unwrap();
            rows.next().unwrap().map_or_else(BTreeMap::new, |row| {
                names
                    .into_iter()
                    .enumerate()
                    .map(|(index, field)| (field, row.get(index).unwrap()))
                    .collect()
            })
        }
    }
}

// Frozen evidence, original intent and authority are observed by physical names, not roundtripping
// through SnapshotRow/ReceiptRow. Legacy inert columns are retained by the SQLite boundary owner.
pub(super) const KUBERNETES_FIELDS: &[&str] = &[
    "operation_id",
    "namespace",
    "deployment",
    "container",
    "immutable_image_digest",
    "authorization_id",
    "authorization_signer_key_id",
    "authorization_grant_digest",
    "signed_authorization_grant",
    "state",
    "write_strategy",
    "target_rejection",
    "apply_attempted",
    "target_uid",
    "target_resource_version",
    "apply_accepted",
    "requested_generation",
    "apply_resource_version",
    "receiver_uid",
    "receiver_image",
    "receiver_operation_marker",
    "current_generation",
    "observed_generation",
    "receiver_resource_version",
    "desired_replicas",
    "updated_replicas",
    "available_replicas",
    "unavailable_replicas",
    "result",
    "receipt_digest",
    "receipt_bytes",
    "receipt_key_id",
    "rollout_condition_type",
    "rollout_condition_status",
    "rollout_condition_reason",
    "approved_uid",
    "approved_resource_version",
    "preflight_uid",
    "preflight_resource_version",
];

pub(super) const GIT_FIELDS: &[&str] = &[
    "operation_id",
    "repository_id",
    "ref_name",
    "old_commit",
    "new_commit",
    "authorization_id",
    "authorization_signer_key_id",
    "authorization_grant_digest",
    "signed_authorization_grant",
    "state",
    "target_rejection",
    "acknowledgement",
    "observed_ref_kind",
    "observed_commit",
    "receipt_digest",
    "receipt_bytes",
    "receipt_key_id",
];

pub(super) fn text<'a>(raw: &'a BTreeMap<String, Value>, field: &str) -> Option<&'a str> {
    match raw.get(field) {
        Some(Value::Text(value)) => Some(value),
        _ => None,
    }
}

pub(super) fn integer(raw: &BTreeMap<String, Value>, field: &str) -> Option<i64> {
    match raw.get(field) {
        Some(Value::Integer(value)) => Some(*value),
        _ => None,
    }
}

#[derive(Default)]
pub(super) struct Observations {
    pub(super) sends: Vec<(SetDeploymentImageRequest, TargetIdentity)>,
    pub(super) reads: usize,
    pub(super) preflight: Option<TargetIdentity>,
    pub(super) returned: Option<ReceiverObservation>,
    pub(super) response: Option<ApplyOutcome>,
    pub(super) violation: Option<&'static str>,
}

#[derive(Clone)]
pub(super) struct Adapter {
    pub(super) intent: Intent,
    pub(super) store: Store,
    pub(super) io: Arc<Mutex<Observations>>,
    pub(super) receiver: Receiver,
    pub(super) lose_response: bool,
    pub(super) fresh: bool,
    pub(super) gate: Option<(IoPoint, Arc<Notify>)>,
}

impl Adapter {
    pub(super) async fn pause(&self, point: IoPoint) {
        if let Some((selected, resume)) = &self.gate {
            if *selected == point {
                resume.notified().await;
            }
        }
    }
}

impl DeploymentImageAdapter for Adapter {
    async fn identify(
        &mut self,
        selected: &SetDeploymentImageRequest,
    ) -> Result<TargetIdentity, TargetReadError> {
        {
            let mut io = self.io.lock().unwrap();
            io.reads += 1;
            if selected != &self.intent.request {
                io.violation = Some("original_intent");
            }
        }
        self.pause(IoPoint::Preflight).await;
        if matches!(self.receiver, Receiver::Unavailable) {
            return Err(TargetReadError::Transient);
        }
        let target = TargetIdentity {
            deployment_uid: if matches!(self.receiver, Receiver::Replaced) {
                "replacement-uid".into()
            } else {
                self.intent.uid.clone()
            },
            resource_version: if matches!(self.receiver, Receiver::StaleVersion) {
                "stale-version".into()
            } else {
                self.intent.version.clone()
            },
        };
        self.io.lock().unwrap().preflight = Some(target.clone());
        Ok(target)
    }

    async fn apply(&mut self, permission: DispatchPermission) -> Result<ApplyOutcome, ()> {
        let (request, target) = permission.into_payload();
        let raw = self.store.raw(&self.intent.request.operation_id);
        let outcome = {
            let mut io = self.io.lock().unwrap();
            if !self.fresh
                || self.store.control.last_delivery(StorageWrite::Attempt)
                    != Some(Delivery::Confirmed)
                || text(&raw, "state") != Some("apply_started")
            {
                io.violation = Some("dispatch_provenance");
            }
            if request != self.intent.request
                || target.deployment_uid != self.intent.uid
                || target.resource_version != self.intent.version
            {
                io.violation = Some("original_intent");
            }
            io.sends.push((request, target));
            let outcome = ApplyOutcome {
                accepted: true,
                requested_generation: Some(7),
                deployment_uid: Some(self.intent.uid.clone()),
                resource_version: Some("after-patch".into()),
            };
            if self.lose_response {
                return Err(());
            }
            io.response = Some(outcome.clone());
            outcome
        };
        self.pause(IoPoint::Mutation).await;
        Ok(outcome)
    }

    async fn observe(
        &mut self,
        selected: &SetDeploymentImageRequest,
        outcome: &ApplyOutcome,
    ) -> Result<ReceiverObservation, ()> {
        let observation = {
            let mut io = self.io.lock().unwrap();
            io.reads += 1;
            if selected != &self.intent.request
                || outcome.deployment_uid.as_deref() != Some(self.intent.uid.as_str())
            {
                io.violation = Some("original_intent");
            }
            if matches!(self.receiver, Receiver::Unavailable) {
                return Err(());
            }
            let sent = !io.sends.is_empty();
            let failed = matches!(self.receiver, Receiver::Failed);
            let pending = matches!(self.receiver, Receiver::Pending);
            let observation = ReceiverObservation {
                deployment_uid: Some(if matches!(self.receiver, Receiver::Replaced) {
                    "replacement-uid".into()
                } else {
                    self.intent.uid.clone()
                }),
                resource_version: Some(
                    if sent {
                        "observed-version"
                    } else {
                        &self.intent.version
                    }
                    .into(),
                ),
                current_generation: Some(if sent { 7 } else { 3 }),
                observed_generation: Some(
                    if matches!(self.receiver, Receiver::WrongGeneration) || (sent && pending) {
                        6
                    } else if sent {
                        7
                    } else {
                        3
                    },
                ),
                image: sent.then(|| self.intent.request.immutable_image_digest.clone()),
                operation_marker: sent.then(|| self.intent.request.operation_id.clone()),
                desired_replicas: Some(if pending { 5 } else { 1 }),
                updated_replicas: Some(if pending { 4 } else { i32::from(!failed) }),
                available_replicas: Some(if pending { 2 } else { i32::from(!failed) }),
                unavailable_replicas: Some(if pending { 3 } else { i32::from(failed) }),
                rollout_condition_type: Some(
                    if failed { "Progressing" } else { "Available" }.into(),
                ),
                rollout_condition_status: Some(
                    if failed || pending { "False" } else { "True" }.into(),
                ),
                rollout_condition_reason: failed.then(|| "ProgressDeadlineExceeded".into()),
            };
            io.returned = Some(observation.clone());
            observation
        };
        self.pause(IoPoint::Observation).await;
        Ok(observation)
    }
}

// Effect-specific law over original intent and actual I/O. No phase predictor or production
// classifier/receipt builder is used. Healthy eligible work must succeed, not only stay immutable.
#[derive(Clone)]
pub(super) struct Intent {
    pub(super) request: SetDeploymentImageRequest,
    pub(super) uid: String,
    pub(super) version: String,
    pub(super) authorization_id: String,
    pub(super) authorization_key: String,
    pub(super) authority_seed: [u8; 32],
    pub(super) grant: Vec<u8>,
    pub(super) receipt_seed: [u8; 32],
    pub(super) receipt_key: String,
}

impl Intent {
    pub(super) fn new(peer: usize) -> Self {
        let distinct = |original: &str| {
            if peer == 0 {
                original.to_owned()
            } else {
                format!("{original}-{peer}")
            }
        };
        let request = SetDeploymentImageRequest {
            operation_id: distinct(ID),
            namespace: distinct("demo"),
            deployment: distinct("api"),
            container: distinct("api"),
            immutable_image_digest: if peer == 0 {
                IMAGE.into()
            } else {
                format!("registry.example/api@sha256:{peer:064x}")
            },
        };
        let uid = distinct(UID);
        let version = distinct(VERSION);
        let authorization_id = distinct("original-authorization");
        let authorization_key = distinct("original-authority");
        let authority_seed = [17 + u8::try_from(peer).unwrap(); 32];
        let authorization = ExactAuthorization {
            authorization_id: authorization_id.clone(),
            operation_id: request.operation_id.clone(),
            namespace: request.namespace.clone(),
            deployment: request.deployment.clone(),
            container: request.container.clone(),
            immutable_image_digest: request.immutable_image_digest.clone(),
            approved_target: Some(ApprovedTarget {
                uid: uid.clone(),
                resource_version: version.clone(),
            }),
        };
        let grant = crate::gateway::sign_authorization_grant(
            &authorization,
            &authority_seed,
            &authorization_key,
        )
        .unwrap();
        Self {
            request,
            uid,
            version,
            authorization_id,
            authorization_key,
            authority_seed,
            grant,
            receipt_seed: [23 + u8::try_from(peer).unwrap(); 32],
            receipt_key: distinct("original-receipt"),
        }
    }

    pub(super) fn git(peer: usize) -> (Self, GitRefAuthorization) {
        let mut intent = Self::new(peer);
        intent.request.operation_id = format!("kernel-git-{peer}");
        let approval = GitRefAuthorization {
            authorization_id: intent.authorization_id.clone(),
            operation_id: intent.request.operation_id.clone(),
            repository_id: format!("kernel-repository-{peer}"),
            reference: kapsel_authority::APPROVED_GIT_REF.into(),
            old_commit: format!("{:040x}", peer + 1),
            new_commit: format!("{:040x}", peer + 5),
        };
        intent.grant = kapsel_authority::sign_git_ref_grant(
            &approval,
            &intent.authority_seed,
            &intent.authorization_key,
        )
        .unwrap();
        (intent, approval)
    }

    pub(super) fn trust(&self) -> AuthorizationTrust {
        AuthorizationTrust {
            key_id: self.authorization_key.clone(),
            public_key: SigningKey::from_bytes(&self.authority_seed)
                .verifying_key()
                .to_bytes(),
        }
    }

    pub(super) fn matches_record(&self, raw: &BTreeMap<String, Value>) -> bool {
        let grant_digest = hex(&Sha256::digest(&self.grant));
        text(raw, "authorization_id") == Some(self.authorization_id.as_str())
            && text(raw, "authorization_signer_key_id") == Some(self.authorization_key.as_str())
            && text(raw, "authorization_grant_digest") == Some(grant_digest.as_str())
            && text(raw, "operation_id") == Some(self.request.operation_id.as_str())
            && text(raw, "namespace") == Some(self.request.namespace.as_str())
            && text(raw, "deployment") == Some(self.request.deployment.as_str())
            && text(raw, "container") == Some(self.request.container.as_str())
            && text(raw, "immutable_image_digest")
                == Some(self.request.immutable_image_digest.as_str())
            && raw.get("signed_authorization_grant") == Some(&Value::Blob(self.grant.clone()))
            && text(raw, "approved_uid") == Some(self.uid.as_str())
            && text(raw, "approved_resource_version") == Some(self.version.as_str())
    }

    pub(super) fn approval(&self) -> ServiceApproval {
        ServiceApproval {
            signed_grant: self.grant.clone(),
            label: "exact snapshot".into(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub(super) struct PeerSnapshot {
    pub(super) record: BTreeMap<String, Value>,
    pub(super) reads: usize,
    pub(super) sends: usize,
}

pub(super) struct Peer {
    pub(super) adapter: Adapter,
    pub(super) checker: Checker,
    pub(super) eligible_progress: bool,
    pub(super) signer: Signer,
    pub(super) original_signing: ([u8; 32], String),
    pub(super) git: Option<GitPeer>,
}

pub(super) struct GitPeer {
    pub(super) authorization: GitRefAuthorization,
    pub(super) script: Script,
    pub(super) durable_ack: Mutex<Option<Acknowledgement>>,
}

impl Peer {
    pub(super) fn signing_material(&self) -> ([u8; 32], String) {
        let id = &self.adapter.intent.request.operation_id;
        match self.signer {
            Signer::Rotated => {
                let seed = self.original_signing.0.map(|byte| byte + 60);
                (seed, format!("rotated-receipt-{id}"))
            },
            Signer::Original => self.original_signing.clone(),
            Signer::Invalid => (self.original_signing.0, "invalid key".into()),
        }
    }

    pub(super) fn replacement(&self, index: usize) -> (ServiceApproval, AuthorizationTrust) {
        let mut replacement = Intent::new(index);
        replacement.authorization_id = format!("replacement-authorization-{index}");
        replacement.authorization_key = format!("replacement-authority-{index}");
        replacement.authority_seed = [63 + u8::try_from(index).unwrap(); 32];
        replacement.grant = if let Some(git) = &self.git {
            let mut authorization = git.authorization.clone();
            authorization
                .authorization_id
                .clone_from(&replacement.authorization_id);
            authorization.repository_id = format!("replacement-repository-{index}");
            authorization.new_commit = format!("{:040x}", index + 19);
            kapsel_authority::sign_git_ref_grant(
                &authorization,
                &replacement.authority_seed,
                &replacement.authorization_key,
            )
            .unwrap()
        } else {
            let mut request = self.adapter.intent.request.clone();
            request.immutable_image_digest = format!("registry.example/other@sha256:{index:064x}");
            crate::gateway::sign_authorization_grant(
                &ExactAuthorization {
                    authorization_id: replacement.authorization_id.clone(),
                    operation_id: request.operation_id,
                    namespace: request.namespace,
                    deployment: request.deployment,
                    container: request.container,
                    immutable_image_digest: request.immutable_image_digest,
                    approved_target: Some(ApprovedTarget {
                        uid: "replacement-uid".into(),
                        resource_version: "replacement-version".into(),
                    }),
                },
                &replacement.authority_seed,
                &replacement.authorization_key,
            )
            .unwrap()
        };
        (replacement.approval(), replacement.trust())
    }
}

impl Peer {
    pub(super) fn gate(&mut self, point: Option<IoPoint>, resume: Option<Arc<Notify>>) {
        self.adapter.gate = point.zip(resume.clone());
        if let Some(git) = &self.git {
            let mut state = git.script.state.lock().unwrap();
            state.barrier = point.map(|point| match point {
                IoPoint::Preflight => Barrier::Preflight,
                IoPoint::Mutation => Barrier::Mutation,
                IoPoint::Observation => Barrier::Observation,
            });
            state.resume = resume;
            state.fresh_attempt = true;
            state.fault = None;
        }
    }

    pub(super) fn snapshot(&self) -> PeerSnapshot {
        let (reads, sends) = self.git.as_ref().map_or_else(
            || {
                let io = self.adapter.io.lock().unwrap();
                (io.reads, io.sends.len())
            },
            |git| {
                let io = git.script.state.lock().unwrap();
                (io.reads, io.sends)
            },
        );
        PeerSnapshot {
            record: self.adapter.store.raw_effect(
                &self.adapter.intent.request.operation_id,
                self.git.is_some(),
            ),
            reads,
            sends,
        }
    }
}
