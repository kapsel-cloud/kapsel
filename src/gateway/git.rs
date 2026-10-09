//! Sends exact Git ref transitions to an operator-owned local receiver.
//!
//! A push acknowledgement records the original attempt's outcome. A later ref read records present
//! state and cannot replace a missing acknowledgement. Paths, executable and repositories belong
//! to the operator. Only confirmation of a fresh attempt commit grants dispatch permission.
//! Recovery only observes.

use std::{
    ffi::OsString,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use kapsel_authority::{git_commit_id_is_valid, GitRefAuthorization, APPROVED_GIT_REF};
use rustix::process::{kill_process_group, Pid, Signal};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
};

use super::{
    journal::{
        git::{GitBinding, GitPhase, GitRejection},
        Journal, WorkerLock,
    },
    receipt::git as evidence,
    GatewayError, ReceiptSettings,
};

#[cfg(test)]
pub(crate) mod exploration;

const VERSION: &[u8] = b"git version 2.55.0\n";
const OUTPUT_MAX: usize = 16 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const TREE_ENTRIES_MAX: usize = 100_000;

/// Original per-ref acknowledgement, never inferred from a later ref read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Acknowledgement {
    /// The fresh push acknowledged the exact fast-forward transition.
    Updated,
    /// Git definitely rejected the ref before sending its update command.
    RejectedBeforeSend,
    /// The receiver rejected the ref transition. Hooks may already have run.
    ReceiverRejected,
    /// No qualifying per-ref acknowledgement was retained.
    Unknown,
}

impl Acknowledgement {
    /// Fixed evidence token for this acknowledgement.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Updated => "updated",
            Self::RejectedBeforeSend => "rejected_before_send",
            Self::ReceiverRejected => "receiver_rejected",
            Self::Unknown => "unknown",
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "updated" => Some(Self::Updated),
            "rejected_before_send" => Some(Self::RejectedBeforeSend),
            "receiver_rejected" => Some(Self::ReceiverRejected),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// One present-ref observation, separate from attribution of the original attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservedRef {
    /// The exact full branch was directly observed at this commit OID.
    Commit(String),
    /// A successful read found no exact branch.
    Missing,
    /// No qualifying present-ref observation was available.
    Unknown,
}

/// Operator-owned execution material for the fixed local Git receiver.
///
/// Socket callers select an approved identity and cannot supply these paths or repository identity.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitReceiverConfiguration {
    /// Absolute canonical path to the operator's Git 2.55.0 executable, named `git`.
    pub executable: PathBuf,
    /// Absolute canonical path to the private prepared bare sender repository.
    pub sender: PathBuf,
    /// Absolute canonical path to the private bare receiver repository.
    pub receiver: PathBuf,
    /// Operator repository identity, also configured as `kapsel.repositoryId` at the receiver.
    pub repository_id: String,
}

impl GitReceiverConfiguration {
    /// Decodes one bounded operator JSON object without opening receiver paths.
    pub fn from_document(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty()
            || bytes.len() > 4096
            || bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
        {
            return None;
        }
        serde_json::from_slice(bytes).ok()
    }

    pub(crate) async fn validate_preparation(
        &self,
        authorization: &GitRefAuthorization,
    ) -> Result<(), GatewayError> {
        self.receiver()
            .map_err(|_| GatewayError::GitReceiverUnavailable)?
            .prepare(authorization)
            .await
            .map(|_| ())
            .map_err(|_| GatewayError::GitReceiverUnavailable)
    }

    fn receiver(&self) -> Result<GitReceiver, GitError> {
        GitReceiver::new(
            self.executable.clone(),
            self.sender.clone(),
            self.receiver.clone(),
            self.repository_id.clone(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GitError {
    Custody,
    Configuration,
    Unavailable,
    InvalidApproval,
    InvalidObjects,
    StaleRef,
}

/// All locations are supplied by the operator, not decoded from a grant or caller request.
pub(crate) struct GitReceiver {
    executable: PathBuf,
    sender: PathBuf,
    receiver: PathBuf,
    repository_id: String,
    #[cfg(test)]
    packet_trace: Option<PathBuf>,
    #[cfg(test)]
    script: Option<std::sync::Arc<std::sync::Mutex<exploration::State>>>,
}

/// Binds a preflight-checked approval to this receiver without granting dispatch permission.
pub(super) struct PreparedTransition<'receiver> {
    receiver: &'receiver GitReceiver,
    authorization: GitRefAuthorization,
}

impl PreparedTransition<'_> {
    pub(super) fn authorization(&self) -> &GitRefAuthorization {
        &self.authorization
    }

    #[cfg(test)]
    pub(in crate::gateway) fn exploration_attempt_acknowledgement_lost(&self) -> bool {
        self.receiver
            .exploration_fault(super::FaultPoint::AttemptCommitAcknowledgementLost)
    }
}

struct CommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
}

// Keep the group identity only while the direct child has not been reaped. This prevents killing
// a reused PID. Cancellation kills the local transport and hooks in the same process group, not
// only the sender. Operator hooks that escape that group are outside this process boundary.
struct ChildGroup {
    child: Child,
    pid: Option<Pid>,
}

impl Drop for ChildGroup {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            let _ = kill_process_group(pid, Signal::KILL);
        }
    }
}

impl GitReceiver {
    pub(super) fn new(
        executable: PathBuf,
        sender: PathBuf,
        receiver: PathBuf,
        repository_id: String,
    ) -> Result<Self, GitError> {
        if !kapsel_authority::identity_is_valid(&repository_id) {
            return Err(GitError::Configuration);
        }
        // Canonical paths prevent URL escaping, symlink redirection and option-like repository
        // arguments. Their private parent excludes caller replacement between checks and spawn.
        for path in [&executable, &sender, &receiver] {
            if !path.is_absolute()
                || fs::canonicalize(path).map_err(|_| GitError::Custody)? != *path
                || !path.to_str().is_some_and(|text| {
                    text.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
                })
            {
                return Err(GitError::Custody);
            }
        }
        let binary = fs::metadata(&executable).map_err(|_| GitError::Custody)?;
        if executable.file_name() != Some(std::ffi::OsStr::new("git"))
            || !binary.is_file()
            || binary.mode() & 0o022 != 0
            || (binary.uid() != 0 && binary.uid() != rustix::process::geteuid().as_raw())
        {
            return Err(GitError::Custody);
        }
        trusted_ancestors(&executable)?;
        if sender == receiver {
            return Err(GitError::Configuration);
        }
        let result = Self {
            executable,
            sender,
            receiver,
            repository_id,
            #[cfg(test)]
            packet_trace: None,
            #[cfg(test)]
            script: None,
        };
        result.require_custody()?;
        Ok(result)
    }

    fn require_custody(&self) -> Result<(), GitError> {
        for repository in [&self.sender, &self.receiver] {
            let parent = repository.parent().ok_or(GitError::Custody)?;
            let metadata = fs::symlink_metadata(parent).map_err(|_| GitError::Custody)?;
            if !metadata.is_dir()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o7777 != 0o700
            {
                return Err(GitError::Custody);
            }
            trusted_ancestors(repository)?;
            private_tree(repository)?;
        }
        Ok(())
    }

    pub(super) async fn prepare(
        &self,
        authorization: &GitRefAuthorization,
    ) -> Result<PreparedTransition<'_>, GitError> {
        if !authorization.is_valid() || authorization.repository_id != self.repository_id {
            return Err(GitError::InvalidApproval);
        }
        #[cfg(test)]
        if let Some(script) = &self.script {
            return self.scripted_prepare(script, authorization).await;
        }
        self.require_custody()?;
        if self.run(None, &["--version".into()]).await?.stdout != VERSION {
            return Err(GitError::Configuration);
        }
        for repository in [&self.sender, &self.receiver] {
            self.require_configuration(repository).await?;
        }
        for oid in [&authorization.old_commit, &authorization.new_commit] {
            let output = self
                .run(
                    Some(&self.sender),
                    &["cat-file".into(), "-t".into(), oid.into()],
                )
                .await?;
            if !output.status.success() {
                // Git uses the same fatal exit for absent objects and operating failures.
                // Without a positive type result, rejection would freeze uncertain preflight.
                return Err(GitError::Unavailable);
            }
            match output.stdout.as_slice() {
                b"commit\n" => {},
                b"blob\n" | b"tree\n" | b"tag\n" => return Err(GitError::InvalidObjects),
                _ => return Err(GitError::Unavailable),
            }
        }
        let ancestry = self
            .run(
                Some(&self.sender),
                &[
                    "merge-base".into(),
                    "--is-ancestor".into(),
                    authorization.old_commit.clone().into(),
                    authorization.new_commit.clone().into(),
                ],
            )
            .await?;
        match ancestry.status.code() {
            Some(0) => {},
            Some(1) => return Err(GitError::InvalidObjects),
            _ => return Err(GitError::Unavailable),
        }
        match self.observe().await {
            ObservedRef::Commit(oid) if oid == authorization.old_commit => {},
            ObservedRef::Commit(_) | ObservedRef::Missing => return Err(GitError::StaleRef),
            ObservedRef::Unknown => return Err(GitError::Unavailable),
        }
        Ok(PreparedTransition {
            receiver: self,
            authorization: authorization.clone(),
        })
    }

    async fn require_configuration(&self, repository: &Path) -> Result<(), GitError> {
        // Exclude includes, remotes, helpers, alternate object stores, shallow boundaries and
        // replacement objects. Preparation must be complete and local so Git never fetches missing
        // objects during execution.
        for relative in [
            "objects/info/alternates",
            "objects/info/http-alternates",
            "shallow",
            "info/grafts",
            "refs/replace",
            "commondir",
        ] {
            if fs::symlink_metadata(repository.join(relative)).is_ok() {
                return Err(GitError::Configuration);
            }
        }
        let output = self
            .run(
                Some(repository),
                &[
                    "config".into(),
                    "--local".into(),
                    "--no-includes".into(),
                    "--null".into(),
                    "--list".into(),
                ],
            )
            .await?;
        if !output.status.success() {
            return Err(GitError::Configuration);
        }
        let mut bare = false;
        let mut identity = false;
        let mut deny_deletes = false;
        let mut deny_non_ff = false;
        let mut names = std::collections::BTreeSet::new();
        for entry in output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            let separator = entry
                .iter()
                .position(|byte| *byte == b'\n')
                .ok_or(GitError::Configuration)?;
            let (name, rest) = entry.split_at(separator);
            let value = &rest[1..];
            if !names.insert(name) {
                return Err(GitError::Configuration);
            }
            match (name, value) {
                (b"core.repositoryformatversion", b"0")
                | (b"core.filemode", b"true")
                | (
                    b"core.logallrefupdates" | b"core.ignorecase" | b"core.precomposeunicode",
                    b"true" | b"false",
                ) => {},
                (b"core.bare", b"true") => bare = true,
                (b"receive.denydeletes", b"true") => deny_deletes = true,
                (b"receive.denynonfastforwards", b"true") => deny_non_ff = true,
                (b"kapsel.repositoryid", value) if value == self.repository_id.as_bytes() => {
                    identity = true;
                },
                _ => return Err(GitError::Configuration),
            }
        }
        if !bare || (repository == self.receiver && !(identity && deny_deletes && deny_non_ff)) {
            return Err(GitError::Configuration);
        }
        Ok(())
    }

    // Only a freshly committed journal transition can provide this one-use permission.
    pub(super) async fn send(
        &self,
        permission: super::journal::git::GitDispatchPermission<'_>,
    ) -> Acknowledgement {
        let prepared = permission.into_prepared();
        if !std::ptr::eq(self, prepared.receiver)
            || prepared.authorization.repository_id != self.repository_id
        {
            return Acknowledgement::Unknown;
        }
        let authorization = prepared.authorization;
        #[cfg(test)]
        if let Some(script) = &self.script {
            return self.scripted_send(script, &authorization).await;
        }
        if self.require_custody().is_err()
            || self.require_configuration(&self.sender).await.is_err()
            || self.require_configuration(&self.receiver).await.is_err()
        {
            return Acknowledgement::Unknown;
        }
        let args = [
            "-c".into(),
            "protocol.file.allow=always".into(),
            "push".into(),
            "--porcelain".into(),
            "--no-verify".into(),
            "--no-follow-tags".into(),
            "--recurse-submodules=no".into(),
            format!("--receive-pack={} receive-pack", self.executable.display()).into(),
            format!(
                "--force-with-lease={APPROVED_GIT_REF}:{}",
                authorization.old_commit
            )
            .into(),
            format!("file://{}", self.receiver.display()).into(),
            format!("{}:{APPROVED_GIT_REF}", authorization.new_commit).into(),
        ];
        match self.run(Some(&self.sender), &args).await {
            Ok(output) => acknowledgement(&output.stdout, output.status.success(), &authorization),
            Err(_) => Acknowledgement::Unknown,
        }
    }

    pub(super) async fn observe(&self) -> ObservedRef {
        #[cfg(test)]
        if let Some(script) = &self.script {
            return self.scripted_observe(script).await;
        }
        if self.require_custody().is_err()
            || !self
                .run(None, &["--version".into()])
                .await
                .is_ok_and(|output| output.status.success() && output.stdout == VERSION)
            || self.require_configuration(&self.receiver).await.is_err()
        {
            return ObservedRef::Unknown;
        }
        let args = [
            "for-each-ref".into(),
            "--format=%(refname)%09%(objectname)%09%(objecttype)%09%(symref)".into(),
            APPROVED_GIT_REF.into(),
        ];
        match self.run(Some(&self.receiver), &args).await {
            Ok(output) if output.status.success() => observed_ref(&output.stdout),
            _ => ObservedRef::Unknown,
        }
    }

    async fn run(
        &self,
        repository: Option<&Path>,
        args: &[OsString],
    ) -> Result<CommandOutput, GitError> {
        let mut command = Command::new(&self.executable);
        let executable_directory = self.executable.parent().ok_or(GitError::Configuration)?;
        command
            .env_clear()
            .env("PATH", executable_directory)
            .env("LC_ALL", "C")
            .arg(format!("--exec-path={}", executable_directory.display()))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .arg("--no-pager")
            .arg("-c")
            .arg("protocol.allow=never")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        if let Some(repository) = repository {
            command.arg("--git-dir").arg(repository);
        }
        command.args(args);
        #[cfg(test)]
        if let Some(trace) = &self.packet_trace {
            command.env("GIT_TRACE_PACKET", trace);
        }
        run_bounded(command, COMMAND_TIMEOUT).await
    }
}

pub(crate) struct RetainedGitOperation {
    pub(crate) signed_grant: Vec<u8>,
    pub(crate) state: super::OperationState,
    pub(crate) targets: super::GitOperationTargets,
    pub(crate) rejection: Option<super::TargetRejection>,
    pub(crate) result: Option<super::OperationResult>,
    pub(crate) receipt: Option<(Vec<u8>, String)>,
}

impl RetainedGitOperation {
    fn from_phase(binding: &GitBinding, phase: GitPhase) -> Self {
        let statement = phase.statement(binding);
        let acknowledgement = match &phase {
            GitPhase::Attempted(ack) => *ack,
            GitPhase::Observed {
                acknowledgement, ..
            } => Some(*acknowledgement),
            GitPhase::Finalized { statement, .. } => Some(statement.acknowledgement),
            GitPhase::Authorized | GitPhase::NotAttempted(_) => None,
        };
        let rejection = match phase {
            GitPhase::NotAttempted(GitRejection::StaleRef) => {
                Some(super::TargetRejection::GitStaleRef)
            },
            GitPhase::NotAttempted(GitRejection::InvalidObjects) => {
                Some(super::TargetRejection::GitInvalidObjects)
            },
            _ => None,
        };
        Self {
            signed_grant: binding.signed_grant().to_vec(),
            state: phase.state(),
            rejection,
            result: statement.as_ref().map(evidence::GitStatement::result),
            targets: super::GitOperationTargets {
                approval: binding.authorization().clone(),
                attempted: matches!(
                    phase,
                    GitPhase::Attempted(_) | GitPhase::Observed { .. } | GitPhase::Finalized { .. }
                ),
                acknowledgement,
                observed_ref: statement.map(|statement| statement.observed),
            },
            receipt: match phase {
                GitPhase::Finalized { receipt, .. } => Some((receipt.bytes, receipt.digest)),
                _ => None,
            },
        }
    }
}

impl super::Gateway {
    pub(crate) fn retained_git(
        &self,
        id: &str,
    ) -> Result<Option<RetainedGitOperation>, GatewayError> {
        super::validate_identity(super::InputField::OperationId, id)?;
        self.journal
            .retained_git(id, &self.authorization_trust)
            .map(|operation| {
                operation.map(|(binding, phase)| RetainedGitOperation::from_phase(&binding, phase))
            })
    }

    pub(crate) fn authorized_git(
        &self,
        grant: &[u8],
    ) -> Result<Option<RetainedGitOperation>, GatewayError> {
        let binding = GitBinding::verify(grant, &self.authorization_trust)?;
        self.journal
            .git_operation(&binding)
            .map(|phase| phase.map(|phase| RetainedGitOperation::from_phase(&binding, phase)))
    }

    pub(crate) async fn admit_and_reconcile_git(
        &mut self,
        id: &str,
        grant: &[u8],
        receiver: Option<&GitReceiverConfiguration>,
        #[cfg(test)] simulated_receiver: Option<&GitReceiver>,
        signing: Option<&ReceiptSettings<'_>>,
        acknowledged: impl FnOnce(super::AdmissionDecision) + Send,
    ) -> Result<(), super::ReconciliationError> {
        use super::{OperationState, ReconciliationBlockage, ReconciliationError};
        let binding = GitBinding::verify(grant, &self.authorization_trust)
            .map_err(ReconciliationError::Submission)?;
        if binding.authorization().operation_id != id {
            return Err(ReconciliationError::Submission(
                GatewayError::AuthorizationMismatch,
            ));
        }
        let existing = self
            .journal
            .git_operation(&binding)
            .map_err(ReconciliationError::Submission)?;
        let Some((worker, admitted)) = self.admit_service_operation(
            existing.as_ref().map(GitPhase::state),
            |journal, worker| {
                journal
                    .insert_git(&binding, worker)
                    .map(|phase| phase.state())
            },
            acknowledged,
        )?
        else {
            return Ok(());
        };
        let needs_receiver = matches!(
            admitted,
            OperationState::Authorized | OperationState::ApplyStarted
        );
        #[cfg(test)]
        let needs_receiver = needs_receiver && simulated_receiver.is_none();
        let receiver = if needs_receiver {
            Some(
                receiver
                    .ok_or(ReconciliationError::Blocked(
                        ReconciliationBlockage::ReceiverUnavailable,
                    ))?
                    .receiver()
                    .map_err(|_| {
                        ReconciliationError::Blocked(ReconciliationBlockage::ReceiverUnavailable)
                    })?,
            )
        } else {
            None
        };
        let receiver = receiver.as_ref();
        #[cfg(test)]
        let receiver = simulated_receiver.or(receiver);
        let phase = advance(&mut self.journal, &binding, receiver, signing, &worker)
            .await
            .map_err(|error| match error {
                GatewayError::Receipt(_) => ReconciliationError::Completion,
                error => ReconciliationError::Advancement(error),
            })?;
        if matches!(phase, GitPhase::Observed { .. }) {
            return Err(ReconciliationError::Blocked(
                ReconciliationBlockage::SigningUnavailable,
            ));
        }
        Ok(())
    }
}

/// Advances only an admitted identity under the caller's already-held journal worker lease.
/// Attempted history never enters prepare/send, even if the ref has returned to the old commit.
#[allow(
    clippy::needless_pass_by_ref_mut,
    reason = "exclusive borrowing keeps this future Send without requiring SQLite to be Sync"
)]
pub(super) async fn advance(
    journal: &mut Journal,
    binding: &GitBinding,
    receiver: Option<&GitReceiver>,
    signing: Option<&ReceiptSettings<'_>>,
    worker: &WorkerLock,
) -> Result<GitPhase, GatewayError> {
    if !journal.owns_worker(worker) {
        return Err(GatewayError::InvalidTransition);
    }
    let mut phase = journal
        .git_operation(binding)?
        .ok_or(GatewayError::InvalidTransition)?;
    if matches!(phase, GitPhase::Authorized | GitPhase::Attempted(_))
        && receiver
            .is_some_and(|receiver| receiver.repository_id != binding.authorization().repository_id)
    {
        return Err(GatewayError::GitReceiverUnavailable);
    }
    #[cfg(test)]
    let fresh = phase == GitPhase::Authorized;
    if phase == GitPhase::Authorized {
        let receiver = receiver.ok_or(GatewayError::GitReceiverUnavailable)?;
        match receiver.prepare(binding.authorization()).await {
            Ok(prepared) => {
                #[cfg(test)]
                exploration_checkpoint(Some(receiver), super::FaultPoint::TargetObserved)?;
                let permission = journal.begin_git_attempt(binding, prepared, worker)?;
                #[cfg(test)]
                exploration_checkpoint(Some(receiver), super::FaultPoint::ApplyStartedCommitted)?;
                let acknowledgement = receiver.send(permission).await;
                #[cfg(test)]
                exploration_checkpoint(Some(receiver), super::FaultPoint::ApplyReturned)?;
                #[cfg(feature = "demo-harness")]
                super::demo_control::checkpoint_after_apply()
                    .map_err(|()| GatewayError::GitReceiverUnavailable)?;
                journal.record_git_acknowledgement(binding, acknowledgement, worker)?;
                #[cfg(test)]
                exploration_checkpoint(Some(receiver), super::FaultPoint::ApplyOutcomeCommitted)?;
            },
            Err(GitError::StaleRef) => {
                journal.reject_git(binding, GitRejection::StaleRef, worker)?;
            },
            Err(GitError::InvalidObjects) => {
                journal.reject_git(binding, GitRejection::InvalidObjects, worker)?;
            },
            Err(
                GitError::Custody
                | GitError::Configuration
                | GitError::Unavailable
                | GitError::InvalidApproval,
            ) => return Err(GatewayError::GitReceiverUnavailable),
        }
        phase = journal
            .git_operation(binding)?
            .ok_or(GatewayError::InvalidTransition)?;
    }
    if matches!(phase, GitPhase::Attempted(_)) {
        let receiver = receiver.ok_or(GatewayError::GitReceiverUnavailable)?;
        let observed = receiver.observe().await;
        #[cfg(test)]
        if fresh {
            exploration_checkpoint(Some(receiver), super::FaultPoint::ReceiverRead)?;
        }
        journal.freeze_git_observation(binding, &observed, worker)?;
        #[cfg(test)]
        exploration_checkpoint(Some(receiver), super::FaultPoint::ReceiverObservedCommitted)?;
        phase = journal
            .git_operation(binding)?
            .ok_or(GatewayError::InvalidTransition)?;
    }
    if matches!(phase, GitPhase::Observed { .. }) {
        if let Some(signing) = signing {
            let statement = phase
                .statement(binding)
                .ok_or(GatewayError::InvalidPersistedState)?;
            let bytes = evidence::sign(&statement, signing.signing_seed, signing.key_id)
                .map_err(GatewayError::Receipt)?;
            #[cfg(feature = "demo-harness")]
            super::demo_control::checkpoint_before_receipt_commit()
                .map_err(|()| GatewayError::InvalidTransition)?;
            #[cfg(test)]
            exploration_checkpoint(receiver, super::FaultPoint::BeforeReceiptCommit)?;
            journal.commit_git_receipt(binding, &bytes, worker)?;
            #[cfg(test)]
            exploration_checkpoint(
                receiver,
                super::FaultPoint::ReceiptCommitAcknowledgementLost,
            )?;
            #[cfg(feature = "demo-harness")]
            super::demo_control::checkpoint_after_receipt_commit()
                .map_err(|()| GatewayError::InvalidTransition)?;
            phase = journal
                .git_operation(binding)?
                .ok_or(GatewayError::InvalidTransition)?;
        }
    }
    Ok(phase)
}

#[cfg(test)]
fn exploration_checkpoint(
    receiver: Option<&GitReceiver>,
    point: super::FaultPoint,
) -> Result<(), GatewayError> {
    if receiver.is_some_and(|receiver| receiver.exploration_fault(point)) {
        Err(GatewayError::InjectedFault)
    } else {
        Ok(())
    }
}

async fn run_bounded(mut command: Command, deadline: Duration) -> Result<CommandOutput, GitError> {
    let child = command.spawn().map_err(|_| GitError::Unavailable)?;
    let pid = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw)
        .ok_or(GitError::Unavailable)?;
    let mut group = ChildGroup {
        child,
        pid: Some(pid),
    };
    let stdout = group.child.stdout.take().ok_or(GitError::Unavailable)?;
    let stderr = group.child.stderr.take().ok_or(GitError::Unavailable)?;
    let result = tokio::time::timeout(deadline, async {
        let (stdout, _) = tokio::try_join!(read_bounded(stdout), read_bounded(stderr))?;
        let status = group
            .child
            .wait()
            .await
            .map_err(|_| GitError::Unavailable)?;
        group.pid = None;
        Ok::<_, GitError>(CommandOutput { status, stdout })
    })
    .await;
    if let Ok(Ok(output)) = result {
        Ok(output)
    } else {
        if let Some(pid) = group.pid.take() {
            let _ = kill_process_group(pid, Signal::KILL);
        }
        let _ = group.child.kill().await;
        Err(GitError::Unavailable)
    }
}

async fn read_bounded(mut stream: impl AsyncRead + Unpin) -> Result<Vec<u8>, GitError> {
    let mut output = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|_| GitError::Unavailable)?;
        if count == 0 {
            return Ok(output);
        }
        if count > OUTPUT_MAX - output.len() {
            return Err(GitError::Unavailable);
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

fn trusted_ancestors(path: &Path) -> Result<(), GitError> {
    for ancestor in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| GitError::Custody)?;
        let owner = metadata.uid();
        let sticky_root = owner == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || (owner != 0 && owner != rustix::process::geteuid().as_raw())
            || (metadata.mode() & 0o022 != 0 && !sticky_root)
        {
            return Err(GitError::Custody);
        }
    }
    Ok(())
}

fn private_tree(root: &Path) -> Result<(), GitError> {
    let mut pending = vec![(root.to_owned(), 0)];
    let mut count = 0;
    while let Some((path, depth)) = pending.pop() {
        count += 1;
        if count > TREE_ENTRIES_MAX || depth > 32 {
            return Err(GitError::Custody);
        }
        let metadata = fs::symlink_metadata(&path).map_err(|_| GitError::Custody)?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
            return Err(GitError::Custody);
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).map_err(|_| GitError::Custody)? {
                if pending.len() + count >= TREE_ENTRIES_MAX {
                    return Err(GitError::Custody);
                }
                pending.push((entry.map_err(|_| GitError::Custody)?.path(), depth + 1));
            }
        } else if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(GitError::Custody);
        }
    }
    Ok(())
}

fn acknowledgement(bytes: &[u8], success: bool, approval: &GitRefAuthorization) -> Acknowledgement {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Acknowledgement::Unknown;
    };
    let mut lines = text.split('\n');
    let Some(header) = lines.next() else {
        return Acknowledgement::Unknown;
    };
    let Some(status) = lines.next() else {
        return Acknowledgement::Unknown;
    };
    if !header.starts_with("To ")
        || lines.next() != Some("Done")
        || lines.next() != Some("")
        || lines.next().is_some()
    {
        return Acknowledgement::Unknown;
    }
    let expected = format!("{}:{APPROVED_GIT_REF}", approval.new_commit);
    let fields: Vec<_> = status.split('\t').collect();
    if fields.len() != 3 || fields[1] != expected {
        return Acknowledgement::Unknown;
    }
    match (fields[0], fields[2], success) {
        (" ", summary, true) if fast_forward_summary(summary, approval) => Acknowledgement::Updated,
        ("!", summary, false) if summary.starts_with("[rejected] (") && summary.ends_with(')') => {
            Acknowledgement::RejectedBeforeSend
        },
        ("!", summary, false)
            if summary.starts_with("[remote rejected] (") && summary.ends_with(')') =>
        {
            Acknowledgement::ReceiverRejected
        },
        _ => Acknowledgement::Unknown,
    }
}

fn fast_forward_summary(summary: &str, approval: &GitRefAuthorization) -> bool {
    summary.split_once("..").is_some_and(|(old, new)| {
        (4..=40).contains(&old.len())
            && (4..=40).contains(&new.len())
            && approval.old_commit.starts_with(old)
            && approval.new_commit.starts_with(new)
    })
}

fn observed_ref(bytes: &[u8]) -> ObservedRef {
    if bytes.is_empty() {
        return ObservedRef::Missing;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return ObservedRef::Unknown;
    };
    let Some(line) = text.strip_suffix('\n') else {
        return ObservedRef::Unknown;
    };
    let fields: Vec<_> = line.split('\t').collect();
    if fields.len() == 4
        && fields[0] == APPROVED_GIT_REF
        && git_commit_id_is_valid(fields[1])
        && fields[2] == "commit"
        && fields[3].is_empty()
    {
        ObservedRef::Commit(fields[1].to_owned())
    } else {
        ObservedRef::Unknown
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::gateway::OperationResult;

    fn approval() -> GitRefAuthorization {
        GitRefAuthorization {
            authorization_id: "approval-1".into(),
            operation_id: "operation-1".into(),
            repository_id: "repository-1".into(),
            reference: APPROVED_GIT_REF.into(),
            old_commit: "a".repeat(40),
            new_commit: "b".repeat(40),
        }
    }

    fn porcelain(flag: &str, summary: &str) -> Vec<u8> {
        format!(
            "To file:///operator/receiver.git\n{flag}\t{}:{APPROVED_GIT_REF}\t{summary}\nDone\n",
            approval().new_commit
        )
        .into_bytes()
    }

    #[test]
    fn only_exact_fresh_fast_forward_acknowledgement_establishes_update() {
        let bytes = porcelain(" ", "aaaaaaa..bbbbbbb");
        assert_eq!(
            acknowledgement(&bytes, true, &approval()),
            Acknowledgement::Updated
        );
        assert_eq!(
            acknowledgement(&bytes, false, &approval()),
            Acknowledgement::Unknown
        );
        for (flag, summary) in [
            ("=", "[up to date]"),
            ("+", "aaaaaaa...bbbbbbb"),
            ("*", "[new branch]"),
            ("-", "[deleted]"),
            (" ", "ccccccc..bbbbbbb"),
            (" ", "aaaaaaa..ccccccc"),
            (" ", "a..b"),
        ] {
            assert_eq!(
                acknowledgement(&porcelain(flag, summary), true, &approval()),
                Acknowledgement::Unknown
            );
        }
        let mut duplicate = bytes.clone();
        duplicate.extend_from_slice(&bytes);
        assert_eq!(
            acknowledgement(&duplicate, true, &approval()),
            Acknowledgement::Unknown
        );
        let wrong_ref = String::from_utf8(bytes)
            .unwrap()
            .replace(APPROVED_GIT_REF, "refs/heads/main");
        assert_eq!(
            acknowledgement(wrong_ref.as_bytes(), true, &approval()),
            Acknowledgement::Unknown
        );
    }

    #[test]
    fn per_ref_rejection_is_not_transport_failure_or_hook_nonexecution() {
        for (summary, expected) in [
            (
                "[rejected] (stale info)",
                Acknowledgement::RejectedBeforeSend,
            ),
            (
                "[remote rejected] (hook declined)",
                Acknowledgement::ReceiverRejected,
            ),
            (
                "[remote failure] (remote failed to report status)",
                Acknowledgement::Unknown,
            ),
        ] {
            assert_eq!(
                acknowledgement(&porcelain("!", summary), false, &approval()),
                expected
            );
        }
        assert_eq!(
            acknowledgement(b"", true, &approval()),
            Acknowledgement::Unknown
        );
        assert_eq!(
            acknowledgement(b"fatal: disconnected\n", false, &approval()),
            Acknowledgement::Unknown
        );
    }

    #[test]
    fn present_commit_is_separate_from_acknowledgement_and_attribution() {
        let present = format!("{APPROVED_GIT_REF}\t{}\tcommit\t\n", approval().new_commit);
        assert_eq!(
            observed_ref(present.as_bytes()),
            ObservedRef::Commit(approval().new_commit)
        );
        assert_eq!(observed_ref(b""), ObservedRef::Missing);
        for invalid in [
            present.replace("commit", "blob"),
            present.replace("\t\n", "\tHEAD\n"),
            present.replace(APPROVED_GIT_REF, "refs/heads/approved/child"),
            format!("{present}{present}"),
            present.trim_end().into(),
        ] {
            assert_eq!(observed_ref(invalid.as_bytes()), ObservedRef::Unknown);
        }
    }

    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .kill_on_drop(true);
        command
    }

    #[tokio::test]
    async fn subprocess_output_and_time_are_bounded_on_both_streams() {
        for redirect in ["", " >&2"] {
            let script =
                format!("while :; do printf '012345678901234567890123456789'{redirect}; done");
            assert!(run_bounded(shell(&script), Duration::from_secs(2))
                .await
                .is_err());
        }
        assert!(run_bounded(shell("sleep 20"), Duration::from_millis(30))
            .await
            .is_err());
        let result = run_bounded(
            shell("printf ok; printf diagnostic >&2"),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"ok");
    }

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "kapsel-git-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn custody_rejects_symlinks_shared_writes_and_linked_objects() {
        let fixture = Fixture::new();
        let repo = fixture.0.join("repo");
        fs::create_dir(&repo).unwrap();
        fs::write(repo.join("object"), b"content").unwrap();
        fs::set_permissions(&repo, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(repo.join("object"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(private_tree(&repo).is_ok());
        std::os::unix::fs::symlink("object", repo.join("link")).unwrap();
        assert_eq!(private_tree(&repo), Err(GitError::Custody));
        fs::remove_file(repo.join("link")).unwrap();
        fs::hard_link(repo.join("object"), repo.join("link")).unwrap();
        assert_eq!(private_tree(&repo), Err(GitError::Custody));
        fs::remove_file(repo.join("link")).unwrap();
        fs::set_permissions(repo.join("object"), fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(private_tree(&repo), Err(GitError::Custody));
    }

    fn git(executable: &Path, root: &Path, args: &[&str]) -> Vec<u8> {
        let output = std::process::Command::new(executable)
            .args(args)
            .current_dir(root)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn commit(
        executable: &Path,
        repository: &Path,
        tree: &str,
        parent: Option<&str>,
        name: &str,
    ) -> String {
        let mut args = vec![
            "--git-dir",
            repository.to_str().unwrap(),
            "commit-tree",
            tree,
            "-m",
            name,
        ];
        if let Some(parent) = parent {
            args.extend(["-p", parent]);
        }
        String::from_utf8(git(executable, repository, &args))
            .unwrap()
            .trim()
            .to_owned()
    }

    fn journaled_permission<'receiver>(
        fixture: &Fixture,
        approval: &GitRefAuthorization,
        prepared: PreparedTransition<'receiver>,
    ) -> super::super::journal::git::GitDispatchPermission<'receiver> {
        use super::super::journal::Journal;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = fixture
            .0
            .join(format!("journal-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
        let journal = Journal::open(path).unwrap();
        let binding = binding_for(approval);
        let worker = journal.try_lock_worker().unwrap().unwrap();
        journal.insert_git(&binding, &worker).unwrap();
        let permission = journal
            .begin_git_attempt(&binding, prepared, &worker)
            .unwrap();
        assert_eq!(
            journal.git_operation(&binding).unwrap(),
            Some(super::super::journal::git::GitPhase::Attempted(None))
        );
        permission
    }

    fn install_hooks(fixture: &Fixture, receiver: &GitReceiver, kill_at: &str) {
        fs::create_dir_all(receiver.receiver.join("hooks")).unwrap();
        for name in ["pre-receive", "post-receive"] {
            let script = format!(
                r"#!/bin/sh
printf 'invoked\n' >> '{}'
while read -r line; do :; done
{}",
                fixture.0.join(name).display(),
                if name == kill_at {
                    r#"kill -KILL "$PPID"
"#
                } else {
                    ""
                },
            );
            let hook = receiver.receiver.join("hooks").join(name);
            fs::write(&hook, script).unwrap();
            fs::set_permissions(hook, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn receiver_counts(fixture: &Fixture, approval: &GitRefAuthorization) -> (usize, usize, usize) {
        let trace = fs::read_to_string(fixture.0.join("packets")).unwrap_or_default();
        let command = format!(
            "receive-pack< {} {} {}",
            approval.old_commit, approval.new_commit, APPROVED_GIT_REF
        );
        let requests = trace.lines().filter(|line| line.contains(&command)).count();
        let pre = fs::read_to_string(fixture.0.join("pre-receive"))
            .unwrap_or_default()
            .lines()
            .count();
        let post = fs::read_to_string(fixture.0.join("post-receive"))
            .unwrap_or_default()
            .lines()
            .count();
        (requests, pre, post)
    }

    fn operator_push(receiver: &GitReceiver, oid: &str) {
        git(
            &receiver.executable,
            &receiver.sender,
            &[
                "--git-dir",
                receiver.sender.to_str().unwrap(),
                "push",
                receiver.receiver.to_str().unwrap(),
                &format!("{oid}:{APPROVED_GIT_REF}"),
            ],
        );
    }

    #[tokio::test]
    #[ignore = "requires operator-selected Git 2.55.0; KAPSEL_TEST_GIT is an absolute executable"]
    #[allow(
        clippy::too_many_lines,
        reason = "one cross-boundary failure and recovery matrix"
    )]
    async fn real_git_journal_recovery_freezes_evidence_without_replay() {
        for case in [
            "healthy",
            "pre-receive",
            "post-receive",
            "unsent-aba",
            "unsent-present-b",
            "onward",
        ] {
            let (fixture, mut receiver, approval, _) = receiver_fixture();
            receiver.packet_trace = Some(fixture.0.join("packets"));
            install_hooks(&fixture, &receiver, case);
            let binding = binding_for(&approval);
            let path = fixture.0.join("recovery-journal");
            let journal = Journal::open(&path).unwrap();
            let worker = journal.try_lock_worker().unwrap().unwrap();
            journal.insert_git(&binding, &worker).unwrap();
            let mut expected_observed = approval.new_commit.clone();
            if matches!(case, "unsent-aba" | "unsent-present-b" | "onward") {
                let prepared = receiver.prepare(&approval).await.unwrap();
                let permission = journal
                    .begin_git_attempt(&binding, prepared, &worker)
                    .unwrap();
                if matches!(case, "unsent-aba" | "unsent-present-b") {
                    drop(permission);
                    operator_push(&receiver, &approval.new_commit);
                    if case == "unsent-aba" {
                        git(
                            &receiver.executable,
                            &fixture.0,
                            &[
                                "--git-dir",
                                receiver.receiver.to_str().unwrap(),
                                "update-ref",
                                APPROVED_GIT_REF,
                                &approval.old_commit,
                                &approval.new_commit,
                            ],
                        );
                        expected_observed.clone_from(&approval.old_commit);
                    }
                } else {
                    let ack = receiver.send(permission).await;
                    journal
                        .record_git_acknowledgement(&binding, ack, &worker)
                        .unwrap();
                    let tree = String::from_utf8(git(
                        &receiver.executable,
                        &fixture.0,
                        &[
                            "--git-dir",
                            receiver.sender.to_str().unwrap(),
                            "rev-parse",
                            &format!("{}^{{tree}}", approval.new_commit),
                        ],
                    ))
                    .unwrap();
                    let onward = commit(
                        &receiver.executable,
                        &receiver.sender,
                        tree.trim(),
                        Some(&approval.new_commit),
                        "D",
                    );
                    operator_push(&receiver, &onward);
                    expected_observed = onward;
                }
            } else if case == "pre-receive" {
                expected_observed.clone_from(&approval.old_commit);
            }
            drop(worker);
            drop(journal);
            let mut journal = Journal::open(&path).unwrap();
            let worker = journal.try_lock_worker().unwrap().unwrap();
            let signing = ReceiptSettings {
                signing_seed: &[9; 32],
                key_id: "receipt-owner",
            };
            let frozen = advance(
                &mut journal,
                &binding,
                Some(&receiver),
                Some(&signing),
                &worker,
            )
            .await
            .unwrap();
            let GitPhase::Finalized { statement, receipt } = &frozen else {
                unreachable!("advance did not finalize {case}")
            };
            assert_eq!(
                statement.observed,
                ObservedRef::Commit(expected_observed),
                "{case}"
            );
            let expected_ack = if matches!(case, "healthy" | "onward") {
                Acknowledgement::Updated
            } else {
                Acknowledgement::Unknown
            };
            assert_eq!(statement.acknowledgement, expected_ack, "{case}");
            assert_eq!(
                statement.result(),
                if expected_ack == Acknowledgement::Updated {
                    OperationResult::Succeeded
                } else {
                    OperationResult::Unknown
                },
                "{case}"
            );
            let counts = receiver_counts(&fixture, &approval);
            assert_eq!(
                counts,
                match case {
                    "healthy" | "post-receive" => (1, 1, 1),
                    "pre-receive" => (1, 1, 0),
                    "unsent-aba" | "unsent-present-b" => (0, 1, 1),
                    "onward" => (1, 2, 2),
                    _ => unreachable!(),
                },
                "{case}"
            );
            assert_eq!(
                &evidence::decode(&receipt.bytes).unwrap().1,
                statement.as_ref()
            );
            drop(worker);
            drop(journal);
            let mut journal = Journal::open(&path).unwrap();
            let worker = journal.try_lock_worker().unwrap().unwrap();
            assert_eq!(
                advance(&mut journal, &binding, None, None, &worker)
                    .await
                    .unwrap(),
                frozen
            );
            assert_eq!(receiver_counts(&fixture, &approval), counts, "{case}");
        }
    }

    #[tokio::test]
    #[ignore = "requires operator-selected Git 2.55.0; KAPSEL_TEST_GIT is an absolute executable"]
    #[allow(
        clippy::too_many_lines,
        reason = "one service lifecycle proves signing-only resumption after material removal"
    )]
    async fn real_git_service_reconnects_and_signs_frozen_evidence_without_receiver() {
        use crate::{
            OperationReceipt, OperationStatus, ServiceApplication, ServiceApproval,
            ServiceConfiguration, ServiceExecution,
        };
        for case in ["healthy", "post-receive"] {
            let (fixture, receiver, approval, _) = receiver_fixture();
            install_hooks(&fixture, &receiver, case);
            let material = GitReceiverConfiguration {
                executable: receiver.executable.clone(),
                sender: receiver.sender.clone(),
                receiver: receiver.receiver.clone(),
                repository_id: receiver.repository_id.clone(),
            };
            let grant = crate::provision_git_ref_grant(&approval, &material, &[7; 32], "owner")
                .await
                .unwrap();
            assert_eq!(receiver_counts(&fixture, &approval), (0, 0, 0));
            let mut configuration = ServiceConfiguration {
                journal_path: fixture.0.join("service-journal"),
                authorization_trust: vec![kapsel_authority::AuthorizationTrust {
                    key_id: "owner".into(),
                    public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                        .verifying_key()
                        .to_bytes(),
                }],
                approvals: vec![ServiceApproval {
                    signed_grant: grant,
                    label: "Approved Git".into(),
                }],
            };
            let mut service = ServiceApplication::open(configuration.clone()).unwrap();
            let stopped = service
                .select(
                    &approval.operation_id,
                    ServiceExecution {
                        kubernetes_client: None,
                        git_receiver: Some(material),
                        receipt_signing: None,
                    },
                    |admission| {
                        assert_eq!(
                            admission,
                            crate::ServiceAdmission::Admitted(crate::OperationState::Authorized)
                        );
                        assert_eq!(receiver_counts(&fixture, &approval), (0, 0, 0));
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                stopped,
                crate::ServiceStop::Blocked(crate::ExecutionCondition::SigningUnavailable)
            );
            assert_eq!(
                service.status(&approval.operation_id).unwrap().0,
                OperationStatus::InProgress
            );
            assert_eq!(receiver_counts(&fixture, &approval), (0, 1, 1));
            drop(service);
            fs::remove_dir_all(&receiver.receiver).unwrap();
            fs::remove_file(&receiver.executable).unwrap();
            configuration.approvals.clear();
            let mut service = ServiceApplication::open(configuration).unwrap();
            assert_eq!(
                service
                    .select(
                        &approval.operation_id,
                        ServiceExecution {
                            kubernetes_client: None,
                            git_receiver: None,
                            receipt_signing: Some(([9; 32], "receipt-owner".into())),
                        },
                        |_| {},
                    )
                    .await
                    .unwrap(),
                crate::ServiceStop::Finished
            );
            let expected = if case == "healthy" {
                OperationStatus::Succeeded
            } else {
                OperationStatus::Unknown
            };
            assert_eq!(service.status(&approval.operation_id).unwrap().0, expected);
            assert!(matches!(
                service.receipt(&approval.operation_id).unwrap(),
                OperationReceipt::Ready { .. }
            ));
            assert_eq!(receiver_counts(&fixture, &approval), (0, 1, 1));
        }
    }

    #[tokio::test]
    #[ignore = "requires operator-selected Git 2.55.0; KAPSEL_TEST_GIT is an absolute executable"]
    async fn real_git_preflight_read_failures_remain_authorized_and_resumable() {
        for case in ["object-read", "ancestry-read"] {
            let (fixture, mut receiver, mut approval, _) = receiver_fixture();
            receiver.packet_trace = Some(fixture.0.join("packets"));
            install_hooks(&fixture, &receiver, "healthy");
            let withheld = approval.new_commit.clone();
            if case == "ancestry-read" {
                let tree = String::from_utf8(git(
                    &receiver.executable,
                    &fixture.0,
                    &[
                        "--git-dir",
                        receiver.sender.to_str().unwrap(),
                        "rev-parse",
                        &format!("{}^{{tree}}", approval.new_commit),
                    ],
                ))
                .unwrap();
                approval.new_commit = commit(
                    &receiver.executable,
                    &receiver.sender,
                    tree.trim(),
                    Some(&withheld),
                    "descendant",
                );
            }
            let object = receiver
                .sender
                .join("objects")
                .join(&withheld[..2])
                .join(&withheld[2..]);
            let saved = fixture.0.join("withheld-object");
            fs::rename(&object, &saved).unwrap();
            let binding = binding_for(&approval);
            let path = fixture.0.join("preflight-journal");
            let mut journal = Journal::open(&path).unwrap();
            let worker = journal.try_lock_worker().unwrap().unwrap();
            journal.insert_git(&binding, &worker).unwrap();
            assert!(
                matches!(
                    advance(&mut journal, &binding, Some(&receiver), None, &worker).await,
                    Err(GatewayError::GitReceiverUnavailable)
                ),
                "{case}"
            );
            assert_eq!(
                journal.git_operation(&binding).unwrap(),
                Some(GitPhase::Authorized)
            );
            assert_eq!(receiver_counts(&fixture, &approval), (0, 0, 0));
            drop(worker);
            drop(journal);
            fs::rename(saved, object).unwrap();
            let mut journal = Journal::open(&path).unwrap();
            let worker = journal.try_lock_worker().unwrap().unwrap();
            let signing = ReceiptSettings {
                signing_seed: &[9; 32],
                key_id: "receipt-owner",
            };
            let phase = advance(
                &mut journal,
                &binding,
                Some(&receiver),
                Some(&signing),
                &worker,
            )
            .await
            .unwrap();
            let GitPhase::Finalized { statement, .. } = phase else {
                unreachable!()
            };
            assert_eq!(statement.acknowledgement, Acknowledgement::Updated);
            assert_eq!(receiver_counts(&fixture, &approval), (1, 1, 1));
        }
    }

    #[tokio::test]
    #[ignore = "requires operator-selected Git 2.55.0; KAPSEL_TEST_GIT is an absolute executable"]
    async fn real_git_positive_type_and_non_ancestry_evidence_reject_before_attempt() {
        let (fixture, mut receiver, mut approval, competitor) = receiver_fixture();
        receiver.packet_trace = Some(fixture.0.join("packets"));
        install_hooks(&fixture, &receiver, "healthy");
        let tree = String::from_utf8(git(
            &receiver.executable,
            &fixture.0,
            &[
                "--git-dir",
                receiver.sender.to_str().unwrap(),
                "rev-parse",
                &format!("{}^{{tree}}", approval.new_commit),
            ],
        ))
        .unwrap()
        .trim()
        .to_owned();
        approval.old_commit = approval.new_commit.clone();
        for (index, new_commit) in [tree, competitor].into_iter().enumerate() {
            approval.new_commit = new_commit;
            let binding = binding_for(&approval);
            let mut journal = Journal::open(fixture.0.join(format!("invalid-{index}"))).unwrap();
            let worker = journal.try_lock_worker().unwrap().unwrap();
            journal.insert_git(&binding, &worker).unwrap();
            assert_eq!(
                advance(&mut journal, &binding, Some(&receiver), None, &worker)
                    .await
                    .unwrap(),
                GitPhase::NotAttempted(GitRejection::InvalidObjects)
            );
            assert_eq!(receiver_counts(&fixture, &approval), (0, 0, 0));
        }
    }

    fn binding_for(approval: &GitRefAuthorization) -> GitBinding {
        let seed = [7; 32];
        let bytes = kapsel_authority::sign_git_ref_grant(approval, &seed, "owner").unwrap();
        let trust = kapsel_authority::AuthorizationTrust {
            key_id: "owner".into(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        };
        GitBinding::verify(&bytes, &[trust]).unwrap()
    }

    fn receiver_fixture() -> (Fixture, GitReceiver, GitRefAuthorization, String) {
        let installed = fs::canonicalize(std::env::var_os("KAPSEL_TEST_GIT").unwrap()).unwrap();
        let fixture = Fixture::new();
        let executable = fixture.0.join("git");
        fs::copy(installed, &executable).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(git(&executable, &fixture.0, &["--version"]), VERSION);
        for name in ["sender.git", "receiver.git"] {
            git(
                &executable,
                &fixture.0,
                &["init", "--quiet", "--bare", name],
            );
        }
        let sender = fixture.0.join("sender.git");
        let receiver = fixture.0.join("receiver.git");
        for (name, value) in [
            ("receive.denyDeletes", "true"),
            ("receive.denyNonFastForwards", "true"),
            ("kapsel.repositoryId", "repository-1"),
        ] {
            git(
                &executable,
                &fixture.0,
                &[
                    "--git-dir",
                    receiver.to_str().unwrap(),
                    "config",
                    name,
                    value,
                ],
            );
        }
        let tree = String::from_utf8(git(
            &executable,
            &fixture.0,
            &[
                "--git-dir",
                sender.to_str().unwrap(),
                "hash-object",
                "-w",
                "-t",
                "tree",
                "/dev/null",
            ],
        ))
        .unwrap()
        .trim()
        .to_owned();
        let old = commit(&executable, &sender, &tree, None, "A");
        let new = commit(&executable, &sender, &tree, Some(&old), "B");
        let competitor = commit(&executable, &sender, &tree, Some(&old), "C");
        git(
            &executable,
            &fixture.0,
            &[
                "--git-dir",
                sender.to_str().unwrap(),
                "push",
                receiver.to_str().unwrap(),
                &format!("{old}:{APPROVED_GIT_REF}"),
            ],
        );
        let adapter =
            GitReceiver::new(executable, sender, receiver, "repository-1".into()).unwrap();
        let mut approval = approval();
        approval.old_commit = old;
        approval.new_commit = new;
        (fixture, adapter, approval, competitor)
    }

    #[tokio::test]
    #[ignore = "requires operator-selected Git 2.55.0; KAPSEL_TEST_GIT is an absolute executable"]
    async fn real_git_exact_transition_and_stale_competitor() {
        let (fixture, adapter, approval, competitor) = receiver_fixture();
        let new = approval.new_commit.clone();
        let first = adapter.prepare(&approval).await.unwrap();
        let mut other = approval.clone();
        other.new_commit = competitor;
        let second = adapter.prepare(&other).await.unwrap();
        assert_eq!(
            adapter
                .send(journaled_permission(&fixture, &approval, first))
                .await,
            Acknowledgement::Updated
        );
        assert_eq!(adapter.observe().await, ObservedRef::Commit(new.clone()));
        assert_eq!(
            adapter
                .send(journaled_permission(&fixture, &other, second))
                .await,
            Acknowledgement::RejectedBeforeSend
        );
        assert_eq!(adapter.observe().await, ObservedRef::Commit(new));
        assert!(matches!(
            adapter.prepare(&approval).await,
            Err(GitError::StaleRef)
        ));
    }

    #[tokio::test]
    #[ignore = "requires operator-selected Git 2.55.0; KAPSEL_TEST_GIT is an absolute executable"]
    async fn real_git_prepared_transition_cannot_transfer_to_another_receiver() {
        let (fixture, first, approval, _) = receiver_fixture();
        let second_path = fixture.0.join("second.git");
        git(
            &first.executable,
            &fixture.0,
            &[
                "clone",
                "--bare",
                "--no-local",
                first.receiver.to_str().unwrap(),
                second_path.to_str().unwrap(),
            ],
        );
        // Cloning adds a remote. Provision only the same fixed receiver configuration.
        fs::write(
            second_path.join("config"),
            concat!(
                "[core]\nrepositoryformatversion=0\nfilemode=true\nbare=true\n",
                "[receive]\ndenyDeletes=true\ndenyNonFastForwards=true\n",
                "[kapsel]\nrepositoryId=repository-2\n",
            ),
        )
        .unwrap();
        let mut second = GitReceiver::new(
            first.executable.clone(),
            first.sender.clone(),
            second_path,
            "repository-2".into(),
        )
        .unwrap();
        for identity in ["repository-2", "repository-1"] {
            second.repository_id = identity.into();
            git(
                &first.executable,
                &fixture.0,
                &[
                    "--git-dir",
                    second.receiver.to_str().unwrap(),
                    "config",
                    "kapsel.repositoryId",
                    identity,
                ],
            );
            let prepared = first.prepare(&approval).await.unwrap();
            assert_eq!(
                second
                    .send(journaled_permission(&fixture, &approval, prepared))
                    .await,
                Acknowledgement::Unknown
            );
            assert_eq!(
                first.observe().await,
                ObservedRef::Commit(approval.old_commit.clone())
            );
            assert_eq!(
                second.observe().await,
                ObservedRef::Commit(approval.old_commit.clone())
            );
        }
    }
}
