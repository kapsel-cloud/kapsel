//! Concrete local maintenance roles for the serialized sandbox controller host.

use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    object_identity_parts, storage_error, timestamp, CleanupAbsenceEvidence, CleanupState,
    DispatchLease, Service, ServiceError, PROVISIONED_OBJECT_OWNERS_MAX,
};

const CLEANUP_ESCALATION_SECONDS: i64 = 15 * 60;
type CleanupCandidate = (String, String, String, CleanupState, Option<i64>, bool);

/// One bounded scheduler reconciliation step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchedulerStep {
    /// No queued run was available or another unexpired process lease owns recovery.
    Waiting,
    /// The local role still owns the current active lease.
    Active(DispatchLease),
    /// The local role recovered the sole active run under a fresh lease generation.
    Recovered(DispatchLease),
    /// The local role dispatched the oldest queued run.
    Dispatched(DispatchLease),
}

/// Serial scheduler role over the concrete sandbox service transitions.
pub struct SchedulerRole {
    service: Service,
    current: Option<DispatchLease>,
}

impl SchedulerRole {
    /// Creates one process-local scheduler role for the owner-private service state.
    pub fn new(service: Service) -> Self {
        Self {
            service,
            current: None,
        }
    }

    /// Recovers the sole active run before considering one FIFO dispatch.
    ///
    /// # Errors
    ///
    /// Returns a bounded service error when durable capacity, lease, time, or storage state is
    /// invalid. An unexpired lease owned by another process returns [`SchedulerStep::Waiting`].
    pub fn run_once(&mut self, now_unix_s: i64) -> Result<SchedulerStep, ServiceError> {
        timestamp(now_unix_s)?;
        let active = self.service.recoverable_runs()?;
        if active.len() > 1 {
            return Err(ServiceError::Unavailable);
        }
        if let Some(run_id) = active.first() {
            if let Some(current) = self
                .current
                .as_ref()
                .filter(|lease| lease.run_id == *run_id)
            {
                if now_unix_s < current.expires_at_unix_s.saturating_sub(5) {
                    return Ok(SchedulerStep::Active(current.clone()));
                }
                let recovered = self
                    .service
                    .recover_run(run_id, Some(current), now_unix_s)?;
                self.current = Some(recovered.clone());
                return Ok(SchedulerStep::Recovered(recovered));
            }
            return match self.service.recover_run(run_id, None, now_unix_s) {
                Ok(recovered) => {
                    self.current = Some(recovered.clone());
                    Ok(SchedulerStep::Recovered(recovered))
                },
                Err(ServiceError::LeaseBusy) => Ok(SchedulerStep::Waiting),
                Err(error) => Err(error),
            };
        }

        self.current = None;
        match self.service.dispatch_next(now_unix_s) {
            Ok(lease) => {
                self.current = Some(lease.clone());
                Ok(SchedulerStep::Dispatched(lease))
            },
            Err(ServiceError::RunNotFound) => Ok(SchedulerStep::Waiting),
            Err(error) => Err(error),
        }
    }
}

/// Periodic public-retention role over the concrete sandbox service transition.
pub struct RetentionRole {
    service: Service,
}

impl RetentionRole {
    /// Creates one local retention role.
    pub fn new(service: Service) -> Self {
        Self { service }
    }

    /// Runs one bounded expiry and tombstone sweep.
    ///
    /// # Errors
    ///
    /// Returns a time, storage, or immutable-object deletion failure.
    pub fn run_once(&self, now_unix_s: i64) -> Result<(), ServiceError> {
        self.service.sweep_retention(now_unix_s)
    }
}

/// One exact object identity owned by the active cleanup generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupOwnedObject {
    /// Exact Kubernetes kind.
    pub kind: String,
    /// Exact namespace, absent only for the owned Namespace object.
    pub namespace: Option<String>,
    /// Exact object name.
    pub name: String,
    /// Immutable UID recorded before deletion.
    pub uid: String,
    /// Exact cleanup owner marker.
    pub owner_label: String,
}

/// The sole cleanup work item selected from durable state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupWork {
    /// Public run identity.
    pub run_id: String,
    /// Exact server-owned cleanup identity.
    pub cleanup_identity: String,
    /// Immutable namespace UID recorded before cleanup.
    pub namespace_uid: String,
    /// Append-only exact object inventory.
    pub objects: Vec<CleanupOwnedObject>,
    /// Whether the one fifteen-minute escalation is durably due or already emitted.
    pub escalated: bool,
}

/// UID- and owner-safe local cleanup role over concrete service transitions.
pub struct CleanupRole {
    service: Service,
}

impl CleanupRole {
    /// Creates one local cleanup role.
    pub fn new(service: Service) -> Self {
        Self { service }
    }

    /// Selects the sole eligible cleanup item and durably starts cleanup when pending.
    ///
    /// # Errors
    ///
    /// Returns a bounded ownership, state, time, or storage failure. More than one active cleanup
    /// item fails closed.
    pub fn next(&self, now_unix_s: i64) -> Result<Option<CleanupWork>, ServiceError> {
        timestamp(now_unix_s)?;
        let candidate = self.service.cleanup_candidate()?;
        let Some((run_id, cleanup_identity, namespace_uid, state, started_at, escalated)) =
            candidate
        else {
            return Ok(None);
        };
        if state == CleanupState::Pending {
            self.service
                .start_cleanup(&run_id, &cleanup_identity, &namespace_uid, now_unix_s)?;
        } else if !matches!(state, CleanupState::Running | CleanupState::Failed) {
            return Err(ServiceError::InvalidTransition);
        }
        let escalated = if state == CleanupState::Failed
            && !escalated
            && started_at.is_some_and(|started| {
                now_unix_s.saturating_sub(started) >= CLEANUP_ESCALATION_SECONDS
            }) {
            self.service
                .mark_cleanup_escalated(&run_id, &cleanup_identity, now_unix_s)?;
            true
        } else {
            escalated
        };
        Ok(Some(CleanupWork {
            objects: self
                .service
                .cleanup_owned_objects(&run_id, &cleanup_identity)?,
            run_id,
            cleanup_identity,
            namespace_uid,
            escalated,
        }))
    }

    /// Records one coalesced retryable cleanup failure without changing operation outcome.
    ///
    /// # Errors
    ///
    /// Returns a bounded ownership, transition, time, or storage failure.
    pub fn fail(&self, work: &CleanupWork, now_unix_s: i64) -> Result<(), ServiceError> {
        match self.service.fail_cleanup(
            &work.run_id,
            &work.cleanup_identity,
            &work.namespace_uid,
            now_unix_s,
        ) {
            Ok(()) => Ok(()),
            Err(ServiceError::InvalidTransition) => {
                let current = self.service.cleanup_candidate()?;
                if current.as_ref().is_some_and(
                    |(run_id, cleanup_identity, namespace_uid, state, _, _)| {
                        run_id == &work.run_id
                            && cleanup_identity == &work.cleanup_identity
                            && namespace_uid == &work.namespace_uid
                            && *state == CleanupState::Failed
                    },
                ) {
                    Ok(())
                } else {
                    Err(ServiceError::InvalidTransition)
                }
            },
            Err(error) => Err(error),
        }
    }

    /// Releases serialized capacity only after exact fresh absence evidence is accepted.
    ///
    /// # Errors
    ///
    /// Returns a bounded ownership, presence, transition, time, or storage failure.
    pub fn complete(
        &self,
        work: &CleanupWork,
        evidence: &CleanupAbsenceEvidence,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        self.service
            .complete_cleanup(&work.run_id, &work.cleanup_identity, evidence, now_unix_s)
    }
}

impl Service {
    fn cleanup_candidate(&self) -> Result<Option<CleanupCandidate>, ServiceError> {
        let connection = self.connection()?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM cleanup_records WHERE active = 1 AND eligible = 1",
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if count > 1 {
            return Err(ServiceError::Unavailable);
        }
        connection
            .query_row(
                concat!(
                    "SELECT cleanup_records.run_id, cleanup_records.cleanup_identity, ",
                    "cleanup_records.namespace_uid, cleanup_records.state, ",
                    "cleanup_records.started_at, cleanup_records.escalated FROM cleanup_records ",
                    "JOIN runs ON runs.run_id = cleanup_records.run_id ",
                    "WHERE cleanup_records.active = 1 AND cleanup_records.eligible = 1 ",
                    "AND cleanup_records.resource_state = 'owned' ORDER BY runs.admission_order ",
                    "LIMIT 1"
                ),
                [],
                |row| {
                    let state = row.get::<_, String>(3)?;
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        CleanupState::parse(&state).map_err(|_| rusqlite::Error::InvalidQuery)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)
    }

    fn cleanup_owned_objects(
        &self,
        run_id: &str,
        cleanup_identity: &str,
    ) -> Result<Vec<CleanupOwnedObject>, ServiceError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(concat!(
                "SELECT identity, uid, owner_label FROM provisioned_object_owners ",
                "WHERE run_id = ?1 ORDER BY uid"
            ))
            .map_err(storage_error)?;
        let rows = statement
            .query_map([run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(storage_error)?;
        let mut objects = Vec::new();
        for row in rows {
            let (identity, uid, owner_label) = row.map_err(storage_error)?;
            if owner_label != cleanup_identity {
                return Err(ServiceError::OwnershipMismatch);
            }
            let (kind, namespace, name) = object_identity_parts(&identity)?;
            objects.push(CleanupOwnedObject {
                kind,
                namespace,
                name,
                uid,
                owner_label,
            });
        }
        if objects.is_empty()
            || i64::try_from(objects.len()).ok() > Some(PROVISIONED_OBJECT_OWNERS_MAX)
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(objects)
    }

    fn mark_cleanup_escalated(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let changed = transaction
            .execute(
                concat!(
                    "UPDATE cleanup_records SET escalated = 1 WHERE run_id = ?1 ",
                    "AND cleanup_identity = ?2 AND active = 1 AND eligible = 1 ",
                    "AND state = 'failed' AND escalated = 0 AND started_at IS NOT NULL ",
                    "AND ?3 - started_at >= ?4"
                ),
                params![
                    run_id,
                    cleanup_identity,
                    now_unix_s,
                    CLEANUP_ESCALATION_SECONDS
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(ServiceError::InvalidTransition);
        }
        transaction.commit().map_err(storage_error)
    }
}
