//! Atomic effect record I/O and projection into lifecycle-owned validated snapshots.

use std::sync::OnceLock;

use rusqlite::{
    types::{FromSql, Value},
    Connection, OptionalExtension, TransactionBehavior,
};

use super::{changed_one, schema, GatewayError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Table {
    Kubernetes,
    Git,
}

impl Table {
    fn columns(self) -> &'static [&'static str] {
        match self {
            Self::Kubernetes => schema::CURRENT_COLUMNS,
            Self::Git => schema::GIT_COLUMNS,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Kubernetes => "kubernetes_image_operations",
            Self::Git => "git_ref_operations",
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Kubernetes => Self::Git,
            Self::Git => Self::Kubernetes,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct Record {
    values: Vec<Value>,
    table: Table,
}

impl Record {
    pub(super) fn empty(id: &str) -> Self {
        let mut record = Self {
            values: vec![Value::Null; schema::CURRENT_COLUMNS.len()],
            table: Table::Kubernetes,
        };
        record.set("operation_id", id.to_owned());
        for field in ["target_read_failures", "apply_attempted"] {
            record.set(field, 0_i64);
        }
        record
    }

    pub(super) fn git_empty(id: &str) -> Self {
        let mut record = Self {
            values: vec![Value::Null; schema::GIT_COLUMNS.len()],
            table: Table::Git,
        };
        record.set("operation_id", id.to_owned());
        record
    }

    #[allow(
        clippy::expect_used,
        reason = "column names are fixed internal code, never input"
    )]
    fn index(&self, field: &str) -> usize {
        self.table
            .columns()
            .iter()
            .position(|name| *name == field)
            .expect("record fields are fixed internal schema column names")
    }

    pub(super) fn get<T: FromSql>(&self, field: &str) -> Result<T, GatewayError> {
        T::column_result((&self.values[self.index(field)]).into())
            .map_err(|_| GatewayError::InvalidPersistedState)
    }

    pub(super) fn set(&mut self, field: &str, value: impl Into<Value>) {
        let index = self.index(field);
        self.values[index] = value.into();
    }

    pub(super) fn set_optional<T: Into<Value>>(&mut self, field: &str, value: Option<T>) {
        let index = self.index(field);
        self.values[index] = value.map_or(Value::Null, Into::into);
    }

    #[cfg(test)]
    fn bounded(&self) -> bool {
        let lengths = self
            .values
            .iter()
            .map(|value| match value {
                Value::Null => 0,
                Value::Text(text) => text.len(),
                Value::Blob(bytes) => bytes.len(),
                Value::Integer(value) => value.to_string().len(),
                Value::Real(value) => value.to_string().len(),
            })
            .collect::<Vec<_>>();
        lengths
            .iter()
            .zip(self.table.columns())
            .all(|(length, field)| *length <= field_limit(field))
            && lengths.iter().sum::<usize>()
                <= usize::try_from(schema::PERSISTED_ROW_BYTES_MAX).unwrap()
    }

    pub(super) fn has_value(&self, field: &str) -> bool {
        self.values[self.index(field)] != Value::Null
    }

    fn from_sql(row: &rusqlite::Row<'_>, table: Table) -> rusqlite::Result<Self> {
        let persisted_values_within_bounds = row.get::<_, bool>(table.columns().len())?;
        if !persisted_values_within_bounds {
            return Err(rusqlite::Error::InvalidQuery);
        }

        (0..table.columns().len())
            .map(|index| row.get(index))
            .collect::<rusqlite::Result<Vec<_>>>()
            .map(|values| Self { values, table })
    }
}

pub(super) fn decode(
    record: &Record,
    #[cfg(test)] control: &Control,
) -> Result<super::LoadedOperation, GatewayError> {
    let snapshot = super::SnapshotRow {
        approved_uid: record.get("approved_uid")?,
        approved_resource_version: record.get("approved_resource_version")?,
        preflight_uid: record.get("preflight_uid")?,
        preflight_resource_version: record.get("preflight_resource_version")?,
        operation_id: record.get("operation_id")?,
        namespace: record.get("namespace")?,
        deployment: record.get("deployment")?,
        container: record.get("container")?,
        immutable_image_digest: record.get("immutable_image_digest")?,
        state: record.get("state")?,
        result: record.get("result")?,
        target_rejection: record.get("target_rejection")?,
        authorization_id: record.get("authorization_id")?,
        authorization_signer_key_id: record.get("authorization_signer_key_id")?,
        authorization_grant_digest: record.get("authorization_grant_digest")?,
        write_strategy: record.get("write_strategy")?,
        apply_attempted: record.get("apply_attempted")?,
        target_uid: record.get("target_uid")?,
        target_resource_version: record.get("target_resource_version")?,
        apply_accepted: record.get("apply_accepted")?,
        requested_generation: record.get("requested_generation")?,
        apply_resource_version: record.get("apply_resource_version")?,
        receiver_facts_present: [
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
            "rollout_condition_type",
            "rollout_condition_status",
            "rollout_condition_reason",
        ]
        .iter()
        .any(|field| record.has_value(field)),
        receipt_digest: record.get("receipt_digest")?,
        receipt_bytes: record.get("receipt_bytes")?,
        receipt_key_id: record.get("receipt_key_id")?,
    };
    let statement = if matches!(snapshot.state.as_str(), "receiver_observed" | "finalized") {
        let available_field = "available_replicas";
        #[cfg(test)]
        let available_field = if control.exercise(Defect::ReceiptProjectionSwap) {
            "updated_replicas"
        } else {
            available_field
        };
        Some(
            super::ReceiptRow {
                approved_uid: record.get("approved_uid")?,
                approved_resource_version: record.get("approved_resource_version")?,
                operation_id: record.get("operation_id")?,
                authorization_id: record.get("authorization_id")?,
                authorization_signer_key_id: record.get("authorization_signer_key_id")?,
                authorization_grant_digest: record.get("authorization_grant_digest")?,
                namespace: record.get("namespace")?,
                deployment: record.get("deployment")?,
                container: record.get("container")?,
                immutable_image_digest: record.get("immutable_image_digest")?,
                write_strategy: record.get("write_strategy")?,
                target_uid: record.get("target_uid")?,
                target_resource_version: record.get("target_resource_version")?,
                receiver_uid: record.get("receiver_uid")?,
                observed_image: record.get("receiver_image")?,
                observed_operation_marker: record.get("receiver_operation_marker")?,
                current_generation: record.get("current_generation")?,
                requested_generation: record.get("requested_generation")?,
                observed_generation: record.get("observed_generation")?,
                observed_resource_version: record.get("receiver_resource_version")?,
                desired_replicas: record.get("desired_replicas")?,
                updated_replicas: record.get("updated_replicas")?,
                available_replicas: record.get(available_field)?,
                unavailable_replicas: record.get("unavailable_replicas")?,
                rollout_condition_type: record.get("rollout_condition_type")?,
                rollout_condition_status: record.get("rollout_condition_status")?,
                rollout_condition_reason: record.get("rollout_condition_reason")?,
                result: record.get("result")?,
            }
            .into_statement()?,
        )
    } else {
        None
    };
    snapshot.into_operation(statement)
}

fn field_limit(field: &str) -> usize {
    if field == "signed_authorization_grant" {
        4096
    } else {
        schema::PERSISTED_VALUE_BYTES_MAX
    }
}

pub(super) fn read(connection: &Connection, id: &str) -> Result<Option<Record>, GatewayError> {
    read_table(connection, id, Table::Kubernetes)
}

pub(super) fn read_git(connection: &Connection, id: &str) -> Result<Option<Record>, GatewayError> {
    read_table(connection, id, Table::Git)
}

fn read_table(
    connection: &Connection,
    id: &str,
    table: Table,
) -> Result<Option<Record>, GatewayError> {
    // Opening enforces per-value and aggregate persisted bounds. Keep those same bounds on reads
    // after opening: direct edits are not made safe by possession of the worker lease.
    static KUBERNETES_QUERY: OnceLock<String> = OnceLock::new();
    static GIT_QUERY: OnceLock<String> = OnceLock::new();
    let query = match table {
        Table::Kubernetes => &KUBERNETES_QUERY,
        Table::Git => &GIT_QUERY,
    }
    .get_or_init(|| {
        let columns = table.columns().join(", ");
        let lengths = table
            .columns()
            .iter()
            .map(|field| format!("coalesce(length(CAST({field} AS BLOB)), 0)"))
            .collect::<Vec<_>>();
        let bounds = lengths
            .iter()
            .zip(table.columns())
            .map(|(length, field)| format!("{length} <= {}", field_limit(field)))
            .collect::<Vec<_>>()
            .join(" AND ");
        let total = lengths.join(" + ");
        format!(
            "SELECT {columns}, ({bounds} AND ({total}) <= {}) \
            FROM {} WHERE operation_id = ?1",
            schema::PERSISTED_ROW_BYTES_MAX,
            table.name()
        )
    });
    connection
        .prepare_cached(query)
        .map_err(GatewayError::Database)?
        .query_row([id], |row| Record::from_sql(row, table))
        .optional()
        .map_err(|error| match error {
            rusqlite::Error::InvalidQuery => GatewayError::InvalidPersistedState,
            error => GatewayError::Database(error),
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum Write {
    Admission,
    Authorization,
    Rejection,
    Attempt,
    Response,
    Observation,
    Receipt,
}

#[derive(Default)]
pub(super) struct Io {
    #[cfg(test)]
    pub(crate) control: Control,
}

impl Io {
    #[allow(
        clippy::unused_self,
        reason = "decoder defect controls exist only in test builds"
    )]
    pub(super) fn decode(&self, record: &Record) -> Result<super::LoadedOperation, GatewayError> {
        decode(
            record,
            #[cfg(test)]
            &self.control,
        )
    }

    #[allow(
        clippy::unused_self,
        reason = "virtual record reads exist only in test builds"
    )]
    pub(super) fn read(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<Option<Record>, GatewayError> {
        self.read_table(connection, id, Table::Kubernetes)
    }

    pub(super) fn read_git(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<Option<Record>, GatewayError> {
        self.read_table(connection, id, Table::Git)
    }

    #[allow(
        clippy::unused_self,
        reason = "virtual record reads exist only in test builds"
    )]
    fn read_table(
        &self,
        connection: &Connection,
        id: &str,
        table: Table,
    ) -> Result<Option<Record>, GatewayError> {
        #[cfg(test)]
        if let Some(store) = &self.control.0.lock().unwrap().virtual_store {
            let store = store.lock().unwrap();
            return store
                .get(id)
                .filter(|record| record.table == table)
                .map(|record| {
                    if record.bounded() {
                        Ok(record.clone())
                    } else {
                        Err(GatewayError::InvalidPersistedState)
                    }
                })
                .transpose();
        }
        read_table(connection, id, table)
    }

    #[cfg(test)]
    pub(super) fn other_identity(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<Option<String>, GatewayError> {
        if let Some(store) = &self.control.0.lock().unwrap().virtual_store {
            return Ok(store
                .lock()
                .unwrap()
                .keys()
                .find(|peer| peer.as_str() != id)
                .cloned());
        }
        connection
            .query_row(
                "SELECT operation_id FROM kubernetes_image_operations
             WHERE operation_id != ?1 ORDER BY operation_id LIMIT 1",
                [id],
                |row| row.get(0),
            )
            .optional()
            .map_err(GatewayError::Database)
    }

    // Complete-record comparison binds every conditional write, including frozen facts and grant
    // bytes. SQLite changes only differing fields: inert/history columns are not rewritten.
    pub(super) fn replace(
        &self,
        connection: &Connection,
        expected: Option<&Record>,
        next: &Record,
        write: Write,
    ) -> Result<(), GatewayError> {
        #[cfg(test)]
        let id: String = next.get("operation_id")?;
        #[cfg(test)]
        {
            let mut control = self.control.0.lock().unwrap();
            let delivery = control.take_delivery(write);
            if let Some(store) = control.virtual_store.clone() {
                let mut store = store.lock().unwrap();
                if store
                    .get(&id)
                    .is_some_and(|record| record.table != next.table)
                {
                    return Err(GatewayError::OperationIdentityConflict);
                }
                let ignore_binding = control.defect == Some(Defect::UnconditionalWrite);
                if ignore_binding {
                    control.defect_reached.push(Defect::UnconditionalWrite);
                }
                if !ignore_binding && store.get(&id) != expected {
                    return Err(GatewayError::InvalidTransition);
                }
                if delivery != Delivery::NoCommit {
                    store.insert(id, next.clone());
                }
                drop(store);
                return delivery.result();
            }
            drop(control);
            self.replace_sqlite(connection, expected, next, write, delivery)
        }
        #[cfg(not(test))]
        {
            let _ = write;
            self.replace_sqlite(connection, expected, next)
        }
    }

    #[allow(
        clippy::unused_self,
        reason = "test builds record SQL, delivery and seeded defects"
    )]
    fn replace_sqlite(
        &self,
        connection: &Connection,
        expected: Option<&Record>,
        next: &Record,
        #[cfg(test)] write: Write,
        #[cfg(test)] delivery: Delivery,
    ) -> Result<(), GatewayError> {
        let transaction =
            rusqlite::Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
                .map_err(GatewayError::Database)?;
        let id: String = next.get("operation_id")?;
        let retained_record_matches =
            read_table(&transaction, &id, next.table)?.as_ref() == expected;
        #[cfg(test)]
        let retained_record_matches =
            self.control.exercise(Defect::UnconditionalWrite) || retained_record_matches;
        if !retained_record_matches {
            return Err(GatewayError::InvalidTransition);
        }

        if let Some(previous) = expected {
            self.update_changed_columns(
                &transaction,
                previous,
                next,
                id,
                #[cfg(test)]
                write,
            )?;
        } else {
            let has_other_effect_identity: bool = transaction
                .query_row(
                    &format!(
                        "SELECT EXISTS (SELECT 1 FROM {} WHERE operation_id = ?1)",
                        next.table.other().name()
                    ),
                    [&id],
                    |row| row.get(0),
                )
                .map_err(GatewayError::Database)?;
            if has_other_effect_identity {
                return Err(GatewayError::OperationIdentityConflict);
            }
            super::capacity::require_admission(&transaction)?;
            let parameters = (1..=next.values.len())
                .map(|index| format!("?{index}"))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "INSERT INTO {} ({}) \
                VALUES ({parameters})",
                next.table.name(),
                next.table.columns().join(", ")
            );
            #[cfg(test)]
            self.control
                .0
                .lock()
                .unwrap()
                .sql
                .push((write, sql.clone()));
            transaction
                .execute(&sql, rusqlite::params_from_iter(&next.values))
                .map_err(GatewayError::Database)?;
        }
        #[cfg(test)]
        {
            if write == Write::Receipt && next.table == Table::Kubernetes {
                crate::gateway::tests::storage::receipt_precommit_checkpoint(&transaction);
            }
            if delivery == Delivery::NoCommit {
                return delivery.result();
            }
        }

        transaction.commit().map_err(GatewayError::Database)?;
        #[cfg(test)]
        return delivery.result();
        #[cfg(not(test))]
        Ok(())
    }

    #[allow(clippy::unused_self, reason = "test builds record the executed SQL")]
    fn update_changed_columns(
        &self,
        transaction: &rusqlite::Transaction<'_>,
        previous: &Record,
        next: &Record,
        id: String,
        #[cfg(test)] write: Write,
    ) -> Result<(), GatewayError> {
        let changes = next
            .table
            .columns()
            .iter()
            .enumerate()
            .filter(|(index, _)| previous.values[*index] != next.values[*index])
            .collect::<Vec<_>>();
        let assignments = changes
            .iter()
            .enumerate()
            .map(|(parameter, (_, field))| format!("{field} = ?{}", parameter + 1))
            .collect::<Vec<_>>()
            .join(", ");
        if assignments.is_empty() {
            return Err(GatewayError::InvalidTransition);
        }

        let mut values = changes
            .iter()
            .map(|(index, _)| next.values[*index].clone())
            .collect::<Vec<_>>();
        values.push(Value::Text(id));
        let sql = format!(
            "UPDATE {} SET {assignments} \
            WHERE operation_id = ?{}",
            next.table.name(),
            values.len()
        );
        #[cfg(test)]
        self.control
            .0
            .lock()
            .unwrap()
            .sql
            .push((write, sql.clone()));

        changed_one(
            transaction
                .execute(&sql, rusqlite::params_from_iter(values))
                .map_err(GatewayError::Database)?,
        )
    }
}

#[cfg(test)]
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum Delivery {
    NoCommit,
    #[default]
    Confirmed,
    LostAcknowledgement,
}

#[cfg(test)]
impl Delivery {
    fn result(self) -> Result<(), GatewayError> {
        match self {
            Self::Confirmed => Ok(()),
            // Neither failure tells the lifecycle whether the record reached storage.
            Self::NoCommit | Self::LostAcknowledgement => Err(GatewayError::InjectedFault),
        }
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct Control(Arc<Mutex<Controls>>);

#[cfg(test)]
#[derive(Default)]
struct Controls {
    virtual_store: Option<Arc<Mutex<BTreeMap<String, Record>>>>,
    deliveries: VecDeque<(Write, Delivery)>,
    refuse_writes: bool,
    reached: Vec<Write>,
    deliveries_seen: Vec<(Write, Delivery)>,
    defect: Option<Defect>,
    defect_reached: Vec<Defect>,
    sql: Vec<(Write, String)>,
    original_trust: Option<Vec<crate::AuthorizationTrust>>,
}

#[cfg(test)]
impl Controls {
    fn take_delivery(&mut self, write: Write) -> Delivery {
        self.reached.push(write);
        let delivery = if self.refuse_writes {
            Delivery::NoCommit
        } else if self
            .deliveries
            .front()
            .is_some_and(|(point, _)| *point == write)
        {
            self.deliveries.pop_front().unwrap().1
        } else {
            Delivery::Confirmed
        };
        self.deliveries_seen.push((write, delivery));
        delivery
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum Defect {
    Remint,
    InitialUnknown,
    NoOp,
    UnconditionalWrite,
    ReplicaSwap,
    WrongSigner,
    WrongPeerRead,
    ReceiptProjectionSwap,
    GitInferredAcknowledgement,
    GitObservationSubstitution,
    ReceiptRewrite,
    StatusProjectionSwap,
    TargetProjectionSwap,
    CatalogConflictAccepted,
    StaleTrust,
    CustodyIgnored,
}

#[cfg(test)]
impl Control {
    pub(crate) fn appointed_trust(
        &self,
        current: Vec<crate::AuthorizationTrust>,
    ) -> Vec<crate::AuthorizationTrust> {
        let mut control = self.0.lock().unwrap();
        let original = control
            .original_trust
            .get_or_insert_with(|| current.clone())
            .clone();
        if control.defect == Some(Defect::StaleTrust) && original != current {
            control.defect_reached.push(Defect::StaleTrust);
            original
        } else {
            current
        }
    }

    pub(crate) fn seed(&self, defect: Defect) {
        self.0.lock().unwrap().defect = Some(defect);
    }

    pub(crate) fn exercise(&self, defect: Defect) -> bool {
        let mut control = self.0.lock().unwrap();
        if control.defect == Some(defect) {
            control.defect_reached.push(defect);
            true
        } else {
            false
        }
    }

    pub(crate) fn defect_reached(&self) -> Vec<Defect> {
        self.0.lock().unwrap().defect_reached.clone()
    }

    pub(crate) fn executed_sql(&self) -> Vec<(Write, String)> {
        self.0.lock().unwrap().sql.clone()
    }

    pub(crate) fn last_delivery(&self, write: Write) -> Option<Delivery> {
        self.0
            .lock()
            .unwrap()
            .deliveries_seen
            .iter()
            .rev()
            .find(|(point, _)| *point == write)
            .map(|(_, delivery)| *delivery)
    }

    pub(crate) fn value(&self, id: &str, field: &str) -> Option<Value> {
        let control = self.0.lock().unwrap();
        control.virtual_store.as_ref().and_then(|store| {
            store
                .lock()
                .unwrap()
                .get(id)
                .map(|row| row.values[row.index(field)].clone())
        })
    }

    pub(crate) fn set_value(&self, id: &str, field: &str, value: Value) {
        let control = self.0.lock().unwrap();
        let mut store = control.virtual_store.as_ref().unwrap().lock().unwrap();
        store.get_mut(id).unwrap().set(field, value);
    }

    pub(crate) fn virtualized() -> Self {
        let control = Self::default();
        control.0.lock().unwrap().virtual_store = Some(Arc::new(Mutex::new(BTreeMap::new())));
        control
    }

    pub(crate) fn refuse_writes(&self, refuse: bool) {
        self.0.lock().unwrap().refuse_writes = refuse;
    }

    pub(crate) fn fail_next(&self, write: Write, delivery: Delivery) {
        self.0
            .lock()
            .unwrap()
            .deliveries
            .push_back((write, delivery));
    }

    pub(crate) fn reached(&self) -> Vec<Write> {
        self.0.lock().unwrap().reached.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        let mut original = Record::empty("atomic-binding");
        for (field, value) in [
            ("namespace", "demo"),
            ("deployment", "api"),
            ("container", "original"),
            ("immutable_image_digest", "image"),
            ("state", "authorized"),
        ] {
            original.set(field, value.to_owned());
        }
        original
    }

    fn binding_law(
        virtualized: bool,
        defect: bool,
        git: bool,
    ) -> Result<(bool, Vec<Defect>), GatewayError> {
        let scratch = crate::kernel_simulation_tests::Scratch::new();
        let mut journal = super::super::Journal::open(scratch.0.join("journal.sqlite3")).unwrap();
        let control = if virtualized {
            Control::virtualized()
        } else {
            Control::default()
        };
        journal.control_storage(control.clone());
        let original = if git {
            let mut record = Record::git_empty("atomic-binding");
            for (field, value) in [
                ("repository_id", "repository"),
                ("ref_name", "refs/heads/approved"),
                ("old_commit", "a"),
                ("new_commit", "b"),
                ("state", "authorized"),
            ] {
                record.set(field, value.to_owned());
            }
            record
        } else {
            record()
        };
        journal
            .records
            .replace(&journal.connection, None, &original, Write::Admission)
            .unwrap();
        let mut foreign = original.clone();
        foreign.set(
            if git { "new_commit" } else { "container" },
            "different".to_owned(),
        );
        journal
            .records
            .replace(
                &journal.connection,
                Some(&original),
                &foreign,
                Write::Authorization,
            )
            .unwrap();
        if defect {
            control.seed(Defect::UnconditionalWrite);
        }
        let mut stale_next = original.clone();
        stale_next.set("state", "apply_started".to_owned());
        let refused = match journal.records.replace(
            &journal.connection,
            Some(&original),
            &stale_next,
            Write::Attempt,
        ) {
            Ok(()) => false,
            Err(GatewayError::InvalidTransition) => true,
            Err(error) => return Err(error),
        };
        let retained = journal
            .records
            .read_table(
                &journal.connection,
                "atomic-binding",
                if git { Table::Git } else { Table::Kubernetes },
            )
            .unwrap();
        Ok((
            refused && retained.as_ref() == Some(&foreign),
            control.defect_reached(),
        ))
    }

    #[test]
    fn oversized_optional_facts_and_grants_are_rejected_before_record_copy() {
        for virtualized in [true, false] {
            for (field, maximum) in [
                ("receiver_image", schema::PERSISTED_VALUE_BYTES_MAX),
                ("signed_authorization_grant", 4096),
            ] {
                let scratch = crate::kernel_simulation_tests::Scratch::new();
                let mut journal =
                    super::super::Journal::open(scratch.0.join("journal.sqlite3")).unwrap();
                let control = if virtualized {
                    Control::virtualized()
                } else {
                    Control::default()
                };
                journal.control_storage(control.clone());
                let original = record();
                journal
                    .records
                    .replace(&journal.connection, None, &original, Write::Admission)
                    .unwrap();
                let value = if field == "signed_authorization_grant" {
                    Value::Blob(vec![1; maximum + 1])
                } else {
                    Value::Text("a".repeat(maximum + 1))
                };
                if virtualized {
                    let mut corrupt = original;
                    corrupt.set(field, value);
                    control
                        .0
                        .lock()
                        .unwrap()
                        .virtual_store
                        .as_ref()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .insert("atomic-binding".into(), corrupt);
                } else {
                    // Independent direct column edit, after opening and outside the record mapper.
                    journal
                        .connection
                        .execute(
                            &format!(
                                "UPDATE kubernetes_image_operations \
                        SET {field} = ?1"
                            ),
                            [value],
                        )
                        .unwrap();
                }
                assert!(matches!(
                    journal.records.read(&journal.connection, "atomic-binding"),
                    Err(GatewayError::InvalidPersistedState)
                ));
            }
        }
    }

    #[test]
    fn atomic_record_binding_rejects_stale_foreign_facts_and_detects_unconditional_write() {
        for virtualized in [true, false] {
            for git in [false, true] {
                assert!(binding_law(virtualized, false, git).unwrap().0);
                let (holds, reached) = binding_law(virtualized, true, git).unwrap();
                assert!(!holds, "conditional_binding defect survived");
                assert!(reached.contains(&Defect::UnconditionalWrite));
            }
        }
    }
}
