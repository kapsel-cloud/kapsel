//! Exact private SQLite schema identity for the fixed sandbox service.

pub(crate) const SERVICE_STATE: &str = r"CREATE TABLE IF NOT EXISTS service_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1), stopped INTEGER NOT NULL,
  boundary_uid_digest TEXT NOT NULL DEFAULT ''
);";

pub(crate) const AUTHORITY_COLLECTION: &str = r"CREATE TABLE IF NOT EXISTS authority_collection (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  generation INTEGER NOT NULL, manifest_digest TEXT NOT NULL
);";

pub(crate) const RUNS: &str = r"CREATE TABLE IF NOT EXISTS runs (
  admission_order INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL UNIQUE, idempotency_key TEXT NOT NULL UNIQUE,
  scenario TEXT NOT NULL, operation_id TEXT NOT NULL UNIQUE,
  admitted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  execution_state TEXT NOT NULL, receiver_result TEXT,
  target_rejection TEXT, receipt_available INTEGER NOT NULL,
  cleanup_state TEXT NOT NULL, last_sequence INTEGER NOT NULL,
  active INTEGER NOT NULL, deadline_emitted INTEGER NOT NULL,
  application_invoked INTEGER NOT NULL, public_retained INTEGER NOT NULL,
  policy_revision TEXT NOT NULL, policy_inventory TEXT NOT NULL,
  policy_inventory_digest TEXT NOT NULL, cleanup_identity TEXT NOT NULL,
  deadline_seconds INTEGER NOT NULL, deadline_at INTEGER,
  policy_verified INTEGER NOT NULL, provisioned_objects TEXT,
  cleanup_resource_state TEXT NOT NULL, dispatched_at INTEGER,
  namespace_uid TEXT, lease_id TEXT NOT NULL,
  lease_epoch INTEGER NOT NULL, lease_expires_at INTEGER NOT NULL,
  handoff_credential_verifier BLOB NOT NULL,
  provisioning_closed INTEGER NOT NULL DEFAULT 0,
  deployment_uid TEXT NOT NULL DEFAULT '',
  deployment_resource_version TEXT NOT NULL DEFAULT '',
  deployment_current_image TEXT NOT NULL DEFAULT '',
  cleanup_epoch TEXT NOT NULL DEFAULT '',
  runner_revoked INTEGER NOT NULL DEFAULT 0,
  runner_process_absent INTEGER NOT NULL DEFAULT 0,
  journal_handoff INTEGER NOT NULL DEFAULT 0,
  runner_state_retiring INTEGER NOT NULL DEFAULT 0,
  runner_state_retired INTEGER NOT NULL DEFAULT 0,
  cleanup_attempt INTEGER NOT NULL DEFAULT 0,
  cleanup_plan_digest TEXT NOT NULL DEFAULT '',
  cleanup_plan_issued INTEGER NOT NULL DEFAULT 0,
  cleanup_pending_observation_id TEXT NOT NULL DEFAULT '',
  cleanup_observation_id TEXT NOT NULL DEFAULT '',
  authority_generation INTEGER,
  authority_manifest_digest TEXT NOT NULL DEFAULT ''
);";

pub(crate) const CLEANUP_RECORDS: &str = r"CREATE TABLE IF NOT EXISTS cleanup_records (
  run_id TEXT PRIMARY KEY, cleanup_identity TEXT NOT NULL,
  namespace_uid TEXT, resource_state TEXT NOT NULL, state TEXT NOT NULL,
  active INTEGER NOT NULL, eligible INTEGER NOT NULL,
  started_at INTEGER, escalated INTEGER NOT NULL
);";

pub(crate) const PROVISIONED_OBJECT_OWNERS: &str = concat!(
    r"CREATE TABLE IF NOT EXISTS provisioned_",
    r"object_owners (
  uid TEXT PRIMARY KEY, run_id TEXT NOT NULL, identity TEXT NOT NULL,
  owner_label TEXT NOT NULL
);"
);

pub(crate) const EVENTS: &str = r"CREATE TABLE IF NOT EXISTS events (
  run_id TEXT NOT NULL, sequence INTEGER NOT NULL, kind TEXT NOT NULL,
  occurred_at INTEGER NOT NULL, execution_state TEXT NOT NULL,
  receiver_result TEXT, target_rejection TEXT,
  receipt_available INTEGER NOT NULL, cleanup_state TEXT NOT NULL,
  PRIMARY KEY (run_id, sequence)
);";

pub(crate) const RECEIPTS: &str = r"CREATE TABLE IF NOT EXISTS receipts (
  run_id TEXT PRIMARY KEY, digest TEXT NOT NULL, object_name TEXT NOT NULL UNIQUE
);";

pub(crate) const RECEIPT_PUBLICATIONS: &str = r"CREATE TABLE IF NOT EXISTS receipt_publications (
  run_id TEXT PRIMARY KEY, digest TEXT NOT NULL, object_name TEXT NOT NULL UNIQUE,
  started_at INTEGER NOT NULL
);";

pub(crate) const APPLICATION_REPORTS: &str = r"CREATE TABLE IF NOT EXISTS application_reports (
  run_id TEXT PRIMARY KEY, kind TEXT NOT NULL, receiver_result TEXT,
  target_rejection TEXT, receipt_digest TEXT, payload_digest BLOB NOT NULL
);";

pub(crate) const TOMBSTONES: &str = r"CREATE TABLE IF NOT EXISTS tombstones (
  run_digest TEXT PRIMARY KEY, key_digest TEXT NOT NULL UNIQUE,
  delete_at INTEGER NOT NULL,
  authority_generation INTEGER NOT NULL,
  authority_manifest_digest TEXT NOT NULL
);";

pub(crate) const TABLES_BY_NAME: [&str; 10] = [
    APPLICATION_REPORTS,
    AUTHORITY_COLLECTION,
    CLEANUP_RECORDS,
    EVENTS,
    PROVISIONED_OBJECT_OWNERS,
    RECEIPT_PUBLICATIONS,
    RECEIPTS,
    RUNS,
    SERVICE_STATE,
    TOMBSTONES,
];
