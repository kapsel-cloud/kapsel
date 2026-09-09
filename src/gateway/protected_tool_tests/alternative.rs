//! Experiment-only typed tool. No Kapsel imports, grant, receipt, or classifier calls.

use std::{
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::Duration,
};

use k8s_openapi::api::apps::v1::Deployment;
use kube::{
    api::{Patch, PatchParams},
    Api, Client,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Request {
    pub operation: String,
    pub namespace: String,
    pub deployment: String,
    pub container: String,
    pub image: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Approval {
    pub request: Request,
    pub uid: String,
    pub version: String,
}

pub(super) struct Tool {
    db: Connection,
    worker: File,
}

impl Tool {
    pub(super) fn open(root: &Path) -> Self {
        let path = root.join("typed.sqlite3");
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let db = Connection::open(path).unwrap();
        db.execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS action (
                id INTEGER PRIMARY KEY CHECK(id=1), approval TEXT NOT NULL,
                phase TEXT NOT NULL, generation INTEGER, evidence TEXT);",
        )
        .unwrap();
        let worker = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(root.join("typed.lock"))
            .unwrap();
        Self { db, worker }
    }

    // Operator-only provisioning. An existing action never acquires replacement authority.
    pub(super) fn approve(&self, approval: &Approval) -> bool {
        let encoded = serde_json::to_string(approval).unwrap();
        self.db
            .execute(
                "INSERT OR IGNORE INTO action VALUES (1,?1,'approved',NULL,NULL)",
                [&encoded],
            )
            .unwrap();
        self.approval() == *approval
    }

    fn approval(&self) -> Approval {
        let text: String = self
            .db
            .query_row("SELECT approval FROM action WHERE id=1", [], |row| {
                row.get(0)
            })
            .unwrap();
        serde_json::from_str(&text).unwrap()
    }

    pub(super) fn accepts(&self, request: &Request) -> bool {
        self.approval().request == *request
    }

    pub(super) fn retained(&self) -> Option<String> {
        self.db
            .query_row("SELECT evidence FROM action WHERE id=1", [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    pub(super) fn lock(&self) {
        self.worker.try_lock().unwrap();
    }
    pub(super) fn unlock(&self) {
        self.worker.unlock().unwrap();
    }

    // `cut` is an operator test control, not a request field or production tool option.
    #[allow(
        clippy::needless_pass_by_ref_mut,
        clippy::too_many_lines,
        reason = "keep the experiment's sequential ordering and exclusive SQLite borrow visible"
    )]
    pub(super) async fn execute(&mut self, request: &Request, client: Client, cut: &str) -> bool {
        if !self.accepts(request) || self.worker.try_lock().is_err() {
            return false;
        }
        let approval = self.approval();
        let (phase, mut generation): (String, Option<i64>) = self
            .db
            .query_row(
                "SELECT phase,generation FROM action WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        if matches!(phase.as_str(), "finished" | "rejected") {
            self.unlock();
            return true;
        }
        let api: Api<Deployment> = Api::namespaced(client, &request.namespace);
        if phase == "approved" {
            let target =
                tokio::time::timeout(Duration::from_secs(10), api.get(&request.deployment))
                    .await
                    .unwrap()
                    .unwrap();
            if target.metadata.uid.as_deref() != Some(&approval.uid)
                || target.metadata.resource_version.as_deref() != Some(&approval.version)
            {
                let evidence = json!({"result":"NOT_ATTEMPTED", "reason":"STALE_APPROVAL",
                    "approved": approval, "observed": target.metadata});
                self.finish("rejected", &evidence);
                self.unlock();
                return true;
            }
            // Autocommit acknowledgement precedes the only dispatch branch. The lock spans I/O.
            assert_eq!(
                self.db
                    .execute(
                        "UPDATE action SET phase='attempted' WHERE id=1
                AND phase='approved'",
                        []
                    )
                    .unwrap(),
                1
            );
            if cut == "pre-send" {
                std::process::exit(73);
            }
            let patch = json!({"apiVersion":"apps/v1", "kind":"Deployment", "metadata": {
                "name":request.deployment, "namespace":request.namespace,
                "uid":approval.uid, "resourceVersion":approval.version,
                "annotations":{"kapsel.dev/kap0038-operation-id":request.operation}},
                "spec":{"template":{"spec":{"containers":[{
                    "name":request.container,"image":request.image}]}}}});
            let applied = tokio::time::timeout(
                Duration::from_secs(10),
                api.patch(
                    &request.deployment,
                    &PatchParams::default(),
                    &Patch::Strategic(patch),
                ),
            )
            .await;
            if cut == "lost-response" {
                std::process::exit(73);
            }
            if let Ok(Ok(applied)) = applied {
                if applied.metadata.uid.as_deref() == Some(&approval.uid)
                    && applied.metadata.resource_version.is_some()
                {
                    generation = applied.metadata.generation;
                    self.db
                        .execute("UPDATE action SET generation=?1 WHERE id=1", [generation])
                        .unwrap();
                }
            }
        }
        let observation = tokio::time::timeout(Duration::from_secs(30), async {
            let mut latest = json!({"result":"UNKNOWN", "observed":null});
            for attempt in 0..30 {
                let observed = api.get(&request.deployment).await.ok();
                let (result, complete, requested) = observed
                    .as_ref()
                    .map_or(("UNKNOWN", false, generation), |deployment| {
                        classify(&approval, generation, deployment)
                    });
                latest = json!({"result":result, "observed":observed,
                    "requested_generation":requested});
                if complete || attempt == 29 {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            latest
        })
        .await
        .unwrap_or_else(|_| json!({"result":"UNKNOWN", "observed":null}));
        let evidence = json!({"approved":approval,
            "requested_generation":observation["requested_generation"],
            "result":observation["result"], "observed":observation["observed"],
            "attribution":"not_established"});
        self.finish("finished", &evidence);
        self.unlock();
        true
    }

    fn finish(&self, phase: &str, evidence: &Value) {
        let bytes = serde_json::to_string(evidence).unwrap();
        assert!(bytes.len() <= 16 * 1024);
        self.db
            .execute(
                "UPDATE action SET phase=?1,evidence=?2 WHERE id=1 AND evidence IS NULL",
                params![phase, bytes],
            )
            .unwrap();
    }
}

// An independently written interpretation of the common receiver requirements, not an oracle.
fn classify(
    approval: &Approval,
    requested: Option<i64>,
    deployment: &Deployment,
) -> (&'static str, bool, Option<i64>) {
    let metadata = &deployment.metadata;
    let image = deployment
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .and_then(|s| {
            s.containers
                .iter()
                .find(|c| c.name == approval.request.container)
        })
        .and_then(|c| c.image.as_deref());
    let marker = metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get("kapsel.dev/kap0038-operation-id"));
    let operation_matches =
        image == Some(&approval.request.image) && marker == Some(&approval.request.operation);
    let Some(status) = &deployment.status else {
        return ("UNKNOWN", false, requested);
    };
    let current = metadata.generation;
    let observed =
        current.is_some_and(|g| g >= 0 && status.observed_generation.is_some_and(|v| v >= g));
    let conditions = status.conditions.as_deref().unwrap_or_default();
    let failed = conditions.iter().any(|c| {
        c.type_ == "Progressing"
            && c.status == "False"
            && c.reason.as_deref() == Some("ProgressDeadlineExceeded")
    });
    let desired = deployment.spec.as_ref().and_then(|s| s.replicas);
    let available = desired.is_some_and(|n| n >= 0)
        && Some(status.updated_replicas.unwrap_or(0)) == desired
        && Some(status.available_replicas.unwrap_or(0)) == desired
        && status.unavailable_replicas.unwrap_or(0) == 0
        && conditions
            .iter()
            .any(|c| c.type_ == "Available" && c.status == "True");
    let complete = operation_matches && observed && (available || failed);
    let uid_matches = metadata.uid.as_deref() == Some(&approval.uid);
    let requested = requested.or(if operation_matches && uid_matches {
        current
    } else {
        None
    });
    let result = if complete && uid_matches && requested.is_some() && requested == current {
        if failed {
            "FAILED"
        } else {
            "SUCCEEDED"
        }
    } else {
        "UNKNOWN"
    };
    (result, complete, requested)
}
