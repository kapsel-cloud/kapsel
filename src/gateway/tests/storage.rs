//! Bounded storage qualification fixtures; no production storage API or filesystem reservation.

use std::{
    collections::BTreeMap,
    io::{Seek as _, SeekFrom, Write as _},
};

use rusqlite::types::Value;

use super::*;

pub(super) type StoredRows = BTreeMap<String, Vec<Value>>;

type ReceiptCheckpoint = Box<dyn FnOnce(&Connection)>;
thread_local! {
    static RECEIPT_CHECKPOINT: std::cell::RefCell<Option<ReceiptCheckpoint>> = const {
        std::cell::RefCell::new(None)
    };
}

pub(in crate::gateway) fn receipt_precommit_checkpoint(connection: &Connection) {
    let checkpoint = RECEIPT_CHECKPOINT.with(|slot| slot.borrow_mut().take());
    if let Some(checkpoint) = checkpoint {
        checkpoint(connection);
    }
}

fn set_receipt_checkpoint(checkpoint: impl FnOnce(&Connection) + 'static) {
    RECEIPT_CHECKPOINT.with(|slot| assert!(slot.replace(Some(Box::new(checkpoint))).is_none()));
}

pub(super) fn stored_rows(connection: &Connection) -> StoredRows {
    let mut statement = connection
        .prepare("SELECT * FROM kubernetes_image_operations")
        .unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                (0..columns)
                    .map(|index| row.get(index))
                    .collect::<Result<Vec<_>, _>>()?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

// All existing live pages are retained. Rebuild only the freelist, including a zero-leaf
// trunk followed by full trunks. Alternating distant leaves defeat
// contiguous-allocation assumptions.
pub(super) fn fragmented_maximum_page_count(path: &Path) {
    maximum_page_count_freelist(path, false);
}

fn maximum_page_count_freelist(path: &Path, sparse_tail_first: bool) {
    let connection = Connection::open(path).unwrap();
    let mut free = {
        let mut statement = connection
            .prepare("SELECT pageno FROM dbstat('main')")
            .unwrap();
        let live = statement
            .query_map([], |row| row.get::<_, u32>(0))
            .unwrap()
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .unwrap();
        (1..=16_384_u32)
            .filter(|page| !live.contains(page))
            .collect::<Vec<_>>()
    };
    drop(connection);
    assert!(free.len() > 2_048);
    if sparse_tail_first {
        free.reverse();
    } else {
        let ascending = free.clone();
        for (index, page) in free.iter_mut().enumerate() {
            *page = if index % 2 == 0 {
                ascending[index / 2]
            } else {
                ascending[ascending.len() - 1 - index / 2]
            };
        }
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.set_len(64 * 1024 * 1024).unwrap();
    let mut offset = 0;
    let mut trunks = Vec::new();
    while offset < free.len() {
        let leaves = if offset == 0 && !sparse_tail_first {
            0
        } else {
            (free.len() - offset - 1).min(1016)
        };
        trunks.push((free[offset], free[offset + 1..offset + 1 + leaves].to_vec()));
        offset += leaves + 1;
    }
    for (index, (page, leaves)) in trunks.iter().enumerate() {
        let mut bytes = [0_u8; 4096];
        let next = trunks.get(index + 1).map_or(0, |entry| entry.0);
        bytes[..4].copy_from_slice(&next.to_be_bytes());
        bytes[4..8].copy_from_slice(&u32::try_from(leaves.len()).unwrap().to_be_bytes());
        for (index, leaf) in leaves.iter().enumerate() {
            bytes[8 + index * 4..12 + index * 4].copy_from_slice(&leaf.to_be_bytes());
        }
        file.seek(SeekFrom::Start(u64::from(*page - 1) * 4096))
            .unwrap();
        file.write_all(&bytes).unwrap();
    }
    file.seek(SeekFrom::Start(28)).unwrap();
    file.write_all(&16_384_u32.to_be_bytes()).unwrap();
    file.write_all(&free[0].to_be_bytes()).unwrap();
    file.write_all(&u32::try_from(free.len()).unwrap().to_be_bytes())
        .unwrap();
    file.sync_all().unwrap();
    drop(file);
    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert_eq!(
        connection
            .query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        16_384
    );
    assert_eq!(
        connection
            .query_row("PRAGMA freelist_count", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        u32::try_from(free.len()).unwrap()
    );
    eprintln!(
        concat!(
            "fragmented maximum database: {} free pages, {} trunks; ",
            "sparse_tail_first={}, full trunks1016",
        ),
        free.len(),
        trunks.len(),
        sparse_tail_first
    );
}

pub(super) fn maximal_request(index: i64) -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: format!("{index:0128}"),
        namespace: "n".repeat(63),
        deployment: format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        ),
        container: "c".repeat(63),
        immutable_image_digest: format!("{}@sha256:{}", "i".repeat(440), "0".repeat(64)),
    }
}

fn maximal_gateway(path: &Path) -> Gateway {
    Gateway::open(
        path,
        AuthorizationTrust {
            key_id: "g".repeat(128),
            public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes(),
        },
    )
    .unwrap()
}

fn maximal_grant(operation: &SetDeploymentImageRequest) -> Vec<u8> {
    let mut approval = authorization(operation);
    approval.authorization_id = "a".repeat(128);
    approval.approved_target = Some(ApprovedTarget {
        uid: "u".repeat(128),
        resource_version: "r".repeat(128),
    });
    sign_authorization_grant(&approval, &[7; 32], &"g".repeat(128)).unwrap()
}

pub(super) fn maximal_adapter(path: &Path, operation: &SetDeploymentImageRequest) -> FakeAdapter {
    let mut adapter = failed_adapter(path, operation);
    adapter.identified_target = TargetIdentity {
        deployment_uid: "u".repeat(128),
        resource_version: "r".repeat(128),
    };
    adapter.outcome.deployment_uid = Some("u".repeat(128));
    adapter.outcome.resource_version = Some("r".repeat(128));
    adapter.outcome.requested_generation = Some(i64::MAX);
    adapter.observation.deployment_uid = Some("u".repeat(128));
    adapter.observation.resource_version = Some("r".repeat(128));
    adapter.observation.current_generation = Some(i64::MAX);
    adapter.observation.observed_generation = Some(i64::MAX);
    adapter.observation.desired_replicas = Some(i32::MAX);
    adapter.observation.updated_replicas = Some(i32::MAX);
    adapter.observation.available_replicas = Some(i32::MAX);
    adapter.observation.unavailable_replicas = Some(i32::MAX);
    adapter.observation.rollout_condition_type = Some("t".repeat(128));
    adapter.observation.rollout_condition_status = Some("s".repeat(128));
    adapter.observation.rollout_condition_reason = Some("r".repeat(128));
    adapter
}

pub(super) async fn qualify_full_capacity() {
    for order in ["ascending", "descending", "alternating"] {
        for phase in [
            OperationState::Authorized,
            OperationState::ApplyStarted,
            OperationState::ReceiverObserved,
        ] {
            qualify_full_capacity_case(order, phase).await;
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one trace compares every retained row through full-capacity completion"
)]
async fn qualify_full_capacity_case(order: &str, phase: OperationState) {
    let path = database_path(&format!("full-capacity-{order}-{phase:?}"));
    let mut gateway = maximal_gateway(&path);
    let key = "k".repeat(128);
    let settings = ReceiptSettings {
        signing_seed: &[13; 32],
        key_id: &key,
    };
    let mut pending = Vec::new();
    for index in 0..504 {
        let identity = match order {
            "ascending" => index,
            "descending" => 503 - index,
            _ if index % 2 == 0 => index / 2,
            _ => 503 - index / 2,
        };
        let operation = maximal_request(identity);
        let grant = maximal_grant(&operation);
        gateway
            .submit_authorized_with_fault(&operation, &grant, None)
            .unwrap();
        if index >= 472 && phase == OperationState::Authorized {
            pending.push((operation, grant));
            continue;
        }
        let mut adapter = maximal_adapter(&path, &operation);
        let fault = (index >= 472 && phase == OperationState::ApplyStarted)
            .then_some(FaultPoint::ApplyOutcomeCommitted);
        let result = gateway
            .run_operation_once_with_adapter_and_fault(&operation.operation_id, &mut adapter, fault)
            .await;
        if fault.is_some() {
            assert!(matches!(result, Err(GatewayError::InjectedFault)));
        } else {
            assert_eq!(result.unwrap(), Some(OperationState::ReceiverObserved));
        }
        assert_eq!(adapter.apply_calls, 1);
        if index >= 472 {
            pending.push((operation, grant));
        } else {
            gateway
                .finalize_operation_receipt_once(&operation.operation_id, &settings)
                .unwrap();
        }
    }
    let overflow = request();
    assert!(matches!(
        gateway.submit_authorized_with_fault(&overflow, &maximal_grant(&overflow), None),
        Err(GatewayError::JournalFull)
    ));
    let mut original = stored_rows(&gateway.journal.connection);
    drop(gateway);
    fragmented_maximum_page_count(&path);
    for (operation, grant) in pending {
        journal::Journal::validate_replacement(&path, &[]).unwrap();
        let mut gateway = maximal_gateway(&path);
        assert_eq!(
            gateway
                .submit_authorized_with_fault(&operation, &grant, None)
                .unwrap(),
            SubmissionResult::Existing(phase)
        );
        let mut adapter = maximal_adapter(&path, &operation);
        gateway
            .run_operation_once_with_adapter(&operation.operation_id, &mut adapter)
            .await
            .unwrap();
        assert_eq!(
            adapter.apply_calls,
            usize::from(phase == OperationState::Authorized)
        );
        assert_eq!(
            adapter.observe_calls,
            usize::from(phase != OperationState::ReceiverObserved)
        );
        let frozen = gateway
            .journal
            .receipt_statement(&operation.operation_id)
            .unwrap();
        assert!(matches!(
            gateway.finalize_operation_receipt_once_with_fault(
                &operation.operation_id,
                &settings,
                Some(FaultPoint::ReceiptCommitAcknowledgementLost)
            ),
            Err(GatewayError::InjectedFault)
        ));
        assert_eq!(
            gateway
                .journal
                .receipt_statement(&operation.operation_id)
                .unwrap(),
            frozen
        );
        let receipt = Gateway::read_loaded_receipt(
            gateway
                .journal
                .operation(&operation.operation_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            gateway
                .finalize_operation_receipt_once(&operation.operation_id, &settings)
                .unwrap(),
            None
        );
        drop(gateway);
        journal::Journal::validate_replacement(&path, &[]).unwrap();
        let reopened = maximal_gateway(&path);
        assert_eq!(
            Gateway::read_loaded_receipt(
                reopened
                    .journal
                    .operation(&operation.operation_id)
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            receipt
        );
        let mut after = stored_rows(&reopened.journal.connection);
        let updated = after.remove(&operation.operation_id).unwrap();
        let prior = original.remove(&operation.operation_id).unwrap();
        assert_eq!(
            &updated[..9],
            &prior[..9],
            "original request and signed authority changed"
        );
        assert_eq!(
            &updated[38..40],
            &prior[38..40],
            "approved snapshot changed"
        );
        if phase != OperationState::Authorized {
            assert_eq!(
                &updated[10..19],
                &prior[10..19],
                "frozen attempt/outcome changed"
            );
            assert_eq!(&updated[40..], &prior[40..], "frozen preflight changed");
        }
        if phase == OperationState::ReceiverObserved {
            assert_eq!(
                &updated[19..32],
                &prior[19..32],
                "frozen receiver facts changed"
            );
            assert_eq!(
                &updated[35..38],
                &prior[35..38],
                "frozen conditions changed"
            );
        }
        assert_eq!(after, original, "an unrelated retained row changed");
        after.insert(operation.operation_id, updated);
        original = after;
    }
    assert_eq!(fs::metadata(&path).unwrap().len(), 64 * 1024 * 1024);
    eprintln!("completed504 retained/32 {phase:?}, order={order}, fragmented16384-page database");
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

pub(super) fn park_receipt_after_sql(ready: PathBuf) {
    set_receipt_checkpoint(move |_| {
        fs::write(ready, b"receipt-sql-executed-before-commit").unwrap();
        loop {
            std::thread::park();
        }
    });
}

async fn failure_history(path: &Path) -> SetDeploymentImageRequest {
    let mut gateway = Gateway::open_for_test(path).unwrap();
    let mut selected = maximal_request(0);
    selected.operation_id = "op-001".into();
    for index in 0..504 {
        let operation = if index == 503 {
            selected.clone()
        } else {
            maximal_request(index + 1)
        };
        gateway
            .submit_exact_for_test(&operation, &authorization(&operation))
            .unwrap();
        if index == 0 || index >= 472 {
            let mut adapter = maximal_adapter(path, &operation);
            gateway
                .run_operation_once_with_adapter(&operation.operation_id, &mut adapter)
                .await
                .unwrap();
            assert_eq!(adapter.apply_calls, 1);
            if index == 0 {
                gateway
                    .finalize_operation_receipt_once(
                        &operation.operation_id,
                        &ReceiptSettings {
                            signing_seed: &[13; 32],
                            key_id: "earlier-receipt",
                        },
                    )
                    .unwrap();
            }
        } else {
            let LoadedOperation::Authorized(operation) = gateway
                .journal
                .operation(&operation.operation_id)
                .unwrap()
                .unwrap()
            else {
                unreachable!("newly submitted fixture is authorized");
            };
            gateway
                .journal
                .mark_not_attempted(&operation, TargetRejection::DeploymentNotFound)
                .unwrap();
        }
    }
    selected
}

#[tokio::test]
async fn full_capacity_process_kills_before_sql_after_sql_and_after_commit_preserve_history() {
    for scenario in ["before_receipt_commit", "receipt_sql_executed", "receipt"] {
        let path = database_path(&format!("full-capacity-kill-{scenario}"));
        let selected = failure_history(&path).await;
        fragmented_maximum_page_count(&path);
        let before = stored_rows(&Connection::open(&path).unwrap());
        let ready = path.parent().unwrap().join("ready");
        let mut child = spawn_process_child(scenario, &path, &ready, None, None);
        wait_for_child_seam(&mut child, &ready);
        if scenario == "receipt_sql_executed" {
            let journal_path = PathBuf::from(format!("{}-journal", path.display()));
            assert!(fs::metadata(journal_path).unwrap().len() > 0);
        }
        kill_child(&mut child);
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        let mut after = stored_rows(&gateway.journal.connection);
        let current = after.remove(&selected.operation_id).unwrap();
        let mut expected = before;
        let old = expected.remove(&selected.operation_id).unwrap();
        assert_eq!(after, expected);
        if scenario != "receipt" {
            assert_eq!(current, old);
        }
        let frozen = gateway
            .journal
            .receipt_statement(&selected.operation_id)
            .unwrap();
        let mut adapter = maximal_adapter(&path, &selected);
        gateway
            .run_operation_once_with_adapter(&selected.operation_id, &mut adapter)
            .await
            .unwrap();
        assert_eq!((adapter.apply_calls, adapter.observe_calls), (0, 0));
        gateway
            .finalize_operation_receipt_once(
                &selected.operation_id,
                &ReceiptSettings {
                    signing_seed: &[13; 32],
                    key_id: "recovered-receipt",
                },
            )
            .unwrap();
        assert_eq!(
            gateway
                .journal
                .receipt_statement(&selected.operation_id)
                .unwrap(),
            frozen
        );
        if scenario == "receipt" {
            assert_eq!(
                stored_rows(&gateway.journal.connection).get(&selected.operation_id),
                Some(&current)
            );
        }
        drop(gateway);
        journal::Journal::validate_replacement(&path, &[]).unwrap();
        drop(Gateway::open_for_test(&path).unwrap());
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[cfg(target_os = "linux")]
fn require_enospc_mount() -> PathBuf {
    let root = PathBuf::from("/kapsel-enospc");
    assert_eq!(
        std::env::var("KAPSEL_ENOSPC_FIXTURE").unwrap(),
        "dedicated-tmpfs-v1"
    );
    assert_eq!(fs::canonicalize(&root).unwrap(), root);
    let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(mounts.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.get(4) == Some(&"/kapsel-enospc") && line.contains(" - tmpfs ")
    }));
    let stats = rustix::fs::statfs(&root).unwrap();
    assert_eq!(stats.f_type, 0x0102_1994); // Linux TMPFS_MAGIC.
    let bytes = stats.f_blocks * u64::try_from(stats.f_bsize).unwrap();
    assert!(bytes > 0 && bytes <= 128 * 1024 * 1024);
    eprintln!("verified dedicated tmpfs: {bytes} bytes");
    root
}

#[cfg(target_os = "linux")]
fn fill_owned_tmpfs(filler: &Path) {
    let root = require_enospc_mount();
    assert!(filler.starts_with(&root));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(filler)
        .unwrap();
    let block = [0x5a_u8; 64 * 1024];
    let mut written = 0;
    loop {
        assert!(
            written < 128 * 1024 * 1024,
            "absolute filler write ceiling reached without ENOSPC"
        );
        let remaining = 128 * 1024 * 1024 - written;
        match file.write(&block[..remaining.min(block.len())]) {
            Ok(count) => {
                assert!(count > 0, "filler write made no progress");
                written += count;
            },
            Err(error) => {
                assert_eq!(
                    error.raw_os_error(),
                    Some(28),
                    "expected actual Linux ENOSPC"
                );
                break;
            },
        }
    }
    assert_eq!(file.write(&[1]).unwrap_err().raw_os_error(), Some(28));
    eprintln!("actual OS ENOSPC after {written} bounded filler bytes");
}

#[cfg(target_os = "linux")]
fn require_sparse_receipt_destinations(connection: &Connection, path: &Path, allocated: u64) {
    use std::os::unix::fs::MetadataExt as _;
    let mut statement = connection
        .prepare("SELECT pageno FROM dbstat('main') WHERE pageno BETWEEN 15368 AND 16383")
        .unwrap();
    let pages = statement
        .query_map([], |row| row.get::<_, u32>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        !pages.is_empty(),
        "receipt SQL must allocate an original sparse tail leaf"
    );
    let file = fs::File::open(path).unwrap();
    for page in &pages {
        let offset = u64::from(*page - 1) * 4096;
        assert_eq!(
            rustix::fs::seek(&file, rustix::fs::SeekFrom::Hole(offset)).unwrap(),
            offset,
            "new receipt page must still be a filesystem hole before commit"
        );
    }
    eprintln!(
        "SQL allocated {} verified filesystem-hole pages",
        pages.len()
    );
    assert_eq!(
        fs::metadata(path).unwrap().blocks(),
        allocated,
        "cache spilling changed main-file allocation before commit"
    );
    let rollback = PathBuf::from(format!("{}-journal", path.display()));
    let bytes = fs::read(&rollback).unwrap();
    let sector = usize::try_from(u32::from_be_bytes(bytes[20..24].try_into().unwrap())).unwrap();
    assert_eq!((bytes.len() - sector) % 4104, 0);
    assert!(
        bytes[sector..]
            .as_chunks::<4104>()
            .0
            .iter()
            .any(|record| record[..4] == 1_u32.to_be_bytes()),
        "page1 must already be journaled, so commit cannot need another original-page record"
    );
    eprintln!(
        "SQL executed; precommit rollback length={}, page1 already journaled",
        bytes.len()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires scripts/test-storage-enospc.py dedicated bounded container tmpfs"]
async fn genuine_enospc_during_receipt_sql_and_commit_recovers_without_resend() {
    use std::os::unix::fs::MetadataExt as _;
    for at_commit in [false, true] {
        let root = require_enospc_mount();
        let directory = root.join(if at_commit {
            "commit"
        } else {
            "journal-growth"
        });
        private_directory(&directory);
        let path = directory.join("journal.sqlite3");
        let selected = failure_history(&path).await;
        maximum_page_count_freelist(&path, at_commit);
        journal::Journal::validate_replacement(&path, &[]).unwrap();
        let gateway = Gateway::open_for_test(&path).unwrap();
        let mut original = stored_rows(&gateway.journal.connection);
        let frozen = gateway
            .journal
            .receipt_statement(&selected.operation_id)
            .unwrap();
        let filler = directory.join("owned-filler");
        let reached = std::rc::Rc::new(std::cell::Cell::new(false));
        let flag = std::rc::Rc::clone(&reached);
        let checkpoint_path = path.clone();
        let checkpoint_filler = filler.clone();
        let allocated = fs::metadata(&path).unwrap().blocks();
        set_receipt_checkpoint(move |connection| {
            flag.set(true);
            if at_commit {
                require_sparse_receipt_destinations(connection, &checkpoint_path, allocated);
                fill_owned_tmpfs(&checkpoint_filler);
            }
        });
        if !at_commit {
            fill_owned_tmpfs(&filler);
        }
        let result = gateway.finalize_operation_receipt_once(
            &selected.operation_id,
            &ReceiptSettings {
                signing_seed: &[13; 32],
                key_id: "enospc-receipt",
            },
        );
        eprintln!(
            "at_commit={at_commit}, sql_executed={}, result={result:?}",
            reached.get()
        );
        assert_eq!(reached.get(), at_commit);
        assert!(
            matches!(result, Err(GatewayError::Database(rusqlite::Error::SqliteFailure(error, _)))
            if error.code == rusqlite::ErrorCode::DiskFull)
        );
        RECEIPT_CHECKPOINT.with(|slot| {
            slot.borrow_mut().take();
        });
        fs::remove_file(&filler).unwrap();
        drop(gateway);
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(stored_rows(&gateway.journal.connection), original);
        let mut adapter = maximal_adapter(&path, &selected);
        gateway
            .run_operation_once_with_adapter(&selected.operation_id, &mut adapter)
            .await
            .unwrap();
        assert_eq!((adapter.apply_calls, adapter.observe_calls), (0, 0));
        gateway
            .finalize_operation_receipt_once(
                &selected.operation_id,
                &ReceiptSettings {
                    signing_seed: &[13; 32],
                    key_id: "enospc-recovered",
                },
            )
            .unwrap();
        assert_eq!(
            gateway
                .journal
                .receipt_statement(&selected.operation_id)
                .unwrap(),
            frozen
        );
        let mut completed = stored_rows(&gateway.journal.connection);
        completed.remove(&selected.operation_id);
        original.remove(&selected.operation_id);
        assert_eq!(completed, original, "completion changed unrelated history");
        drop(gateway);
        journal::Journal::validate_replacement(&path, &[]).unwrap();
        drop(Gateway::open_for_test(&path).unwrap());
        fs::remove_dir_all(directory).unwrap();
    }
    eprintln!("KAPSEL_REAL_ENOSPC_CASES_PASSED");
}

#[test]
fn pinned_owned_write_plans_have_no_extra_tree_mutation_pass() {
    let path = database_path("owned-write-plans");
    let gateway = Gateway::open_for_test(&path).unwrap();
    assert_eq!(rusqlite::version(), "3.53.2");
    // Test the actual owner's plain SQL literals, not separately maintained example queries.
    // A new write or changed source form must deliberately revalidate this qualification.
    let owner = include_str!("../journal/mod.rs")
        .split("\n#[cfg(test)]\nmod tests {")
        .next()
        .unwrap();
    let statements = owner
        .split('"')
        .filter(|sql| {
            sql.starts_with("INSERT INTO kubernetes_image_operations")
                || sql.starts_with("UPDATE kubernetes_image_operations")
        })
        .collect::<Vec<_>>();
    assert_eq!(statements.len(), 8);
    for sql in statements {
        let insert = sql.starts_with("INSERT");
        let mut statement = gateway
            .journal
            .connection
            .prepare(&format!("EXPLAIN {sql}"))
            .unwrap();
        let parameters = vec![Value::Null; statement.parameter_count()];
        let opcodes = statement
            .query_map(rusqlite::params_from_iter(parameters), |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, i64>(6)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(opcodes.iter().filter(|(op, _)| op == "Insert").count(), 1);
        assert_eq!(
            opcodes.iter().filter(|(op, _)| op == "IdxInsert").count(),
            usize::from(insert)
        );
        for forbidden in [
            "Delete",
            "IdxDelete",
            "Program",
            "OpenEphemeral",
            "SorterOpen",
            "Savepoint",
        ] {
            assert!(
                !opcodes.iter().any(|(op, _)| op == forbidden),
                "unexpected {forbidden} in {sql}"
            );
        }
        eprintln!(
            "owned {} plan: one table Insert, {} index Insert, Transaction flags {:?}",
            if insert { "INSERT" } else { "UPDATE" },
            usize::from(insert),
            opcodes
                .iter()
                .filter(|(op, _)| op == "Transaction")
                .collect::<Vec<_>>()
        );
    }
    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn rollback_journal_records_each_original_page_once_without_spilling() {
    let path = database_path("rollback-unique-original-pages");
    let gateway = Gateway::open_for_test(&path).unwrap();
    gateway
        .submit_exact_for_test(&request(), &authorization(&request()))
        .unwrap();
    drop(gateway);
    fragmented_maximum_page_count(&path);
    let gateway = Gateway::open_for_test(&path).unwrap();
    let original = stored_rows(&gateway.journal.connection);
    for (pragma, expected) in [
        ("cache_spill", 0),
        ("synchronous", 2),
        ("max_page_count", 16384),
    ] {
        assert_eq!(
            gateway
                .journal
                .connection
                .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get::<_, i64>(0))
                .unwrap(),
            expected
        );
    }
    assert_eq!(
        gateway
            .journal
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "delete"
    );
    let transaction = gateway.journal.connection.unchecked_transaction().unwrap();
    let rollback = PathBuf::from(format!("{}-journal", path.display()));
    let before = fs::read(&path).unwrap();
    let mut length = None;
    for value in 2..18 {
        transaction
            .execute(
                concat!(
                    "UPDATE kubernetes_image_operations SET target_read_failures = ?1 ",
                    "WHERE operation_id = ?2",
                ),
                params![value, request().operation_id],
            )
            .unwrap();
        let current = fs::metadata(&rollback).unwrap().len();
        if let Some(length) = length {
            assert_eq!(current, length);
        } else {
            length = Some(current);
        }
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "cache-spill-off main file changed before commit"
        );
    }
    let bytes = fs::read(&rollback).unwrap();
    let sector = usize::try_from(u32::from_be_bytes(bytes[20..24].try_into().unwrap())).unwrap();
    assert!(sector <= 65536);
    assert_eq!((bytes.len() - sector) % 4104, 0);
    let page_ids = bytes[sector..]
        .as_chunks::<4104>()
        .0
        .iter()
        .map(|record| u32::from_be_bytes(record[..4].try_into().unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(
        page_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        page_ids.len()
    );
    eprintln!(
        "rollback stable over16 updates: {} bytes, {} unique original-page records, sector{sector}",
        bytes.len(),
        page_ids.len()
    );
    transaction.rollback().unwrap();
    assert_eq!(stored_rows(&gateway.journal.connection), original);
    drop(gateway);
    journal::Journal::validate_replacement(&path, &[]).unwrap();
    drop(Gateway::open_for_test(&path).unwrap());
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn full_page_count_fragmented_freelist_is_accepted_by_both_owners() {
    let path = database_path("maximum-fragmented-freelist");
    drop(Gateway::open_for_test(&path).unwrap());
    fragmented_maximum_page_count(&path);
    journal::Journal::validate_replacement(&path, &[]).unwrap();
    drop(Gateway::open_for_test(&path).unwrap());
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
