//! Bounded storage qualification fixtures; no production storage API or filesystem reservation.

#[cfg(target_os = "linux")]
use std::{cell::Cell, rc::Rc};
use std::{
    cell::RefCell,
    collections::BTreeSet,
    io::{Seek as _, SeekFrom, Write as _},
};

use rusqlite::types::Value;

use super::{Journal, *};

type ReceiptCheckpoint = Box<dyn FnOnce(&Connection)>;
thread_local! {
    static RECEIPT_CHECKPOINT: RefCell<Option<ReceiptCheckpoint>> = const {
        RefCell::new(None)
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

// All existing live pages are retained. Rebuild only the freelist, including a zero-leaf
// trunk followed by full trunks. Alternating distant leaves defeat
// contiguous-allocation assumptions.
pub(super) fn fragmented_maximum_page_count(path: &Path) {
    maximum_page_count_freelist(path, false);
}

fn maximum_page_count_freelist(path: &Path, sparse_tail_first: bool) {
    let connection = Connection::open(path).unwrap();
    let mut free_pages = {
        let mut statement = connection
            .prepare("SELECT pageno FROM dbstat('main')")
            .unwrap();
        let live_pages = statement
            .query_map([], |row| row.get::<_, u32>(0))
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap();
        (1..=16_384_u32)
            .filter(|page| !live_pages.contains(page))
            .collect::<Vec<_>>()
    };

    drop(connection);
    assert!(free_pages.len() > 2_048);
    if sparse_tail_first {
        free_pages.reverse();
    } else {
        let ascending = free_pages.clone();
        for (index, page) in free_pages.iter_mut().enumerate() {
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
    while offset < free_pages.len() {
        let leaves = if offset == 0 && !sparse_tail_first {
            0
        } else {
            (free_pages.len() - offset - 1).min(1016)
        };
        trunks.push((
            free_pages[offset],
            free_pages[offset + 1..offset + 1 + leaves].to_vec(),
        ));
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
    file.write_all(&free_pages[0].to_be_bytes()).unwrap();
    file.write_all(&u32::try_from(free_pages.len()).unwrap().to_be_bytes())
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
        u32::try_from(free_pages.len()).unwrap()
    );
    eprintln!(
        concat!(
            "fragmented maximum database: {} free pages, {} trunks; ",
            "sparse_tail_first={}, full trunks1016",
        ),
        free_pages.len(),
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

fn maximal_history(operation: SetDeploymentImageRequest, signer: &str) -> History {
    let mut history = History::with_authority(
        operation,
        Some(ApprovedTarget {
            uid: "u".repeat(128),
            resource_version: "r".repeat(128),
        }),
        &"a".repeat(128),
        signer,
    );
    let s = &mut history.statement;
    s.target_uid = "u".repeat(128);
    s.target_resource_version = "r".repeat(128);
    s.receiver_uid = Some("u".repeat(128));
    s.observed_image = Some(s.immutable_image_digest.clone());
    s.observed_operation_marker = Some(s.operation_id.clone());
    s.observed_resource_version = Some("r".repeat(128));
    s.current_generation = Some(i64::MAX);
    s.requested_generation = Some(i64::MAX);
    s.observed_generation = Some(i64::MAX);
    s.desired_replicas = Some(i32::MAX);
    s.updated_replicas = Some(i32::MAX);
    s.available_replicas = Some(i32::MAX);
    s.unavailable_replicas = Some(i32::MAX);
    s.rollout_condition_type = Some("t".repeat(128));
    s.rollout_condition_status = Some("s".repeat(128));
    s.rollout_condition_reason = Some("r".repeat(128));
    history
}

// Independent SQL supplies retained authority/facts, not the production transition writer.
// Lifecycle laws own interruption/effect matrices; this fixture owns maximal aggregate growth.
fn capacity_history(path: &Path, phases: &[&str], signer: &str) -> Vec<History> {
    let gateway = Gateway::open_for_test(path).unwrap();
    let transaction = gateway.journal.connection.unchecked_transaction().unwrap();
    let mut pending = Vec::new();
    for index in 0..504 {
        let history = maximal_history(maximal_request(index), signer);
        let phase = if index < 472 {
            "finalized"
        } else {
            phases[usize::try_from(index - 472).unwrap() % phases.len()]
        };
        history.insert(&transaction, phase);
        if phase != "authorized" {
            transaction
                .execute(
                    "UPDATE kubernetes_image_operations SET apply_accepted=1,
                 requested_generation=?2, apply_resource_version=?3 WHERE operation_id=?1",
                    params![history.request.operation_id, i64::MAX, "r".repeat(128)],
                )
                .unwrap();
        }
        if index >= 472 {
            pending.push(history);
        }
    }
    transaction.commit().unwrap();
    pending
}

pub(super) fn maximal_adapter(path: &Path, operation: &SetDeploymentImageRequest) -> FakeAdapter {
    let mut adapter = failed_rollout_adapter(path, operation);
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

#[tokio::test]
async fn full_identity_capacity_completes_maximal_mixed_phase_history() {
    let path = database_path("full-capacity-completion");
    let phases = ["authorized", "apply_started", "receiver_observed"];
    let mut trust = journal::test_history::trust();
    trust.key_id = "g".repeat(128);
    let pending = capacity_history(&path, &phases, &trust.key_id);
    fragmented_maximum_page_count(&path);
    Journal::validate_replacement(&path, &[]).unwrap();
    let mut gateway = Gateway::open(&path, trust.clone()).unwrap();
    for index in 0..472 {
        assert!(gateway
            .retained_operation(&maximal_request(index).operation_id)
            .unwrap()
            .is_some());
    }
    let mut retained = stored_rows(&gateway.journal.connection);
    let key = "k".repeat(128);
    let settings = ReceiptSettings {
        signing_seed: &[13; 32],
        key_id: &key,
    };
    for (index, history) in pending.iter().enumerate() {
        let id = &history.request.operation_id;
        let original = retained.remove(id).unwrap();
        let phase = phases[index % phases.len()];
        // Decoding/authentication is a fixture precondition, not the expected transition oracle.
        assert!(gateway.retained_operation(id).unwrap().is_some());
        let mut adapter = maximal_adapter(&path, &history.request);
        assert_eq!(
            gateway
                .run_operation_once_with_adapter(id, &mut adapter)
                .await
                .unwrap(),
            (phase != "receiver_observed").then_some(OperationState::ReceiverObserved)
        );
        assert_eq!(adapter.apply_calls, usize::from(phase == "authorized"));
        assert_eq!(
            adapter.observe_calls,
            usize::from(phase != "receiver_observed")
        );
        gateway
            .finalize_operation_receipt_once(id, &settings)
            .unwrap();
        let mut current = stored_rows(&gateway.journal.connection);
        let completed = current.remove(id).unwrap();
        assert_eq!(completed[9], Value::Text("finalized".into()));
        assert_eq!(&completed[..9], &original[..9]);
        assert_eq!(&completed[38..40], &original[38..40]);
        if phase != "authorized" {
            assert_eq!(&completed[10..19], &original[10..19]);
            assert_eq!(&completed[40..], &original[40..]);
        }
        if phase == "receiver_observed" {
            assert_eq!(&completed[10..32], &original[10..32]);
            assert_eq!(&completed[35..], &original[35..]);
            // Bind signed bytes to independently authored frozen facts, not the row decoder.
            assert_eq!(
                completed[33],
                Value::Blob(receipt::sign_statement(&history.statement, &[13; 32], &key).unwrap())
            );
        }
        assert_eq!(current, retained, "unrelated history changed");
        retained.insert(id.clone(), completed);
    }
    assert_eq!(fs::metadata(&path).unwrap().len(), 64 * 1024 * 1024);
    drop(gateway);
    Journal::validate_replacement(&path, &[]).unwrap();
    let reopened = Gateway::open(&path, trust).unwrap();
    assert_eq!(stored_rows(&reopened.journal.connection), retained);
    eprintln!("completed504 retained/32 mixed-phase identities in fragmented16384 pages");
    drop(reopened);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

// Copy committed bytes only; each case owns a fresh worker lock and rollback journal.
pub(in crate::gateway) fn copy_closed_journal(source: &Path, destination: &Path) {
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", source.display()));
        assert!(!sidecar.exists());
    }
    fs::copy(source, destination).unwrap();
}

pub(super) fn park_receipt_after_sql(ready: PathBuf) {
    set_receipt_checkpoint(move |_| {
        fs::write(ready, b"receipt-sql-executed-before-commit").unwrap();
        loop {
            std::thread::park();
        }
    });
}

#[tokio::test]
async fn receipt_process_kills_before_sql_after_sql_and_after_commit_preserve_history() {
    let baseline = database_path("receipt-kill-baseline");
    let setup = Gateway::open_for_test(&baseline).unwrap();
    let signer = "effect-gateway-authorization-test-key";
    let selected = maximal_history(request(), signer);
    selected.insert(&setup.journal.connection, "receiver_observed");
    maximal_history(maximal_request(1), signer).insert(&setup.journal.connection, "finalized");
    drop(setup);
    let selected = selected.request;
    for scenario in [
        "before_receipt_commit",
        "receipt_sql_executed",
        "hot_rollback",
        "receipt",
    ] {
        let path = database_path(&format!("receipt-kill-{scenario}"));
        copy_closed_journal(&baseline, &path);
        let before = stored_rows(&Connection::open(&path).unwrap());
        let ready = path.parent().unwrap().join("ready");
        let mut child = spawn_process_child(scenario, &path, &ready);
        wait_for_child_seam(&mut child, &ready);
        if scenario == "receipt_sql_executed" {
            let journal_path = PathBuf::from(format!("{}-journal", path.display()));
            assert!(fs::metadata(journal_path).unwrap().len() > 0);
        }
        kill_child(&mut child);
        if scenario == "hot_rollback" {
            let bytes = fs::read(format!("{}-journal", path.display())).unwrap();
            assert_eq!(
                &bytes[..8],
                &[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
            );
            let unrecovered = fs::read(&path).unwrap();
            assert_ne!(unrecovered, fs::read(&baseline).unwrap());
            assert!(Journal::validate_replacement(&path, &[]).is_err());
            assert_eq!(fs::read(&path).unwrap(), unrecovered);
        }
        let mut gateway = Gateway::open_for_test(&path).unwrap();

        let mut current_rows = stored_rows(&gateway.journal.connection);
        let current_row = current_rows.remove(&selected.operation_id).unwrap();
        let mut expected = before;

        let original_row = expected.remove(&selected.operation_id).unwrap();
        assert_eq!(current_rows, expected);
        if scenario == "receipt" {
            // Only state and the three receipt columns may change at commitment. Pin every
            // frozen fact and original grant to the row captured before spawning the child.
            assert_eq!(current_row[9], Value::Text("finalized".into()));
            for fields in [0..9, 10..32, 35..current_row.len()] {
                assert_eq!(current_row[fields.clone()], original_row[fields]);
            }
        } else {
            assert_eq!(current_row, original_row);
        }

        let frozen_statement = gateway
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
            frozen_statement
        );
        if scenario == "receipt" {
            assert_eq!(
                stored_rows(&gateway.journal.connection).get(&selected.operation_id),
                Some(&current_row)
            );
        }

        drop(gateway);
        Journal::validate_replacement(&path, &[]).unwrap();
        drop(Gateway::open_for_test(&path).unwrap());
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    fs::remove_dir_all(baseline.parent().unwrap()).unwrap();
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
    let mut written_bytes = 0;
    loop {
        assert!(
            written_bytes < 128 * 1024 * 1024,
            "absolute filler write ceiling reached without ENOSPC"
        );
        let remaining_bytes = 128 * 1024 * 1024 - written_bytes;
        match file.write(&block[..remaining_bytes.min(block.len())]) {
            Ok(count) => {
                assert!(count > 0, "filler write made no progress");
                written_bytes += count;
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
    eprintln!("actual OS ENOSPC after {written_bytes} bounded filler bytes");
}

#[cfg(target_os = "linux")]
fn require_sparse_receipt_destinations(
    connection: &Connection,
    path: &Path,
    allocated_blocks: u64,
) {
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
        allocated_blocks,
        "cache spilling changed main-file allocation before commit"
    );
    let rollback = PathBuf::from(format!("{}-journal", path.display()));
    let bytes = fs::read(&rollback).unwrap();
    let sector_bytes =
        usize::try_from(u32::from_be_bytes(bytes[20..24].try_into().unwrap())).unwrap();
    assert_eq!((bytes.len() - sector_bytes) % 4104, 0);
    assert!(
        bytes[sector_bytes..]
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
async fn qualify_admission_enospc() {
    let directory = require_enospc_mount().join("admission");
    private_directory(&directory);
    let path = directory.join("journal.sqlite3");
    let original_request = request();
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway
        .submit_exact_for_test(&original_request, &authorization(&original_request))
        .unwrap();

    let mut adapter = failed_rollout_adapter(&path, &original_request);
    gateway
        .run_operation_once_with_adapter(&original_request.operation_id, &mut adapter)
        .await
        .unwrap();
    gateway
        .finalize_operation_receipt_once(
            &original_request.operation_id,
            &ReceiptSettings {
                signing_seed: &[13; 32],
                key_id: "original-receipt",
            },
        )
        .unwrap();

    let retained_rows = stored_rows(&gateway.journal.connection);
    let mut selected = original_request.clone();
    selected.operation_id = "enospc-admission".into();
    let signed = sign_authorization_grant(
        &authorization(&selected),
        &[7; 32],
        "effect-gateway-authorization-test-key",
    )
    .unwrap();
    let filler = directory.join("owned-filler");
    fill_owned_tmpfs(&filler);
    let mut acknowledged = false;
    let result = gateway
        .admit_and_reconcile::<FakeAdapter>(
            &selected,
            &signed,
            None,
            None,
            |_| acknowledged = true,
            None,
        )
        .await;
    assert!(
        !acknowledged,
        "disk-full admission is not a capacity refusal"
    );
    assert!(matches!(result, Err(ReconciliationError::Submission(
        GatewayError::Database(rusqlite::Error::SqliteFailure(error, _))))
        if error.code == rusqlite::ErrorCode::DiskFull));
    assert_eq!(stored_rows(&gateway.journal.connection), retained_rows);
    fs::remove_file(&filler).unwrap();

    drop(gateway);
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    assert_eq!(stored_rows(&gateway.journal.connection), retained_rows);
    let result = gateway
        .admit_and_reconcile::<FakeAdapter>(
            &selected,
            &signed,
            None,
            None,
            |decision| {
                assert!(matches!(
                    decision,
                    AdmissionDecision::Admitted(OperationState::Requested)
                ));
            },
            None,
        )
        .await;
    assert!(matches!(
        result,
        Err(ReconciliationError::Blocked(
            ReconciliationBlockage::ReceiverUnavailable
        ))
    ));
    let mut repaired = stored_rows(&gateway.journal.connection);
    repaired.remove(&selected.operation_id);
    assert_eq!(
        repaired, retained_rows,
        "repair changed retained facts or original receipt bytes"
    );
    assert_eq!((adapter.apply_calls, adapter.observe_calls), (1, 1));

    drop(gateway);
    fs::remove_dir_all(directory).unwrap();
    eprintln!("KAPSEL_ADMISSION_ENOSPC_PASSED");
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires tests/qualification/run_storage_enospc.py bounded container tmpfs"]
async fn genuine_enospc_during_admission_and_receipt_recovers_without_resend() {
    use std::os::unix::fs::MetadataExt as _;
    qualify_admission_enospc().await;
    for at_commit in [false, true] {
        let root = require_enospc_mount();
        let directory = root.join(if at_commit {
            "commit"
        } else {
            "journal-growth"
        });
        private_directory(&directory);
        let path = directory.join("journal.sqlite3");
        let selected = maximal_request(503);
        capacity_history(
            &path,
            &["receiver_observed"],
            "effect-gateway-authorization-test-key",
        );
        maximum_page_count_freelist(&path, at_commit);
        Journal::validate_replacement(&path, &[]).unwrap();
        let gateway = Gateway::open_for_test(&path).unwrap();

        let mut retained_rows = stored_rows(&gateway.journal.connection);

        let frozen_statement = gateway
            .journal
            .receipt_statement(&selected.operation_id)
            .unwrap();
        let filler = directory.join("owned-filler");
        let sql_checkpoint_reached = Rc::new(Cell::new(false));
        let checkpoint_flag = Rc::clone(&sql_checkpoint_reached);
        let checkpoint_path = path.clone();
        let checkpoint_filler = filler.clone();
        let allocated_blocks = fs::metadata(&path).unwrap().blocks();
        set_receipt_checkpoint(move |connection| {
            checkpoint_flag.set(true);
            if at_commit {
                require_sparse_receipt_destinations(connection, &checkpoint_path, allocated_blocks);
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
            sql_checkpoint_reached.get()
        );
        assert_eq!(sql_checkpoint_reached.get(), at_commit);
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
        assert_eq!(stored_rows(&gateway.journal.connection), retained_rows);
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
            frozen_statement
        );
        let mut completed = stored_rows(&gateway.journal.connection);
        completed.remove(&selected.operation_id);
        retained_rows.remove(&selected.operation_id);
        assert_eq!(
            completed, retained_rows,
            "completion changed unrelated history"
        );

        drop(gateway);
        Journal::validate_replacement(&path, &[]).unwrap();
        drop(Gateway::open_for_test(&path).unwrap());
        fs::remove_dir_all(directory).unwrap();
    }
    eprintln!("KAPSEL_REAL_ENOSPC_CASES_PASSED");
}

#[tokio::test]
async fn pinned_owned_write_plans_have_no_extra_tree_mutation_pass() {
    let path = database_path("owned-write-plans");
    let gateway = Gateway::open_for_test(&path).unwrap();
    assert_eq!(rusqlite::version(), "3.53.2");
    // Both effects supply the statements actually executed through atomic record I/O.
    // The local SQLite bridge consumes every write kind, including nullable observation layouts.
    let statements = journal::executed_write_statements()
        .await
        .into_iter()
        .map(|(_, sql)| sql);
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
    History::kube("rollback-page").insert(&gateway.journal.connection, "authorized");
    drop(gateway);
    fragmented_maximum_page_count(&path);
    let gateway = Gateway::open_for_test(&path).unwrap();

    let retained_rows = stored_rows(&gateway.journal.connection);
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
                params![value, "rollback-page"],
            )
            .unwrap();
        let current_rollback_bytes = fs::metadata(&rollback).unwrap().len();
        if let Some(length) = length {
            assert_eq!(current_rollback_bytes, length);
        } else {
            length = Some(current_rollback_bytes);
        }
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "cache-spill-off main file changed before commit"
        );
    }
    let bytes = fs::read(&rollback).unwrap();
    let sector_bytes =
        usize::try_from(u32::from_be_bytes(bytes[20..24].try_into().unwrap())).unwrap();
    assert!(sector_bytes <= 65536);
    assert_eq!((bytes.len() - sector_bytes) % 4104, 0);
    let page_ids = bytes[sector_bytes..]
        .as_chunks::<4104>()
        .0
        .iter()
        .map(|record| u32::from_be_bytes(record[..4].try_into().unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(
        page_ids.iter().collect::<BTreeSet<_>>().len(),
        page_ids.len()
    );
    eprintln!(
        "rollback stable over16 updates: {} bytes, {} unique original-page records, sector{sector}",
        bytes.len(),
        page_ids.len(),
        sector = sector_bytes
    );
    transaction.rollback().unwrap();
    assert_eq!(stored_rows(&gateway.journal.connection), retained_rows);

    drop(gateway);
    Journal::validate_replacement(&path, &[]).unwrap();
    drop(Gateway::open_for_test(&path).unwrap());
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn full_page_count_fragmented_freelist_is_accepted_by_both_owners() {
    let path = database_path("maximum-fragmented-freelist");
    drop(Gateway::open_for_test(&path).unwrap());
    fragmented_maximum_page_count(&path);
    Journal::validate_replacement(&path, &[]).unwrap();
    drop(Gateway::open_for_test(&path).unwrap());
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
