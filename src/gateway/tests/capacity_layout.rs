use super::*;

// SQLite creates all records and overflow chains. Only the table's b-tree packing is changed
// by the sparse fixture below; unrelated retained rows are deliberately not selectable operations.

fn layout_live_pages(path: &Path) -> i64 {
    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    let facts = connection
        .prepare(concat!(
            "SELECT name, pageno, ncell, mx_payload FROM dbstat ",
            "WHERE aggregate = TRUE ORDER BY name",
        ))
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    eprintln!("dbstat: {facts:?}");
    connection
        .query_row(
            "SELECT (SELECT page_count FROM pragma_page_count) -
        (SELECT freelist_count FROM pragma_freelist_count)",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn layout_request() -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: "o".repeat(128),
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

fn create_padded_layout(path: &Path, padding: usize) {
    let gateway = Gateway::open_for_test(path).unwrap();
    gateway
        .submit_exact_for_test(&layout_request(), &authorization(&layout_request()))
        .unwrap();
    drop(gateway);
    let connection = Connection::open(path).unwrap();
    assert_eq!(rusqlite::version(), "3.53.2");
    let sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let padded = sql.replacen('(', &format!("({}", " ".repeat(padding)), 1);
    connection
        .execute_batch(
            "CREATE TEMP TABLE saved AS SELECT * FROM kubernetes_image_operations;
        DROP TABLE kubernetes_image_operations",
        )
        .unwrap();
    connection.execute_batch(&padded).unwrap();
    connection
        .execute_batch("INSERT INTO kubernetes_image_operations SELECT * FROM saved")
        .unwrap();
}

fn insert_long_retained_rows(path: &Path, count: usize) {
    let connection = Connection::open(path).unwrap();
    for index in 0..count {
        let id = format!("{index:04}{}", "x".repeat(16 * 1024 - 4));
        connection
            .execute(
                "INSERT INTO kubernetes_image_operations
            (operation_id, namespace, deployment, container, immutable_image_digest, state)
            VALUES (?1, ?2, ?2, ?3, ?4, 'not_attempted')",
                params![
                    id,
                    "n".repeat(16 * 1024),
                    "c".repeat(16_180),
                    request().immutable_image_digest
                ],
            )
            .unwrap();
    }
}

async fn complete_layout_operation(path: &Path, request: &SetDeploymentImageRequest) {
    // Shared read-only snapshot acceptance is separate from logical selection of the valid row.
    journal::Journal::validate_replacement(path, &[]).unwrap();
    let mut gateway = Gateway::open_for_test(path).unwrap();
    assert_eq!(
        gateway
            .submit_exact_for_test(request, &authorization(request))
            .unwrap(),
        SubmissionResult::Existing(OperationState::Authorized)
    );
    let mut adapter = failed_adapter(path, request);
    adapter.identified_target.deployment_uid = "u".repeat(128);
    adapter.identified_target.resource_version = "r".repeat(128);
    adapter.outcome.deployment_uid = Some("u".repeat(128));
    adapter.outcome.resource_version = Some("r".repeat(128));
    adapter.observation.deployment_uid = Some("u".repeat(128));
    adapter.observation.resource_version = Some("r".repeat(128));
    adapter.observation.rollout_condition_reason = Some("r".repeat(128));
    assert_eq!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(
        gateway
            .finalize_operation_receipt_once(
                &request.operation_id,
                &ReceiptSettings {
                    signing_seed: &[13; 32],
                    key_id: "layout-receipt",
                }
            )
            .unwrap(),
        Some(OperationState::Finalized)
    );
    assert_eq!(adapter.apply_calls, 1);
    let receipt = Gateway::read_loaded_receipt(
        gateway
            .journal
            .operation(&request.operation_id)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    drop(gateway);
    eprintln!("completed live pages: {}", layout_live_pages(path));
    journal::Journal::validate_replacement(path, &[]).unwrap();
    let reopened = Gateway::open_for_test(path).unwrap();
    assert_eq!(
        Gateway::read_loaded_receipt(
            reopened
                .journal
                .operation(&request.operation_id)
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        receipt
    );
}

fn page_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn cell_varint(bytes: &[u8], offset: &mut usize) -> usize {
    let mut value = 0;
    for _ in 0..8 {
        let byte = bytes[*offset];
        *offset += 1;
        value = (value << 7) | usize::from(byte & 127);
        if byte < 128 {
            return value;
        }
    }
    unreachable!("fixture payloads and rowids use at most eight varint bytes")
}

fn collect_table_cells(
    bytes: &[u8],
    page: u32,
    pages: &mut Vec<u32>,
    cells: &mut Vec<(usize, Vec<u8>)>,
) {
    pages.push(page);
    let start = (page as usize - 1) * 4096;
    let data = &bytes[start..start + 4096];
    let count = usize::from(u16::from_be_bytes(data[3..5].try_into().unwrap()));
    assert!(count > 0);
    let header = if data[0] == 13 {
        8
    } else {
        assert_eq!(data[0], 5);
        12
    };
    for index in 0..count {
        let pointer = header + 2 * index;
        let offset = usize::from(u16::from_be_bytes(
            data[pointer..pointer + 2].try_into().unwrap(),
        ));
        if data[0] == 5 {
            collect_table_cells(bytes, page_u32(data, offset), pages, cells);
        } else {
            let mut cursor = offset;
            let payload = cell_varint(data, &mut cursor);
            let rowid = cell_varint(data, &mut cursor);
            assert!(payload <= 65536);
            let local = if payload <= 4061 {
                payload
            } else {
                let candidate = 489 + (payload - 489) % 4092;
                if candidate <= 4061 {
                    candidate
                } else {
                    489
                }
            };
            let end = cursor + local + if local < payload { 4 } else { 0 };
            cells.push((rowid, data[offset..end].to_vec()));
        }
    }
    if data[0] == 5 {
        collect_table_cells(bytes, page_u32(data, 8), pages, cells);
    }
}

fn sparse_subtree(bytes: &mut Vec<u8>, page: u32, cells: &[(usize, Vec<u8>)]) {
    let mut data = vec![0_u8; 4096];
    data[3..5].copy_from_slice(&1_u16.to_be_bytes());
    if cells.len() == 1 {
        data[0] = 13;
        let offset = 4096 - cells[0].1.len();
        data[5..7].copy_from_slice(&u16::try_from(offset).unwrap().to_be_bytes());
        data[8..10].copy_from_slice(&u16::try_from(offset).unwrap().to_be_bytes());
        data[offset..].copy_from_slice(&cells[0].1);
    } else {
        assert_eq!(cells.len() % 2, 0);
        data[0] = 5;
        let left = u32::try_from(bytes.len() / 4096 + 1).unwrap();
        let right = left + 1;
        bytes.resize(bytes.len() + 8192, 0);
        data[5..7].copy_from_slice(&4091_u16.to_be_bytes());
        data[8..12].copy_from_slice(&right.to_be_bytes());
        data[12..14].copy_from_slice(&4091_u16.to_be_bytes());
        data[4091..4095].copy_from_slice(&left.to_be_bytes());
        let middle = cells.len() / 2;
        data[4095] = u8::try_from(cells[middle - 1].0).unwrap();
        assert!(data[4095] < 128);
        sparse_subtree(bytes, left, &cells[..middle]);
        sparse_subtree(bytes, right, &cells[middle..]);
    }
    let start = (page as usize - 1) * 4096;
    bytes[start..start + 4096].copy_from_slice(&data);
}

fn repack_sparse_table(path: &Path) {
    let connection = Connection::open(path).unwrap();
    let root: u32 = connection
        .query_row(
            "SELECT rootpage FROM sqlite_schema WHERE type = 'table'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let mut bytes = fs::read(path).unwrap();
    assert!(bytes.len() < 1024 * 1024);
    assert_eq!(
        page_u32(&bytes, 36),
        0,
        "generated fixture has no preexisting freelist"
    );
    let mut pages = Vec::new();
    let mut cells = Vec::new();
    collect_table_cells(&bytes, root, &mut pages, &mut cells);
    assert_eq!(cells.len(), 8);
    assert!(cells.windows(2).all(|pair| pair[0].0 < pair[1].0));
    sparse_subtree(&mut bytes, root, &cells);
    // Return all displaced table pages except the reused root as one valid freelist trunk.
    let free = &pages[1..];
    assert!(!free.is_empty() && free.len() <= 1023);
    let trunk = (free[0] as usize - 1) * 4096;
    bytes[trunk..trunk + 4096].fill(0);
    bytes[trunk + 4..trunk + 8]
        .copy_from_slice(&u32::try_from(free.len() - 1).unwrap().to_be_bytes());
    for (index, page) in free[1..].iter().enumerate() {
        bytes[trunk + 8 + index * 4..trunk + 12 + index * 4].copy_from_slice(&page.to_be_bytes());
    }
    let page_count = u32::try_from(bytes.len() / 4096).unwrap();
    bytes[28..32].copy_from_slice(&page_count.to_be_bytes());
    bytes[32..36].copy_from_slice(&free[0].to_be_bytes());
    bytes[36..40].copy_from_slice(&u32::try_from(free.len()).unwrap().to_be_bytes());
    fs::write(path, bytes).unwrap();
}

fn assert_layout_open_paths(path: &Path, accepted: bool) {
    layout_live_pages(path);
    let before = fs::read(path).unwrap();
    let readonly = journal::Journal::validate_replacement(path, &[]);
    assert_eq!(fs::read(path).unwrap(), before);
    let writable = Gateway::open_for_test(path);
    if accepted {
        readonly.unwrap();
        drop(writable.unwrap());
    } else {
        assert!(matches!(readonly, Err(GatewayError::InvalidPersistedState)));
        assert!(matches!(writable, Err(GatewayError::InvalidPersistedState)));
    }
    assert_eq!(fs::read(path).unwrap(), before);
}

fn maximum_payload(path: &Path, tree: &str) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT mx_payload FROM dbstat('main') WHERE aggregate = TRUE AND name = ?1",
            [tree],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn encoded_table_and_schema_payload_boundaries_use_actual_record_headers() {
    for size in [65_536, 65_537] {
        let path = database_path(&format!("encoded-table-{size}"));
        create_padded_layout(&path, 0);
        insert_long_retained_rows(&path, 1);
        let current = maximum_payload(&path, "kubernetes_image_operations");
        Connection::open(&path).unwrap().execute(
            "UPDATE kubernetes_image_operations SET container = ?1 WHERE state = 'not_attempted'",
            ["c".repeat(usize::try_from(16_180 + size - current).unwrap())]).unwrap();
        assert_eq!(maximum_payload(&path, "kubernetes_image_operations"), size);
        assert_layout_open_paths(&path, size == 65_536);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();

        let path = database_path(&format!("encoded-schema-{size}"));
        // Normal initialization/ALTER produces a 1440-byte table schema record; crossing
        // the SQL serial-type varint boundary adds one header byte as well as the padding.
        create_padded_layout(&path, usize::try_from(size - 1440 - 1).unwrap());
        assert_eq!(maximum_payload(&path, "sqlite_schema"), size);
        assert_layout_open_paths(&path, size == 65_536);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

// Add a nonminimal but equivalent header-length varint to the maximum-sized index record.
// Its four SQLite-created overflow pages and logical key/rowid remain unchanged.
fn extend_index_record_header(path: &Path) {
    let connection = Connection::open(path).unwrap();
    let root: u32 = connection
        .query_row(
            "SELECT rootpage FROM sqlite_schema WHERE type = 'index'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let mut bytes = fs::read(path).unwrap();
    let start = (root as usize - 1) * 4096;
    assert_eq!(bytes[start], 10);
    let count = usize::from(u16::from_be_bytes(
        bytes[start + 3..start + 5].try_into().unwrap(),
    ));
    let mut modified = false;
    for index in 0..count {
        let pointer = start + 8 + 2 * index;
        let cell = start
            + usize::from(u16::from_be_bytes(
                bytes[pointer..pointer + 2].try_into().unwrap(),
            ));
        let mut cursor = cell;
        let size = cell_varint(&bytes, &mut cursor);
        if size != 16_397 {
            continue;
        }
        assert!(!modified);
        let mut payload = bytes[cursor..cursor + 489].to_vec();
        let mut overflow = page_u32(&bytes, cursor + 489);
        let mut chain = Vec::new();
        while overflow != 0 {
            let offset = (overflow as usize - 1) * 4096;
            chain.push(offset);
            payload.extend_from_slice(&bytes[offset + 4..offset + 4096]);
            overflow = page_u32(&bytes, offset);
        }
        assert_eq!(chain.len(), 4);
        payload.truncate(size);
        assert_eq!(payload[0], 5);
        assert_eq!(payload[4], 6);
        payload[0] = 6;
        payload.insert(0, 0x80);
        bytes[cursor - 1] += 1; // Same three-byte payload-length varint, no carry.
        bytes[cursor..cursor + 489].copy_from_slice(&payload[..489]);
        for (offset, chunk) in chain.iter().zip(payload[489..].chunks(4092)) {
            bytes[offset + 4..offset + 4 + chunk.len()].copy_from_slice(chunk);
        }
        modified = true;
    }
    assert!(modified);
    fs::write(path, bytes).unwrap();
}

#[test]
fn encoded_index_payload_boundary_includes_noncanonical_header_bytes() {
    let path = database_path("encoded-index-header-boundary");
    create_padded_layout(&path, 0);
    insert_long_retained_rows(&path, 1);
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE kubernetes_image_operations
        SET rowid = 9223372036854775807 WHERE state = 'not_attempted'",
            [],
        )
        .unwrap();
    let tree = "sqlite_autoindex_kubernetes_image_operations_1";
    assert_eq!(maximum_payload(&path, tree), 16_397);
    assert_layout_open_paths(&path, true);
    extend_index_record_header(&path);
    assert_eq!(maximum_payload(&path, tree), 16_398);
    assert_layout_open_paths(&path, false);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

// Move an existing leaf root into one child. For the empty-child control add a second,
// empty leaf, preserving row/index contents and balanced depths. Only page 1 may be unary.
fn wrap_leaf_root(path: &Path, schema: bool, empty_child: bool) {
    let connection = Connection::open(path).unwrap();
    let root: u32 = if schema {
        1
    } else {
        connection
            .query_row(
                "SELECT rootpage FROM sqlite_schema WHERE type = 'table'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    };
    drop(connection);
    let mut bytes = fs::read(path).unwrap();
    let start = (root as usize - 1) * 4096;
    let header = if schema { 100 } else { 0 };
    assert_eq!(bytes[start + header], 13);
    let mut child = bytes[start..start + 4096].to_vec();
    if schema {
        assert_eq!(u16::from_be_bytes(child[103..105].try_into().unwrap()), 2);
        child.copy_within(100..112, 0);
    }
    let child_page = u32::try_from(bytes.len() / 4096 + 1).unwrap();
    bytes.extend_from_slice(&child);
    bytes[start + header..start + 4096].fill(0);
    bytes[start + header] = 5;
    bytes[start + header + 5..start + header + 7].copy_from_slice(&4096_u16.to_be_bytes());
    bytes[start + header + 8..start + header + 12].copy_from_slice(&child_page.to_be_bytes());
    if empty_child {
        assert!(!schema);
        let empty_page = child_page + 1;
        let mut leaf = vec![0_u8; 4096];
        leaf[0] = 13;
        leaf[5..7].copy_from_slice(&4096_u16.to_be_bytes());
        bytes.extend_from_slice(&leaf);
        bytes[start + 3..start + 5].copy_from_slice(&1_u16.to_be_bytes());
        bytes[start + 5..start + 7].copy_from_slice(&4091_u16.to_be_bytes());
        bytes[start + 12..start + 14].copy_from_slice(&4091_u16.to_be_bytes());
        bytes[start + 4091..start + 4095].copy_from_slice(&empty_page.to_be_bytes());
        // Separator rowid zero: every real row in this fixture has positive rowid.
    }
    let count = u32::try_from(bytes.len() / 4096).unwrap();
    bytes[28..32].copy_from_slice(&count.to_be_bytes());
    fs::write(path, bytes).unwrap();
}

#[test]
fn empty_children_and_unary_operation_roots_are_rejection_controls() {
    for empty_child in [false, true] {
        let path = database_path(&format!("empty-tree-control-{empty_child}"));
        create_padded_layout(&path, 0);
        wrap_leaf_root(&path, false, empty_child);
        let before = fs::read(&path).unwrap();
        let integrity =
            Connection::open(&path)
                .unwrap()
                .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0));
        eprintln!("empty_child={empty_child}, integrity={integrity:?}");
        assert!(
            matches!(integrity, Err(rusqlite::Error::SqliteFailure(error, _))
            if error.code == rusqlite::ErrorCode::DatabaseCorrupt)
        );
        assert!(journal::Journal::validate_replacement(&path, &[]).is_err());
        assert!(Gateway::open_for_test(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[test]
fn schema_page_one_may_be_an_empty_internal_root() {
    let path = database_path("schema-empty-internal-root");
    create_padded_layout(&path, 0);
    wrap_leaf_root(&path, true, false);
    assert_eq!(layout_live_pages(&path), 4);
    assert_layout_open_paths(&path, true);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn empty_operation_leaf_roots_are_accepted() {
    let path = database_path("empty-operation-roots");
    drop(Gateway::open_for_test(&path).unwrap());
    assert_eq!(layout_live_pages(&path), 3);
    assert_layout_open_paths(&path, true);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn persisted_record_limit_is_enforced_on_reopen() {
    let path = database_path("encoded-record-bound");
    create_padded_layout(&path, 0);
    insert_long_retained_rows(&path, 1);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE kubernetes_image_operations SET receipt_bytes = zeroblob(16384)
        WHERE state = 'not_attempted'",
            [],
        )
        .unwrap();
    drop(connection);
    eprintln!(
        "oversized encoded record live pages: {}",
        layout_live_pages(&path)
    );
    assert_eq!(
        maximum_payload(&path, "kubernetes_image_operations"),
        81_889
    );
    assert_layout_open_paths(&path, false);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn sparse_accepted_layout_preserves_live_bound_after_legitimate_completion() {
    for padding_kib in [56, 60] {
        let path = database_path(&format!("sparse-accepted-completion-{padding_kib}"));
        create_padded_layout(&path, padding_kib * 1024);
        insert_long_retained_rows(&path, 7);
        repack_sparse_table(&path);
        let before = layout_live_pages(&path);
        eprintln!(
            "sparse initial live pages: {before}; former bound: {}",
            21 * 8 + 3
        );
        assert_eq!(before, if padding_kib == 56 { 171 } else { 172 });
        complete_layout_operation(&path, &layout_request()).await;
        assert_eq!(layout_live_pages(&path), before + 1);
        assert!(layout_live_pages(&path) <= 23 * 8 + 38);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn long_retained_ids_and_padded_schema_complete_selected_legitimate_operation() {
    let path = database_path("long-retained-padded-schema");
    create_padded_layout(&path, 48 * 1024);
    // Populate after schema creation: an empty padded schema alone need not pass the live bound.
    insert_long_retained_rows(&path, 7);
    let request = layout_request();
    eprintln!("initial live pages: {}", layout_live_pages(&path));
    complete_layout_operation(&path, &request).await;
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
