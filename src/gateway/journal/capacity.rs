//! Fixed completion accounting for the sole journal layout.
//!
//! Charges are reconstructed from retained identities, never released by phase changes. This is
//! configured SQLite capacity, not filesystem-space reservation or a guarantee against I/O failure.
//!
//! The bound depends on the owned SQL, not just these constants. Each insert adds one table record
//! and one index record. Each update replaces one table record without changing its rowid or
//! indexed ID. Fresh statement preparation with dedicated record registers preserves the
//! OP_MakeRecord size check. Reusable record buffers are not covered.
//!
//! In pinned SQLite, sqlite3BtreeInsert creates at most one replacement chain before freeing
//! the old chain, then balances once. The exact schema excludes triggers, foreign keys,
//! extra indexes and autoincrement tables. These restrictions keep temporary allocation within
//! the completion headroom. The write-plan regression in tests/storage.rs detects extra mutation
//! passes in the owned SQL. It does not measure SQLite's allocation peak.
//!
//! Revalidate these premises when changing SQLite, schema, SQL or preparation. The cross-module
//! layout, transient-page and rollback-file argument is in docs/contributing/storage_capacity.md.

use rusqlite::Connection;

use super::{schema, GatewayError};

pub(in crate::gateway) const PAGE_BYTES: i64 = 4096;
pub(in crate::gateway) const DATABASE_PAGES: i64 = 16_384;
pub(in crate::gateway) const IDENTITY_PAGES: i64 = 32;
pub(in crate::gateway) const COMPLETION_HEADROOM_PAGES: i64 = 256;
pub(in crate::gateway) const IDENTITY_CAPACITY: i64 =
    (DATABASE_PAGES - COMPLETION_HEADROOM_PAGES) / IDENTITY_PAGES;
pub(in crate::gateway) const UNFINISHED_CAPACITY: i64 = 32;

// Includes record headers: 16-KiB retained key, eight-byte rowid, five-byte header.
const INDEX_PAYLOAD_BYTES_MAX: usize = schema::PERSISTED_VALUE_BYTES_MAX + 8 + 5;
const LIVE_PAGES_PER_IDENTITY: i64 = 23;
// Four schema records (two typed operation tables and their primary indexes), plus four roots.
const LIVE_FIXED_PAGES: i64 = 76;
const TREE_DEPTH_MAX: usize = 20;

pub(super) fn counts(connection: &Connection) -> Result<(i64, i64), GatewayError> {
    connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(state IN (
                'requested', 'authorized', 'apply_started', 'receiver_observed'
             )), 0) FROM (
                SELECT state FROM kubernetes_image_operations
                UNION ALL SELECT state FROM git_ref_operations
             )",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(GatewayError::Database)
}

pub(super) fn require_admission(connection: &Connection) -> Result<(), GatewayError> {
    let (retained_identities, unfinished_identities) = counts(connection)?;
    if retained_identities >= IDENTITY_CAPACITY || unfinished_identities >= UNFINISHED_CAPACITY {
        return Err(GatewayError::JournalFull);
    }
    Ok(())
}

pub(super) fn require_retained_bounds(connection: &Connection) -> Result<(), GatewayError> {
    let (retained_identities, unfinished_identities) = counts(connection)?;
    if retained_identities > IDENTITY_CAPACITY || unfinished_identities > UNFINISHED_CAPACITY {
        return Err(GatewayError::InvalidPersistedState);
    }

    let database_pages: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(GatewayError::Database)?;
    let freelist_pages: i64 = connection
        .query_row("PRAGMA freelist_count", [], |row| row.get(0))
        .map_err(GatewayError::Database)?;
    // Integrity checking must precede this check in the same read snapshot: orphan pages are
    // neither live b-tree/overflow pages nor reusable freelist space.
    let live_pages = database_pages
        .checked_sub(freelist_pages)
        .ok_or(GatewayError::InvalidPersistedState)?;
    if live_pages < 0
        || live_pages > LIVE_PAGES_PER_IDENTITY * retained_identities + LIVE_FIXED_PAGES
        || database_pages > DATABASE_PAGES
    {
        return Err(GatewayError::InvalidPersistedState);
    }

    require_physical_bounds(connection, retained_identities, database_pages, live_pages)
}

// Call only after exact schema recognition and integrity checking in the same snapshot.
// SQLITE_LIMIT_LENGTH bounds writes and individual reads, not existing encoded record sizes.
fn require_physical_bounds(
    connection: &Connection,
    retained_identities: i64,
    database_pages: i64,
    live_pages: i64,
) -> Result<(), GatewayError> {
    let mut page_statistics_query = connection
        .prepare("SELECT name, path, pageno, pagetype, ncell, mx_payload FROM dbstat('main')")
        .map_err(GatewayError::Database)?;
    let mut page_statistics_rows = page_statistics_query
        .query([])
        .map_err(GatewayError::Database)?;
    let mut seen_live_pages = 0;
    let (kubernetes_identities, git_identities): (i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM kubernetes_image_operations),
                (SELECT COUNT(*) FROM git_ref_operations)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(GatewayError::Database)?;
    if kubernetes_identities + git_identities != retained_identities {
        return Err(GatewayError::InvalidPersistedState);
    }
    let expected_cells = [
        kubernetes_identities,
        kubernetes_identities,
        git_identities,
        git_identities,
        4,
    ];
    let mut root_counts = [0; 5];
    let mut cell_counts = [0_i64; 5];
    while let Some(row) = page_statistics_rows
        .next()
        .map_err(GatewayError::Database)?
    {
        let tree_name: String = row.get(0).map_err(GatewayError::Database)?;
        let tree_path: String = row.get(1).map_err(GatewayError::Database)?;
        let page_number: i64 = row.get(2).map_err(GatewayError::Database)?;
        let page_kind: String = row.get(3).map_err(GatewayError::Database)?;
        let cell_count: i64 = row.get(4).map_err(GatewayError::Database)?;
        let maximum_payload_bytes: i64 = row.get(5).map_err(GatewayError::Database)?;
        let tree_index = match tree_name.as_str() {
            "kubernetes_image_operations" => 0,
            "sqlite_autoindex_kubernetes_image_operations_1" => 1,
            "git_ref_operations" => 2,
            "sqlite_autoindex_git_ref_operations_1" => 3,
            "sqlite_schema" => 4,
            _ => return Err(GatewayError::InvalidPersistedState),
        };
        seen_live_pages += 1;
        if seen_live_pages > database_pages
            || !(1..=database_pages).contains(&page_number)
            || cell_count < 0
            || maximum_payload_bytes < 0
        {
            return Err(GatewayError::InvalidPersistedState);
        }
        if page_kind == "overflow" {
            if cell_count != 0 || maximum_payload_bytes != 0 {
                return Err(GatewayError::InvalidPersistedState);
            }
            continue;
        }
        let is_root = tree_path == "/";
        root_counts[tree_index] += i32::from(is_root);
        let allows_empty_root = is_root
            && ((page_kind == "leaf" && tree_index != 4 && expected_cells[tree_index] == 0)
                || (page_kind == "internal" && tree_index == 4 && page_number == 1));
        let payload_limit_bytes = if tree_index == 1 || tree_index == 3 {
            i64::try_from(INDEX_PAYLOAD_BYTES_MAX)
                .map_err(|_| GatewayError::InvalidPersistedState)?
        } else {
            i64::from(schema::PERSISTED_ROW_BYTES_MAX)
        };
        if !matches!(page_kind.as_str(), "leaf" | "internal")
            || (cell_count == 0 && !allows_empty_root)
            || tree_path.bytes().filter(|byte| *byte == b'/').count() > TREE_DEPTH_MAX
            || maximum_payload_bytes > payload_limit_bytes
        {
            return Err(GatewayError::InvalidPersistedState);
        }
        if tree_index == 1 || tree_index == 3 || page_kind == "leaf" {
            cell_counts[tree_index] += cell_count;
        }
    }
    if root_counts != [1; 5] || cell_counts != expected_cells || seen_live_pages != live_pages {
        return Err(GatewayError::InvalidPersistedState);
    }
    Ok(())
}

pub(super) fn configure(connection: &Connection, fresh: bool) -> Result<(), GatewayError> {
    if fresh {
        connection
            .pragma_update(None, "page_size", PAGE_BYTES)
            .map_err(GatewayError::Database)?;
    }
    require_layout(connection)?;

    let configured_maximum_pages: i64 = connection
        .query_row("PRAGMA max_page_count = 16384", [], |row| row.get(0))
        .map_err(GatewayError::Database)?;
    if configured_maximum_pages != DATABASE_PAGES {
        return Err(GatewayError::InvalidPersistedState);
    }

    // One bounded transaction must not generate repeated sector-padded rollback segments.
    connection
        .pragma_update(None, "cache_spill", false)
        .map_err(GatewayError::Database)?;
    let cache_spill: i64 = connection
        .query_row("PRAGMA cache_spill", [], |row| row.get(0))
        .map_err(GatewayError::Database)?;
    if cache_spill != 0 {
        return Err(GatewayError::InvalidPersistedState);
    }
    Ok(())
}

pub(super) fn require_layout(connection: &Connection) -> Result<(), GatewayError> {
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(GatewayError::Database)?;
    let auto_vacuum: i64 = connection
        .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
        .map_err(GatewayError::Database)?;
    if page_size != PAGE_BYTES || auto_vacuum != 0 {
        return Err(GatewayError::InvalidPersistedState);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_statement_transient_and_main_rollback_bounds_fit_fixed_limits() {
        // At most 19 original non-root groups plus the child created by root deepening.
        // Quick balancing costs one destination; five bounds either balancing choice.
        let tree_allocations = i64::try_from(TREE_DEPTH_MAX).unwrap() * 5 + 1;
        let transient_pages = 2 * tree_allocations + 2 * 17;
        assert_eq!(transient_pages, 236);
        assert!(transient_pages < COMPLETION_HEADROOM_PAGES);
        assert!(
            LIVE_PAGES_PER_IDENTITY * IDENTITY_CAPACITY + LIVE_FIXED_PAGES + transient_pages
                <= DATABASE_PAGES
        );
        // This is only the main rollback file, not statement sub-journals or process memory.
        let rollback_bytes = DATABASE_PAGES * (PAGE_BYTES + 8) + 2 * 65_536;
        assert_eq!(rollback_bytes, 67_371_008);
        assert!(rollback_bytes < 65 * 1024 * 1024);
    }

    #[test]
    fn physical_layout_terms_fit_unchanged_retained_charge() {
        assert_eq!((65_536_usize - 489).div_ceil(4092), 16);
        assert_eq!((INDEX_PAYLOAD_BYTES_MAX - 489).div_ceil(4092), 4);
        assert_eq!(INDEX_PAYLOAD_BYTES_MAX, 16_397);
        assert_eq!(LIVE_FIXED_PAGES, 4 * 16 + 8 + 4);
        assert_eq!(LIVE_PAGES_PER_IDENTITY, 2 + 16 + 1 + 4);
        for retained_identities in 0..=IDENTITY_CAPACITY {
            let live_pages = LIVE_PAGES_PER_IDENTITY * retained_identities + LIVE_FIXED_PAGES;
            assert!(live_pages + COMPLETION_HEADROOM_PAGES <= DATABASE_PAGES);
            if retained_identities >= 9 {
                assert!(live_pages <= retained_identities * IDENTITY_PAGES);
            }
        }
        assert_eq!(
            LIVE_PAGES_PER_IDENTITY * IDENTITY_CAPACITY + LIVE_FIXED_PAGES,
            11_668
        );
    }

    #[test]
    fn conservative_charge_fits_every_admitted_identity_and_completion_headroom() {
        assert_eq!(IDENTITY_CAPACITY, 504);
        assert_eq!(IDENTITY_PAGES * PAGE_BYTES, 128 * 1024);
        assert_eq!(DATABASE_PAGES * PAGE_BYTES, 64 * 1024 * 1024);
        const {
            assert!(
                IDENTITY_CAPACITY * IDENTITY_PAGES + COMPLETION_HEADROOM_PAGES <= DATABASE_PAGES
            );
            assert!(
                (IDENTITY_CAPACITY + 1) * IDENTITY_PAGES + COMPLETION_HEADROOM_PAGES
                    > DATABASE_PAGES
            );
        }
    }
}
