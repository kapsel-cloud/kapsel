//! Fixed completion accounting for the sole journal layout.
//!
//! Charges are reconstructed from retained identities, never released by phase changes. This is
//! configured SQLite capacity, not filesystem-space reservation or a guarantee against I/O failure.

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
const LIVE_FIXED_PAGES: i64 = 38;
const TREE_DEPTH_MAX: usize = 20;

pub(super) fn counts(connection: &Connection) -> Result<(i64, i64), GatewayError> {
    connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(state IN (
                'requested', 'authorized', 'apply_started', 'receiver_observed'
             )), 0) FROM kubernetes_image_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(GatewayError::Database)
}

pub(super) fn require_admission(connection: &Connection) -> Result<(), GatewayError> {
    let (identities, unfinished) = counts(connection)?;
    if identities >= IDENTITY_CAPACITY || unfinished >= UNFINISHED_CAPACITY {
        return Err(GatewayError::JournalFull);
    }
    Ok(())
}

pub(super) fn require_retained_bounds(connection: &Connection) -> Result<(), GatewayError> {
    let (identities, unfinished) = counts(connection)?;
    if identities > IDENTITY_CAPACITY || unfinished > UNFINISHED_CAPACITY {
        return Err(GatewayError::InvalidPersistedState);
    }
    let pages: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(GatewayError::Database)?;
    let free: i64 = connection
        .query_row("PRAGMA freelist_count", [], |row| row.get(0))
        .map_err(GatewayError::Database)?;
    // Integrity checking must precede this check in the same read snapshot: orphan pages are
    // neither live b-tree/overflow pages nor reusable freelist space.
    let live = pages
        .checked_sub(free)
        .ok_or(GatewayError::InvalidPersistedState)?;
    if live < 0
        || live > LIVE_PAGES_PER_IDENTITY * identities + LIVE_FIXED_PAGES
        || pages > DATABASE_PAGES
    {
        return Err(GatewayError::InvalidPersistedState);
    }
    require_physical_bounds(connection, identities, pages, live)
}

// Call only after exact schema recognition and integrity checking in the same snapshot.
// SQLITE_LIMIT_LENGTH bounds writes and individual reads, not existing encoded record sizes.
fn require_physical_bounds(
    connection: &Connection,
    identities: i64,
    pages: i64,
    live: i64,
) -> Result<(), GatewayError> {
    let mut statement = connection
        .prepare("SELECT name, path, pageno, pagetype, ncell, mx_payload FROM dbstat('main')")
        .map_err(GatewayError::Database)?;
    let mut rows = statement.query([]).map_err(GatewayError::Database)?;
    let mut seen_pages = 0;
    let mut roots = [0; 3];
    let mut cells = [0_i64; 3];
    while let Some(row) = rows.next().map_err(GatewayError::Database)? {
        let name: String = row.get(0).map_err(GatewayError::Database)?;
        let path: String = row.get(1).map_err(GatewayError::Database)?;
        let page: i64 = row.get(2).map_err(GatewayError::Database)?;
        let kind: String = row.get(3).map_err(GatewayError::Database)?;
        let count: i64 = row.get(4).map_err(GatewayError::Database)?;
        let payload: i64 = row.get(5).map_err(GatewayError::Database)?;
        let tree = match name.as_str() {
            "kubernetes_image_operations" => 0,
            "sqlite_autoindex_kubernetes_image_operations_1" => 1,
            "sqlite_schema" => 2,
            _ => return Err(GatewayError::InvalidPersistedState),
        };
        seen_pages += 1;
        if seen_pages > pages || !(1..=pages).contains(&page) || count < 0 || payload < 0 {
            return Err(GatewayError::InvalidPersistedState);
        }
        if kind == "overflow" {
            if count != 0 || payload != 0 {
                return Err(GatewayError::InvalidPersistedState);
            }
            continue;
        }
        let root = path == "/";
        roots[tree] += i32::from(root);
        let empty_root = root
            && ((kind == "leaf" && tree != 2 && identities == 0)
                || (kind == "internal" && tree == 2 && page == 1));
        let maximum = if tree == 1 {
            i64::try_from(INDEX_PAYLOAD_BYTES_MAX)
                .map_err(|_| GatewayError::InvalidPersistedState)?
        } else {
            i64::from(schema::PERSISTED_ROW_BYTES_MAX)
        };
        if !matches!(kind.as_str(), "leaf" | "internal")
            || (count == 0 && !empty_root)
            || path.bytes().filter(|byte| *byte == b'/').count() > TREE_DEPTH_MAX
            || payload > maximum
        {
            return Err(GatewayError::InvalidPersistedState);
        }
        if tree == 1 || kind == "leaf" {
            cells[tree] += count;
        }
    }
    if roots != [1; 3] || cells != [identities, identities, 2] || seen_pages != live {
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
    let maximum: i64 = connection
        .query_row("PRAGMA max_page_count = 16384", [], |row| row.get(0))
        .map_err(GatewayError::Database)?;
    if maximum != DATABASE_PAGES {
        return Err(GatewayError::InvalidPersistedState);
    }
    // One bounded transaction must not generate repeated sector-padded rollback segments.
    connection
        .pragma_update(None, "cache_spill", false)
        .map_err(GatewayError::Database)?;
    let spill: i64 = connection
        .query_row("PRAGMA cache_spill", [], |row| row.get(0))
        .map_err(GatewayError::Database)?;
    if spill != 0 {
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
        // At most19 original non-root groups plus the child created by root deepening.
        // Quick balancing costs one destination; five bounds either balancing choice.
        let tree_allocations = i64::try_from(TREE_DEPTH_MAX).unwrap() * 5 + 1;
        let transient = 2 * tree_allocations + 2 * 17;
        assert_eq!(transient, 236);
        assert!(transient < COMPLETION_HEADROOM_PAGES);
        assert!(
            LIVE_PAGES_PER_IDENTITY * IDENTITY_CAPACITY + LIVE_FIXED_PAGES + transient
                <= DATABASE_PAGES
        );
        // This is only the main rollback file, not statement sub-journals or process memory.
        let rollback = DATABASE_PAGES * (PAGE_BYTES + 8) + 2 * 65_536;
        assert_eq!(rollback, 67_371_008);
        assert!(rollback < 65 * 1024 * 1024);
    }

    #[test]
    fn physical_layout_terms_fit_unchanged_retained_charge() {
        assert_eq!((65_536_usize - 489).div_ceil(4092), 16);
        assert_eq!((INDEX_PAYLOAD_BYTES_MAX - 489).div_ceil(4092), 4);
        assert_eq!(INDEX_PAYLOAD_BYTES_MAX, 16_397);
        assert_eq!(LIVE_FIXED_PAGES, 2 * 16 + 4 + 2);
        assert_eq!(LIVE_PAGES_PER_IDENTITY, 2 + 16 + 1 + 4);
        for identities in 0..=IDENTITY_CAPACITY {
            let live = LIVE_PAGES_PER_IDENTITY * identities + LIVE_FIXED_PAGES;
            assert!(live + COMPLETION_HEADROOM_PAGES <= DATABASE_PAGES);
            if identities >= 5 {
                assert!(live <= identities * IDENTITY_PAGES);
            }
        }
        assert_eq!(
            LIVE_PAGES_PER_IDENTITY * IDENTITY_CAPACITY + LIVE_FIXED_PAGES,
            11_630
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
