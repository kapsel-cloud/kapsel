# Why admitted work fits the journal

Accepting an operation means taking responsibility for finishing its record. A journal that admitted
work until it was full could leave an attempted operation without room for its receipt. Kapsel
therefore limits admission before reaching its configured SQLite ceiling.

The [storage contract](../reference/storage.md#configured-completion-guarantee) defines that promise
and its exclusions. This page derives the page and main rollback-file bounds. Operators can use the
limits and [repair procedure](../guides/operator.md#storage-refusal-and-repair) without reading the
derivation.

## The accounting model

The journal does not reserve filesystem blocks for each operation. Instead, it charges every
retained identity a conservative number of SQLite pages, then leaves separate space for temporary
allocations during completion.

| Part                        | Pages  | Meaning                              |
| --------------------------- | ------ | ------------------------------------ |
| Configured database ceiling | 16,384 | 64 MiB at 4 KiB per page             |
| Retained-identity budget    | 16,128 | 504 identities × 32 pages            |
| Shared completion headroom  | 256    | 1 MiB for transient page allocations |

The charge is 128 KiB per identity regardless of payload or phase. Completing an operation does not
release its retained charge. Admission checks counts and inserts original authority in the same
transaction. The gateway checks for an existing identity before refusing new work. At most 32
identities may remain `requested`, `authorized`, `apply_started` or `receiver_observed`.

Three questions must be answered separately:

1. How many pages can any accepted retained layout use?
2. How many additional pages can an owned write allocate before releasing old pages?
3. How large can the main rollback file grow while protecting the transaction?

Passing a full-capacity test answers none of these for every possible layout. The argument below
supplies the bounds. Tests check the assumptions behind them and specific failure cases.

## Bound the retained layout

A file's length does not tell us how much reusable space it contains. A fragmented 64-MiB database
can still have ample free pages. Conversely, small logical values do not prove that existing encoded
records fit the write limits.

For that reason, opening validates the actual physical layout. Format 6 requires 4 KiB pages, no
reserved page bytes, no auto-vacuum and one primary index per typed operation table. In one read
snapshot, exact schema recognition and full integrity checking precede
[SQLite `dbstat`](https://sqlite.org/dbstat.html) inspection of every owned b-tree and overflow
page. The argument uses the pinned SQLite 3.53.2
[file format](https://sqlite.org/fileformat.html#b_tree_pages).

### Accepted records and trees

The physical checks require:

- Table and `sqlite_schema` cell payloads, including record headers, are at most 65,536 bytes.
- Primary-index cell payloads are at most 16,397 bytes. This fits a retained 16-KiB key, an
  eight-byte rowid and a five-byte canonical record header. The check measures actual encodings
  rather than assuming they are canonical.
- Every non-root b-tree page is nonempty, and depth is at most 20 pages. Empty leaf roots are
  allowed for empty operation trees. Page 1 alone may be an empty internal root of `sqlite_schema`.
- Metadata accounts for exactly the retained table rows, the same number of index cells (including
  interior cells), four schema rows, and all live pages.

Ordinary admitted IDs remain at most 128 bytes. Unrelated retained IDs may use the existing 16-KiB
value allowance. Equivalent whitespace-expanded schema SQL is accepted within the physical limits.
Oversized physical records are rejected, not repaired.

### Derive the page count

Overflow pages have 4,092 usable bytes. An overflowing record retains at least 489 bytes locally.
For `N > 0` records:

| Tree component                   | Bound               | Reason                                                      |
| -------------------------------- | ------------------- | ----------------------------------------------------------- |
| Table overflow                   | 16 pages per record | `ceil((65536 - 489) / 4092)`                                |
| Table b-tree                     | `2*N - 1` pages     | Nonempty leaves and at least two children per internal node |
| Index overflow                   | 4 pages per record  | `ceil((16397 - 489) / 4092)`                                |
| Index b-tree                     | `N` pages           | Each nonempty page holds at least one distinct index cell   |
| Schema and empty operation roots | 76 pages            | 64 schema overflow + 8 schema b-tree + 4 empty roots        |

Combining the table and index bounds gives:

```text
live pages <= 23 * retained identities + 76
at 504 IDs: 23 * 504 + 76 = 11,668 pages
```

That is below the 16,128-page retained budget. The bound covers accepted layouts after growth, not
only newly created files. Integrity checking identifies genuinely free pages. Orphan pages do not
count as completion space.

Owned inserts and updates retain the 64-KiB encoded write limit. Inserts create one bounded
canonical index record. Updates change neither indexed identity nor rowid. Neither changes schema,
and SQLite balancing preserves nonempty trees. Writable and read-only reopening both repeat the
physical checks. The statement-preparation and replacement-path premises live beside the
[capacity implementation](../../src/gateway/journal/capacity.rs). Those assumptions do not apply to
arbitrary SQL.

## Bound temporary page allocation

A replacement can allocate its new record before freeing the old one. Tree balancing may also need
new pages. Counting only the final layout would miss that temporary demand.

The [owned-write premises](../../src/gateway/journal/capacity.rs) restrict SQL to one table/index
insertion or one single-row table replacement, with no extra tree mutation pass. The replacement
path permits one new record chain and one balancing pass. The old chain is already counted in the
retained layout. Charging it again would count existing pages as new allocation.

The conservative allocation allowance is:

| Component                       | Allowance                               |
| ------------------------------- | --------------------------------------- |
| Balancing destinations per tree | 20 groups × 5 pages                     |
| Root deepening per tree         | 1 copied page                           |
| New overflow chain per tree     | 17 pages                                |
| Two trees combined              | `2 * (20 * 5 + 1) + 2 * 17 = 236` pages |

Five destination pages cover both non-root balancing, which reuses old siblings before allocating,
and quick balancing, which needs one new sibling. The 20 groups cover at most 19 original non-root
levels plus a child group created by root deepening. That child's at-most-five destinations need at
most four root separators. Those fit a 4-KiB root, so no second deepening pass follows.

Root collapse and discarded siblings free pages. Balancing transfers existing overflow pointers,
rather than making another payload chain. The 17-page chain allowance exceeds both physical maxima
of 16 table overflow pages and four index overflow pages. Counting all allocations is conservative
even when a statement reuses pages it just freed.

The 236-page allowance fits the 256-page headroom. The retained live bound plus temporary allocation
also remains below `max_page_count`. SQLite uses freelist leaves and trunks before extending the
file, with no contiguous-space requirement. The owned paths perform no vacuum, schema change or
additional tree allocation. Changing the SQL shape, schema, index or observation fields requires
revalidating both the retained and temporary bounds.

## Bound the main rollback file

The rollback file protects original database pages while a transaction changes them. Its bound is
separate from the number of free database pages.

Every owned write connection disables cache spilling. In pinned SQLite this prevents the dirty-page
stress path from syncing and starting another rollback segment. Ordinary commit calls
`syncJournal(..., 0)`, not the new-header path. The transaction's original-page bitset permits at
most one original image per page, with eight framing bytes. Pages beyond the original database size
need no original image. Sector size is capped at 65,536 bytes.

Allowing two whole sectors for framing and alignment:

```text
16384 * (4096 + 8) + 2 * 65536 = 67,371,008 bytes < 65 MiB
```

This assumes owned single-database transactions: no `ATTACH`/super-journal, no explicit or repeated
savepoint rollback, no continued writes after a failed owned statement, and DELETE/FULL with cache
spilling off.

An implicit statement sub-journal is a separate object. It does not reset the main original-page
bitset or add a main header, but its size is **not** covered by this ceiling. The 65-MiB bound is
not a total temporary-file, process-memory or filesystem-footprint bound. `journal_size_limit` is
not a peak-space guarantee.

## What a maintainer must revalidate

The direct owners are [`capacity.rs`](../../src/gateway/journal/capacity.rs),
[`schema.rs`](../../src/gateway/journal/schema.rs),
[`opening.rs`](../../src/gateway/journal/opening.rs), and the atomic write statements in
[`records.rs`](../../src/gateway/journal/records.rs). Transition policy remains in
[`mod.rs`](../../src/gateway/journal/mod.rs) and [`git.rs`](../../src/gateway/journal/git.rs). The
locked `libsqlite3-sys` 0.38.2 amalgamation supplies SQLite 3.53.2.

| Change                                                           | Argument to revisit                                                               |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| SQLite version/build, opcodes, preparation or register reuse     | Encoded-write checks, replacement path and balancing                              |
| Schema, indexes, triggers, rowid/identity or field bounds        | Record headers, overflow and tree count                                           |
| Accepted layout or opening path                                  | Page size, reserved bytes, occupancy/depth, schema padding and validated freelist |
| Transactions, savepoints, failure continuation, spilling or sync | Temporary allocation and main rollback framing                                    |
| Identity charge, logical limits, headroom or file ceilings       | All three bounds                                                                  |

Spare space in the conservative bound is not permission to raise the 504/32 limits.

## Evidence and its limits

[Accepted-layout tests](qualification.md#accepted-journal-layouts) check physical rejection and
legitimate reopening.
[Storage qualification](qualification.md#bounded-storage-failure-qualification) checks owned write
plans, rollback accounting, last-slot concurrency and full-capacity completion. Its full-capacity
cases cover all nine insertion-order/pending-phase combinations, fragmented 16,384-page files and
exact preservation of other history. The separate tmpfs lane produces real, bounded ENOSPC.

Process-kill tests stop execution before SQL, after SQL but before commit, and after commit. They do
not observe a kill inside SQLite commit. These tests complement the source argument without
measuring a universal allocation peak. Tmpfs exhaustion does not establish disk-backed power-loss
durability, native installed-host behaviour or live Kubernetes results.

A full filesystem, failed sync or lost storage can still prevent completion. An indeterminate commit
still needs a stored read. None of those failures can manufacture a receiver result or grant another
mutation opportunity.
