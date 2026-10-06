# Journal storage and capacity

This reference defines format-6 journal limits, completion capacity, and safe continuation after
storage failure. The [effect gateway](effect_gateway.md) defines admission and recovery. Operators
should use [storage refusal and repair](../guides/operator.md#storage-refusal-and-repair) when
writes or reads fail. No procedure here authorizes editing retained rows or replaying an attempted
action.

## Journal bounds

| Resource                                                       | Limit                 |
| -------------------------------------------------------------- | --------------------- |
| Retained identities, across both effects                       | 504                   |
| Unfinished identities, across both effects                     | 32                    |
| Main database                                                  | 64 MiB / 16,384 pages |
| Main rollback-journal artifact                                 | 65 MiB                |
| Individual persisted text or blob                              | 16 KiB                |
| Original signed grant                                          | 4 KiB                 |
| Encoded table or schema cell payload, including record headers | 64 KiB                |
| Encoded primary-index cell payload                             | 16,397 bytes          |
| Accepted b-tree depth                                          | 20 pages              |

Terminal work releases an unfinished slot, never its retained identity or original evidence.
Exporting a receipt releases neither limit. There is no supported pruning, reset, stale-state
restore or limit-raising recovery command.

The implementation uses SQLite's rollback journal with `synchronous=FULL` and verifies both settings
whenever it opens the journal. Files are exact mode `0600` and their parent is exact mode `0700`.
Larger, permissive, linked, or replaced artifacts fail before SQLite reads or recovery. SQLite's
per-value-or-row write allocation limit is 64 KiB. That setting alone does not bound existing
records on read. Every reopen separately checks physical encoded payloads through bundled SQLite's
`dbstat` metadata, plus retained/unfinished capacity, before loading operations. These caps bound
integrity checking and persisted allocation even for malformed owner-controlled journals. They do
not reserve filesystem space or promise retention after storage loss.

Format 6 requires two exact typed tables. `kubernetes_image_operations` retains Kubernetes facts.
`git_ref_operations` stores Git authority, acknowledgement and ref observations. Both share the
journal, worker lease, identity namespace and aggregate limits. Cross-table identity collisions are
refused. Both appear in retained history through the caller interface. Existing format-6 journals
reopen without rewriting schema, rows or version. Older formats are rejected unchanged, with no
migration or silent recreation.

## Completion accounting

### Configured completion guarantee

Accepting an operation means taking responsibility for finishing its record. The journal therefore
leaves room for completion before admitting more work. Admission must leave configured SQLite
capacity to finish already admitted work. This protects against the configured page ceiling. It does
not protect against a full filesystem, failed storage device or unsuccessful execution:

- Logical limits bound retained identities and unfinished responsibility.
- Physical layout validation and owned-write bounds establish that completion fits the configured
  page ceiling, including transient allocation and the main rollback-file ceiling.
- External ENOSPC, I/O or sync failure, storage loss and indeterminate commits remain operating
  failures. Page accounting cannot resolve commit ambiguity.

For example, admission at 503 retained identities and 31 unfinished actions can accept one more
identity. The worker-excluded path checks capacity and inserts original authority in the same
immediate transaction. Confirmed admission leaves 504 retained identities and 32 unfinished actions.
Another new identity is refused. The last admitted action can still record its attempt, freeze
receiver facts, and commit its receipt through the owned writes. This remains true for accepted
fragmented, full-length database files: completion needs reusable pages, not contiguous space or a
shorter file. Existing-identity lookup precedes new-work refusal.

Finalization releases one unfinished slot, but a 505th identity remains refused. Attempt recovery
never dispatches again. Receipt completion uses frozen observations and preserves an already
committed original receipt. Freeing filesystem space cannot repair a configured SQLite ceiling.

### Physical bound

Each identity is charged 32 pages (128 KiB), regardless of phase or actual payload. Another 256
pages (1 MiB) provide shared transient-completion headroom. The charge never shrinks. Format 6 uses
4 KiB pages, no reserved page bytes, no auto-vacuum and one primary index per typed table.

[Why admitted work fits the journal](../contributing/storage_capacity.md) explains the
accepted-layout, transient-allocation and main rollback-file arguments. It includes the exact SQLite
assumptions and what maintainers must recheck when they change the implementation. Its source
argument and tests must be revalidated when those premises change. Finite tests alone do not
establish a universal allocation bound. The 65-MiB ceiling covers only the main rollback file, not
total temporary-file, memory or filesystem footprint.

## Storage failure and commit alternatives

New-work capacity refusal is definite `NOT_ADMITTED / CAPACITY`. Filesystem exhaustion or a failed
write is not that refusal. Before admission acknowledgement, any storage error leaves acceptance
unconfirmed. Read the same identity after repair. Never substitute a replacement identity.

The fault tests map interrupted writes to these stored alternatives:

| Interrupted boundary                   | Possible retained state                                         | Safe continuation                                                                                            |
| -------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| First admission transaction            | No row, or `requested` with exact original grant                | Inspect the same ID after storage repair; no receiver call preceded this commit.                             |
| Authorization or pre-attempt rejection | Previous phase, or complete next phase                          | Reauthenticate original authority; repeat only safe preflight reads if needed.                               |
| Attempt commit                         | `authorized`, or `apply_started`                                | Only a confirmed fresh commit issues dispatch permission. Attempted history never issues another permission. |
| Apply-response or receiver-facts write | Previous attempted facts, or complete newly frozen facts        | Observe only if facts are not frozen. Never resend.                                                          |
| Receipt transaction                    | `receiver_observed`, or `finalized` with original receipt bytes | Complete frozen facts or retrieve committed bytes; no new receiver calls.                                    |

Each transaction retains either its previous facts or the complete next state under the documented
SQLite/filesystem assumptions. An error alone cannot identify which alternative survived. Injected
acknowledgement-loss tests exercise the alternatives. Process kills do not test power-loss behaviour
or show a kill inside SQLite commit. Actual bounded tmpfs ENOSPC covers admission, receipt SQL and
receipt commit separately. The first-admission row describes Kubernetes. Git first records
`authorized` with its original grant.

Writable startup and cold validation refuse absent database history when a worker lock or SQLite
sidecar survives. Writable startup also refuses an empty database with those artifacts. They do not
create a replacement database. Missing-history, invalid/unsupported-history and unavailable-storage
operator codes remain distinct. Caller wire errors retain `operation_failure`. A genuinely fresh,
safe directory can initialize storage. Complete removal of every artifact cannot be distinguished
from a fresh install. The operator must preserve custody and continuity. Exported receipts cannot
reconstruct no-resend history.

Use the [operator repair stop point](../guides/operator.md#storage-refusal-and-repair). Restoring
storage availability is not permission to change retained facts. There is no backup-restoration or
host-loss recovery protocol.
