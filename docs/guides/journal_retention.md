# Preserve operation history

The journal is part of Kapsel's execution boundary, not a disposable cache. It retains original
authority, attempted-operation history, and exact signed receipt bytes. Use this checklist when
stopping the service, changing storage or removing executables. The
[operator guide](operator.md#stop-replace-or-remove-executables) gives the procedure. The
[effect gateway](../reference/effect_gateway.md) defines durable state and immutable evidence.

## Keep state and authority together

Preserve the journal, SQLite sidecars, locks, and the operator's original trust and access materials
under private custody. Exported receipts preserve evidence but cannot reconstruct no-resend history
or authorize further execution. Consistent backups must preserve action history and receipt bytes
together. Kapsel supplies no backup-restoration or host-loss recovery protocol.

Consider a backup taken before `apply_started`. Kapsel later records the attempt and sends the
change, then the host loses its current journal. The backup still says the operation has not been
attempted. Restoring it could make an already sent change appear eligible to send again. A valid
SQLite file can still be the wrong history.

Never edit a format marker, remove attempted rows, rotate to an empty journal, mint a new identity,
or restore a stale backup to retry an ambiguous operation. Restoring bytes does not establish
continuity. A separate empty installation cannot continue an existing action.

## Stop and restart safely

1. Stop new selection and retire the service through its documented lifecycle. Preserve all state.
   Process exit does not prove that an external effect failed.
2. Make only the authorized configuration, material or executable change. Retain roots, identity,
   original grants, historical trust and evidence. Do not bypass lifecycle locks.
3. Start read-first and inspect the original operation IDs. Advancement requires explicit selection
   of the same ID under its original authority. Attempted history remains observation-only.

Current binaries accept journal format 6 and reject older formats unchanged before processing. There
is no migration, downgrade or cross-version support promise. If a binary refuses history, preserve
exact bytes and stop. Do not edit the database or create replacement history to make it start. Use
the original binary for inspection where necessary, not as permission to resume mutation.

If continuity cannot be established, preserve evidence and stop dependent automation. The
[storage repair stop point](operator.md#storage-refusal-and-repair) applies even when a fresh
startup would otherwise succeed.
