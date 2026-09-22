# Journal retention and binary replacement

Current Kapsel uses journal format 5. It accepts fresh journals and existing format-5 journals and
rejects every older format unchanged before action processing. There is no migration, downgrade,
pruning, automatic backup, or host-loss recovery protocol.

The [effect-gateway contract](EFFECT_GATEWAY.md) owns durable state and immutable receipts. The
[service operator guide](KAPSEL_SERVICE_OPERATOR.md) owns process retirement, preparation, and
read-first startup. This page owns the operating precautions around retained state.

## Preserve action history

The journal retains original authority, attempted-action history, and exact signed receipt bytes.
Keep that state, its SQLite sidecars, and the operator's original trust and access materials
protected together. Exported receipts may preserve evidence but do not reconstruct no-resend history
or authorize further execution.

Never edit a journal version marker, remove attempted rows, rotate to an empty journal, mint a new
identity, or restore a stale backup as a way to retry an ambiguous operation. A backup predating an
attempt can erase the only local evidence that the effect might have happened. Restoring bytes does
not by itself establish continuity.

## Replace a binary without inventing continuity

1. Identify the exact current binary, journal version, and state location. Retain matching binaries
   and operator materials needed to inspect existing history.
2. Stop new selection and retire the service through its documented lifecycle. Preserve all state;
   do not treat process exit as proof that an external effect failed.
3. Authenticate the replacement artifact and check its documented journal compatibility before
   activation. Unsupported journals must remain unchanged under their matching binary.
4. Start read-first and inspect retained action identities. Advancement requires explicit selection
   of the same ID under its original authority. Attempted history remains observation-only.

Executable replacement is not a migration or downgrade guarantee. A separate empty installation is
not a continuation of an existing action. If continuity cannot be established, preserve evidence and
stop dependent automation rather than creating another attempt.

## Published older beta

The v0.1.1-to-v0.2.0 backup, migration, rollback, and downgrade procedures apply only to that exact
release pair. Use the
[v0.2.0 tagged upgrade guide](https://github.com/kapsel-cloud/kapsel/blob/v0.2.0/docs/UPGRADE.md)
with matching binaries. Those historical procedures do not apply to format 5.

## Evidence limits

The [journal-version rejection test](BUILD.md#journal-version-rejection) proves older journals
remain unchanged. Current recovery and storage tests establish named process-loss and bounded
storage-failure cases. They do not establish disk-backed power-loss durability, recovery after host
loss, or a safe stale-backup restore procedure. [Testing](TESTING.md) maps the maintained proof.
