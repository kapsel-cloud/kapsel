# Upgrade, backup, rollback, and downgrade

Status: active v0.2 beta operator contract.

Kind: guide and compatibility contract. Authority: the supported `v0.1.1` to v0.2 private-journal
upgrade, backup, restore, rollback, and downgrade procedure.

Owns: Required offline backup names and integrity, first-open recognition, failure handling, restore
cleanup, and the exact `v0.1.1` downgrade decision.

Does not own: Internal SQL or fixture construction, another release pair, release installation, or
Kubernetes lifecycle and receipt meaning.

See [Evaluator commands](COMMANDS.md) for the unchanged command grammar, [MCP](MCP.md) for EOF
shutdown, and [Build](BUILD.md#upgrade-and-rollback-fixture-gate) for the focused source-fixture
gate.

## Supported path

This procedure supports an owner-private journal last opened by exact Kapsel `v0.1.1` and the
candidate v0.2 binary on x86-64 GNU/Linux. The operation schema is identical between those versions,
so the upgrade does not transform operation rows or receipt facts. The v0.2 opener records one
private format marker after recognizing the store. It does not add a command or change the adopted
`provision-grant`, `operate`, `inspect`, or `mcp` grammar.

The marker changes database bytes, so an existing unmarked store requires a verified backup even
though its operation rows need no migration. A newly created empty journal initializes directly.

## Before the first v0.2 open

Finish or stop every Kapsel CLI and MCP process that uses the journal, and prevent a supervisor from
restarting one. There must be no open SQLite connection, provider work, receipt publication, or
backup writer. The journal's immediate parent must remain an owner-owned mode-0700 real directory;
this private-parent boundary prevents another OS user from replacing its entries. Kapsel detects a
simple pathname replacement but does not claim defense against a malicious same-owner ABA sequence.

Run the following fail-fast block with GNU coreutils while Kapsel remains stopped. Replace only the
first path. It requires exact owner, mode, link-count, sidecar, and digest syntax and creates both
artifacts without following or clobbering an existing or dangling-symlink name.

```bash
set -eu
set -C
journal=/absolute/operator/path/journal.sqlite3
parent=$(dirname -- "$journal")
backup="${journal}.kapsel-v011.backup"
checksum="${backup}.sha256"
owner=$(id -u)

require_private_file() {
  test ! -L "$1"
  test "$(stat -c %F -- "$1")" = "regular file"
  test "$(stat -c %u -- "$1")" = "$owner"
  test "$(stat -c %a -- "$1")" = 600
  test "$(stat -c %h -- "$1")" = 1
}
require_private_directory() {
  test ! -L "$1"
  test "$(stat -c %F -- "$1")" = directory
  test "$(stat -c %u -- "$1")" = "$owner"
  test "$(stat -c %a -- "$1")" = 700
}
digest_of() {
  value=$(sha256sum -- "$1")
  value=${value%% *}
  test "${#value}" -eq 64
  case "$value" in *[!0-9a-f]*) return 1 ;; esac
  printf '%s' "$value"
}

require_private_directory "$parent"
require_private_file "$journal"
for sidecar in "${journal}-journal" "${journal}-wal" "${journal}-shm"; do
  test ! -e "$sidecar" && test ! -L "$sidecar"
done
test ! -e "$backup" && test ! -L "$backup"
test ! -e "$checksum" && test ! -L "$checksum"

umask 077
: >"$backup"
chmod 600 "$backup"
cp --reflink=never -- "$journal" "$backup"
require_private_file "$backup"
source_digest=$(digest_of "$journal")
backup_digest=$(digest_of "$backup")
test "$source_digest" = "$backup_digest"

: >"$checksum"
printf '%s\n' "$backup_digest" >|"$checksum"
chmod 600 "$checksum"
require_private_file "$checksum"
test "$(wc -c <"$checksum")" -eq 65
IFS= read -r recorded_digest <"$checksum"
test "$recorded_digest" = "$backup_digest"
sync "$backup" "$checksum"
sync -f "$parent"
```

Do not hard-link any artifact. Keep the backup, sidecar, active journal, worker lock, and receipt
directory owner-private. Receipt files are not copied or moved by this journal procedure; their
absolute paths and exact bytes remain authoritative.

## Migration-only first open and reopen

Do not use `operate` for either initial open: it can submit or reconcile an operation immediately.
Instead, close MCP stdin without sending an initialization or tool frame. MCP constructs the
application before reading stdin and then exits successfully on clean EOF, so these commands cross
journal open without lifecycle work:

```bash
set -eu
kapsel=/absolute/path/to/v0.2/kapsel
operator_config=/absolute/path/to/operator.json
"$kapsel" mcp --operator-config "$operator_config" </dev/null
"$kapsel" mcp --operator-config "$operator_config" </dev/null
```

Both invocations must exit zero, produce no stdout, and emit no diagnostic. Only after both succeed
may the operator resume the ordinary documented `operate` command or an initialized MCP tool call.
Keep the backup and sidecar through the rollback window.

Before its marker transaction, the opener rejects WAL or another unsupported database mode without
checkpointing it, configures and verifies rollback-journal `DELETE` plus `synchronous=FULL`,
verifies an unmarked source and backup, takes exclusive SQLite ownership, rechecks the source
digest, runs the full structural integrity check, and recognizes the complete owned layout.
Recognition includes the normalized owned table definition, every ordinary/hidden column fact, the
exact implicit primary-key index, and absence of another table, view, trigger, or index. The marker
and any pre-existing private legacy maintenance then commit in one transaction. Exact `v0.1.1` rows
require no data migration.

Slice 2 proves completed first open and idempotent reopen for every historical fixture. SQLite
transaction design makes an interrupted commit recover as old or new, but KAP-0060 Slice 3 owns real
subprocess loss before, during, and after the marker and restore. No Slice 2 result is process-loss
proof.

Normal fixture opens preserve every lifecycle state, authorization and receiver fact,
provider-call-count fact, receipt byte, absolute path, digest, signing-key identity, and retained
receipt-v2 inspection meaning. Upgrade does not call Kubernetes or re-sign a receipt.

## Bounded failures

CLI and MCP retain their bounded configuration or operation failure classes; they do not print SQL,
database contents, receipt bytes, signing material, or new path details. If the migration-only MCP
command fails, stop and use these offline checks rather than `operate`:

- **Missing, permissive, symlinked, multiply linked, malformed, or mismatched artifact:** preserve
  the active source. Remove only the rejected backup pair you created, then repeat the stopped,
  fail-fast backup block from the unchanged source.
- **Source changed after backup:** stop the writer, remove the rejected backup pair, and repeat the
  complete offline procedure. Do not keep retrying the opener.
- **SQLite sidecar or WAL/unsupported mode:** do not delete or checkpoint it speculatively. Let the
  exact binary that created the state recover it, stop that binary cleanly, and begin again.
- **Integrity or exact-layout refusal:** preserve the journal, backup, digest, receipts, and worker
  lock. Do not edit database or receipt bytes.
- **Unknown or newer marker:** the candidate refuses before SQLite mutation. Use the matching newer
  binary or a backup proven to belong to this journal generation; never reset the marker.

A failed open does not authorize Kubernetes work, another mutation, receipt reconstruction, or
receipt movement.

## Restore and failed-upgrade rollback

Restore is supported only when the first v0.2 open failed and no later lifecycle work occurred. If
v0.2 advanced an operation or published a receipt, do not restore an older generation: use the
direct downgrade below or continue with v0.2.

Stop Kapsel and supervisor restarts. Require all three SQLite sidecars to be absent; if one exists,
recover and stop the exact creating binary rather than deleting it. The following fail-fast block
revalidates the backup pair, prepares and verifies a distinct replacement, copies and synchronizes
the still-active generation into a new quarantine, and finally atomically renames the prepared file
over the still-present active journal. There is no missing-active-path window.

```bash
set -eu
set -C
journal=/absolute/operator/path/journal.sqlite3
parent=$(dirname -- "$journal")
backup="${journal}.kapsel-v011.backup"
checksum="${backup}.sha256"
restore="${journal}.restore.$$"
quarantine="${journal}.quarantine.$(date +%s).$$"
quarantined="$quarantine/journal.sqlite3"
quarantined_checksum="$quarantine/journal.sqlite3.sha256"
owner=$(id -u)

require_private_file() {
  test ! -L "$1"
  test "$(stat -c %F -- "$1")" = "regular file"
  test "$(stat -c %u -- "$1")" = "$owner"
  test "$(stat -c %a -- "$1")" = 600
  test "$(stat -c %h -- "$1")" = 1
}
require_private_directory() {
  test ! -L "$1"
  test "$(stat -c %F -- "$1")" = directory
  test "$(stat -c %u -- "$1")" = "$owner"
  test "$(stat -c %a -- "$1")" = 700
}
digest_of() {
  value=$(sha256sum -- "$1")
  value=${value%% *}
  test "${#value}" -eq 64
  case "$value" in *[!0-9a-f]*) return 1 ;; esac
  printf '%s' "$value"
}

require_private_directory "$parent"
require_private_file "$journal"
require_private_file "$backup"
require_private_file "$checksum"
test "$(wc -c <"$checksum")" -eq 65
IFS= read -r recorded_digest <"$checksum"
case "$recorded_digest" in *[!0-9a-f]*) exit 1 ;; esac
test "${#recorded_digest}" -eq 64
test "$recorded_digest" = "$(digest_of "$backup")"
for sidecar in "${journal}-journal" "${journal}-wal" "${journal}-shm"; do
  test ! -e "$sidecar" && test ! -L "$sidecar"
done
test ! -e "$restore" && test ! -L "$restore"
test ! -e "$quarantine" && test ! -L "$quarantine"

umask 077
: >"$restore"
chmod 600 "$restore"
cp --reflink=never -- "$backup" "$restore"
require_private_file "$restore"
test "$(digest_of "$restore")" = "$recorded_digest"
cmp -s -- "$backup" "$restore"
sync "$restore"

mkdir -m 700 -- "$quarantine"
require_private_directory "$quarantine"
: >"$quarantined"
chmod 600 "$quarantined"
cp --reflink=never -- "$journal" "$quarantined"
require_private_file "$quarantined"
active_digest=$(digest_of "$journal")
test "$(digest_of "$quarantined")" = "$active_digest"
: >"$quarantined_checksum"
printf '%s\n' "$active_digest" >|"$quarantined_checksum"
chmod 600 "$quarantined_checksum"
require_private_file "$quarantined_checksum"
sync "$quarantined" "$quarantined_checksum"
sync -f "$quarantine"

require_private_file "$journal"
test "$(digest_of "$restore")" = "$recorded_digest"
mv -T -- "$restore" "$journal"
require_private_file "$journal"
test "$(digest_of "$journal")" = "$recorded_digest"
sync "$journal"
sync -f "$parent"
sync -f "$quarantine"
```

Do not move or delete the receipt directory. Keep quarantine until the restored generation passes
the two migration-only MCP opens and expected operation/receipt inspection. If any step before
`mv -T` fails, the active pathname remains the old generation. The rename itself is namespace
atomic, but Slice 3 still owns subprocess interruption and restart evidence for this protocol.

## Downgrade to exact v0.1.1

The exact `v0.1.1` source at commit `ad799b39112ccd6ef06e1ec954c615b6635650f6` can directly reopen
the v0.2-marked store because this release pair has the same operation schema and lifecycle and
receipt semantics. The normal-open matrix proves that the exact old opener preserves database bytes
at every durable state, including both `apply_started` provider-call facts.

Stop v0.2 cleanly, preserve the backup pair, and start only exact `v0.1.1` against the same active
journal and receipt paths. Do not run both versions concurrently. This applies only to this exact
release pair. Downgrade never reverses a Kubernetes effect or authorizes a provider retry.

## Exact cleanup

After the rollback window and successful inspection, stop Kapsel. Remove only the named artifacts
from the procedure and synchronize their parent. Retaining them offline is safer.

```bash
set -eu
journal=/absolute/operator/path/journal.sqlite3
parent=$(dirname -- "$journal")
backup="${journal}.kapsel-v011.backup"
checksum="${backup}.sha256"
rm -- "$backup" "$checksum"
sync -f "$parent"
```

After the active generation and receipt references are verified, remove one known quarantine with:

```bash
set -eu
journal=/absolute/operator/path/journal.sqlite3
parent=$(dirname -- "$journal")
quarantine=/absolute/operator/path/journal.sqlite3.quarantine.EXACT-NAME
rm -- "$quarantine/journal.sqlite3" "$quarantine/journal.sqlite3.sha256"
rmdir -- "$quarantine"
sync -f "$parent"
```

The focused tests prove completed SQLite transactions and normal source-built opens on the local
host. They do not prove Slice 3 process-loss seams, arbitrary filesystem or hardware flush
correctness, sudden power loss, a live copy, a moved receipt directory, a downloaded artifact,
another release pair, or restoration after lifecycle advancement.
