# Kubernetes effect-gateway contract

## SQLite-owned receipt completion

Receipt completion commits the original signed evidence in SQLite, independently of export.
`receiver_observed` durably freezes the historical receiver statement before signing. One
conditional SQLite transaction commits the exact signed receipt bytes, their SHA-256 digest, signer
identity, and terminal `finalized` state together. `finalized` means durable terminal evidence, not
an installed filesystem copy. Recovery before that commit signs only frozen facts. A signing failure
leaves the observation unchanged, and commit acknowledgement loss is resolved by reading durable
state rather than dispatching or observing again.

Journal format 5 retains the original signed authorization grant at first insertion. Fresh journals
and existing format 5 journals are accepted. Format 4 and older versions are rejected unchanged
before action processing, without migration. Preserve their journal, sidecars and access materials
under the matching binary. A fresh journal is not continuity or permission to recreate old actions.
Receipt v2/v3, grant v1/v2, trust, exact approval, and observation-only recovery semantics remain
unchanged.

Filesystem export is separate from execution. CLI and MCP adapters export committed bytes to their
configured directory for their existing filename response. Export failure cannot reopen the
finalized action or prevent later application/service retrieval. The service does not require an
installed receipt copy. Supplementary observations, if separately implemented, must bind the
operation identity and original receipt SHA-256 without modifying the original receipt or result.

Receipt retrieval depends on database availability. Consistent operator-owned backups must preserve
receipt bytes and action history together. Exported copies may survive database loss, but execution
does not guarantee creating them. No automatic backup or replication protocol is provided. SQLite
rollback-journal/FULL settings, private storage, and allocation bounds remain. Process-exit tests do
not prove power-loss behavior or the filesystem and hardware assumptions of
[SQLite atomic commit](https://sqlite.org/atomiccommit.html).

Status: current execution contract. The published preview pins its exact source and artifact bytes.

This contract owns one operation's authorization, durable lifecycle, receiver observation, result
meaning, receipt bytes, and demonstration. It does not define a generic agent runtime, MCP or
Kubernetes protocol semantics, reusable provider seam, stable package format, external witnessing,
or production assurance.

## Short answer

An agent may request one bounded operation. The gateway verifies an owner-signed, fixed-purpose,
single-operation grant against application-configured trust, durably records the target and attempt,
issues at most one conditional mutation request, observes the receiver, reconciles after a crash,
and emits an inspectable receipt whose classifier inputs can be recomputed offline.

```text
agent intent
  -> owner-signed exact grant under application-configured trust
  -> durable pre-attempt rejection or target identity
  -> Kubernetes deployment-image request when eligible
  -> rollout observation or bounded unknown
  -> signed, classifier-complete receipt
```

The receipt preserves the execution account. It is not a compliance product, evidence of complete
capture, or a claim that a signature proves the Kubernetes state was true. Signatures allow a
consumer with separately appointed trust to authenticate portable bytes and reject tampering. They
do not add receiver knowledge or establish decision quality. The signed grant and receipt remain
part of the current contract.

## One capability

Kapsel accepts only `kubernetes.set_deployment_image` with:

- Kubernetes namespace;
- deployment name;
- container name; and
- immutable OCI image digest.

Authorization binds all four values and one stable local operation identity. The current
implementation uses this deliberately narrow input grammar:

- operation and authorization identities are 1–128 ASCII bytes containing only letters, digits, `.`,
  `_`, `:`, or `-`;
- namespaces are 1–63 byte lowercase Kubernetes DNS labels;
- deployments are 1–253 byte lowercase Kubernetes DNS subdomains whose labels are each at most 63
  bytes;
- containers are 1–63 byte lowercase Kubernetes DNS labels; and
- the image is at most 512 ASCII bytes and has the exact form
  `<named-image>@sha256:<64-lowercase-hex>`. The named image is slash-separated lowercase components
  that begin and end with an ASCII letter or digit and contain only letters, digits, `.`, `_`, or
  `-`. This bounded grammar excludes tags, registry ports, tag-plus-digest forms, digest-only
  values, empty components, and uppercase spelling even where a wider ecosystem grammar may allow
  them.

No wildcard namespace, deployment, container, tag, shell command, manifest, arbitrary patch, or
second Kubernetes operation is in scope. The logical ceiling is 10,000 distinct identities, but
format-5 completion accounting limits admission to 504 retained identities and 32 unfinished
identities. An existing identical identity remains readable and idempotent at either limit. The
owner-signed grant carries one bounded authorization identity and an exact copy of the operation
identity, namespace, deployment, container, and image. It has no wildcards, policy rules, ambient
lookup, or expiry semantics. Each application-configured grant trust appointment contains one exact
signing-key identity and Ed25519 verifying key. CLI/MCP retain one appointment. The service
application accepts at most 128 appointments with unique key IDs. An empty set permits opening safe
storage but cannot authenticate retained actions. The gateway accepts only the fixed effect-gateway
grant purpose, persists the signer identity and SHA-256 digest of the exact signed grant bytes, and
does not accept trust from the request or grant.

The release-owned demonstration uses a local `kind` cluster. It does not require a cloud account,
hosted Kapsel service, or production credentials.

## Exact-snapshot approval

An approval for one object version must not become authority over a later object. Grant v2 binds
`approved_target`, the Deployment UID and opaque resourceVersion independently acquired by the
operator, in addition to the exact v1 authorization tuple. Each value is 1–128 ASCII bytes. Equality
is byte-for-byte, with no numeric interpretation, normalization, or refresh. Kubernetes assigns
[UIDs](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids) to distinguish
recreated objects. Its
[conditional updates](https://v1-33.docs.kubernetes.io/docs/reference/using-api/api-concepts/#patch-and-apply)
use resourceVersion to reject intervening writes.

Grant v2 uses `KAPSEL-KAP0038-K8S-GRANT-STATEMENT-V2\0` and `KAPSEL-KAP0038-K8S-GRANT-V2\0`, with
purpose `kapsel.kap0038.kubernetes-set-deployment-image-grant.v2`. Statement fields 1–6 retain their
v1 order. Fields 7 and 8 are approved UID and resourceVersion. Envelope order and signature
construction are unchanged. The 2 KiB statement, 4 KiB grant, 512-byte individual text, strict
record ordering, and existing identity/trust bounds remain. Mixed envelope/statement versions fail
closed.

Resident service execution requires v2. Read-first startup may authenticate retained v1 history
without allowing v1 selection or advancement. Legacy CLI/MCP paths still accept v1 with its original
late-bound meaning. Every path accepting v2 enforces the snapshot. Neither existing grant bytes nor
existing operation handles can acquire snapshot authority. Reapproval needs an operator-created
grant and a new handle. It is not an automatic retry after `UNKNOWN`.

`kapsel provision-snapshot-grant` uses the existing operator authorization JSON (no UID or version
fields), signing seed, key ID and output arguments, plus an explicit private `--kubeconfig`. It
validates the tuple, reads the named Deployment through the bounded production adapter, validates
the named container, and signs the independently read UID/version. It accepts no caller-supplied
snapshot bytes. The operator owns the proposal file, credentials, invocation and output. Acquisition
has the existing ten-second deadline and 2 MiB response cap. No snapshot document format or second
authority store is introduced.

Before `apply_started`, a successful target read supplies `observed_target`, distinct from approval.
Mismatch durably freezes `NOT_ATTEMPTED / STALE_APPROVAL`, including that observed target, without
attempt, receiver result, effect receipt, or signed denial artifact. Other permanent read rejections
retain their meanings and have no observed target. A matching read freezes `attempt_target` using
the approved values, never substituted fresh values. The actual strategic merge PATCH includes both
approved UID and resourceVersion. An intervening conflict after the marker is still an attempted
path, never `NOT_ATTEMPTED`. The marker does not establish network transmission. Recovery after it
only observes and never resends.

Journal format 5 retains nullable approved UID/version and preflight observed UID/version columns.
Legacy-grant actions have null approval and retain their original meaning. Older journal versions,
including the former format-3 snapshot layout, are rejected without migration before processing. New
requests atomically retain the exact signed grant bytes with original grant identity, signer, digest
and snapshot at their first durable insertion, including the requested window. Stored bytes never
appoint trust. Authorized reads and identical submission compare original bytes and provenance in
the same SQLite snapshot. Snapshot authority never replaces authority on an existing row.

`approved_target` is the signed approval or null for legacy authority. `attempt_target` is the
frozen PATCH precondition pair or null before the marker. `observed_target` is the successful
preflight read before the marker, and the frozen receiver UID/version once receiver observation is
complete (either member may be absent). These projections disclose bounded public identity/version
facts, not grant bytes, trust, credentials or paths. No observation is invented for a rejection
without a successful read. Status is read-only and projects these facts alongside the disposition.

Snapshot attempts emit receipt/statement v3 with magic prefixes ending `RECEIPT-V3\0` and
`STATEMENT-V3\0`, and purpose `kapsel.kap0038.kubernetes-effect-receipt.v3`. Fields 1–27 retain
their v2 meaning. Fields 28–29 contain approved UID/version. Fields 10–11 are `attempt_target`,
which must exactly equal approval. Fields 12 and 18 are `observed_target`, not approval. Receipt and
statement bounds do not change. Trust v2 remains the trust encoding but must explicitly appoint the
v3 purpose for snapshot receipts. Old receipt v2 remains inspectable under its original purpose,
with null approval, never invented snapshot evidence. Legacy actions still emit v2. Frozen bytes are
never re-signed or upgraded. The sections below describe the unchanged legacy v1 grant/v2 receipt
wire where not explicitly extended here. The older beta remains pinned to its tagged contract.

## Service admission and historical authority

The service application resolves a caller-selected ID against retained original authority first,
then the bounded operator catalog only if no record exists. Retained bytes do not appoint a key. The
gateway loads retained bytes, authenticates under external appointments and compares provenance and
lifecycle facts within one SQLite read snapshot. Advancement carries the original authorization
binding through continuation reloads and rechecks custody after receiver I/O before recording
returned facts. The worker lease does not authorize direct SQLite edits. Missing required trust
fails for that ID, without returning its tuple or receipt. It does not hide unrelated
authenticatable history.

Admission is not a receiver operation. A new identity requires a nonwaiting journal worker lease, a
repeated identity check and a capacity-checked first commit containing the original grant. The
acknowledgement callback runs only after confirmed commit or definite busy/capacity refusal. It
reports durable phase, not worker liveness or receiver result. A storage error before that callback
is not definite non-admission. The lease remains owned through acknowledgement and the bounded
advancement pass. It cannot be reacquired through the same journal handle while outstanding.

Identical existing identities resolve before slot/capacity refusal. Terminal selection is read-only.
An unfinished identical selection with a busy worker acknowledges its existing responsibility and
starts no new work. Missing execution material leaves admitted work unfinished. Receipt completion
needs signing material, but stored reads and original receipt retrieval do not. Legacy CLI/MCP
submission and requested-phase authorization behavior remain separate and unchanged.

The socket runtime must preserve task and resource ownership until blocking storage actually stops,
even if a response deadline or disconnect occurs. The application callback alone does not prove that
runtime obligation. No queue, startup selection or new observation policy follows from it.

## Execution guidance, not historical evidence

An admitted action can be unfinished without a running worker. Service status therefore keeps
execution disposition separate from the existing receiver result and immutable target/receipt facts.
The application owns the typed projection. Runtime supplies current-process physical job ownership
and bounded stop conditions. Protocol code only renders that projection.

A current physical job means `active`, including time blocked on storage. It does not promise
progress or receiver availability. Another locally owned job means `waiting_for_worker`. Without
current ownership or a surviving stop explanation, unfinished history means `resume_required` with
an unknown cause. Restart, cancellation and diagnostic eviction never invent a historical cause.
Terminal history always supersedes process diagnostics. Status and process observations are separate
snapshots, not an atomic global liveness oracle. A contending external journal worker can only be
reported from a failed acquisition, not inferred live from durable state.

Safe preflight read failure supports explicit same-ID selection. Missing receiver material, missing
signing material and failed receipt completion require operator remediation before selection.
Receiver errors do not hide authenticated history or force a terminal disposition. Receipt
completion failure preserves frozen facts. The application classifies typed failures without
retaining raw errors. The [service contract](KAPSEL_SERVICE.md#actionable-execution-status) owns
wire tokens, process-local retention and operator diagnostics.

Any authenticated service caller may explicitly select a retained v2 identity through the existing
ID-only submit command, even after catalog removal, provided original external authority remains
available. This grants no new lifecycle authority: the gateway alone decides the safe continuation.
Before attempt, resumption repeats safe reads before a fresh conditional attempt. After attempt it
only observes, or completes frozen facts. Reads never resume, reset an observation budget or change
receipt bytes. No automatic retry, reapproval, new durable diagnostic field, schema change or
reinterpretation of format 5 is introduced. The inert `target_read_failures` column stays inert.

## Operation lifecycle

The journal has explicit local states:

```text
requested
  -> authorized
       -> not_attempted
       -> apply_started
            -> receiver_observed
            -> finalized
```

- `requested` records the bounded input and stable operation identity.
- `authorized` records that the exact request matched an authentic fixed-purpose grant under the
  application-configured owner trust. The signer identity and digest of the exact signed grant bytes
  are frozen.
- From `authorized`, the adapter safely reads and validates the target Deployment and named
  container. A transient API error leaves the selected operation `authorized` without a journal
  update or PATCH. A retry or crash before the next transition repeats only this safe GET before a
  fresh attempt.
- `not_attempted` is terminal and records exactly one bounded pre-attempt rejection:
  `deployment_not_found`, `container_not_found`, `invalid_target`, or `stale_approval`. No mutation
  marker, provider write, receiver observation, receiver result, or effect receipt exists for this
  disposition. It is never reported as receiver `FAILED` or `UNKNOWN`.
- `apply_started` atomically records the target Deployment UID, target resource version,
  write-strategy identity, and attempt marker before Kubernetes mutation. The strategic merge patch
  carries both target preconditions, changes the exact name-keyed container image, and writes the
  operation identity in the `kapsel.dev/kap0038-operation-id` Deployment annotation. Target
  precondition conflicts fail before mutating a different target. A successful patch response must
  return the same Deployment UID and a resource version; missing or replacement identity facts fail
  closed. Recovery from `apply_started` never issues a blind second patch.
- `receiver_observed` records every bounded classifier input and the resulting classification,
  including target and receiver identity, observed image and operation marker, current, requested,
  and observed generations, replica counts, and rollout condition, or explicit missing facts.
- `finalized` atomically commits the exact signed receipt bytes, SHA-256 digest, signing key
  identity, and terminal state in SQLite. It is terminal and read-only. Filesystem export happens
  separately from this transition.

Observation-only recovery determines what can be concluded without sending the mutation again. After
`apply_started`, it uses the stored Deployment UID, operation annotation, and requested image digest
to observe and classify the operation. It does not replay even the frozen conditional patch:
Kubernetes UID and resource-version preconditions bound persisted updates, but do not prevent a
stale replay from invoking mutating admission and its allowed out-of-band effects again. Decision
[0011](decisions/0011-retain-observation-only-recovery.md) owns the comparison and evidence.

When the patch response was lost, an exact matching UID, operation annotation, and image binds the
observed current generation to the request; without all three facts the requested generation remains
unknown. If a later template writer retains those three facts, that generation may satisfy the
classifier, but the result does not attribute that later rollout to the original patch. If the
available receiver facts cannot establish the result, the result is `UNKNOWN`; it is never guessed
from request success or a timeout.

## Durable facts and recovery

| State               | Durable facts written before entering the state                                                                                                                     | Recovery rule                                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `requested`         | Operation identity plus bounded namespace, deployment, container, and image digest.                                                                                 | Re-run validation and grant verification before any Kubernetes call.                                |
| `authorized`        | Authorization identity, exact authorized tuple, grant signer identity, and signed-grant digest.                                                                     | Safely read the selected target again after transient errors; permanent rejection becomes terminal. |
| `not_attempted`     | One bounded permanent target-rejection reason and an explicit zero-attempt disposition.                                                                             | Read-only; do not observe Kubernetes, classify a receiver result, or prepare an effect receipt.     |
| `apply_started`     | Target UID and resource version, write-strategy identity, and attempt marker, atomically committed.                                                                 | Do not blindly patch again. Observe the deployment and classify from receiver facts or `UNKNOWN`.   |
| `receiver_observed` | Target and receiver UID, observed image and operation marker, current/requested/observed generations, resource versions, replica counts, rollout condition, result. | Prepare the receipt from frozen facts only. Do not call Kubernetes to improve the result.           |
| `finalized`         | Exact signed receipt bytes, digest, signing-key identity, and terminal state in one SQLite transaction.                                                             | Read-only. Export the committed bytes separately when requested.                                    |

Execution and receipt completion select only the configured operation identity, with no queue or
fairness guarantee. Journal format 5 requires schema validation of the inert `target_read_failures`
column. Execution neither increments nor uses it, including for retry timing. Existing values remain
untouched, with no migration or reinterpretation of persisted rows.

The implementation explicitly uses SQLite's rollback journal with `synchronous=FULL` and verifies
both settings whenever it opens the journal. The main journal is at most 64 MiB; a rollback-journal
artifact is at most 65 MiB to allow bounded SQLite framing around the owned database pages. Every
persisted text or blob value is additionally at most 16 KiB. SQLite's per-value-or-row write
allocation limit is 64 KiB; that setting alone does not bound existing records on read. Every reopen
separately checks encoded cell payloads, including record headers, through bundled SQLite's `dbstat`
metadata, plus retained/unfinished capacity before operation loading. Original signed grants have
their narrower 4 KiB bound. Files are exact mode 0600 and their parent is exact mode 0700. Larger,
permissive, linked, or replaced artifacts fail before SQLite reads or recovery. These physical and
logical caps bound integrity checking and persisted allocation even when an owner-controlled journal
is malformed; they do not reserve filesystem space or promise retention after storage loss.

### Completion accounting

#### v0.3 disposition

Retain the configured completion-capacity guarantee for v0.3. Admission should not consume the
SQLite capacity needed to finish already admitted work. This is a bounded storage-progress promise,
not a promise that execution succeeds or that storage cannot fail. The existing physical checks, 504
retained-identity limit and 32 unfinished-identity limit remain authoritative. No journal format,
opening compatibility, authority, recovery rule or receipt meaning changes with this decision.

The implementation reviewed is `72bae952ad3f9195ae798440a03170a269f8e801`, including durable
multi-action admission, cold replacement validation and the fixed initial observation policy. The
decision retains the [physical bound](#physical-bound) below rather than replacing it with a
row-count heuristic. Three obligations remain distinct:

- Logical limits bound retained identities and unfinished responsibility. Terminal work releases an
  unfinished slot, never its retained identity or original evidence.
- Physical layout validation and owned-write bounds establish that completion fits the configured
  SQLite page ceiling, including transient allocation and the main rollback-file ceiling.
- External ENOSPC, I/O or sync failure, storage loss and indeterminate commits remain operating
  failures. Page accounting reserves no filesystem space and cannot resolve commit ambiguity.

**At capacity.** Start with 503 retained identities and 31 unfinished actions. Existing-identity
lookup still precedes refusal. For a new exact authorization, the worker-excluded admission path
rechecks identity and uses an immediate SQLite transaction to check capacity and insert the bounded
request with its original signed grant. Confirmed admission leaves 504 retained identities and 32
unfinished actions. Another new identity is refused without acquiring responsibility. The last
admitted action can still commit authorization, the attempt marker, receiver facts and its signed
receipt through the owned single-row writes. The physical argument applies even to a 16,384-page
file with a fragmented, integrity-validated freelist. Completion needs reusable pages, not
contiguous space or a shorter file. Finalization releases one unfinished slot but not a retained
charge, so a 505th identity remains refused. Attempt recovery never dispatches again; receipt
completion uses frozen observations and preserves any already committed original receipt.

**Smallest credible alternative.** Keep SQLite, exact authority, durable admission/attempt
exclusion, frozen evidence, logical 504/32 limits and safe opening refusal, but withdraw the
configured completion-progress promise. Completion would then be allowed to report storage blockage
even when only Kapsel's own page ceiling, rather than the filesystem, prevents progress. That could
remove the transient balancing proof and its opcode qualification. It would not automatically
justify removing physical record checks: accepted pre-existing records also need bounded reading,
and rollback files still need a justified opening ceiling. The alternative is therefore smaller, but
not equivalent.

Under that weaker promise, an acknowledged action could remain unfinished until the operator repairs
storage or a separately designed capacity change becomes available. Freeing disk space does not
repair a configured SQLite ceiling. There is no current supported pruning, journal reset,
stale-state restore or limit-raising recovery command. An attempted action must remain
observation-only, and frozen facts cannot be replaced to make completion easier. Moving this
avoidable failure onto the operator costs more than retaining the bounded proof for one fixed schema
and eight owned write statements. This alternative is not adopted. A smaller equivalent bound would
first have to establish its premises for every accepted layout, including long retained keys, padded
schema records, noncanonical record headers and sparse trees. Successful stress tests or a row limit
alone cannot do that.

**Maintenance obligation.** The journal module keeps this SQLite-specific knowledge private.
Retention adds no interface, dependency, configuration or reservation ledger, and removes no
existing checks. Revalidate the source argument and owning evidence when changing any of these
premises:

- Bundled SQLite version/build, generated write opcodes or statement preparation/register reuse.
  `OP_MakeRecord`'s size check and `sqlite3BtreeInsert`'s replacement/balancing path are part of the
  proof, not a generic guarantee for arbitrary SQL.
- Schema, indexes, triggers, rowid/identity updates, persisted field bounds or observation/receipt
  shape. Encoded record headers and overflow allocation matter, not only logical value lengths.
- Accepted layouts or opening paths, including page size/reserved bytes, auto-vacuum, physical
  payload checks, tree occupancy/depth, schema padding and integrity-validated freelist accounting.
- Transaction shape, savepoints, failure continuation, cache spilling, journal mode or sync
  settings. The pager's original-page bitset, commit framing and sector cap own the main rollback
  bound, not a total temporary-storage or memory bound.
- Logical identity limits, per-identity charge, shared headroom or database/rollback file ceilings.
  Spare space in the present conservative bound is not permission to raise the 504/32 limits.

Format 5 requires the complete recognized table layout, including snapshot columns in their existing
physical order. Existing format-5 journals must remain recognized without rewriting their schema,
rows, or version. Changes to fresh initialization must preserve completion accounting,
accepted-layout checks, and schema-payload bounds.

Owned evidence is in `journal/capacity.rs`, `journal/schema.rs`, `journal/opening.rs` and the eight
write statements in `journal/mod.rs`, under `src/gateway/`. The locked `libsqlite3-sys` 0.38.2
amalgamation supplies SQLite 3.53.2. The [accepted-layout tests](BUILD.md#accepted-journal-layouts)
and [storage qualification](BUILD.md#bounded-storage-failure-qualification) cover physical
rejection, write plans, rollback accounting, last-slot concurrency, full-capacity completion and
bounded failure recovery. They complement source inspection, not a universal peak-allocation
measurement. Disk-backed power loss, native installed-host behavior and live Kubernetes remain
separate evidence, not claims established by this retention decision.

#### Physical bound

Format 5 uses 4 KiB pages, no reserved page bytes, no auto-vacuum and the single existing primary
index. The connection enforces 16,384 pages (64 MiB) with `max_page_count`. Each admitted identity
is charged 32 pages (128 KiB), regardless of phase or actual payload. A further 256 pages (1 MiB)
are held as shared transient-completion headroom. Thus at most 504 identities fit. The charge never
shrinks when an action terminates; there is no pruning or reservation ledger. The same transaction
checks counts and inserts original authority. Existing identity lookup precedes new-work refusal. At
most 32 rows may be `requested`, `authorized`, `apply_started` or `receiver_observed`.

The accepted-layout bound uses pinned SQLite 3.53.2 and its
[file format](https://sqlite.org/fileformat.html#b_tree_pages). In one read snapshot, exact schema
recognition and full integrity checking precede [dbstat](https://sqlite.org/dbstat.html) inspection
of every owned b-tree and overflow page. Table and `sqlite_schema` cell payloads, including encoded
record headers, must be at most 65,536 bytes. Primary-index cell payloads must be at most 16,397
bytes: a retained 16-KiB key, an eight-byte rowid and a five-byte canonical record header fit. The
check measures actual payload, not an assumption that stored encodings are canonical. Ordinary
admitted operation IDs remain at most 128 bytes; unrelated retained IDs may still use the existing
16-KiB value allowance. Equivalent whitespace-expanded schema SQL remains allowed within these
physical limits. Oversized physical records fail without repair or migration.

Every non-root b-tree page must be nonempty. Empty leaf roots are allowed for empty operation trees;
page 1 alone may be an empty internal root of `sqlite_schema`. Tree depth is at most 20 pages.
Metadata must account for exactly the retained table rows, the same number of index cells (including
interior index cells), two schema rows, and all live pages. With 4,092 usable bytes per overflow
page and at least 489 local bytes for overflowing records:

- Each table record needs at most `ceil((65536 - 489) / 4092) = 16` overflow pages. Nonempty leaves
  and at least two children per internal node give at most `2*N - 1` table b-tree pages for `N > 0`.
- Each index record needs at most `ceil((16397 - 489) / 4092) = 4` overflow pages. Every nonempty
  index page holds at least one of the `N` distinct index cells, so there are at most `N` such
  pages.
- The two schema rows need at most 32 overflow pages and four b-tree pages, including page 1's
  possible empty internal root. Two additional empty operation roots cover `N = 0`.

Thus live pages, excluding the integrity-validated freelist, must fit the conservative
`23 * identities + 38` bound. This is at most 11,630 pages at 504 identities, below the unchanged
16,128-page retained charge. Unlike the former `21*N+3` check, these premises bound every accepted
layout after growth, not only its initial size. Owned inserts and updates retain the 64-KiB encoded
write limit using fresh-prepared, single-row statements and dedicated record registers; this does
not generalize to arbitrary SQLite statements or reusable record buffers. Insertion creates one
bounded canonical index record, and updates do not change the indexed identity or rowid. Neither
changes schema. SQLite balancing preserves nonempty trees; physical checks apply again on both
writable and read-only reopening. Orphan pages cannot masquerade as reserved completion space.

**Transient allocation.** The pinned owned SQL consists of one table/index insertion or one
single-row table replacement. Exact schema excludes triggers, foreign keys, additional indexes and
autoincrement tables; updates change neither the indexed identity nor rowid. Their generated plans
have no real deletion, index rewrite or auxiliary mutation pass. SQLite's replacement path creates
at most one new record chain before freeing the old chain, then balances once. The old chain is
already included in starting live pages, not charged again as a new allocation.

For each of the two trees, conservatively allow five destination pages per balancing group. This
covers non-root balancing (which reuses old siblings before allocating) and quick balancing (one new
sibling). At most 19 original non-root levels plus one child group after root deepening are visited;
root deepening adds one copied page. That child group's at-most-five destinations require at most
four root separators, which fit a 4-KiB root, so it does not cause another deepening pass. Root
collapse and discarded siblings free pages; balancing transfers existing overflow pointers rather
than creating another payload chain. Allowing 17 new overflow pages for each tree is looser than the
physical 16/4 maxima above. Thus `2 * (20 * 5 + 1) + 2 * 17 = 236` additional pages fits the
unchanged 256-page headroom. This counts all allocations conservatively, even when freed pages can
be reused within the statement. The accepted live bound plus this transient allowance stays below
`max_page_count`. The allocator uses freelist leaves and trunks before extending, without a
contiguous-space requirement. There is no vacuum, schema change or additional tree allocation in
these operation paths. A new SQL shape, schema, index or observation field must revalidate both
arguments.

**Main rollback file.** Cache spilling is disabled on every owned write connection. In pinned SQLite
this suppresses the dirty-page stress path that could sync and start another rollback segment.
Ordinary commit calls `syncJournal(..., 0)`, not the new-header path. A transaction's original-page
bitset admits at most one original image per page, with eight framing bytes; new pages beyond the
original database size do not need original images. Sector size is capped at 65,536 bytes. Including
two whole sectors for framing/alignment gives `16384 * (4096 + 8) + 2 * 65536 = 67,371,008` bytes,
below 65 MiB.

This main-file argument assumes the owned single-database transactions: no `ATTACH`/super-journal,
no explicit or repeated savepoint rollback, no continued writes after a failed owned statement, and
DELETE/FULL with cache spilling off. SQLite may use an implicit statement sub-journal; that is a
separate object, does not reset the main original-page bitset or add a main header, and is **not**
covered by the 65-MiB main rollback ceiling. The ceiling is not a bound on total temporary-file,
process-memory or filesystem footprint. `journal_size_limit` is not used as a peak-space guarantee.

The [storage qualification lane](BUILD.md#bounded-storage-failure-qualification) complements these
source-backed bounds with all nine insertion-order/pending-phase combinations at 504 retained
identities, fragmented 16,384-page files, exact history preservation and real bounded tmpfs ENOSPC.
Process kills cover before SQL, SQL-executed/precommit and after commit; they are not kills observed
inside SQLite commit. Tmpfs ENOSPC is not disk-backed, power-loss, installed-host or live Kubernetes
proof. These finite tests do not by themselves establish a universal allocation bound.

Configured capacity does not prevent external filesystem exhaustion, failed sync, storage loss or an
indeterminate commit. Such failure must preserve admitted responsibility and already frozen facts.
It cannot manufacture a receiver result or authorize another mutation.

The implementation holds one crash-released exclusive worker lock around provider and receiver I/O
so two processes cannot advance the same journal concurrently. A contender performs no provider or
receiver call and changes no public fact. The implementation may add other internal lease or
scheduling fields, but those fields are not public facts and must not change result meaning.

### Fresh dispatch permission

A durable attempt records that dispatch may have happened. It does not establish that a request was
sent, and recovery cannot derive permission from it. In current source, dispatch permission is a
private, one-use value issued after a successful fresh attempt commit and consumed by the adapter.
The transaction checks the complete authorized snapshot against its durable row, including request,
approval, and authorization provenance. A snapshot from another journal cannot substitute different
facts under the same operation identity.

The permission binds the frozen request and attempted target. It is neither `Clone` nor `Copy`, and
the Kubernetes adapter consumes it instead of accepting separately supplied request and target
arguments. Loading attempted history, losing the conditional transition, or an ambiguous commit
acknowledgement cannot produce permission. Cancellation or loss after commitment may discard an
unsent permission. The action remains attempted, and recovery observes without resending or
inventing `NOT_ATTEMPTED`, success, or failure.

The gateway still holds the crash-released worker lock through provider and receiver I/O. Permission
is not lifetime-bound to that lock and does not replace process exclusion, conditional database
writes, or the driver's obligation to keep the lock. This is an internal sequential boundary, not a
public API or a shared approval/recovery kernel. The
[design decision](decisions/0011-retain-observation-only-recovery.md#sequential-boundary-comparison)
records its adoption and finite evidence.

One consumed permission must not become multiple mutation requests through client retries. The
shared application client disables kube-client's automatic server-response retries, including PATCH
retries on 429, 503, and 504. Explicit target-read retries and bounded receiver observation remain.
Operator-supplied custom clients must uphold the same no-mutation-retry obligation. A local HTTP
fixture verifies request counts across response loss, cancellation, and restart. It does not prove
arbitrary proxy or HTTP/2 behavior, prevent admission reinvocation within one Kubernetes request, or
establish power-loss durability or exactly-once effects.

## Result meaning

For operations that reached `apply_started`, the receiver result is exactly one of:

| Result      | Establishes                                                                                                                                                              | Does not establish                                                              |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `SUCCEEDED` | The observed deployment reached the requested generation and reports an available rollout for the requested image digest.                                                | Causation, workload correctness, complete cluster health, or universal capture. |
| `FAILED`    | The same deployment UID and requested image are observed at the requested generation, and Kubernetes reports `Progressing=False` with reason `ProgressDeadlineExceeded`. | Permanence, why Kubernetes failed, or whether another actor later changed it.   |
| `UNKNOWN`   | Kapsel could not establish either defined observed outcome within its bounded reconciliation procedure.                                                                  | That the request failed, was not received, or was later harmless.               |

`not_attempted` is a local pre-attempt disposition, not a receiver result. An accepted Kubernetes
request is not a rollout result. A healthy rollout does not prove that no other change occurred. A
conditional patch conflict is never forced or blindly retried and does not by itself establish a
failed rollout. `ReplicaFailure=True` may be retained as an observed condition but does not by
itself classify `FAILED`. A local observation timeout always classifies `UNKNOWN`. Deployment UIDs,
resource versions, operation markers, and condition reasons retained from Kubernetes are ASCII and
at most 128 bytes each. Generations and replica counts must be nonnegative. The requested and
observed image remains subject to the 512-byte immutable-image grammar above. Target observation and
the conditional strategic merge patch each have a ten-second request deadline. The root CLI/MCP
composition rejects any single Kubernetes HTTP response body above 2 MiB while it is streamed,
before kube-client can collect or deserialize it; this applies with content-length, chunked, or
close-delimited framing. An oversized target read is transient and cannot create a mutation marker.
An oversized patch response may leave the already marked provider attempt ambiguous, so restart
observes without another patch. An oversized receiver response contributes no facts and therefore
cannot strengthen `UNKNOWN` into another result.

Receiver observation uses a fixed **per-pass** policy: a 180-second monotonic deadline, at most 180
Deployment reads, and a ten-second deadline for each read within the remaining pass time. The first
read starts immediately; subsequent reads wait one second after the preceding read completes or
times out. Reads and sleeps consume the same pass budget. No new read starts at or after the pass
deadline, and a response completing at or after it contributes no facts. This is an observation
bound, not a total execution or storage-latency guarantee.

Observation stops early only when the unchanged receiver classifier can establish `SUCCEEDED` or
`FAILED`, including target UID, requested image, operation marker, generation and rollout facts. An
available condition alone, incomplete replica counts or a terminal signal from another generation is
provisional, not sufficient evidence. Exhausting the read budget returns the last observation;
exhausting elapsed time returns no receiver facts. Neither can strengthen incomplete evidence beyond
`UNKNOWN`. Read failure, deletion, identity mismatch and oversized responses never establish
failure.

A pass starts when initial observation or explicit observation-only recovery starts. Startup remains
read-first. Explicit resumption after an interrupted, unfinished pass starts a fresh budget;
repeated interruptions therefore have no cumulative operation-wide time or read bound. Reconnect,
status, receipt retrieval and selection while the worker is busy do not reset a surviving pass.
Frozen results and receipts never reopen. Wall-clock corrections do not change a pass's monotonic
budget. Suspend accounting follows the host monotonic clock, not a durable wall-clock deadline.
Timer expiry requires runtime scheduling and is not a hard real-time guarantee.

The [live observation-policy tests](BUILD.md#initial-observation-policy) exercise 60- and 210-second
readiness periods. The fixed policy accommodates bounded waiting without promising all rollouts
complete within it. A durable operation-wide deadline would instead need persisted timing facts and
a clock-discontinuity and compatibility policy. The per-pass choice adds no timing columns, journal
version, migration, caller configuration or later-observation path. Format 5 and all finalized
history remain unchanged.

## Authorization and secrets

Kapsel accepts only a canonical signed grant for the exact operation parameters. The owner signs it
for the fixed purpose `kapsel.kap0038.kubernetes-set-deployment-image-grant.v1`; the gateway
verifies it against one application-configured key identity and Ed25519 verifying key. The evaluator
application loads this trust out of band and does not let agent input choose it. Grant parsing is
bounded and canonical. Wrong purpose, key identity, signature, tuple, or grammar fails before
request persistence or Kubernetes calls. The grant has these implementation-specific magic prefixes:

| Document        | Magic                                     |
| --------------- | ----------------------------------------- |
| Grant statement | `KAPSEL-KAP0038-K8S-GRANT-STATEMENT-V1\0` |
| Signed grant    | `KAPSEL-KAP0038-K8S-GRANT-V1\0`           |

The grant statement contains exactly the authorization identity, operation identity, namespace,
Deployment, container, and immutable image digest in that order. The signed grant contains exactly
the fixed purpose, signing-key identity, statement bytes, and Ed25519 signature. The signing input
is the exact byte string `purpose`, one zero byte, then the statement bytes.

The v0.2 beta continues to accept canonical grant v1 bytes emitted by `v0.1.1` and preserves this
exact wire across v0.2.x. The canonical signed known answer is
[`vectors/effect-gateway-grant.hex`](../vectors/effect-gateway-grant.hex); it uses the fixed
authorization, seed, and signer identity in the owner test rather than defining another vector
format. That bounded compatibility appoints no new trust, adds no expiry or revocation semantics,
and creates no generic grant format or promise beyond the v0.2.x beta line.

Kubernetes credentials and signing seeds are owner-controlled private inputs; they never enter agent
requests, SQLite, receipts, reports, or errors. Public signing-key identities and digests are not
secrets and are frozen to identify the accepted authority. The grant does not itself grant
Kubernetes authority, prove a human made a decision, or replace Kubernetes RBAC. The experiment must
reject unsafe paths and must not print secrets or unbounded provider response bodies.

## Receipt and inspection

Kapsel writes one signed, portable receipt and supports offline inspection under separately provided
trust, explicit evaluation time, and explicit resource limits. Its bytes, report language, and trust
inputs remain capability-specific beta surfaces. v0.2 continues offline inspection of canonical
receipt and trust v2 bytes emitted by `v0.1.1`, emits the same receipt v2 wire, and preserves that
wire across v0.2.x. This bounded compatibility never re-signs frozen bytes, appoints receipt-carried
trust, creates a generic receipt format, or promises compatibility beyond the v0.2.x beta line. A
later format must use a new identifier and explicit migration/inspection policy rather than reuse or
rename these bytes. The canonical `v0.1.1` receipt, statement, and trust known answers remain
[`vectors/effect-gateway-receipt.hex`](../vectors/effect-gateway-receipt.hex),
[`vectors/effect-gateway-statement.hex`](../vectors/effect-gateway-statement.hex), and
[`vectors/effect-gateway-trust.hex`](../vectors/effect-gateway-trust.hex).

The receipt bytes are fixed-order length-delimited records with these magic prefixes:

| Document  | Magic                               |
| --------- | ----------------------------------- |
| Statement | `KAPSEL-KAP0038-K8S-STATEMENT-V2\0` |
| Receipt   | `KAPSEL-KAP0038-K8S-RECEIPT-V2\0`   |
| Trust     | `KAPSEL-KAP0038-K8S-TRUST-V2\0`     |

A record is encoded as a one-byte field number, a four-byte big-endian length, and that many value
bytes. Fields must appear exactly once in strictly increasing field-number order. Unknown,
duplicate, missing, reordered, trailing, or truncated records fail closed. Text is UTF-8 ASCII in
the grammar and length stated here. Integers are signed or unsigned big-endian fixed-width values as
owned by the durable facts. Canonical receipt bytes are the original parsed bytes; inspection never
re-encodes and verifies a different representation.

The statement is built only from already frozen durable facts and contains exactly:

| Field | Meaning                                                             |
| ----- | ------------------------------------------------------------------- |
| 1     | operation identity                                                  |
| 2     | authorization identity                                              |
| 3     | authorization grant signing-key identity                            |
| 4     | SHA-256 digest of the exact signed authorization grant bytes        |
| 5     | Kubernetes namespace                                                |
| 6     | Deployment name                                                     |
| 7     | container name                                                      |
| 8     | requested immutable image digest                                    |
| 9     | stored write strategy identity, `conditional-strategic-merge-patch` |
| 10    | target Deployment UID                                               |
| 11    | target resource version                                             |
| 12    | receiver Deployment UID, or empty when not observed                 |
| 13    | observed image digest, or empty when not observed                   |
| 14    | observed operation marker, or empty when not observed               |
| 15    | current generation, or `-1` when not observed                       |
| 16    | requested generation, or `-1` when not established                  |
| 17    | observed generation, or `-1` when not observed                      |
| 18    | observed resource version, or empty when not observed               |
| 19    | desired replica count, or `-1` when not observed                    |
| 20    | updated replica count, or `-1` when not observed                    |
| 21    | available replica count, or `-1` when not observed                  |
| 22    | unavailable replica count, or `-1` when not observed                |
| 23    | rollout condition type, or empty when not observed                  |
| 24    | rollout condition status, or empty when not observed                |
| 25    | rollout condition reason, or empty when not observed                |
| 26    | result, one of `SUCCEEDED`, `FAILED`, or `UNKNOWN`                  |
| 27    | non-claims token list                                               |

The inspector reconstructs the bounded request, apply identity, and receiver observation from these
fields and runs the same pure classifier. A signed statement is structurally rejected when its
stated result differs from the recomputed result. `INSPECTED` therefore authenticates both the
classifier inputs and their deterministic effect-gateway classification; it still does not establish
that Kubernetes reported truthful facts.

The non-claims field is the exact ASCII token list
`no-exactly-once;no-causation;no-kubernetes-truth;no-complete-capture;no-witnessing;not-production`.
It is a signed statement field so report consumers see the implementation's limits even when the
report is separated from the owner document. The statement has no timestamps, no Kubernetes response
body, no secret, no policy, no package identifier, no verifier profile, and no generic capability
field.

A receipt contains exactly:

| Field | Meaning                                                        |
| ----- | -------------------------------------------------------------- |
| 1     | signing purpose, `kapsel.kap0038.kubernetes-effect-receipt.v2` |
| 2     | signing key identifier                                         |
| 3     | statement bytes as encoded above                               |
| 4     | Ed25519 signature over the receipt signing input               |

The receipt signing input is the exact byte string `purpose`, then one zero byte, then the statement
bytes.

The key identifier is 1–128 ASCII bytes containing only letters, digits, `.`, `_`, `:`, or `-`.
Signing uses Ed25519 with a 32-byte verifying key supplied by external trust. The receipt does not
carry trust anchors, fetch keys, appoint authority, or define an issuer policy.

A trust document contains exactly:

| Field | Meaning                                            |
| ----- | -------------------------------------------------- |
| 1     | trusted signing key identifier                     |
| 2     | 32-byte Ed25519 verifying key                      |
| 3     | accepted signing purpose                           |
| 4     | inclusive not-before evaluation time, Unix seconds |
| 5     | exclusive not-after evaluation time, Unix seconds  |

Inspection takes receipt bytes, trust bytes, explicit evaluation time, and explicit limits. It
performs no network, filesystem discovery, ambient clock read, environment lookup, or trust lookup.
Evaluation time must be within the trust interval, the trust purpose must equal the receipt purpose,
and the trust key identifier must equal the receipt key identifier before the signature result can
be reported as trusted. Weak or malformed keys, bad signatures, wrong purpose, wrong key, and time
window failures all produce bounded reports or typed failures without panics.

Resource limits are part of the public inspection contract: receipt bytes are at most 16 KiB,
statement bytes are at most 8 KiB, trust bytes are at most 1 KiB, and any text field is at most 512
bytes unless an earlier grammar bound is smaller. The implementation may accept lower
caller-supplied limits but must not exceed these maxima.

Offline inspection reports an aggregate status using only this vocabulary:

| Status               | Meaning                                                                                              |
| -------------------- | ---------------------------------------------------------------------------------------------------- |
| `STRUCTURE_REJECTED` | Receipt, statement, or trust bytes did not parse within the limits.                                  |
| `SIGNATURE_REJECTED` | Structure parsed, but signature bytes did not authenticate.                                          |
| `UNTRUSTED_SIGNER`   | Signature authenticated, but external trust did not accept the key, purpose, or time.                |
| `INSPECTED`          | Structure, signature, and supplied trust matched; the report states the frozen facts and non-claims. |

Inspected and authenticated-but-untrusted reports disclose the signed fixed non-claims with the
parsed statement. Inspection must never report `VERIFIED`. `INSPECTED` means only that the disclosed
bytes were signed by a supplied trusted key for this purpose at the explicit evaluation time. It
does not mean the Kubernetes facts were true, causal, complete, witnessed, policy-authorized, or
safe.

Receipt filenames are derived by the application from the operation identity and the SHA-256 digest
of the final receipt bytes: `kap0038-<operation-id>-<64-lowercase-hex-receipt-sha256>.receipt`. The
operation identity is already path-component safe by the request grammar. Publication requires a
pre-existing owner-private output directory and installs owner-private immutable bytes without
following symlinks or replacing different existing bytes. This descriptor-relative publication
implementation supports Unix platforms only. The stored receipt digest is the SHA-256 of the exact
SQLite-committed receipt bytes, whether exported or not, rather than decoded facts or report text.

## Required release demonstration

The sequence below describes current source. The published v0.2.0 demonstration retains its original
filesystem-publication seam and is not evidence that the release includes format-4 completion.

The source Unix harness runs from one repository command against one uniquely named, disposable
`kind` cluster. In the fixed archive layout, the script safely locates its adjacent public vector
and the separate demonstration executable; source mode and explicit artifact overrides remain
available for repository and packaging proofs. It uses the supported `kapsel provision-grant`,
`kapsel operate`, and `kapsel inspect` grammar and fixed operator-owned files.

Before creating a workspace or inspecting clusters, the harness reports the detected prerequisite
versions and refuses an unavailable Docker daemon, `kind` older than 0.32, unavailable or pre-1.30
`kubectl`, Python older than 3.11, an unparsable tool version, or unsafe artifact inputs with a
concrete corrective action. It refuses any pre-existing `kind` cluster or colliding harness
directory before creating or mutating resources. A kind node-preparation failure remains a failed
demonstration and identifies the Docker/kind compatibility check to perform; it cannot weaken an
ownership check or continue to mutation.

Every phase reports elapsed time. The final evidence summary distinguishes the durable attempt, both
exact process terminations, restart-only reconciliation, the exactly-one harness apply count,
receiver disposition and its owned condition, frozen receipt identity, offline inspection path, and
the explicit `UNKNOWN` boundary. It does not promote a phase, process exit, timeout, or provider
response into a receiver outcome. The harness removes only the cluster and host directory it
created, reports successful cleanup, and gives an exact owner-scoped retry action if cleanup fails.
Signal and failure cleanup remain ownership-safe; captured command and cluster logs are individually
capped at 64 KiB and contain no configured seeds, credentials, grant bytes, or provider bodies.

The harness demonstrates:

1. an agent submits an authorized request for one immutable image digest and a healthy fixture
   reaches `SUCCEEDED` without changing the untargeted container;
2. a second authorized request uses one unavailable immutable image and Kapsel durably records
   `apply_started` before crossing the Kubernetes mutation seam;
3. the exact `kapsel operate` process is killed after the mutation returns but before its outcome is
   recorded;
4. restart reconciles rather than blindly patching again, the harness-owned apply counter remains
   exactly one, and the unavailable image reaches `FAILED` only from `ProgressDeadlineExceeded`
   receiver facts;
5. exact receipt bytes and terminal state commit together, then the exact `kapsel operate` process
   is killed before export;
6. restart under a rotated receipt key and changed output directory retrieves the original signed
   bytes and exports them to the new directory without re-signing or reopening the action; and
7. `kapsel inspect` runs with unavailable network and ambient Kubernetes configuration and reports
   `INSPECTED`, `FAILED`, the signed classifier inputs exposed by the inspector, and the fixed
   non-claims without `VERIFIED` vocabulary.

Fault control is not part of the agent request, operator JSON, ordinary command grammar, public Rust
interface, journal, or receipt. The harness builds the same `kapsel` binary with the private
`demo-harness` compile-time feature and supplies an owner-private control directory plus exactly one
of two fixed process-environment values: `after_apply` or `after_receipt_commit`. At the selected
internal seam Kapsel creates one owner-private readiness marker, syncs it, and waits to be
terminated. The mutation seam also creates a no-replace `provider-apply-count` file containing `1`;
encountering it again fails closed. Builds without `demo-harness` do not read these variables or
contain the pause behavior. The harness never accepts a lifecycle state, arbitrary fault point,
marker path, shell, manifest, patch, credential, or receipt byte from agent input.

Deterministic black-box tests run the feature-built production executable against a local HTTP
fixture and kill it at both fixed seams. Existing internal tests still exercise every durable
transition. The visual demo runs against `kind`; no live cluster behavior is presented as
deterministic test evidence.

## Explicit exclusions

Do not add:

- arbitrary shell, `kubectl` passthrough, manifests, patches, tags, or credentials in agent input;
- a second capability or provider;
- a generic provider, capability, queue, policy, authorization, receipt, package, trust, or verifier
  module;
- runtime plugins, hosted storage, multi-tenant operation, dashboard, or transparency backend;
- a claim of exactly-once Kubernetes mutation, complete audit capture, compliance, or production
  readiness.

One adapter remains a hypothesis, not a reusable seam. Keep the implementation deep around its one
operation: the caller crosses one narrow experiment interface while the implementation owns
journaling, Kubernetes interaction, recovery, observation, receipt construction, and inspection.
