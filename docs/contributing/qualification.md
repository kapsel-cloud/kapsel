# Qualification commands

Use these lanes when a change needs evidence beyond the everyday deterministic gate. Run commands
from the checkout root after [contributor setup](build.md#prepare-contributor-tools). Each section
states its additional prerequisites and environment ownership. [Testing](testing.md) explains
evidence classes. The [evidence map](evidence.md) connects guarantees to maintained checks.

## Choose a lane

Use `cargo xtask explore sim|fuzz ...` for explicit bounded exploration and
`cargo xtask qualify <boundary> ...` for physical or selected-artifact work. These commands route to
the current owners below; they do not install prerequisites or assemble an implicit archive. Normal
`check` never enters these lanes.

| Boundary        | Current command arguments and owner                                                                                                                                  |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| storage         | `qualify storage [--build-cache DIRECTORY] [--output NEW_DIRECTORY]`: maximal completion and three actual ENOSPC placements                                          |
| artifact        | `qualify artifact --archive A`: existing extracted smoke/direct-guide artifact tests                                                                                 |
| reproducibility | `qualify reproducibility --archive A`: independently assembles B against selected A                                                                                  |
| kubernetes      | `qualify kubernetes --archive A --revision R [--case CASE]`: current packaged runner                                                                                 |
| git             | `qualify git --archive A --revision R --git /absolute/path/to/git [--case CASE]`: current packaged runner                                                            |
| native          | `qualify native --archive A --revision R --extract-to NEW_DIRECTORY`: verify/extract A, then its bundled systemd profile on a separately authorized fresh Linux host |
| security        | `qualify security --output REPORT`: existing source scan and database refresh                                                                                        |

Archive-consuming commands require an existing, explicitly selected A. Receiver case reductions,
model-subsystem retirement and final CI/candidate workflow changes belong to later cutovers. This
router preserves the current owners and prerequisites; selecting a verb does not authorize
publication or changes to an existing host.

- Service startup or runtime: [Linux process tests](#kapsel-service-candidate).
- Receiver rules: [Kubernetes](#live-kubernetes-gate) or [Git](#git-transition-service).
- Storage: [accepted layouts](#accepted-journal-layouts),
  [ENOSPC](#bounded-storage-failure-qualification), and
  [version rejection](#journal-version-rejection).
- Hostile input and lifecycle exploration: [robustness](#robustness-lanes).
- Release candidate: [source scan](#source-privacy-and-security), [artifact](#release-artifact), and
  [packaged receiver workflow](#packaged-service-live-workflow), under the
  [release process](release_process.md).

A source, container, live-receiver, and native-installation pass establish different facts. Preserve
those distinctions when recording results. Do not run a privileged lane against existing resources.

## Contributor tooling details

### Python type checking

[`pyrightconfig.json`](../../pyrightconfig.json) selects Python 3.11, standard checking, and script
directory import roots. The static gate runs the pinned Pyright on Linux and macOS targets,
independent of the host interpreter. `tools/checks/check_source_privacy.py` uses strict checking.
The checked scope includes source checks, release tooling and fixtures, developer tooling, the
maintained fresh-session caller and its tests, and the selected Git and Kubernetes qualification
runners and their extracted fixtures. Other qualification lanes are not yet in the checked scope.

Extracted journey programs remain standalone source. Runners stream their bytes into disposable
containers rather than importing repository modules there. The Git and Kubernetes runners retain the
exact executed source and its digest with their private qualification evidence. The distributed
release verifier remains independent of repository imports and retains its 64-KiB limit.

## Fresh-session caller checks

To run the caller fixture against the real MCP bridge and a scripted socket (not Kubernetes), build
the test-harness binary first:

```sh
cargo build --locked -p kapsel-daemon --features test-harness --bin kapsel-service-mcp
env KAPSEL_TEST_BRIDGE="$PWD/target/debug/kapsel-service-mcp" \
  python3 examples/test_fresh_session_caller.py
```

## Live Kubernetes gate

Requires Docker, kind 0.32+, kubectl 1.30+, Python 3.11+, and OpenSSL. Set `archive` and `revision`
to the accepted clean artifact and its exact source identity as specified below:

```sh
./tests/qualification/run-kind-effect-gateway.sh --archive "$archive" --revision "$revision"
```

This entry point delegates to the packaged-service workflow; it does not compile a separate
source/test-hook suite. The runner creates and removes its own uniquely named cluster and retains
private evidence. See [the evidence map](evidence.md#live-kubernetes-and-demonstration).

## Packaged-service live workflow

Use this lane to check production binaries against a real Kubernetes receiver, including caller
loss, service loss and same-ID recovery. The model-driven healthy action is an optional addition.

1. Prepare Docker, kind 0.32+, kubectl 1.30+, Python 3.11+ and OpenSSL.
2. Select an exact accepted clean release archive, matching sidecars and source revision. Set
   `archive` and `revision` to those identities.
3. Run the scripted workflow below, or add the [model lane](#model-driven-healthy-action).
4. Check the retained results against [expected evidence](#packaged-workflow-evidence).
5. Check [cleanup and retained private state](#packaged-workflow-cleanup), including on failure.

This is a privileged **disposable test environment**, not permission to use an existing cluster:

```sh
python3 tests/qualification/run_kind_agent_action_workflow.py \
  --archive "$archive" --revision "$revision"
```

### Focused packaged cases

Omit `--case` for the full nine-case Kubernetes suite. During iteration, select an affected case:

```sh
python3 tests/qualification/run_kind_agent_action_workflow.py \
  --archive "$archive" --revision "$revision" --case service-loss
```

Repeat `--case` to select more. The runner deduplicates selections and preserves canonical order.
Both `service-loss` and `caller-loss` first execute `healthy`, which supplies the original history
and receipt. The optional model lane also adds `healthy`. `independent` remains approved but
unexecuted for isolation probes; it executes last only when selected.

The full catalog and disposable resources remain provisioned. Unselected Deployments use zero
minimum readiness time; selected cases retain their original readiness periods and observation
bounds. API audit requires zero product PATCHes for every unexecuted case. Reports require every
planned case exactly once, with the existing per-pass read and timing checks.

Summaries record `requested_cases`, added `prerequisite_cases`, actual `executed_cases`, and
`qualification_scope` (`focused` or `full`). A focused pass does not satisfy the full receiver gate
or release acceptance. Unknown, empty and missing case arguments fail before qualification setup.
See [iteration routing](build.md#route-qualification-during-iteration) before choosing other lanes.

### Packaged workflow evidence

Both packaged receiver lanes select one clean archive and exact revision. Cold binary replacement
reinstalls those selected bytes; there is no second producer archive or cross-version qualification
mode.

The runner creates one uniquely named, pinned kind cluster and an isolated Linux service container.
It transfers only extracted production binaries, their public key-generation procedure and scoped
fixture authority into the operating environment. It never builds a test-feature binary or uses a
private product pause hook. Distinct operator/service/caller identities own preparation, execution
and selection. The caller selects approved IDs from one catalog, with no per-action configuration
switching. The fixture operator owns the disposable Deployments' desired state. No existing
reconciler is disabled.

The cases cover healthy and failed rollouts, stale and recreated snapshots, a conditional-update
race, deletion after accepted mutation, service SIGKILL during observation with explicit same-ID
resumption, and caller loss before acknowledgement during a rollout beyond the observation window.
Independent B remains selectable after A's frozen `UNKNOWN`. A conflicting follow-on ID was never
provisioned and must remain unavailable to a hostile caller before and after cold replacement. The
service-loss case also kills the service after terminal status but before the caller's first receipt
export. It compares independently read format-6 grant/receipt/signer bytes through cold signing-key
rotation, original-byte export and repeated same-ID selection. Original receipts remain retrievable
after catalog withdrawal. API-server audit independently counts product PATCH requests and
execution-window GETs, excluding fixture writes. An operator-owned, authenticated loopback barrier
forwards requests to the real API server. It changes the version before the race PATCH, and parks
accepted failed/deleted PATCH responses until service loss. It does not supply receiver observations
or product lifecycle hooks. Repeated product PATCHes still reach the API server and record a
qualification failure. Independent B runs directly against the HTTPS API server using its CA bundle,
without the loopback barrier, so the product's TLS client remains part of live success evidence.

The healthy case checks the unchanged sidecar, one generation and ReplicaSet increase, then replays
the original conditional patch as a fixture write. The API server must return 409 with unchanged
persisted spec, version and controller effects. A scoped, deliberately side-effecting admission
webhook records two distinct admission requests despite only one persisted change. Never install
that webhook in an existing cluster. The fixture operator has separate namespace-scoped credentials
for its writes and observations; the service retains only its named Deployment read/patch scope.

The runner probes private-file and executable custody under the caller identity before submission.
Private fixture credentials and evidence are copied into container-owned directories, not exposed
through host bind mounts whose permission behavior can differ across Docker environments. The
extracted public artifact is the only host bind. These probes are finite process-level evidence, not
a general host-security certification.

### Model-driven healthy action

Supply an independently accepted Linux x86-64 Codex 0.155.1 executable, its matching
`codex-code-mode-host` sibling, and existing model authentication. The runner does not install or
update Codex. The default scripted lane requires no model account or call.

Read the custody and supervision requirements below before running the model lane.

The optional lane copies only the model's `~/.codex/auth.json` into a private caller-owned directory
inside the disposable container. An operator can select another private model-auth file with
`--codex-auth`. No host home directory, agent configuration, Kubernetes authority or Docker socket
is exposed to the model. The source auth file must be private, owned, regular and single-link. It is
not modified or synchronized back. The container copy is removed after the call, and container
cleanup removes any remaining local model state.

Codex runs as UID 61001, distinct from both root preparation and the Kapsel service identity. It
uses the packaged `/usr/bin/kapsel-service-mcp` through its caller-owned Codex configuration to list
actual approvals, submit the existing `healthy` ID, read status and retrieve the receipt. The
independent driver still uses the fixed service client to verify the retained action. Before
starting Codex, the runner must pass the caller's OS custody probes. Codex's inner approval prompts
and sandbox are explicitly bypassed **only inside this externally isolated disposable caller**. The
container's `no-new-privileges`, absent private host mounts and OS identities are the boundary, not
prompt advice or confirmation dialogs. Never copy that bypass flag into a host or operator
invocation.

The agent container has a 4 GiB memory ceiling. The driver waits up to 120 seconds for Codex, then
requires all remaining caller-UID processes to retire before checking evidence or starting scripted
cases. Killing the host `docker exec` process alone is not sufficient. Only the explicit disposable
caller configuration is loaded, with the fixed MCP command and no host user settings. Exec-policy
rules are not loaded, and session persistence is disabled. This tests specific product custody
boundaries, not comprehensive hostile-code containment. The model can read its own model
authentication and has network access.

Run with the same accepted artifact identity:

```sh
python3 tests/qualification/run_kind_agent_action_workflow.py \
  --archive "$archive" --revision "$revision" \
  --agent --codex-binary /absolute/path/to/verified/codex
```

The driver checks product state independently of model prose and refuses success if another fixture
action was admitted. Status comes from the installed native client with its fixed socket. Python
supervision and receipt readers use isolated mode to exclude model-writable imports. The driver
snapshots two bounded, regular, non-symlink independent client exports and compares the original
bytes and digest. It does not treat the model's prose as receipt proof. It records CLI identity,
both executable digests and token usage, not raw model sessions. There is no provider SDK, agent
framework or new product command.

This is one model-driven healthy action. The remaining fault and recovery cases are deterministic
caller programs, not model-driven troubleshooting or evidence of useful action selection. Neither
mode qualifies native systemd installation, application quality, publication, or a cumulative
observation deadline across interruptions.

### Packaged workflow cleanup

The printed private workspace retains result summaries, bounded output, and fixture inputs. It also
contains a cluster-admin kubeconfig and an expiring scoped token. **Do not publish that directory.**
The runner removes its container and cluster. If cleanup fails, inspect those named resources. Do
not run broad Docker or kind cleanup. The native example separately retains its stopped host state.

## Receiver-recovery regressions

The deterministic adapter composition check needs only the repository Rust toolchain, not Docker or
credentials:

```sh
cargo test --locked -p kapsel --lib gateway::kubernetes_composition_tests
```

An independent HTTP fixture supplies exact PATCH assertions and receiver facts for signed receipt
comparisons. Healthy, failed, response-loss, conflict, budget-exhaustion and post-acceptance writer
changes run in the default gate. The shared simulator owns interruption and frozen-recovery laws;
process suites retain actual process-loss evidence. These checks do not show equivalence with
another tool.

### Initial observation policy

The packaged workflow uses 60- and 210-second minimum readiness periods. The service-loss case
requires a completed live observation before SIGKILL and explicit same-ID resumption. The slower
caller-loss case checks unfinished status, unavailable receipt and `BUSY` refusal while the worker
survives. After terminal `UNKNOWN`, it waits for independently observed rollout availability and
checks unchanged status and original receipt bytes.

API-server audit bounds execution-window GETs to 181 on the initial pass and 180 on recovery.
Recovery must finish within 205 seconds of explicit resumption, allowing tolerance above the
180-second product ceiling. Caller-loss terminal evidence must arrive between 175 and 205 seconds.
Both readiness cases must run for more than 30 seconds. Evidence records observation reach, worker
occupancy, stored-read latency and original bytes. This lane uses extracted production binaries and
the actual socket; it does not qualify native systemd or power-loss durability.

Focused deterministic observation checks:

```sh
cargo test --locked -p kapsel gateway::kubernetes
cargo test --locked -p kapsel gateway::kubernetes::adapter::tests::production_policy
cargo test --locked -p kapsel --lib gateway::kubernetes_composition_tests
```

Paused-clock tests distinguish the read ceiling (180 instantaneous reads over 179 one-second waits)
from the elapsed ceiling (180 seconds including stalled reads). Real I/O can exhaust elapsed time
before all reads occur. Per-pass bounds do not promise a cumulative ceiling across interrupted
explicit resumptions. The [gateway contract](../reference/kubernetes_effect.md#result-meaning)
defines that policy.

## Git transition service

The Git lane requires an explicitly selected Git 2.55.0. Receiver fixtures copy it into private
custody rather than discovering it through ambient PATH. Run the core recovery matrix on macOS or
Linux:

```sh
KAPSEL_TEST_GIT=/absolute/path/to/git cargo xtask check core
```

On Linux, exercise real service-process loss and the maintained caller through the fixed-root test
harness, without installation or a live repository:

```sh
cargo build --locked -p kapsel --bin kapsel
cargo build --locked -p kapsel-daemon --features test-harness
python3 tests/qualification/run_git_service.py --git /absolute/path/to/git
```

For the production-artifact journey, use an exact accepted clean archive and an independently
accepted Linux Git 2.55.0 executable compatible with the pinned Debian 12 runner:

```sh
python3 tests/qualification/run_git_artifact.py \
  --archive "$archive" --revision "$revision" --git /absolute/path/to/git
```

The packaged runner also accepts repeatable `--case` selections. Its four cases use separate
containers and have no cross-case prerequisites:

```sh
python3 tests/qualification/run_git_artifact.py \
  --archive "$archive" --revision "$revision" --git /absolute/path/to/git \
  --case post-receive
```

Omit `--case` for the full suite. Focused summaries identify requested and executed cases and cannot
replace full qualification. Each selected case retains its custody, hook/ref, recovery and receipt
checks. Selection changes neither the source profile nor its six-case process matrix.

Both launchers use `git_service_exercise.py` for provisioning, public selection, terminal evidence,
withdrawal, reconnect and offline inspection. Healthy execution first freezes a real acknowledgement
without a signer. The operator withdraws receiver material and the catalog, restores only the
signer, and resumes the original ID through the fresh-session MCP caller. Both profiles inspect
those original signed facts and compare retained receipt bytes after cold reconnect.

The source profile uses current-user identities and fixed-root test-feature binaries without root or
Docker. Its six cases include `after_apply`, `before_receipt_commit` and `after_receipt_commit`.
These establish loss before acknowledgement retention, before receipt SQL and after receipt
commitment, respectively.

The artifact profile has four cases: healthy, pre/post-receive loss and service loss while the
post-receive hook is parked. It does not establish the source profile's receipt-commit placements.
Source checkpoints remain confined to test-feature executables; the installed profile supplies no
product pause environment and never writes product history.

This lane creates one isolated, network-disabled container per case. Extracted production binaries,
the selected Git executable and exact trusted caller/hook helpers enter the operating environment.
Separate service and caller identities enforce private-material custody. Receiver hooks supply
acknowledgement-loss and service-crash windows without a product test hook. The cases check exact
ref and hook inputs, observation-only same-ID recovery, original receipt retrieval after
catalog/material withdrawal, and detached inspection. Hook inputs are not packet counts or proof of
complete hook delivery. The runner removes the containers and retains the printed private evidence
workspace. This is not native systemd, power-loss, or live-repository qualification. Current-release
restart/reconnect evidence is required. The runners accept only the selected archive and revision;
`--retained-archive` and `--retained-revision` are rejected before qualification setup.

See the [Git service example](../guides/git_transition.md) for material, semantics and evidence
limits. Use `cargo xtask check core` for isolated core implementation changes and unscoped `check`
for shared contracts. Linux process witnesses are included in `check service` and unscoped check,
not an additional routine gate.

## Kapsel service candidate

The focused package command above includes the service's private harness. On Linux, run the process
tests:

```sh
cargo test --locked -p kapsel-daemon --features test-harness --test linux_process
```

The Linux process suite separates caller loss from receiver completion. Run its retained-reference
witness through the real bridge and daemon (no receiver):

```sh
cargo test --locked -p kapsel-daemon --features test-harness --test linux_process \
  mcp_caller_loss_preserves_reference_and_service_admission -- --exact
```

For process loss after mutation and receipt commitment, original-byte export through the fixed
client and detached CLI inspection, use the retained public composition journey:

```sh
cargo build --locked --bin kapsel
KAPSEL_TEST_INSPECT="$PWD/target/debug/kapsel" \
  cargo test --locked -p kapsel-daemon --features test-harness --test linux_process \
  ordinary_restart_reuses_frozen_snapshot_receipt_under_rotated_configuration -- --exact
```

The bundled native identity profile checks a caller with a different effective GID and the socket
GID only as a supplementary group. Filesystem access permits its connection, but the ordinary
installed daemon must close it before reading a frame. This witness uses the fresh profile's
identities; it needs neither `sg` nor a developer-owned `docker` group. Native execution requires an
explicitly selected archive and a separately authorized fresh host, as listed above.

Cold publication validation also runs at the shared application owner:

```sh
cargo test --locked -p kapsel --test service_application_contract cold_validation
cargo test --locked -p kapsel-daemon --features test-harness
```

Local real-filesystem startup tests own the complete invalid-socket tuple and unchanged-inode
catalogue. Linux publication tests observe exact bytes, temporary-file sync, custody recheck, rename
and directory sync, with failures at the actual sync-operation boundary. Process tests retain one
stale-socket startup binding, invalid-root refusal, signal/drain and publisher exclusion. Cold
publication changes a label and preserves original history/receipt bytes through read-first restart.
Catalog and trust withdrawal semantics stay with application access and generated histories. These
are deterministic source/process checks, not disk-full, power-loss, native-host or live-Kubernetes
qualification. Never mutate source during a read-only-mounted container gate, and archive untracked
source files alongside its diff.

See [Kapsel service](../reference/service.md) for the current boundary and
[service testing](evidence.md#kapsel-service) for evidence coverage.

## Accepted journal layouts

Run the shared writable/read-only physical-layout regressions and retained-charge arithmetic:

```sh
cargo test --locked -p kapsel --lib gateway::tests::capacity_layout
cargo test --locked -p kapsel --lib gateway::journal::capacity
```

These use bundled SQLite records, long retained keys, padded schema SQL and bounded sparse-tree
fixtures to check [completion accounting](../reference/storage.md#completion-accounting). They prove
encoded-payload rejection and legitimate completion/reopen, not transient-allocation peaks,
filesystem reservation, ENOSPC, power-loss or native/live qualification. The owning broader gate is
`cargo test --locked -p kapsel`.

## Bounded storage failure qualification

Normal `check core` includes executed SQLite write-plan/configuration checks, rollback-record
accounting, accepted layouts, last-slot competing connections and mixed-effect capacity checks. It
also runs the bounded receipt-process witnesses below. It never starts Docker or runs maximal
completion or actual ENOSPC. Focused local command:

```sh
cargo xtask test core
```

Storage qualification requires Docker with `linux/amd64` execution, Python 3.11 or later, and
network access for uncached dependencies. The pinned image must supply the source's selected Rust
toolchain. Use a bounded worker filesystem for the persistent build cache and evidence:

```sh
cargo xtask qualify storage --output /tmp/new-storage-evidence
```

The runner uses one owned container with read-only source and root filesystem, no additional
capabilities, two CPUs, 2 GiB memory without extra swap, and at most 256 PIDs. Its temporary mounts
limit `/tmp` to 64 MiB and `/kapsel-enospc` to 96 MiB. Container lifetime is 1,800 seconds; build
allows 1,200 seconds and each exact test allows 300 seconds. Every command has an 8-MiB output
ceiling; Docker retains at most two 8-MiB container logs. Exceeding a ceiling fails rather than
truncating a passing result. Cleanup verifies the invocation label and removes only the immutable
container ID, then checks its absence. Cleanup uncertainty is failure, even after passing tests.

Cargo builds the library test executable once through `--no-run --locked` and reports its exact
path. The persistent default cache is `target/storage-linux-amd64`; `--build-cache DIRECTORY`
selects an existing compatible cache. Cargo's fresh/compiled artifact counts distinguish reuse from
rebuilding. `qualify storage --prepare-only` builds and lists both exact cases without running
physical tests; its result is `PREPARED`, never `QUALIFIED`. This permits a cache-reuse check
without repeating accepted physical evidence.

`result.json` records revision, committed tree, dirty indication, runner and executable SHA256,
image/target/toolchain, environment, named and executed cases, cleanup ID, and setup/build/execution
timings. `commands.json` retains literal commands, outcomes, elapsed time and bounded log names.
Development runs may be dirty and make no source-reconstruction claim. Release evidence requires
clean candidate source S and records these source-test binaries separately from shipped archive A.

The first exact case independently inserts 472 completed identities and 32 maximal pending records
across three phases. Production writes complete them in one fragmented 16,384-page file; direct row
comparisons and reopen bind original authority, frozen facts and unrelated peers. The larger
Kubernetes record supplies maximal geometry; Git remains covered by aggregate counts and actual SQL
premises. Shared application laws own interruption, acknowledgement-loss and no-resend matrices.

The second exact case verifies the dedicated tmpfs mount/type/size and caps filler writes at 128
MiB. Selection must contain exactly one named test. Maximal completion and each of the three ENOSPC
placements must emit their own completion marker after their assertions and repair. Zero selection,
missing markers, timeout, interruption, nonzero exit or unverified cleanup cannot qualify.

An admission case first exhausts the tmpfs before inserting a new identity. It requires a storage
error without admission acknowledgement, preserved earlier receipt/history bytes and explicit
same-ID admission after removing only its owned filler. At 504 retained identities/32 observed
pending operations, the next case exhausts space before receipt SQL can complete. The second fills
only after receipt SQL executes, with `dbstat` locating new destination pages and Linux `SEEK_HOLE`
confirming they still require filesystem allocation. Page 1 is already in the rollback journal at
that checkpoint. Commit then reports SQLite disk-full under actual OS ENOSPC, not the configured
page ceiling. Both cases remove only their owned filler, recover original rows/grants/frozen
facts/earlier receipts, and complete without another mutation or observation. The main journal
length observed before commit is finite evidence, not a sampled universal peak measurement.

Default deterministic gates never start this container. A two-row process fixture checks before
receipt SQL, SQL-executed/precommit and after commit. A separate uncommitted fixture edit spills
pages under DELETE/FULL to create a genuinely hot rollback journal. Its header and changed main
bytes are observed before read-only refusal and writable recovery. Owned writes still disable
spilling. None of these checkpoints observes a kill inside SQLite commit. This lane uses real tmpfs
exhaustion, not disk-backed durability, power loss, a native installation or live Kubernetes. See
[completion accounting](../reference/storage.md#completion-accounting) for the separate
source-backed page and main-rollback arguments.

## Journal version rejection

Journal format 6 rejects older versions without migration. Run the rejection proof:

```sh
cargo test --locked -p kapsel --lib \
  gateway::tests::migration::prior_construction_and_unknown_versions_are_refused_unchanged -- --exact
```

See [journal retention](../guides/journal_retention.md) before replacing a binary or moving existing
history.

## Robustness lanes

Fuzzing additionally requires cargo-fuzz 0.13+ and uses nightly for sanitizer instrumentation. The
pinned nightly is already installed by contributor setup. Cargo-fuzz is not needed for formatting or
the deterministic gate. Check the target without starting exploration:

```sh
rustup run nightly-2026-07-03 cargo fuzz check --fuzz-dir fuzz
cargo test --locked --manifest-path fuzz/Cargo.toml --test corpus
cargo run --locked --manifest-path fuzz/Cargo.toml --example seed_corpus -- --check
```

The fuzz workspace maintains five distinct targets:

| Target                    | Production entry point and fixture input                                    |
| ------------------------- | --------------------------------------------------------------------------- |
| `inspect_receipt`         | Kubernetes receipt inspection; four-byte big-endian split, receipt, trust   |
| `inspect_git_receipt`     | Git receipt inspection; the same explicit receipt/trust split               |
| `verify_kubernetes_grant` | Kubernetes grant verification; raw v1/v2 envelope, fixed fixture trust      |
| `verify_git_grant`        | Git grant verification; raw envelope, fixed fixture trust                   |
| `service_document`        | Service-document parsing; raw JSON, fixed operator-owned inert journal path |

Receipt targets evaluate at time 150, trust-window boundaries and extreme times. They also exercise
lower legal byte, statement and text limits. Grant targets appoint `owner` and the public key from
fixture seed `[7; 32]` externally. Drivers never open the supplied journal path or contact
receivers. They inspect raw signatures and separately re-sign bounded mutated statements with the
fixture key. Re-signing reaches semantic parser branches without authenticating hostile input for
execution. `seed_corpus` regenerates maintained valid/invalid seeds only when invoked without
`--check`. The deterministic gate reads committed bytes and checks acceptance through production
entry points. Reviewed findings live in `fuzz/regressions/<target>/` with explicit semantic
expectations in `fuzz/tests/corpus.rs`, separately from discovery inputs. New unregistered findings
and missing required findings fail replay.

The job runner requires Python 3.11+ and a new absolute `--output` directory outside the checkout.
Its parent must exist without symlink components. Each invocation creates private output and never
reads previous runs to decide whether it can execute. Existing evidence is neither changed nor
pruned. There is no triage command, shared lane lock, or second scratch root.

Dirty development source is accepted. Keep source unchanged while a job runs. The runner archives
tracked and non-ignored untracked files, including local edits and deletions, and hashes their exact
bytes. Symlink and oversized source inputs are refused. Locked dependencies and recorded compiler
versions identify the build inputs; the archive does not vendor dependencies or attest a build.
Normal Cargo build output is reused, including an explicitly configured `CARGO_TARGET_DIR`. Keep
separate build directories for different checkouts, especially temporary source mutations. Sharing a
target directory can reuse another checkout's executable. Cargo's freshness decision and the
recorded source digest do not establish source-to-binary correspondence.

Select explicit seeds and a separate output for each target:

```sh
jobs="$(mktemp -d)"
for target in inspect_receipt inspect_git_receipt verify_kubernetes_grant verify_git_grant service_document; do
  cargo xtask explore fuzz --output "$jobs/$target" --fuzz-target "$target" \
    --corpus "fuzz/corpus/$target" --seed 2118243591 --runs 10100 --timeout 3600
done
```

`fuzz/smoke.sh` invokes the same `fuzz` job as a longer search. Increase `--runs` explicitly;
`--timeout` bounds the whole invocation, including compilation. Completion requires the exact
requested run count, not merely zero exit or elapsed time. Instrumented smoke needs at least 10,000
runs beyond the finite starting corpus size and observed progress beyond initialization. Increase
the example's count if the input corpus grows above 100 files.

Repeat `--corpus` to include the target's named regression directory, reviewed target-specific
discoveries or a retained legacy corpus. Inputs are read-only: each job copies and hashes their
exact bytes in `corpus-before/`. LibFuzzer writes only to `discoveries/TARGET/` and `artifacts/` in
this job. Review and promote discoveries separately; never combine different targets' inputs. The
runner retains the executed binary, compiler identity, crash inputs and corpus manifests even when
execution fails. A runtime diagnostic without a retained crash input is incomplete evidence, not a
finding. Build failures are always infrastructure failures.

Each target keeps its production length ceiling plus one sentinel byte and receipt split framing.
LibFuzzer retains its ten-second input timeout and sampled 2-GiB RSS limit. These are not hard
resource containment.

### Background sweep and retained evidence

Run the shared atomic-record simulator with explicit seed, case and step limits:

```sh
jobs="$(mktemp -d)"
cargo xtask explore sim --output "$jobs/simulation" \
  --seed 21182435931731969 --cases 1000 --steps 32 --shards 2 --timeout 1800
```

Repeat `--seed` for a sweep. [The nightly wrapper](../../tools/dev/run-nightly-soak.sh) invokes the
same `simulation` job and requires explicit arguments. Cases are bounded to 10,000 per seed, steps
to 8..32 meaningful decisions, and nonempty shards to 128. `--smoke` selects 32 histories, 32 steps
and one shard. Generation chooses actions while actual records remain unfinished, then checks warm
eligible progress. These are application histories on virtual records, not qualification of physical
jobs, SQLite OS failures or actual receivers.

For a duration campaign, select one seed and replace `--cases` with `--duration` in seconds:

```sh
cargo xtask explore sim --output "$jobs/duration" \
  --seed 21182435931731969 --duration 600 --steps 32 --shards 4 --timeout 900
```

Each shard finishes between complete histories after useful work when its monotonic duration
expires. The outer watchdog needs more than ten seconds of recording/cleanup grace after build and
setup. A forced timeout is INCOMPLETE, never duration completion. Each shard must retain its actual
completed count and every corresponding trace. Reaching 10,000 retained histories before expiry is
incomplete, not early success. Count-mode smoke must finish all requested histories before its
watchdog ceiling.

The runner reuses the development test build, copies its executable into output, and executes that
copy. Rust persists each chosen action batch before execution, retaining concrete input even for
unknown crashes. Completion requires each shard's exact count or orderly-duration marker, a
successful test result and all expected trace identities. Passing generated traces are not replayed
a second time. Default corpus and reached negative controls remain in the deterministic gate. A
novel finding retains the full input, minimized input, law and reached-event report. Both full and
minimized inputs must reproduce the law with the original binary before the job reports `FINDING`.
An unrelated panic or failed minimization is `INCOMPLETE`.

The output directory contains:

- `result.json`, `commands.json`, `command-*.log`: selected arguments, timestamps, status, exact
  command vectors, phase timings and process exits. Each command log is bounded to 8 MiB.
- `source.json`, `source.tar`, `executable`, `evidence.json`: source and tool identities, exact
  source archive, executed bytes and retained-file digests.
- For simulation: `simulation.json`, `traces-SEED-SHARD/` and trace hash manifests. A finding also
  has `failure.json` with the original and reduced reached-event reports.
- For fuzz: `fuzz.json`, `corpora.json`, `corpus-before/`, target-specific `discoveries/`,
  `artifacts/` and their hash manifests.

Check retained hashes before selecting an original executable. Replay an exact simulation document
in a new job; this does not regenerate it from its seed:

```sh
python3 tools/dev/run_robustness.py simulation --output "$jobs/original-replay" \
  --replay "$jobs/simulation/traces-21182435931731969-0/case-0.json" \
  --executable "$jobs/simulation/executable"
python3 tools/dev/run_robustness.py simulation --output "$jobs/candidate-replay" \
  --replay "$jobs/simulation/traces-21182435931731969-0/case-0.json"
```

The second command requests a Cargo build against current code, reusing that checkout's cache. The
copied replay document keeps its original source and binary identities. `simulation.json` identifies
the executed binary; `cargo_build_requested` distinguishes Cargo selection from an explicitly
supplied binary, not a cache hit from compilation. For a supplied binary, the current source archive
identifies the launcher checkout, not that older binary's source. Keep the original job's source
archive with it. Legacy evidence remains untouched; use its original executable and matching
documented replay protocol rather than relabeling it as a new job.

| Runner status | Exit | Meaning                                                                 |
| ------------- | ---- | ----------------------------------------------------------------------- |
| `COMPLETED`   | 0    | Requested counts or orderly duration completed with retained evidence   |
| `FINDING`     | 1    | A law or fuzz diagnostic failed with retained reproduction input        |
| `INCOMPLETE`  | 2    | Setup, timeout, truncation, count mismatch, storage or evidence failure |
| `CANCELLED`   | 130  | Handled cancellation after retiring owned commands                      |
| `RUNNING`     | none | No terminal result; an abandoned job is interrupted, never passed       |

Argument errors can exit before output creation. Failed terminal publication leaves no passing
result; temporary JSON files are not terminal records. A failed job does not prevent a new job.
Reproduce findings, add regressions and diagnose infrastructure failures through ordinary
maintenance, without changing old result records.

Each command owns a process group. The launcher terminates remaining group members and reaps its
direct child on completion, failure, timeout and handled cancellation. EOF alone is not completion.
Signal handlers defer cancellation until safe registration/retirement checkpoints. Later signals do
not alter an already selected terminal result. This is not a hostile-code sandbox: the CI/container
owner must prevent process-group escape and handle launcher SIGKILL, reboot and whole-job cleanup.
That owner also supplies CPU, memory and disk limits, a credential-free environment and bounded
storage. Local logs, snapshots and deadlines are bounded; there is no shared retained-storage scan.

A fuzz artifact is not automatically minimized. In the same bounded environment, explicitly select
the retained executable and minimize a copy of its artifact:

```sh
ASAN_OPTIONS=detect_odr_violation=0 "$executable" "$artifact" \
  -minimize_crash=1 -max_total_time=30 -exact_artifact_path="$minimized"
ASAN_OPTIONS=detect_odr_violation=0 "$executable" "$minimized" -runs=1
```

Keep original and minimized bytes, hashes, commands and bounded diagnostics. Require the same
property failure, not a setup error or unrelated panic. Replay those exact bytes against a rebuilt
candidate separately and record its identity. A reducer may find no smaller input; report that
result. Do not overwrite an existing artifact or mutate the baseline checkout.

For detection-strength checks, apply one negative control at a time in disposable source copies. The
deterministic corpus driver must pass on baseline and fail for the named property on each copy:

- Accept trailing binary records: `trailing receipt record` or `trailing grant record`.
- Ignore the receipt trust interval: `trust time window`.
- Accept a service document one byte above 160 KiB: `service byte limit`.
- Accept an inconsistent signed Git result: `inconsistent signed statement`.

Record each exact mutation diff, source/executable/compiler identity, input and failing command.
Minimize and replay at least one failure with its mutated executable, then replay the same bytes
against baseline. These are isolated test faults, not changes to maintained production semantics. A
surviving required control blocks coverage retirement. No mutation-score threshold replaces owner,
compatibility, transport or receiver checks.

Infrastructure should alert on nonzero exits, new findings, missing/stuck scheduled jobs, stale
`RUNNING` records, and incomplete evidence. Passing runs need no alert. The infrastructure owner
controls schedules, alert delivery, and activation. This runner neither installs a resident service
nor qualifies native systemd behavior. Public-PR execution remains on hosted CI unless a separately
reviewed isolation design is approved.

Run the small, offline harness regressions with `python3 tools/dev/test_robustness.py`. They cover
independent runs, retained failures, source/corpus snapshots, bounded output, unsafe inputs, exact
completion counts, timeout and cancellation. They do not qualify isolation or reboot behavior on the
deployment host.

## Source privacy and security

The default static gate runs the source privacy check and offline scanner regressions. Run the
privacy check directly with:

```sh
python3 tools/checks/check_source_privacy.py
python3 tools/checks/test_source_checks.py
```

[Privacy](../reference/privacy.md#source-check) describes its scope and limitations. The separate
source security scan requires cargo-audit 0.22.2 and Trivy 0.72.0, network access to refresh their
databases, and a clean committed checkout:

```sh
python3 tools/checks/scan_source_security.py --output /tmp/kapsel-source-security.json
```

It rejects RustSec vulnerabilities or warnings, Trivy HIGH/CRITICAL vulnerabilities and secrets, and
stale or changing Trivy databases. Lower-severity Trivy findings remain in the output for review.
RustSec database identity is captured after a successful refresh and checked again after the scan.
Trivy scans the complete committed Git tree, not ignored build output or uncommitted files. This
source scan does not replace the exact-artifact SBOM scan in the candidate workflow.

## MCP adapter

The fixed service bridge takes no operator document or arguments. The caller identity launches
`/usr/bin/kapsel-service-mcp` against the resident service. See [MCP](../reference/mcp.md) for
framing and ID-only tools. Use the [focused-gate table](build.md#focused-gates) for source checks.

## Release artifact

Requires a clean checkout, Python 3.11+, and Docker with `linux/amd64` support. The sole release
target is `x86_64-unknown-linux-gnu`. The archive contains four executables and operating assets.
Its checksum-bound verifier companion supplies the
[extraction-only route](../reference/release.md#authenticate-and-extract-the-release) without
repository source. Assemble the archive and sidecars under `dist/`:

```sh
python3 tools/release/assemble_artifact.py --output-directory dist
```

For the complete two-assembly proof, keep output outside the worktree:

```sh
a_dir=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-release-a.XXXXXX")
archive_a=$(python3 tools/release/assemble_artifact.py --output-directory "$a_dir")
python3 tools/release/test_artifact.py --archive "$archive_a"
python3 tools/release/test_reproducibility.py --reference-archive "$archive_a"
```

The artifact test invokes the copied companion outside the checkout for inert extraction, then
explicitly runs the extracted `qualification.py` smoke and direct installed-guide profiles. The
single installed procedure checks fixed executable paths, separate service/caller identities,
socket/private-file custody, actual staged-guide key/preparation/publication commands, selection,
client/MCP reads, inspected receipts and cold read-first restart. All operating programs and the
guide come from the selected archive, not a checkout bind. On ARM, `linux/amd64` is emulated and
cannot qualify the native target. Run the [native profile](#native-installed-systemd-qualification)
separately. Packaged Git/Kubernetes own interrupted execution and real receiver evidence. Graceful
restart does not replace those gates. Do not dispatch signing/publication to obtain test evidence.

For a quick hostile-layout and dependency-graph regression without building:

```sh
python3 tools/release/test_verify_artifact.py
python3 tools/release/test_artifact.py --archive /tmp/unused.tar.gz SourceCorrespondenceTests
python3 tools/release/test_qualification.py
python3 tools/release/test_assemble_artifact.py
```

Remove `"$a_dir"` when its evidence is no longer needed.
[Release artifacts](../reference/release.md) defines layout, authentication, publication, and
reproducibility requirements.

### Documented operator example

The artifact test extracts the marked blocks in the [operator guide](../guides/operator.md) and
checks their actual responses. Run against the accepted artifact and its independently recorded
revision:

```sh
python3 tools/release/test_artifact.py --archive "$archive" \
  ReleaseArtifactTests.test_installed_guide
```

The source revision must match the current clean checkout. The procedure executes the bundled
key-generation, snapshot preparation and cold-publication blocks with separate identities. One
successful selection checks the configured signer through independently appointed inspection trust,
exclusive receipt export and MCP stored reads. A cold label replacement and read-first restart
return the original receipt with no receiver I/O. Direct process start/stop replaces systemd, not
the preparation commands. Shared source laws and packaged Git/Kubernetes retain signer repair, trust
withdrawal, uncertainty and interruption obligations; the installed procedure is not another
semantic regression matrix. It does not edit history.

Optional model supervision/custody has its own offline checks in the live runner suite. Its real
process/receipt probes are a separate Docker lane:

```sh
python3 tools/release/test_qualification.py CallerContainerTests
```

These checks do not qualify useful autonomous selection or replace deterministic caller acceptance.

### Native installed-systemd qualification

The authenticated archive carries `share/kapsel/qualification.py --profile systemd` for no-checkout
fresh-host execution. Its
[command, prerequisites and retained-host footprint](../reference/release.md#native-installed-systemd-qualification)
ship in the release guide. This profile adds actual unit, identities, journald, stopped/disabled
state and cold replacement to the same installed procedure. It requires clean selected bytes and
separate root authorization. It uses a loopback fixture, not a live receiver or product crash hook.
Consumer verification never performs these actions.

## Coverage

With cargo-llvm-cov 0.8.7, matching CI:

```sh
cargo llvm-cov --locked --workspace --codecov --output-path codecov.json
```

Coverage is informational and non-blocking, not correctness evidence. CI keeps its ten-minute
generation budget. Missing reports and upload failures fail the informational job visibly without
failing the Default gate.

## Toolchain ownership

Cargo manifests and `Cargo.lock` own Rust dependencies. `rust-toolchain.toml` selects the compiler;
`rustfmt.toml`, `rustfmt-nightly.toml`, `clippy.toml`, and `ruff.toml` own style settings.
[`scripts/fmt.sh`](../../scripts/fmt.sh), [`scripts/ci.sh`](../../scripts/ci.sh), and
[CI](../../.github/workflows/ci.yml) own tool invocation. CI consumes the same setup implementation
and pins as local development. Optional qualification tools keep their pins in their owning lanes.

### Tooling ownership

| Owner                   | Responsibility                                                     |
| ----------------------- | ------------------------------------------------------------------ |
| `xtask/` and `scripts/` | Contributor grammar and command launchers                          |
| `tools/dev/`            | Tool pins, contributor-tool regressions and unattended soak runner |
| `tools/checks/`         | Source checks and their regression tests                           |
| `tools/release/`        | Assembly, standalone verification, SBOM scanning and their tests   |
| `tests/qualification/`  | Environment-specific and long-running evidence lanes               |
| `examples/`             | Maintained fresh-session caller and its tests                      |
| `fuzz/`                 | Fuzz workspace and bounded smoke runner                            |

Rust owns product semantics; Python and shell retain external orchestration and independent checks.
Contributor commands use `cargo xtask <command>` through one Cargo alias. Stock `cargo build`,
`check`, `test` and `fmt` keep their normal meaning; xtask explicitly selects the broader
contributor workflow. A shared command vocabulary does not require a shared tooling library or a
language rewrite. The release verifier remains a standalone distributed file, independent of xtask
and repository imports.

### Tooling names

Rust and Python files use `snake_case`; shell executables use hyphenated names. Contributor shell
entry points mirror their commands: `setup.sh`, `fmt.sh`, `check.sh`, `explore.sh` and `qualify.sh`.
`ci.sh` temporarily retains workflow aliases; `tools/dev/run_checks.py` owns the fixed area mapping.
Name the responsibility rather than repeating the directory: `tools/release/assemble_artifact.py`,
`verify_artifact.py` and `scan_sbom.py` own distinct release steps.

Use `test` for regression suites, `run` for qualification runners, `probe` for independent
experiments, and `demo` for demonstrations. A `check` enforces source rules; a `scan` produces
security or dependency findings; `verify` authenticates and validates an artifact. A smoke lane is a
bounded exercise, not a substitute for the owning qualification gate. Python regressions import
adjacent modules normally; explicit path loading remains useful across owners and in isolated
subprocesses. These conventions add neither aliases nor a shared tooling library. Source filenames
do not rename distributed companions or paths retained in published tags.
