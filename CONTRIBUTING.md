# Contributing to Kapsel

Kapsel has two concrete effects and some deliberately awkward failure cases. A patch can be accepted
without a response. A Git ref can contain the desired commit without evidence that Kapsel put it
there. A receipt can be complete even though its caller never managed to export it.

If those problems interest you, start with the [tour](docs/tour.md). It follows one operation
through the design. [Architecture](docs/contributing/architecture.md) then shows where the code
implements each choice. For a change you already have in mind, read its contract and tests first.
[Current limits](docs/scope.md) distinguish what works today from what the project does not yet
provide. Check Git status and preserve unrelated work.

## Build and check

[Build and test](docs/contributing/build.md) covers prerequisites and the everyday loop:

```sh
cargo xtask setup
cargo xtask fmt
cargo xtask ci
```

Use focused tests while iterating. Run the full deterministic gate for cross-cutting code or
contract changes and before push. Add the relevant process, live-receiver, native, or artifact lane
from [Qualification](docs/contributing/qualification.md) when a changed guarantee needs it. Name
missing prerequisites instead of treating a smaller passing check as equivalent.

[Test strategy](docs/contributing/testing.md) explains test placement; the
[evidence map](docs/contributing/evidence.md) identifies maintained checks. Try receiver changes in
disposable environments, not existing resources.

## Change the behaviour and its contract together

Prioritize these boundaries:

1. Caller input cannot appoint authority, credentials, trust, signing material, or private paths.
2. Durable state precedes external mutation; attempted recovery cannot send again.
3. Acceptance, transport outcomes, receiver observations, and causation remain distinct.
4. Hostile input is bounded before allocation, I/O, or diagnostics.
5. Original authority and signed evidence remain unchanged across reconnect and recovery.

Prefer concrete implementations and small, deep interfaces. Share machinery only when real
implementations establish the same rule. [Engineering conventions](#engineering-conventions) below
give the Rust, Python, and interface rules. [ADR 0001](docs/decisions/0001-kapsel-style.md) explains
the design criterion.

Include the implementation, tests, and documentation with the change. Put durable rationale in an
owning decision when needed; decisions do not override current contracts. Record unreleased
behaviour differences in the changelog. Published tags and bytes retain their original meaning.

## Engineering conventions

These conventions apply to maintained Rust and Python code. Contracts define behaviour; conventions
must not weaken their guarantees.

### Failures and hostile input

Untrusted bytes must not appoint authority, trigger network access during offline inspection, panic
the gateway or inspector, cause unbounded allocation/recursion, or advance evidence without the
required external fact. Use checked arithmetic and conversions for hostile lengths. Bound individual
items, cumulative work, and diagnostics before use.

Use always-on assertions only for invariants controlled by valid internal code. Return typed errors
for caller input, signatures, trust, provider responses, time, configuration, filesystem, SQLite,
and other operating failures. Never assert a caller-, receiver-, or provider-controlled fact.
Production `expect()` calls must state the invariant making the panic unreachable. Do not use an
unexplained `unwrap()` where operating or adversarial failure is possible.

### Types and interfaces

Keep security-significant facts distinct in types and exhaustive states:

```text
bounded request -> authorized operation -> durable mutation attempt
  -> provider acceptance -> receiver observation -> classified outcome
  -> signed disclosure -> inspected under supplied trust
```

Avoid wildcard matches when a new enum variant should force a policy decision. Pass authority, time,
trust, paths, and limits explicitly; helpers must not discover them through ambient state. Use
identity and unit newtypes when accidental interchange could compile and change meaning.

A function should perform one coherent phase at one abstraction level. Separate validation,
mutation, I/O, and presentation when their responsibilities differ, not to satisfy a line count.
Name functions for the fact they establish.

Add interfaces to contain policy, preserve state or format ownership, separate I/O from pure logic,
maintain dependency direction, or support deterministic tests. Prefer concrete types or exhaustive
enums until real consumers need a trait or generic framework. Prefer `pub(crate)` or narrower
visibility. Avoid generic `util`, `common`, or provider modules without real consumers or a measured
boundary. Use maintained cryptographic and encoding libraries rather than custom implementations.

For a consequential design tradeoff, compare what knowledge each design hides, which rules it
duplicates, and which interfaces or special cases it adds. Record useful rationale in review or the
owning decision. Remove obsolete machinery when its replacement works.

### Rust documentation and layout

Every externally reachable public Rust item needs rustdoc. State caller-visible inputs, bounds,
authority, side effects, failures, and important non-claims. Public `Result` functions need
`# Errors`. Document caller-reachable panics with `# Panics`; prefer removing them. Unsafe APIs
require `# Safety`. The workspace forbids unsafe code. Any exception requires explicit security
review and an accepted decision.

Use applicable rustdoc sections in this order: `# Errors`, `# Panics`, `# Safety`,
`# Cancellation safety`, `# Performance` or `# Complexity`, platform-specific behaviour, then
`# Examples`. Examples must compile as doctests and handle errors without `unwrap()` or `expect()`.

Prefer a better name, type, state, assertion, or smaller scope over a comment. Comments should
explain a non-local invariant, security or crash-recovery subtlety, compatibility constraint, or why
the obvious alternative is wrong.

Authored Rust has a 100-byte physical-line limit. Reshape expressions rather than shorten precise
names or add an abstraction solely to satisfy it. Keep embedded SQL readable and multiline. Markdown
prose wraps at 100 columns; tables, URLs, and code blocks are exempt when wrapping harms clarity.
Automate objective, stable rules; naming, module ownership, comments, and abstraction quality remain
review judgments.

### Python tooling

Rust owns product lifecycle and recovery semantics; Python owns external orchestration and
independent checks. Prefer the standard library. Use annotations at meaningful boundaries and
preserve exception causes when adding context. Validate decoded records before exposing their types;
an annotation or cast does not validate input. Bound subprocess output and execution time, and clean
up only invocation-owned resources.

[`pyrightconfig.json`](pyrightconfig.json) owns maintained typing scope, targeting Python 3.11 on
Linux and macOS. The source-privacy checker uses strict checking; other selected scripts use
standard checking. [`ruff.toml`](ruff.toml) owns Python 3.11-compatible syntax, four-space
indentation, double quotes, LF endings, and a 100-column target. Unlike Rust's physical-line limit,
exact fixture strings and indivisible URLs may remain intact. Lint checks basic errors, unused
names, import ordering, and likely bugs, not general quality or safety.

Use blank lines for logical sections and named intermediate values for conditions, comparisons, or
units. Extract coherent phases, but keep service lifetime, recovery ordering, and cleanup ownership
visible. Comments explain constraints or assertions rather than narrate statements. Passing Ruff and
Pyright does not establish readability.

Keep maintained fixture programs in `.py` files rather than multiline Python strings. Use an
import-safe `main()` and include files in typing scope. Where custody requires isolation, transfer
exact source bytes and execute with an isolated interpreter; do not import caller-writable helpers.
Tiny probes and intentionally malformed-source fixtures may remain inline.

Formatting sorts imports before Ruff's formatter and applies no other lint fixes. Review fixes
explicitly, avoid unsafe fixes, and use only narrow, explained suppressions. Contributor tooling
pins and invocation details are in [Build](docs/contributing/build.md) and
[Qualification](docs/contributing/qualification.md#contributor-tooling-details).

## Technical writing

Write for a reader's task. Separate explanations, procedures, exact reference, and contributor
evidence. A page should answer one primary question. Put prerequisites and safety conditions before
commands, then explain the expected result. Use one concrete scenario instead of repeating abstract
guarantees. [Documentation](docs/index.md) shows the reader routes.

Name the actor and use concrete verbs. Keep identifiers, requirement strength, limits, and release
distinctions exact. In contracts, use “must” for requirements, “should” for recommendations, and
“may” for permission. Use Kapsel terms consistently:

- The operator supplies authority; the caller selects an approved operation.
- A grant authorizes; a receipt records evidence.
- Attempt, acceptance, and observation are different facts. An observation does not prove causation.
- Recovery does not grant permission to resend. `UNKNOWN` is not failure or safe retry.
- Offline inspection reports `INSPECTED`, never `VERIFIED`.

Keep one authoritative definition and link to it. Retain a local warning when it changes the next
action; do not copy full exclusion lists or qualification inventories into every guide. Keep test
commands and evidence production in contributor documentation unless the reader is running a test.
Remove superseded prose rather than adding archives, tombstones, or change narratives. Git history
and release tags retain it. These conventions are not an ASD-STE100 compliance claim.

### Documentation paths

Use lowercase `snake_case.md` for ordinary documentation. Keep established root names such as
`README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `AGENTS.md`, and `CHANGELOG.md`. Numbered decisions
retain their existing hyphenated identifiers and `decisions/README.md` navigation entry.

Keep the documentation map and introductory routes directly under `docs/`. Put procedures in
`docs/guides/`, exact contracts in `docs/reference/`, and implementation and qualification material
in `docs/contributing/`. Use [the map](docs/index.md) for navigation; do not duplicate it with group
landing pages. Prefer one level of grouping and names that identify the reader's task or subject.

Use relative links with exact filename case. Repair inbound paths and heading anchors together when
moving content. Release archive names are separate from source paths: preserve installed names
through the explicit mappings in `tools/release/assemble_artifact.py`. Published tags and artifact
bytes do not change when source documentation moves.

For documentation changes, run formatting, local link/anchor checks, terminology review, and
`git diff --check`. Preserve or repair inbound anchors. Execute changed examples through their
owning checks. Contract edits need semantic review, not just shorter sentences.

## Review and commits

Review the changed boundary: authority, ordering, recovery, result meaning, original bytes, input
bounds, and disclosure. Confirm that tests cross the interface owning the guarantee. Explain the
checks performed and any material limitation. Source coverage and model agreement are not proof that
a workflow works.

Use a plain domain-oriented imperative subject, for example:

```text
k8s: preserve receiver generation across recovery
docs: separate caller procedures from qualification
```

Release acceptance and publication follow the
[release process](docs/contributing/release_process.md).
