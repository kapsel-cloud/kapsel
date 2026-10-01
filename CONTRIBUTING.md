# Contributing to Kapsel

Check Git status and preserve unrelated work. Read [Why Kapsel exists](README.md#why-kapsel-exists)
and the [technical scope](docs/SCOPE.md). Use the [documentation map](docs/INDEX.md) to find the
contract, implementation, tests, and vectors for your change.

Try ideas in disposable environments. Integrate useful results with their contracts and tests. Keep
current source, the v0.3.0-preview.1 service preview, and the older v0.2.0 beta distinct. Link the
exact release when describing its behavior. Source changes do not alter published bytes.

## Engineering rules

[ADR 0001](docs/decisions/0001-kapsel-style.md) owns the engineering philosophy and design
criterion. The [complexity review](#complexity-review) gives design prompts when they help resolve a
real tradeoff.

Prioritize the boundaries that make Kapsel useful:

1. Preserve authority and effect boundaries.
2. Make durable states and transitions explicit.
3. Bound hostile input and resource use before allocation, I/O, or diagnostics.
4. Keep provider acceptance, receiver observation, and transport outcomes distinct.
5. Prefer small, deep interfaces over reusable frameworks.
6. Test contracts at the layer that owns them.

The [technical scope](docs/SCOPE.md) owns the product boundary. The
[effect-gateway contract](docs/EFFECT_GATEWAY.md) owns exact authorization, lifecycle, recovery,
receiver-result, and receipt semantics. Do not duplicate those contracts here.

### Hostile input and operating failures

Untrusted bytes must not:

- appoint authority through their contents;
- trigger network access during offline inspection;
- panic the gateway or inspector;
- cause allocation or recursion without enforced bounds; or
- advance evidence state without the required external fact.

Use checked arithmetic and conversions for hostile lengths. Bound individual items, cumulative work,
and diagnostics.

Use always-on assertions only for invariants controlled by valid internal code. Return typed errors
for caller input, signatures, trust, provider responses, time, configuration, filesystem, SQLite,
and other operating failures. Never assert a fact controlled by a caller, receiver, or provider.
Production `expect()` calls must state the invariant that makes the panic unreachable. Do not use an
unexplained `unwrap()` where an operating or adversarial failure is possible.

### Types, interfaces, and modules

Keep these facts distinct in types and exhaustive states where collapsing them could change security
meaning. Avoid wildcard matches when adding an enum variant should force a policy decision:

```text
bounded request
  -> authorized operation
  -> durable mutation attempt
  -> provider acceptance
  -> receiver observation
  -> classified outcome
  -> signed disclosure
  -> inspected under supplied trust
```

Pass authority, time, trust, paths, and limits explicitly. A helper must not discover them through
the environment, filesystem, network, or ambient configuration.

A function should perform one coherent phase at one level of abstraction. Separate validation,
mutation, I/O, and presentation when they have distinct responsibilities, not to satisfy a line
count. Use identity and unit newtypes when accidental interchange could compile and change meaning.

Add interfaces to contain policy, preserve state or format ownership, separate I/O from pure logic,
maintain dependency direction, or support deterministic tests. Prefer concrete types or exhaustive
enums until real consumers need a trait or generic framework. Prefer `pub(crate)` or narrower
visibility. Avoid generic `util`, `common`, or provider modules without real consumers or a measured
dependency boundary. Name functions for the fact they establish.

### Documentation and dependencies

The README owns purpose and ambition. Contracts own behavior; decisions explain rationale; guides
own procedures. Link to those owners rather than duplicating their detail. Do not describe planned
work as implemented behavior.

Remove superseded documents and retired proposals. Keep valid invariants in their direct owner and
repair inbound links. Git history and release tags retain previous material; do not add archives or
tombstone pages. Integrate useful prototypes with their contracts and tests. Remove discarded paths.

Every externally reachable public Rust item needs rustdoc. State caller-visible inputs, bounds,
authority, side effects, failures, and important non-claims. Public `Result` functions need
`# Errors`. Document caller-reachable panics with `# Panics`; prefer removing them. Unsafe APIs
require `# Safety`. The workspace forbids unsafe code. Any exception requires explicit security
review and an accepted decision.

Use applicable rustdoc sections in this order: `# Errors`, `# Panics`, `# Safety`,
`# Cancellation safety`, `# Performance` or `# Complexity`, platform-specific behavior, then
`# Examples`. Examples must compile as doctests and handle errors without `unwrap()` or `expect()`.

Prefer a better name, type, state, assertion, or smaller scope over a comment. Comments should
explain a non-local invariant, security or crash-recovery subtlety, compatibility constraint, or why
the obvious alternative is wrong. Dependencies are design choices; use maintained cryptographic and
encoding libraries rather than custom implementations.

## Tests and commands

Test behavior at the lowest layer whose interface owns it. Higher layers test composition, authority
separation, durable outcomes, output, and non-disclosure. Do not repeat parser or classifier
matrices there. [Testing](docs/TESTING.md) owns proof placement and evidence classes.

Prepare contributor tools with `cargo xtask setup`. Use `cargo xtask doctor` to check prerequisites
without installing tools. Ordinary Cargo builds and checks remain the fast local entry points.
[Build and test](docs/BUILD.md) owns tool versions, setup details, and optional hooks.

Authored Rust has a 100-byte physical-line limit. Reshape expressions rather than shortening precise
names or adding an abstraction solely to satisfy the limit. Keep embedded SQL readable and
multiline. Markdown prose wraps at 100 columns; tables, URLs, and code blocks are exempt where
wrapping harms clarity. Automate only objective, stable rules; naming, module ownership, comments,
and abstraction quality remain review judgments. Before review, run:

```sh
cargo xtask fmt
cargo xtask ci
```

Use the narrowest owning gate first when the full deterministic gate is impractical.
Documentation-only changes still require formatting, local link and anchor checks, focused
terminology checks, and `git diff --check`.

### Python tooling

Python scripts follow the engineering rules above. Rust owns product lifecycle and recovery
semantics; Python owns external orchestration and independent checks. Prefer the standard library.
Use annotations at meaningful boundaries and preserve exception causes when adding context. Bound
subprocess output and execution time, and clean up only resources owned by the invocation.

[`ruff.toml`](ruff.toml) owns Python style: Python 3.11-compatible syntax, four-space indentation,
double quotes, LF endings, and a 100-column target. Unlike Rust's physical-line limit, the Python
target allows exact fixture strings and indivisible URLs to remain intact. Lint checks basic errors,
unused names, import ordering, and likely bugs, not general code quality or safety.

Formatting sorts imports before running Ruff's formatter. It does not apply other lint fixes. Review
those fixes explicitly. Avoid unsafe fixes and use only narrow, explained suppressions.

## Technical writing

Write for the reader's task. Name the actor, use concrete verbs, and keep each sentence focused. Put
prerequisites and safety conditions before commands, then state the expected result. Keep exact
identifiers, requirement strength, limits, and release distinctions.

Use Kapsel terms consistently. The operator supplies authority; the caller requests an approved
operation. A grant authorizes; a receipt records evidence. An attempt is not acceptance, acceptance
is not a receiver result, and an observation does not prove causation. Recovery does not imply
permission to resend. `SUCCEEDED`, `FAILED`, `UNKNOWN`, `NOT_ATTEMPTED`, and `INSPECTED` retain
their [contract-defined meanings](docs/EFFECT_GATEWAY.md). Do not substitute `VERIFIED` for
`INSPECTED`.

Link to exact contracts instead of copying their full detail. Remove obsolete prose, but retain
warnings needed to act safely. Compare rewrites with their owners and run formatting and local link
and anchor checks. These are project writing conventions, not an ASD-STE100 compliance claim.

## Commits and review

Use a plain domain-oriented, imperative commit subject:

```text
<domain>: <imperative result>
```

Examples: `k8s: preserve receiver generation across recovery` and
`docs: tighten the active capability contract`.

Before handing off a change, check:

- the direct contract owner is correct and no second source of truth was introduced;
- caller input gained no authority, credential, path, lifecycle control, or unbounded field;
- durable state is committed before its effect and recovery cannot blindly repeat a mutation;
- request acceptance, timeout, crash, or transport completion cannot become a receiver result;
- `SUCCEEDED`, `FAILED`, `UNKNOWN`, `NOT_ATTEMPTED`, and `INSPECTED` retain their exact
  owner-defined meanings;
- trust, time, limits, and authority are explicit rather than ambient;
- operating and adversarial failures are typed, bounded, and non-disclosing;
- new interfaces and dependencies have a current concrete need;
- tests sit at the owning layer and the narrowest meaningful gate passed; and
- documentation links resolve, status is current, and the diff contains no stale or duplicated
  truth.

### Complexity review

[ADR 0001](docs/decisions/0001-kapsel-style.md#simplicity-is-the-design-criterion) explains the
design criterion. For a meaningful tradeoff, ask what knowledge each design hides, which rules it
duplicates, and what interfaces or special cases it adds. Try another design when that comparison
could change the choice. Remove obsolete machinery when its replacement works.

Record useful rationale in the review discussion or owning decision. Include the design and
documentation with the change, plus the checks performed and any material limitation.
