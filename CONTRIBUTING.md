# Contributing to Kapsel

Try concrete ideas in a disposable environment and carry useful results into the implementation.

Start by checking Git status and preserving unrelated work. Then read
[Why Kapsel exists](README.md#why-kapsel-exists), the [technical scope](docs/SCOPE.md), the
[documentation map](docs/INDEX.md), and the direct contract, implementation, tests, and vectors for
the surface you will change. Contracts own behavior; decisions explain why; guides own runnable
commands; tests provide executable evidence.

The published v0.3.0-preview.1 service preview and older v0.2.0 beta are different promises. Link
the exact release and technical owner. A published preview is not production support, and current
source changes do not alter previously published bytes.

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

Untrusted bytes must not acquire authority from their contents, trigger network access during
offline inspection, panic the gateway or inspector, allocate or recurse without enforced bounds, or
advance evidence state without the required external fact. Use checked arithmetic and conversions
for hostile lengths. Bound individual items, cumulative work, and diagnostics.

Use always-on assertions only for invariants controlled by valid internal code. Return typed errors
for caller input, signatures, trust, provider responses, time, configuration, filesystem, SQLite,
and other operating failures. Never assert a fact controlled by a caller, receiver, or provider.
Production `expect()` calls must state the invariant that makes the panic unreachable; do not use an
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

A function should perform one coherent phase at one level of abstraction. Treat length as a review
prompt, not a metric: split validation, mutation, I/O, and presentation when they represent distinct
responsibilities, not merely to satisfy a line count. Use identity and unit newtypes when accidental
interchange would compile and could change meaning.

Add an interface only when it contains policy, preserves a durable state or format owner, keeps I/O
from pure logic, maintains dependency direction, or provides a useful deterministic seam. Prefer a
concrete type or exhaustive enum until multiple real consumers establish the need for a trait or
generic framework. Prefer `pub(crate)` or narrower visibility. Avoid generic `util`, `common`,
provider, or package seams without multiple real consumers or a measured dependency boundary. Name
functions for the fact they establish.

### Documentation and dependencies

The README states the project's purpose and technical ambition. Linear owns the ordered roadmap,
priorities, assignments, and progress. Do not duplicate the backlog or progress ledger in Markdown.
Public documentation describes the project, current technical contracts, active rationale, runnable
guidance, and reproducible evidence. A planned change is not implemented behavior.

Delete deprecated documents and retired proposals from the current tree. Preserve still-valid
invariants in the direct owner and repair inbound references in the same change. Git history and
release tags retain previous material; do not add archives or tombstone replacements.

Features, simplifications, and technical exploration all belong here. Compare concrete
implementations before extracting shared machinery. When a prototype works and fits the agreed task,
integrate it with the relevant contracts and tests. When it does not, use the result to improve the
design or explain the concrete obstacle. Remove discarded alternatives once they have served their
purpose.

Public Rust documentation states caller-visible input, bounds, authority, side effects, failures,
and important non-claims. Every externally reachable public item needs rustdoc. Public `Result`
functions need `# Errors`; document caller-reachable panics with `# Panics`, though removing the
panic is usually better. Unsafe APIs require `# Safety`; this workspace currently forbids unsafe
code, and any exception requires an explicit security review and accepted decision. Use applicable
rustdoc sections in this order: `# Errors`, `# Panics`, `# Safety`, `# Cancellation safety`,
`# Performance` or `# Complexity`, platform-specific behavior, then `# Examples`. Examples compile
as doctests and handle errors without `unwrap()` or `expect()`.

Prefer a better name, type, state, assertion, or smaller scope over a comment. Comments should
explain a non-local invariant, security or crash-recovery subtlety, compatibility constraint, or why
the obvious alternative is wrong. Dependencies are design choices; use maintained cryptographic and
encoding libraries rather than custom implementations.

## Tests and commands

Place a test at the lowest layer whose interface owns the behavior. Higher layers prove composition,
authority separation, durable outcomes, observable output, and non-disclosure instead of repeating
the same parser or classifier matrix. The [testing strategy](docs/TESTING.md) owns proof placement
and evidence classes; [Build and test](docs/BUILD.md) owns commands and prerequisites.

Prepare contributor tools once with `cargo xtask setup`. It installs isolated pinned formatters
without global installs or shell activation. Use `cargo xtask doctor` for read-only prerequisite
diagnosis. Ordinary `cargo build --locked --workspace` and `cargo check --locked --workspace` remain
the fast local entry points. The optional pre-commit hook checks staged whitespace only, not test
acceptance. Full checks belong to pre-push and CI.

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

The format command covers Rust, Python, Markdown, structured data, and shell scripts. Prettier reads
`.prettierrc.json`; shfmt 3.14.1 uses two-space indentation, and the static gate runs ShellCheck
0.11.0. Setup installs the shell binaries into the existing isolated tool environment. TOML uses
Taplo 0.10.0. Install it through a system package manager or
`cargo install --locked taplo-cli --version 0.10.0` before running setup.

Formatting sorts imports before running Ruff's formatter. It does not apply other lint fixes. Review
other fixes explicitly, avoid unsafe fixes, and use only narrow, explained suppressions.
[Build and test](docs/BUILD.md#deterministic-gate-and-formatting) owns setup and commands.

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

Put useful rationale in the existing review discussion or owning decision. No fixed candidate count
or report template is required. Design and documentation are part of delivering the change, not
separate permission stages. State what changed, what ran, and any concrete limitation that matters.
