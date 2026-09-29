# Working on Kapsel

Kapsel is an open-source execution boundary for automated workflows and AI agents. Its purpose and
technical ambition live in [README.md](README.md#why-kapsel-exists).

## Get oriented

Check Git status and preserve unrelated work. Read the README and the direct contract, code, and
tests for the change. Use [docs/INDEX.md](docs/INDEX.md) to find them. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for engineering conventions and [docs/BUILD.md](docs/BUILD.md)
for commands. Do not reread every decision for every task.

Linear owns ordered work, dependencies, assignment, and progress. The repository owns technical
ambition, implemented behavior, design rationale, and executable examples. Keep one task queue; do
not create another roadmap or completion ledger here. Current scope describes what exists, not a
ceiling on requested development. Private planning notes are never a prerequisite to code.

## Carry the work through

- A request to implement a feature includes the routine design choices, refactoring, contract
  changes, tests, and documentation needed to complete it. Make those changes together.
- Treat an agreed direction as decided. Revisit it when implementation or failure evidence exposes a
  concrete problem, not merely because a new session starts.
- Use a probe when it answers a real unknown. Once it answers the question, continue the selected
  feature through integration. Do not stop at the probe or create another adoption ticket.
- Prefer maintained, runnable functionality. For an explicitly exploratory task, a useful negative
  result can be the outcome; explain what failed and remove abandoned paths.
- When code and documentation disagree, inspect the owning behavior and fix the inconsistency within
  the task. Explain intentional behavior changes. Do not convert ordinary design work into missing
  permission.
- Ask when a choice changes the requested goal, risks unrelated data, or needs access or external
  effects the user has not authorized. Do all independent work that can still proceed.

## Keep the engineering precise

[docs/SCOPE.md](docs/SCOPE.md) describes current capability and release limits.
[docs/EFFECT_GATEWAY.md](docs/EFFECT_GATEWAY.md) owns authority, lifecycle, recovery, and evidence.

- Keep credentials, grants, trust, signing material, paths, and lifecycle controls outside caller
  input.
- Preserve operation identity, durable ordering, and explicit recovery semantics. Recovery must not
  turn recorded history into fresh permission to mutate.
- Keep request acceptance, transport outcomes, receiver observations, and causation distinct.
  Preserve `UNKNOWN` when the evidence cannot establish an outcome.
- Keep guarantees at their owning boundary. Test failures there; let callers use the interface.
- Prefer concrete implementations and small, deep interfaces. Extract common machinery from real
  implementations. A new receiver needs precise semantics, not a general provider framework.
- Update capability claims when implementation and evidence support them. Planned work is not
  shipped behavior; current source does not rewrite a published release.
- Keep public content reproducible and technical. Omit private evidence and operational paths.

## Finish cleanly

Run `./scripts/format.sh` for Markdown, Rust, and Python formatting. Documentation changes need
local links and anchors and `git diff --check`. Code changes need the relevant behavior checks and
applicable broader gate from [docs/BUILD.md](docs/BUILD.md). Do not repeat checks that add no
evidence. If a check cannot run, name the missing prerequisite and finish what can be verified.

Keep current documentation close to the code. Delete superseded explanations, repair links, and use
Git history for old material. Explain the interesting mechanism in plain technical language. Report
what now works and any material limitation. No mandatory complexity report or adoption form. Commit,
push, release, and deploy only within the user's authorization.
