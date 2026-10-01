# Working on Kapsel

Kapsel is an open-source execution boundary for automated workflows and AI agents.
[README.md](README.md#why-kapsel-exists) owns its purpose and technical ambition.

## Repository owners

- [docs/INDEX.md](docs/INDEX.md): documentation map.
- [CONTRIBUTING.md](CONTRIBUTING.md): engineering and public writing conventions.
- [docs/BUILD.md](docs/BUILD.md): commands, prerequisites, and validation gates.
- [docs/SCOPE.md](docs/SCOPE.md): current capability and release limits.
- [docs/EFFECT_GATEWAY.md](docs/EFFECT_GATEWAY.md): authority, lifecycle, recovery, and evidence.

Read the contract, code, and tests for the changed behavior. Check Git status and preserve unrelated
work. Decisions explain rationale; they do not override current contracts.

## Kapsel constraints

- Keep credentials, grants, trust, signing material, paths, and lifecycle controls outside caller
  input.
- Preserve operation identity and durable ordering. Recovery must not turn recorded history into
  fresh permission to mutate.
- Keep request acceptance, transport outcomes, receiver observations, and causation distinct.
  Preserve `UNKNOWN` when evidence cannot establish an outcome.
- Test guarantees at the boundary that owns them.
- Prefer concrete implementations and small, deep interfaces. Extract shared machinery from real
  implementations, not a speculative provider framework.
- Update capability claims with implementation and evidence. Current source does not change a
  published release.
- Keep public content technical and reproducible. Omit private evidence and operational paths.

## Validation

Run `cargo xtask fmt`. Documentation changes need local link and anchor checks, terminology review,
and `git diff --check`. Follow the [public writing policy](CONTRIBUTING.md#technical-writing). Code
changes also need the relevant behavior checks and broader gate from [docs/BUILD.md](docs/BUILD.md).
Name any missing prerequisite when a required check cannot run.
