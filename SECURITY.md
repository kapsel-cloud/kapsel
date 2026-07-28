# Security policy

Status: current `v0.1.1` experiment policy and adopted v0.2 beta maintenance posture.

Owns: Vulnerability reporting and support posture for the public repository.

Does not own: The threat model, production assurance, technical scope, or release progress.

Kapsel has no supported production version. Do not use the current repository or the planned v0.2
developer beta for consequential production actions. The current published artifact remains
`v0.1.1`; a `0.2.0` candidate implementation and adopted policy do not mean that v0.2 has passed
release acceptance or been published.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability involving request parsing, authorization,
Kubernetes credentials, SQLite recovery, receipt signing or inspection, trust evaluation, filesystem
publication, or sensitive disclosure. Report it privately through
[GitHub Security Advisories](https://github.com/kapsel-cloud/kapsel/security/advisories/new).

Include the affected revision, reproduction steps, impact, and whether disclosure is time-sensitive.
Only the latest v0.2.x patch will receive best-effort security and correctness maintenance. No
response-time, remediation, availability, platform, or production-support SLA is promised.

## Security boundary

Current security claims are owned by:

- [Threat model](docs/THREAT_MODEL.md)
- [Technical scope](docs/SCOPE.md)
- [KAP-0038 experiment owner](docs/experiments/KAP-0038-kubernetes-effect-gateway-boundary.md)
- [Privacy boundary](docs/PRIVACY.md)

The experiment library implements owner-signed exact grants under application-configured trust, a
`FULL`-synchronous SQLite recovery lifecycle, one conditional Kubernetes mutation adapter,
classifier-complete signed prototype receipts, explicit offline trust evaluation, bounded
inspection, and descriptor-relative collision-safe receipt publication on Unix. Deterministic tests
kill a subprocess at the mutation and receipt-publication seams. The explicit live-`kind` gate
covers healthy and unhealthy-image fault-injected journal reopen paths.

Evaluator operation and inspection commands, one thin fixed-schema MCP stdio entrypoint, and a
documented public disposable-`kind` demo exist in `v0.1.1`. The exact CLI, MCP, grant v1, and
receipt/trust v2 surfaces selected by the [v0.2 release design](docs/V0.2.md) are bounded beta
compatibility commitments, not supported production security guarantees. Public Rust exports,
crates.io, docs.rs, `cargo install`, another MCP transport, another platform, and production use
remain unsupported. Release artifact availability and supported targets are owned by the
[release contract](docs/RELEASE.md). The v0.2 candidate contract appoints one exact GitHub Actions
workflow through keyless Sigstore authentication. Its signed digest manifest authenticates the
approved publisher action and named bytes; it does not prove source review, workflow or builder
integrity, dependency safety, production fitness, or current non-withdrawal. A SHA-256 checksum
alone detects byte mismatch but does not authenticate a publisher.

A durable journal narrows crash ambiguity. It does not prove exactly-once provider effects,
Kubernetes truth, authorization legitimacy, causation, complete capture, compliance, or production
readiness.
