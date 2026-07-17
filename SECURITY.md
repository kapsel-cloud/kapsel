# Security policy

Status: pre-release policy.

Owns: Vulnerability reporting and support posture for the public repository.

Does not own: The threat model, production assurance, technical scope, or release progress.

Kapsel has no supported production version. Do not use the current repository for consequential
production actions.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability involving request parsing, authorization,
Kubernetes credentials, SQLite recovery, receipt signing or inspection, trust evaluation, filesystem
publication, or sensitive disclosure. Report it privately through
[GitHub Security Advisories](https://github.com/mitander/kapsel/security/advisories/new).

Include the affected revision, reproduction steps, impact, and whether disclosure is time-sensitive.
No response-time or remediation SLA is promised before production assurance work is activated.

## Security boundary

Current security claims are owned by:

- [Threat model](docs/THREAT_MODEL.md)
- [Technical scope](docs/V1.md)
- [KAP-0038 experiment owner](docs/experiments/KAP-0038-kubernetes-effect-gateway-boundary.md)
- [Privacy boundary](docs/PRIVACY.md)

The experiment library implements owner-signed exact grants under application-configured trust, a
`FULL`-synchronous SQLite recovery lifecycle, one conditional Kubernetes mutation adapter,
classifier-complete signed prototype receipts, explicit offline trust evaluation, bounded
inspection, and descriptor-relative collision-safe receipt publication on Unix. Deterministic tests
kill a subprocess at the mutation and receipt-publication seams. The explicit live-`kind` gate
covers healthy and unhealthy-image fault-injected journal reopen paths.

Prototype evaluator operation and inspection commands, one thin fixed-schema MCP stdio entrypoint,
and a documented public disposable-`kind` demo exist. They remain pre-V1 experiment surfaces, not a
stable interface or supported production security guarantee. No V1 install artifact exists. The
Unix-only crates.io alpha distributes the implemented Rust experiment interface; it does not satisfy
V1 release acceptance.

A durable journal narrows crash ambiguity. It does not prove exactly-once provider effects,
Kubernetes truth, authorization legitimacy, causation, complete capture, compliance, or production
readiness.
