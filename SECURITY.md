# Security policy

Kapsel v0.3.0-preview.1 is a published non-production service preview. The earlier v0.2.0 developer
beta is a separate release. Do not use either for consequential production actions. Only the latest
v0.2.x patch has the beta's existing best-effort security and correctness maintenance posture. The
preview introduces no response-time, remediation, availability, platform, or production-support SLA.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability involving request parsing, authorization,
Kubernetes credentials, recovery, receipt signing or inspection, trust evaluation, filesystem
publication, or sensitive disclosure. Report it privately through
[GitHub Security Advisories](https://github.com/kapsel-cloud/kapsel/security/advisories/new).

Include the affected revision, reproduction steps, impact, and whether disclosure is time-sensitive.

## Technical boundaries

These documents own the current security claims and limits:

- [Technical scope](docs/SCOPE.md) — supported surface, maturity, and non-goals.
- [Effect-gateway contract](docs/EFFECT_GATEWAY.md) — authorization, lifecycle, recovery, results,
  receipts, and inspection.
- [Threat model](docs/THREAT_MODEL.md) — adversaries, assumptions, surviving claims, and non-claims.
- [Privacy](docs/PRIVACY.md) — sensitive fields and disclosure rules.

Report preview vulnerabilities through the same private channel. Preview publication does not extend
the v0.2.0 support posture or establish production support.
