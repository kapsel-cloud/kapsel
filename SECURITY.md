# Security policy

Kapsel v0.2.0 is a published developer beta, not a supported production release. Do not use it for
consequential production actions. Only the latest v0.2.x patch receives best-effort security and
correctness maintenance. Kapsel promises no response-time, remediation, availability, platform, or
production-support SLA.

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

The service and installer present in repository HEAD remain unpublished and unsupported. Their
presence does not extend the v0.2.0 support posture.
