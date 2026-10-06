# Security policy

Kapsel is non-production software. Do not use it for consequential production actions. There is no
response-time, remediation, availability, platform, or production-support SLA. For release-specific
maintenance commitments, consult the security policy shipped with the affected release.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability involving request parsing, authorization,
Kubernetes credentials, recovery, receipt signing or inspection, trust evaluation, filesystem
publication, or sensitive disclosure. Report it privately through
[GitHub Security Advisories](https://github.com/kapsel-cloud/kapsel/security/advisories/new).

Include the affected revision, reproduction steps, impact, and whether disclosure is time-sensitive.

## Technical boundaries

These documents own the current security claims and limits:

- [Technical scope](docs/scope.md) — supported surface, maturity, and non-goals.
- [Effect-gateway contract](docs/reference/effect_gateway.md) — authorization, lifecycle, recovery,
  results, receipts, and inspection.
- [Threat model](docs/reference/threat_model.md) — adversaries, assumptions, surviving claims, and
  non-claims.
- [Privacy](docs/reference/privacy.md) — sensitive fields and disclosure rules.
