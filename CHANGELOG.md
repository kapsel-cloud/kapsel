# Changelog

All notable public alpha distributions of Kapsel are recorded here.

## 0.1.0-alpha.1 - 2026-07-16

First crates.io alpha of the bounded Kubernetes effect-gateway experiment.

- Provides one request grammar for `kubernetes.set_deployment_image` with immutable image digests.
- Verifies one owner-signed exact authorization grant under application-configured trust.
- Persists the crash-recoverable lifecycle in a FULL-synchronous SQLite rollback journal.
- Reconciles after the durable mutation marker without a blind second Kubernetes mutation.
- Classifies bounded receiver facts as `SUCCEEDED`, `FAILED`, or `UNKNOWN`.
- Prepares and immutably publishes classifier-complete prototype receipt bytes.
- Inspects receipts offline under explicit trust, evaluation time, and resource limits.
- Separates request-only `AgentRequest` from operator-owned authority through the Rust `Application`
  composition interface.

This alpha has no supported CLI, MCP adapter, stable Rust API, stable receipt format, or
production-readiness claim.
