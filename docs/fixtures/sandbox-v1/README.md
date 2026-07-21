# Sandbox `v1` contract fixtures

Status: normative consumer fixtures for the demonstration-scoped
[public sandbox API](../../SANDBOX_API.md).

Each JSON file is a bounded HTTP transcript. `request` and `response` own the exact method, path,
headers, status, and JSON body relevant to the named behavior. Header names are lowercase in
fixtures so consumers can compare them without depending on HTTP casing. Real JSON serialization may
vary whitespace but not field names, types, enum spelling, or values derived from one run.

| Fixture                                                  | Behavior                                      |
| -------------------------------------------------------- | --------------------------------------------- |
| [`healthy.json`](healthy.json)                           | Admission, replay, terminal healthy snapshot  |
| [`unavailable-image.json`](unavailable-image.json)       | Failed rollout, events, raw receipt retrieval |
| [`saturation.json`](saturation.json)                     | Capacity rejection before admission           |
| [`setup-failure.json`](setup-failure.json)               | Terminal pre-Application sandbox failure      |
| [`expiry.json`](expiry.json)                             | Non-disclosing expired tombstone              |
| [`errors.json`](errors.json)                             | Remaining bounded v1 error classes            |
| [`incompatible-version.json`](incompatible-version.json) | Unknown version failure                       |
| [`unavailable-service.json`](unavailable-service.json)   | Global-stop/dependency failure                |

`unavailable-image.json` points to a deterministic KAP-0038 V2 receipt hex fixture and its exact
SHA-256. The signed statement uses the same synthetic operation identity and a `FAILED`
`ProgressDeadlineExceeded` observation. The raw bytes are unchanged classifier-complete receipt
evidence at the HTTP boundary; they are not JSON and transport does not appoint trust. The fixed API
transcript uses synthetic times and run identities and does not claim those values were served by a
live deployment.

Validate all fixtures with:

```sh
python3 scripts/test-sandbox-contract.py
```

The gate uses only the Python standard library. It checks exact public key sets, bounds, enum and
nullable-field invariants, event ordering/replay, error vocabulary, receipt digest, fixture
coverage, and forbidden disclosure field names. It does not implement or call a sandbox service.
