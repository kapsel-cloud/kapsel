# Test strategy

Suppose a receipt test passes, but a reconnecting caller receives different bytes. The signature
code may be correct while the service still breaks its promise. Conversely, running every malformed
receipt through a systemd installation would make a parser regression painfully expensive to find.

Test each rule at the lowest interface that owns it. Then test the connections between those
interfaces. This page explains where tests belong and what each kind of check can tell you.

## Place the test

| Location                      | Responsibility                                                             |
| ----------------------------- | -------------------------------------------------------------------------- |
| Inline `#[cfg(test)]` modules | Parsing, classification, SQL/filesystem invariants, private fault seams    |
| Root `tests/application_*.rs` | Service composition and independently counted receiver requests            |
| Root `tests/e2e_*.rs`         | Executable output, exits, restart, and operator workflows                  |
| `crates/<crate>/tests/`       | Exported interfaces of meaningful workspace packages                       |
| `fuzz/`                       | Hostile bytes entering production decoders                                 |
| Simulation targets            | Seeded lifecycle schedules and recovery invariants                         |
| Linux process tests           | Socket identity, physical job lifetime, process loss, and retained history |
| Live-receiver lanes           | Real receiver behaviour in disposable environments                         |
| Artifact lanes                | Extracted production bytes, installation, and packaged caller journeys     |

Keep implementation-local tests beside their owner in an inline `mod tests`. Do not detach them
merely to shorten a file. Cross-component and process scenarios can use separate ordinary modules,
named for their behaviour. Do not use textual `include!` fragments or widen production interfaces
just to expose a test seam. A shared support crate or provider interface needs real consumers.

For receipt retrieval, that division looks like this:

1. Parser and classifier tests check malformed records and result rules beside their
   implementations.
2. Journal tests check that completion commits the exact signed bytes with terminal state.
3. Application and service tests check that reads return those original bytes after restart, even
   when current signing material changes.
4. Client tests check digest validation and exclusive export. An export failure must not reopen the
   operation.

Each test adds a fact the lower test could not establish. It does not repeat the entire lower-layer
matrix. At higher layers, check authority separation, durable ordering, observable output, original
evidence, and non-disclosure. Count receiver requests independently of the classifier being tested.

## Keep deterministic tests deterministic

Use fixed keys, explicit evaluation time, private temporary directories, seeded inputs, and sorted
output. Default semantic tests must not depend on live services, ambient trust, locale, or polling
order. Test intentional SQLite lock conflicts with a zero busy timeout and assert the lock error.
Use paused Tokio time for in-memory deadlines. Process fixtures should acknowledge admission,
handler completion, or readiness rather than assume it after a sleep. A bounded monotonic
coordination timeout does not define result meaning.

Crash tests must cover both loss after mutation and loss after receipt commitment but before export.
Recovery must preserve the original ID, avoid another mutation, and return original receipt bytes. A
successful action followed by graceful restart does not cover those interrupted windows.

## Choose the evidence class

- **Deterministic:** repeatable semantic rules, composition, and hostile-input rejection.
- **Process:** real disconnect, termination, restart, OS identities, and job retention.
- **Live receiver:** Kubernetes or Git behaviour beyond scripted observations.
- **Artifact:** extracted production binaries rather than test-feature executables.
- **Native installation:** the shipped systemd assets on a fresh native target host.
- **Exploration:** fuzz or seeded schedules that search for failures; retain inputs and replay them.

Process exit does not prove disk-backed power-loss durability. Emulated containers do not qualify a
native installation. A fuzz smoke pass does not replace canonical vectors or explicit failure cases.
Record exact source/artifact identities and missing lanes when reporting a result.

## Commands and detailed mappings

Use [Build and test](build.md#focused-gates) for the ordinary loop and
[Qualification](qualification.md) for additional environments. The [evidence map](evidence.md)
contains maintained test names, boundary limits, and guarantee-to-test matrices. Release acceptance
is defined by the [release process](release_process.md), not test counts or coverage percentages.
