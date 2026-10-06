# Run one approved operation

This example runs the release service, submits one approved image change, and inspects its receipt.
It then restarts the service and retrieves the same evidence. A loopback HTTP fixture stands in for
Kubernetes, so no cluster or cloud credentials are needed.

## Before you start

Use a **fresh disposable native x86-64 Debian 12 VM** with:

- systemd as PID 1;
- Python 3.11 or newer;
- sudo/root access;
- `systemd-sysusers`, `systemd-analyze`, `journalctl`, `useradd`, and GNU coreutils;
- Cosign 3.1.2 and GNU `sha256sum` for release authentication.

The VM must have no existing Kapsel accounts, installation, or state. Docker and ARM emulation do
not meet these prerequisites. Do not delete existing state to make the example run.

The command below installs binaries, creates separate service and caller identities, and starts a
systemd unit **inside this VM only**. Use a disposable VM because the example retains its
installation and evidence rather than attempting to erase action history.

## 1. Authenticate the release

Follow
[Authenticate and extract the release](reference/release.md#authenticate-and-extract-the-release).
Keep the archive and its five companions together. Check the signed manifest before executing its
Python verifier. No repository checkout or Rust toolchain is required on the VM.

For the published release, the authentication procedure sets:

```sh
archive=kapsel-0.3.0-x86_64-unknown-linux-gnu.tar.gz
revision=64e204f0b5bdca9c31cc617d5d822cbfb3541597
```

Keep these variables in the shell holding the authenticated files. An unsigned local build needs
independently accepted source and archive digests and trusted transfer. It has no publisher
authentication.

## 2. Run the example

From that directory:

```sh
sudo python3 "$archive.verify.py" --archive "$archive" --expected-revision "$revision" --service-systemd
```

The verifier performs the preparation and caller steps using the shipped production binaries. It
first checks that a service without an operator document refuses startup. It then creates disposable
approval and receipt keys, reads the fixture's Deployment snapshot, signs the approval, and starts
the configured service.

The caller submits `artifact-op-1`. The important results are:

| Result      | Meaning                                                               |
| ----------- | --------------------------------------------------------------------- |
| `ADMITTED`  | The service retained the operation. This is not rollout success.      |
| `SUCCEEDED` | The fixture's observations satisfy the Kubernetes rollout classifier. |
| `INSPECTED` | The receipt passed offline signature, trust, and classifier checks.   |

The example stops the service, replaces its cold catalog, and restarts it without selecting work.
Retrieval must return the byte-identical receipt, and the fixture must count exactly one PATCH. The
unit finishes stopped and disabled.

## 3. Inspect the retained receipt

After a successful run:

```sh
sudo /usr/bin/kapsel inspect --receipt /tmp/kapsel-artifact-receipt-0 \
  --trust /etc/kapsel/example-receipt.trust --evaluation-time-unix-s 150
```

Expect `INSPECTED` with the original operation and result. Time `150` belongs only to the fixture's
artificial trust window. It is not a current trust evaluation or evidence of when a real change
happened.

The receiver fixture is gone when the example command returns. Receipt inspection is offline. Do not
restart this test installation as a real service.

## 4. Retire the VM

Keep the VM while you inspect the evidence. Success retains private state, fixture authority,
installed assets, identities, and receipt exports. Failure can leave a partial installation or an
incomplete stop. Preserve it for diagnosis. Do not rerun by deleting history.

When finished, retire the whole disposable VM. Do not remove individual journals or recycle the
identities to make another attempt.

## Next steps

- [How Kapsel works](tour.md) explains why recording an attempt changes recovery.
- [Caller guide](guides/caller.md) shows explicit submission and reconnect commands on a provisioned
  service.
- [Operator guide](guides/operator.md) covers your own receiver and authority.
- [Capabilities and limits](scope.md) states what the release supports.

This example demonstrates the service mechanism. It is not a live Deployment rollout, a crash or
power-loss test, or a production-readiness claim. Maintainers can find the exact installation
footprint and evidence requirements in
[native qualification](reference/release.md#native-installed-systemd-qualification).
