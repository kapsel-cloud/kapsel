# Kapsel service operator guide

Status: sole install and lifecycle guide for the unpublished Kapsel service preview.

This guide installs one source-independent x86-64 Debian 12/systemd service preview. It is not a
production release, does not modify Kapsel v0.2.0, and supports only the exact
`kubernetes.set_deployment_image` grant configured below.

## Inputs and authority

Start with the archive, adjacent `.sha256` and `.SHA256SUMS`, and—when the archive was
downloaded—its Sigstore bundle plus the expected 40-hex source revision from an independently
trusted channel. Keep all four files in one operator-owned, single-link, mode-`0700` directory that
no other local identity can write, and do not replace them during authentication, verifier
bootstrap, or extraction. The operator separately supplies these private files; they are never
caller input:

```text
operator.json
grant.bin
authorization.pub
kubeconfig.yaml
receipt.seed
receipt.trust
```

`operator.json` must use the existing grammar and exactly these installed paths:

```json
{
  "signed_authorization_grant": "/etc/kapsel/grant.bin",
  "authorization_key_id": "owner-key",
  "authorization_public_key": "/etc/kapsel/authorization.pub",
  "kubeconfig": "/etc/kapsel/kubeconfig.yaml",
  "journal": "/var/lib/kapsel/journal.sqlite3",
  "receipt_directory": "/var/lib/kapsel/receipts",
  "receipt_signing_seed": "/etc/kapsel/receipt.seed",
  "receipt_signing_key_id": "receipt-key"
}
```

The exact grant binds one operation ID, `demo/agent-api`, container `api`, and one immutable image
digest. The kubeconfig carries a short-lived credential for only the bundled namespaced RBAC.

## Authenticate and inspect

A checksum is byte identity, not publisher authentication. For a downloaded candidate, first verify
the Sigstore bundle with the exact candidate-workflow identity and expected source SHA recorded with
that candidate. Then verify the manifest:

```sh
set -eu
input_directory=$(dirname "$archive")
test "$(stat -c %u "$input_directory")" = "$(id -u)"
test "$(stat -c %a "$input_directory")" = 700
for input in "$archive" "$archive.sha256" "$archive.SHA256SUMS" \
  "$archive.SHA256SUMS.sigstore.json"; do
  test -f "$input"
  test ! -L "$input"
  test "$(stat -c %u "$input")" = "$(id -u)"
  test "$(stat -c %h "$input")" = 1
done
cosign verify-blob \
  --bundle "$archive.SHA256SUMS.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity \
    https://github.com/kapsel-cloud/kapsel/.github/workflows/kapsel-service-candidate.yml@refs/heads/master \
  --certificate-github-workflow-repository kapsel-cloud/kapsel \
  --certificate-github-workflow-ref refs/heads/master \
  --certificate-github-workflow-sha "$expected_revision" \
  --certificate-github-workflow-trigger workflow_dispatch \
  "$archive.SHA256SUMS"
(cd "$(dirname "$archive")" && sha256sum --check --strict "$(basename "$archive.SHA256SUMS")")
```

The archive name must be `kapsel-service-$expected_revision-x86_64-unknown-linux-gnu.tar.gz`.
Inspect the exact lexically ordered inventory before extracting into a new empty directory:

```text
LICENSE
SERVICE-METADATA.json
bin/kapsel
bin/kapsel-service-client
lib/systemd/system/kapseld.service
lib/sysusers.d/kapseld.conf
libexec/kapsel/kapseld
share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md
share/kapsel/kapseld-rbac.yaml
share/kapsel/smoke-kapsel-service-artifact.py
share/kapsel/verify-kapsel-service-artifact.py
```

Read only the exact bundled verifier member to standard output, then use it for bounded validation
and exclusive extraction. This bootstrap does not extract archive paths:

```sh
set -eu
archive_name=$(basename "$archive")
basename=${archive_name%.tar.gz}
verifier=$(mktemp)
tar --extract --to-stdout --file "$archive" \
  "$basename/share/kapsel/verify-kapsel-service-artifact.py" >"$verifier"
python3 "$verifier" \
  --archive "$archive" \
  --expected-revision "$expected_revision" \
  --extract-directory /absolute/new-empty-parent/kapsel-service
rm -f "$verifier"
```

The verifier rejects unsafe archive structure before exclusive extraction and checks metadata and
executable digests. Plain `tar` extraction is not the verification path.

## Install and configure

Run from the verifier's safely extracted top-level directory in a disposable non-production Debian
12 environment. The external client name is fixed for this candidate. The service has no reinstall
or upgrade path: every identity, destination, configuration root, state root, and RBAC object must
be absent before the first install.

```sh
set -eu
if getent passwd kapsel >/dev/null; then exit 1; fi
if getent passwd kapsel-service-caller >/dev/null; then exit 1; fi
if getent group kapsel >/dev/null; then exit 1; fi
if getent group kapsel-service-callers >/dev/null; then exit 1; fi
for path in \
  /usr/bin/kapsel /usr/bin/kapsel-service-client /usr/libexec/kapsel/kapseld \
  /usr/lib/systemd/system/kapseld.service /usr/lib/sysusers.d/kapseld.conf \
  /usr/share/kapsel/kapseld-rbac.yaml /usr/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md \
  /etc/kapsel /var/lib/kapsel; do
  test ! -e "$path"
  test ! -L "$path"
done
existing=$(kubectl --namespace demo get rolebinding kapsel-service-agent-api \
  --ignore-not-found -o name)
test -z "$existing"
existing=$(kubectl --namespace demo get serviceaccount kapsel-service \
  --ignore-not-found -o name)
test -z "$existing"
existing=$(kubectl --namespace demo get role kapsel-service-agent-api \
  --ignore-not-found -o name)
test -z "$existing"
sudo install -D -o root -g root -m 0755 bin/kapsel /usr/bin/kapsel
sudo install -D -o root -g root -m 0755 bin/kapsel-service-client /usr/bin/kapsel-service-client
sudo install -D -o root -g root -m 0755 libexec/kapsel/kapseld \
  /usr/libexec/kapsel/kapseld
sudo install -D -o root -g root -m 0644 lib/systemd/system/kapseld.service \
  /usr/lib/systemd/system/kapseld.service
sudo install -D -o root -g root -m 0644 lib/sysusers.d/kapseld.conf \
  /usr/lib/sysusers.d/kapseld.conf
sudo install -D -o root -g root -m 0644 share/kapsel/kapseld-rbac.yaml \
  /usr/share/kapsel/kapseld-rbac.yaml
sudo install -D -o root -g root -m 0644 share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md \
  /usr/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md
sudo systemd-sysusers /usr/lib/sysusers.d/kapseld.conf
sudo useradd --system --no-create-home --shell /usr/sbin/nologin kapsel-service-caller
test "$(sudo passwd --status kapsel | awk '{print $2}')" = L
test "$(sudo passwd --status kapsel-service-caller | awk '{print $2}')" = L
sudo usermod --append --groups kapsel-service-callers kapsel-service-caller
sudo install -d -o kapsel -g kapsel-service-callers -m 0700 \
  /etc/kapsel /var/lib/kapsel /var/lib/kapsel/receipts
for file in operator.json grant.bin authorization.pub kubeconfig.yaml receipt.seed; do
  sudo install -o kapsel -g kapsel-service-callers -m 0600 \
    "/absolute/operator-input/$file" "/etc/kapsel/$file"
done
kubectl create -f /usr/share/kapsel/kapseld-rbac.yaml
sudo systemctl daemon-reload
sudo systemctl enable --now kapseld.service
```

Replace `/absolute/operator-input` only with the operator-owned private input directory. Do not put
that directory, Kubernetes token, signing seed, grant authority, or receipt trust in caller input or
caller-readable paths.

Health is both `systemctl is-active kapseld.service` reporting `active` and one authenticated caller
request succeeding. Bounded service diagnostics are:

```sh
systemctl show kapseld.service \
  --property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,NRestarts
```

## Submit, reconnect, retrieve, inspect

Set the exact values already bound by the installed grant:

```sh
operation_id=service-op-1
image='registry.example/agent-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
sudo -u kapsel-service-caller -g kapsel-service-callers -- \
  /usr/bin/kapsel-service-client submit \
  "$operation_id" demo agent-api api "$image"
sudo -u kapsel-service-caller -g kapsel-service-callers -- \
  /usr/bin/kapsel-service-client status "$operation_id"
```

`ACCEPTED` is not success. Reconnect until status is `SUCCEEDED`, `FAILED`, `UNKNOWN`, or
`NOT_ATTEMPTED`; never convert a timeout or disconnect into a result. Retrieve exact frozen bytes to
a new caller-owned file:

```sh
receipt="/tmp/$operation_id.receipt"
sudo -u kapsel-service-caller -g kapsel-service-callers -- \
  /usr/bin/kapsel-service-client receipt "$operation_id" "$receipt"
evaluation_time_unix_s='<operator-selected Unix second within receipt trust>'
sudo /usr/bin/kapsel inspect \
  --receipt "$receipt" \
  --trust /absolute/operator-input/receipt.trust \
  --evaluation-time-unix-s "$evaluation_time_unix_s"
```

Use the operator's explicit evaluation time. Inspection reports `INSPECTED`, never `VERIFIED`.

## Restart and recovery

Restart once, reconnect, and retrieve to a second new path:

```sh
sudo systemctl restart kapseld.service
sudo -u kapsel-service-caller -g kapsel-service-callers -- \
  /usr/bin/kapsel-service-client status "$operation_id"
second="/tmp/$operation_id.after-restart.receipt"
sudo -u kapsel-service-caller -g kapsel-service-callers -- \
  /usr/bin/kapsel-service-client receipt "$operation_id" "$second"
cmp "$receipt" "$second"
sha256sum "$receipt" "$second"
```

Startup reconciles before binding. After `apply_started`, it observes and never blindly repeats the
mutation. Equal receipt bytes prove only frozen-byte recovery, not exactly-once effect or Kubernetes
truth.

## Ordered uninstall

Stop the external caller first. Then revoke local and Kubernetes use before removing static files:

```sh
set -eu
sudo systemctl disable --now kapseld.service
test "$(systemctl is-active kapseld.service || true)" = inactive
test ! -S /run/kapsel/kapseld.sock
sudo gpasswd --delete kapsel-service-caller kapsel-service-callers
kubectl --namespace demo delete rolebinding kapsel-service-agent-api
kubectl --namespace demo delete serviceaccount kapsel-service
kubectl --namespace demo delete role kapsel-service-agent-api
sudo rm -f /usr/bin/kapsel /usr/bin/kapsel-service-client /usr/libexec/kapsel/kapseld
sudo rm -f /usr/lib/systemd/system/kapseld.service /usr/lib/sysusers.d/kapseld.conf
sudo rm -f /usr/share/kapsel/kapseld-rbac.yaml \
  /usr/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md
sudo systemctl daemon-reload
```

The `kapsel`, `kapsel-service-callers`, and `kapsel-service-caller` identities, `/etc/kapsel`,
`/var/lib/kapsel`, journal, worker lock, and receipts remain. Purge is unsupported.
