# Planned Kapsel service operator journey

Status: approved plan; not yet runnable.

This document specifies the next source-independent x86-64 GNU/Linux Kapsel service preview. It is
not an installation guide until an authenticated installer candidate passes the source and fresh
native gates. The previously accepted archive remains regression evidence, not the next publication
route. This preview is non-production and supports only `kubernetes.set_deployment_image` for the
fixed `demo/agent-api` target.

## Authenticate before the one command

“One-command installation” starts after acquisition and publisher authentication. Download the
installer executable, digest manifest, and Sigstore bundle without executing the installer. Obtain
the expected 40-hex source revision through an independently trusted release record. Verify the
bundle over the exact manifest with the appointed candidate workflow's issuer, repository, ref,
source SHA, and `workflow_dispatch` trigger, then verify the installer digest from that manifest. A
checksum alone proves byte identity, and an installer cannot authenticate itself.

The candidate will publish the exact `cosign verify-blob` invocation after its workflow name and
asset names are frozen. Do not substitute `curl | sh`, execute a downloaded candidate before this
check, or treat a package version or source checkout as publisher identity.

The authenticated installer is one executable of at most 64 MiB containing the exact service
executables and static assets. It performs no runtime download and accepts no archive or
package-manager input.

## Prepare private operator input

Create one absolute root-owned mode-`0700` directory containing exactly these root-owned regular,
single-link, mode-`0600` files:

```text
grant.bin
authorization.pub
receipt.seed
receipt.trust
bootstrap-kubeconfig.yaml
```

`grant.bin` binds one operation ID, namespace `demo`, Deployment `agent-api`, container `api`, and
one immutable image digest. `authorization.pub` is the grant's appointed public key. `receipt.seed`
is the service receipt-signing seed. `receipt.trust` appoints the same derived public key and
remains outside the installation for evaluator-only offline inspection.

`bootstrap-kubeconfig.yaml` is explicit temporary installer administration authority. It contains
one embedded-credential cluster, user, and context. The installer selects only the context named by
`--kube-context`; it reads no `KUBECONFIG` or other client environment. External CA, certificate,
key, or token paths, `exec`, `auth-provider`, proxy, insecure TLS, username/password, extensions,
and unknown fields are rejected. Bootstrap credentials are never copied into `/etc/kapsel`, systemd,
service output, or installer transaction evidence. Refresh and partial-uninstall retry may use a
renewed inline bootstrap token or client certificate/key only when the same directory inode,
context, cluster server, and CA remain unchanged; all four non-bootstrap inputs must remain
byte-identical.

## Install

After authenticating the installer, the complete planned installation command is:

```sh
sudo kapsel-service-installer install \
  --operator-input /secure/kapsel \
  --kube-context nonprod
```

The command validates every private input descriptor-relatively, creates the durable installer
transaction through its crash-safe bootstrap, then performs clean-host and fixed Kubernetes
preflight before any service, identity, or Kubernetes mutation. It installs the embedded assets and
locked identities, creates UID-bound narrow RBAC, requests a short-lived ServiceAccount token,
generates `/etc/kapsel/operator.json` and `/etc/kapsel/kubeconfig.yaml`, activates systemd, and
checks both systemd state and authenticated socket use.

The TokenRequest asks for 3,600 seconds with a ten-second deadline and a streamed 64 KiB response
limit. The installer accepts only a nonempty ASCII token of at most 16 KiB and a server-issued
expiration 1,800–7,200 seconds in the future; it never prints the token. Successful installation
prints only:

```text
{"status":"INSTALLED","credential_expiration":"<server RFC-3339 expirationTimestamp>"}
```

The service credential has only namespaced `get` and `patch` on exact Deployment `demo/agent-api`.
The bootstrap credential is not service authority.

Any prior installer transaction, Kapsel identity, destination, authority/state root, or named RBAC
object fails the clean-install preflight unless it is strongly owned unfinished work that this same
transaction must recover first. The installer never overwrites or adopts it.

## Submit and inspect

After installation, use the fixed caller identity and exact grant-bound values:

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
`NOT_ATTEMPTED`; never convert a timeout, disconnect, expired credential, or Kubernetes outage into
a receiver result. Retrieve exact frozen bytes to a new caller-owned file and inspect them with the
operator-retained evaluator trust:

```sh
receipt="/tmp/$operation_id.receipt"
sudo -u kapsel-service-caller -g kapsel-service-callers -- \
  /usr/bin/kapsel-service-client receipt "$operation_id" "$receipt"
evaluation_time_unix_s='<operator-selected Unix second within receipt trust>'
sudo /usr/bin/kapsel inspect \
  --receipt "$receipt" \
  --trust /secure/kapsel/receipt.trust \
  --evaluation-time-unix-s "$evaluation_time_unix_s"
```

Inspection reports `INSPECTED`, never `VERIFIED`.

## Refresh the credential

There is no automatic refresh, timer, or persisted bootstrap authority. When the recorded credential
has at most 900 seconds remaining, or after it expires, run:

```sh
sudo kapsel-service-installer refresh-credential \
  --operator-input /secure/kapsel \
  --kube-context nonprod
```

An earlier invocation is read-only and prints `CREDENTIAL_CURRENT`; successful replacement prints
`CREDENTIAL_REFRESHED`. Both are sole-line JSON with `credential_expiration`, as defined by the
service contract, and exit 0. At the refresh threshold, the command stops the service, requests and
validates a new bounded token, atomically replaces and syncs the service kubeconfig, then starts the
service. Startup reconciles before socket bind. If Kubernetes is unavailable before replacement, the
old kubeconfig remains and the service remains stopped; repeat the same command. If interruption
follows replacement, repeating the command recovers the recorded inode and restarts with the new
credential. Refresh never rolls back installed resources.

After token expiry, local status and frozen-receipt retrieval remain available while `kapseld` is
running, but Kubernetes work cannot progress until explicit refresh succeeds. If a failed refresh
has stopped the daemon, the socket is unavailable until refresh recovery starts it; already
retrieved receipt bytes remain inspectable offline. Authentication failure before a provider attempt
remains retryable; ambiguity after `apply_started` remains `UNKNOWN` unless bounded receiver facts
establish another result.

## Interrupted install or refresh

Every invocation validates `/var/lib/kapsel-installer/transaction.json` and recovers before new
preflight or mutation. An interrupted install either continues the exact pending action or rolls
back only strongly owned resources. An interrupted refresh retains installed resources and resumes
credential replacement. An interrupted uninstall resumes monotonically and never restores local or
Kubernetes use. Recovery follows the pending-action table in the service contract and never deletes
from an expected name, preflight absence, matching bytes, or an RBAC shape alone.

If complete ownership cannot be established, the command exits nonzero, leaves the evidence and
resource unchanged, and does not continue installation. This preview provides no force or manual
adoption path; dispose of the host. A fully rolled-back first attempt may be retried with the same
authenticated installer, input directory, and context.

## Ordered uninstall and partial result

Use the same explicit operator input and Kubernetes context:

```sh
sudo kapsel-service-installer uninstall \
  --operator-input /secure/kapsel \
  --kube-context nonprod
```

Uninstall recovers first, then:

1. disables and stops `kapseld`, waits for process and connection closure, and verifies socket
   removal;
2. removes the caller's recorded group membership;
3. deletes only the transaction-marker- and UID-matching RoleBinding, ServiceAccount, and Role;
4. removes strongly owned static assets and reloads systemd; and
5. records terminal `uninstalled` state.

If Kubernetes is unavailable after local revocation, the command retains all static assets,
operator/state roots, and installer ownership evidence, exits with status 20, and prints only:

```text
{"status":"PARTIAL_UNINSTALL","retry":["sudo","kapsel-service-installer","uninstall","--operator-input","/secure/kapsel","--kube-context","nonprod"]}
```

The path and context are the original argv values. Run that exact argv after Kubernetes returns. The
retry never re-enables local use and removes no static asset until UID-bound Kubernetes revocation
is complete.

Successful uninstall retains the `kapsel`, `kapsel-service-caller`, and `kapsel-service-callers`
identities, `/etc/kapsel`, `/var/lib/kapsel`, journal, worker lock, receipts, and
`/var/lib/kapsel-installer` evidence. Those retained resources intentionally make the host
non-reinstallable. Reinstall, upgrade, purge, identity reuse, transaction reset, unattended
operation beyond the credential lease, another target, and production use are unsupported; use a
fresh disposable host.
