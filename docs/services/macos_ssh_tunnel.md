# macOS owner-session SSH tunnel

The native `MacosSshTunnelConfig` / `deploy_macos_ssh_tunnel` API preserves the
existing `macos_ssh_tunnel` role's local owner and Aqua-session model. Deployment installs the tunnel stopped,
including when the existing label is enabled and loaded. The existing explicit
lifecycle commands start it.
The full API passed the owned ARM fixture on `cd4ee3e7920232aabcf142971bec96e044611f55`. The earlier published
descriptor-probe prerequisite alone qualified neither deployment nor an
inventory engine switch.

`identity.probe_identity` inspects an existing Ed25519 forwarding identity using
OpenSSH through a pinned regular-file descriptor. It creates no temporary key
copy and passes no private bytes in argv, stdin, environment or logs. Missing
or drifted public material is reported for the separately owned mutation path;
it never rotates a key. When both private/public files are absent the result is
`missing`; an existing private file with no public counterpart reports `drift`.
An orphan `.pub` and exact-mode violations are refused, matching the original
mutation algorithm's contract (including public mode `0644`, not `0600`). Unsafe
links, ownership and replacement races are also refused. A missing identity in
dry planning needs no prospective key.

The packaged ops-library mutation/recovery algorithm remains byte-identical for
actual creation and reconciliation. No-op probes do not call its temporary-key
derivation path. An owner/group-correct, non-writable identity parent whose mode
has drifted (for example `0750`) is reported as drift and repaired by that
unchanged mutator to `0700`; unsafe ancestry, canonical file modes and orphan
refusal remain strict.

Set the actual local `owner`, `home`, relay `host`/`user` and forwarded `target`.
The connection runs as that owner locally and requires the existing GUI launchd
domain. `manage_identity=True` selects the original identity management;
`relay_home` additionally preserves the existing unprivileged relay authorization
step. Authorization failure occurs before stopping a previously loaded tunnel.
`state="absent"` unloads and removes only the tunnel's named files, preserving
the caller-owned identity and relay authorization.

`ssh_port` defaults to `22`, retaining the original SSH template bytes. An
explicit nondefault port appends a `Port` directive inside the sole managed
`Host` block; values must be in `1..65535`. This supports an owned high-port
SSH fixture without altering any machine's existing SSH service. Installation
remains stopped even when the prior label was enabled and loaded; that is a
changed first transition, not a no-op. The unchanged `tunnel_control.py` retains
the explicit start/stop/restart/status/check commands and HTTPS/SNI validation.

The PR-path-triggered and manually dispatchable `Native Mac applications integration` workflow builds and installs
the exact requested Git wheel, requires actual ARM Darwin and the non-root
hosted-runner identity, and proves real OpenSSH derivation with unchanged fixture
metadata across twenty repeats. Its evidence records explicit pass/fail status,
cleanup (including cleanup errors), and limitations. The metadata observer covers
the owned fixture tree; it does not claim a whole-host filesystem syscall trace.
It creates only disposable owned identities, never uses an inventory host or
changes SSH authentication. GitHub's current [runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
lists `macos-15` for ARM; the fixture independently checks the actual architecture.

The same workflow runs one hosted job per owned fixture: descriptor identity and
Darwin uv as the runner, then tunnel, OpsGate, llama-server, Voxhelm control
plane and remote worker as root through the runner's existing sudo. Root
fixtures create unique accounts, labels, ports and a private root; cleanup
removes only those, waiting for the exact PIDs of their launchd jobs and
spawned helpers, and always writes a receipt (including the first failure's
type and code location, never its message) even when setup is refused.

## Delegated authorization transport

Relay authorization uses the original delegated SSH session model: compression,
`ControlMaster=auto` and `ControlPersist=60s`. Set `ssh_connect_timeout` to the
original controller's configured connection budget (default10), and
`ssh_control_path` to its existing absolute control-socket pattern when selected;
`%h`, `%p` and `%r` are supported. For example, a controller configured with
Ansible timeout30 and `/tmp/ansible-ssh-%%h-%%p-%%r` supplies `ssh_connect_timeout=30`
and an absolute `ssh_control_path`, such as
`/Users/operator/.ansible/cp/ansible-ssh-%h-%p-%r`. This keeps the same basename
under the existing owner-private `~/.ansible/cp` directory.
The cache-location deviation from shared `/tmp` is deliberate: an explicit
cache parent must already be a canonical directory owned by the actual owner
with mode0700; existing sockets must be owner-owned mode0600 sockets. The
status fact never creates or hardens that directory. An absent/untrusted cache
uses the ordinary direct SSH fallback. Unselected generic profiles retain
`ControlMaster=no` and `ControlPath=none`.

This affects authorization transport only; all four
tunnel resources and the explicit start/stop/controller remain byte-identical.

Existing identity and strict initial-connection known-host checks remain mandatory.
An explicit multiplex profile trusts a same-owner previously authenticated cached
session, like the original Ansible controller; it does not revalidate known hosts
on each reused channel. Existing shared `/tmp` control sockets are never used or
modified. Planning checks
actual relay authorization, and any changed install actually converges it before
stopping the local job. A relay failure is not treated as success. The local
post-install verification then checks identity, resources, disabled state and
absence of the named GUI job without another remote authorization roundtrip,
matching the original local role. SSH retains its connection deadline; the port's
invented whole-command30-second limit is removed for this original delegated
step. Local subprocess and stop/listener bounds remain unchanged.

For an isolated repair, dispatch the native workflow with `fixture=tunnel` and
an exact implementation SHA. The default `all` and PR selection retain all seven
owned fixtures. No inventory target is accepted by this workflow.
