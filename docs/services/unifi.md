# unifi

`UnifiConfig` / `deploy_unifi` converges **configuration of an existing
UniFi installation**, based on `unifi_deploy` from ops-library main
`3110a0f1` (2.68.0). This is deliberately a subset of that role, not full
deployment parity. First installation, package upgrades, MongoDB provisioning,
Home Assistant user reconciliation, backup, restore and removal remain with
Ansible. The deploy never changes MongoDB authentication, users, data,
device adoption, or MongoDB's service/configuration.

```python
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.unifi import UnifiConfig, deploy_unifi

cfg = UnifiConfig(
    controller_bind_address="10.2.3.4",
    external_hostname="unifi.example.com",
    traefik_ip_allowlist=("10.0.0.0/8",),
)
values = SecretValues(
    SecretRef("secrets/controller.yml"),
    {
        "mongodb_password": mongodb_password,
    },
)
deploy_unifi(cfg, values)
```

Connect directly as root to an existing Debian/Ubuntu x86_64 systemd host
with Python 3, curl, mongosh, Java 17 and the role's fixed `unifi` account
and directory layout. The configured backend IPv4 must match the host's
default-route source address (queried locally without sending a packet).
The `version` setting defaults to the current role's
`9.5.21`: it asserts the installed package version and never installs or
upgrades a package. Unknown settings are rejected.

## Admission and refusals

Before applying changes, a probe checks the package/layout, authenticated
MongoDB connection, running MongoDB settings, and that no newer MongoDB
configuration awaits a restart. Authentication must already be enabled,
bound only to `127.0.0.1:27017`, with the role's quiet logging and diagnostic
parameters. Runtime parameter values come from the typed `getParameter`
command rather than the string-valued `getCmdLineOpts.setParameter` map.
Inactive/disabled MongoDB, changed settings, missing resources,
legacy units containing inline MongoDB URIs, symlinked managed files/directories,
or failed/ambiguous probes stop the deploy. Reconcile these states with
Ansible and retry; this port does not try an authentication bootstrap.

When `create_homeassistant_user=True`, the name is retained for role mapping,
but means **require an existing matching integration**. Supply the additional
`homeassistant_password` secret. The default site, existing user password,
readonly privilege with empty permissions, and persisted password must match.
Privilege foreign keys may be ObjectIds (as written by the role) or hex
strings; all matching records must agree on readonly access. Conflicting
duplicate records are refused.
Missing users/sites and drift are refused, never created or updated. Password
verification uses the host's `libcrypt.so.1` and the existing SHA-512 crypt
hash; it emits neither credential nor hash.

MongoDB passwords must contain only URI-unreserved characters
(`A-Z a-z 0-9 . _ ~ -`) and must not be placeholders. The role's Java
argument template embeds an unescaped URI; ambiguous delimiters are refused
instead of silently interpreting another credential. HA passwords must be
nonempty and not placeholders.

## Managed configuration

The port ships the role's templates byte for byte: the custom systemd unit,
MongoDB Java argument file, Traefik route, MongoDB logrotate and daily log
monitor. Only the argument file and unit trigger a UniFi restart. A previous
interrupted run's pending restart is recovered from file timestamps.
A pending `NeedDaemonReload` is recovered before either start or restart,
even when the unit already matches on disk. The
controller is enabled/started; MongoDB and Traefik are never restarted.
The local self-signed HTTPS `/status` endpoint must return 200; failure now
fails the deploy rather than the role's informational warning.

The argument file is installed with `secret_file`, `root:unifi 0640` under
`/etc/unifi-secrets` (`root:unifi 0750`), outside the public unit and process
arguments. Optional UFW reconciliation retains the role's five allow rules
and comments; UFW must already exist. It never enables UFW or removes rules.
Traefik's watched `/etc/traefik/dynamic/unifi.yml` gets an optional IP
allowlist; empty leaves only the controller's own login as protection.

| Settings | Default | Behavior |
|---|---|---|
| `controller_bind_address`, `external_hostname` | required | IPv4 backend and public route hostname |
| `version` | `9.5.21` | installed-version assertion |
| `jvm_min_heap_mb`, `jvm_max_heap_mb` | `1024`, `2048` | bounded positive heap settings, min ≤ max |
| `traefik_enabled` | `True` | false leaves an existing route untouched |
| `traefik_entrypoints`, `traefik_certresolver` | `("web-secure",)`, `"letsencrypt"` | `None` resolver emits `tls: {}` |
| `traefik_ip_allowlist` | `()` | validated addresses/networks |
| `manage_firewall` | `True` | false leaves UFW untouched |
| `create_homeassistant_user`, `homeassistant_username` | `False`, `"homeassistant"` | existing integration assertion only |
| `mongodb_logrotate_enabled`, `mongodb_monitor_script_enabled` | `True`, `True` | false leaves existing files untouched |
| `mongodb_log_max_size_mb` | `500` | daily monitor threshold |
| `healthcheck_timeout` | `120` | status attempts, each up to 5 seconds plus 1-second delay |

## Check mode and evidence limits

Admission performs database reads only. **Even check mode creates and removes
a unique mode-0700 temporary mongosh HOME**. A non-secret mode-0600 config
preloads `disableLogging: true`, `enableTelemetry: false`, `updateURL: ""`;
the script verifies those settings before authentication. All child output
stays in memory, secrets travel only through redacted stdin, and cleanup runs
on success, failure and timeout. No normal user's mongosh state is modified.
This client footprint is not a persistent configuration change, but check
mode is not literally filesystem-write-free.

The fake connector tests prove operation selection, template parity and
secret-safe logs; host-probe unit tests prove refusal and temporary-state
cleanup. They do not prove real MongoDB/mongosh compatibility or device
health. No live run or zero-change second-run proof has been performed for
this port. Keep the default engine on Ansible until a separately authorized
live manifest and actual second run pass.

MongoDB documents the [logging setting](https://www.mongodb.com/docs/mongodb-shell/logs/disable/)
and [shell settings](https://www.mongodb.com/docs/mongodb-shell/reference/configure-shell-settings/).
