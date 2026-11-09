# unifi

`UnifiConfig` / `deploy_unifi` deploys an initialized controller in the
`unifi_deploy` role's fixed layout. Set `routine=UnifiRoutine(...)` for normal
package/runtime, MongoDB configuration and Home Assistant reconciliation.
Without `routine`, the original configuration-only exact-build API remains
available for compatibility.

```python
from ops_deploy.services.unifi import UnifiConfig, UnifiRoutine, deploy_unifi

cfg = UnifiConfig(
    installed_package_version="9.5.21-31260-1",  # compatibility assertion
    controller_bind_address="10.2.3.4",
    external_hostname="unifi.example.com",
    traefik_ip_allowlist=("10.0.0.0/8",),
    create_homeassistant_user=True,
    routine=UnifiRoutine(
        package_version="9.5.21-31260-1",
        package_url="https://dl.ui.com/unifi/9.5.21/unifi_sysvinit_all.deb",
        package_sha256="7da1cc9ab1ae0c8f302c242d622ee52f867457a69116b2aa4c13812e756986af",
    ),
)
deploy_unifi(cfg, secrets)  # SecretValues: mongodb_password, homeassistant_password
```

## Normal initialized-install deployment

Routine deployment supports Ubuntu 24.04 x86_64, systemd, Python 3 and the
role's fixed account/directory layout and an authenticated MongoDB
installation. Missing-controller admission also requires empty `unifi`,
`unifi_stat` and `unifi_audit` databases and effective read/write, collection
and index permissions on each (including narrowly scoped `readWrite` on
`unifi_audit`). A successful read alone is insufficient. Vendor Factory Default
initialization can reset databases, so nonempty external databases are refused
before writes. Existing installed-controller admission/roles are unchanged.
Only when admission proves the controller and its data absent,
the deploy creates a private0600 `system.properties` selecting the authenticated
external MongoDB; the controller derives its statistics/audit database names
from `unifi.db.name`. Existing files
and database selections are preserved byte-for-byte; there is no embedded-to-external
database migration. JVM flags alone do not configure a fresh controller.
The installer creates these selectors only after both digest and package metadata
verification, immediately before installing the verified package. Failed downloads
or verification leave controller data absent and can be retried. An interrupted
installation after initialization/dpkg may leave partial data/package state; it
is refused for diagnosis, never adopted or deleted automatically.
A missing controller package is installed after creating the
service account, private credential argfile and custom unit; the same API
updates an existing controller. Unpackaged leftover controller data is refused. The controller's default-route IPv4 must match
`controller_bind_address`. Admission authenticates MongoDB before writes and
requires authorization enabled on loopback port 27017. Incorrect credentials,
missing database layout, ambiguous Mongo configuration, unsafe managed
symlinks, and legacy inline unit credentials fail before reconciliation.
There is no authentication-disable fallback or generated password.

The selected UniFi artifact requires a full Debian version, vendor HTTPS URL
and SHA-256. Before stopping the controller, installation verifies the digest,
package name, architecture and version. Downgrades are refused. The vendor's
normal package script may start the existing custom unit; the deployment then
reconciles configuration and rolls out the controller. Packages use a root-owned `/var/cache/ops-deploy-unifi` cache. The role's
legacy `/home/unifi/cache` directory is retained for compatibility; it is not
used for root package installation. Selected artifacts remain cached; this
deploy does not prune them. No machine-wide
`policy-rc.d` is installed. A failed package operation fails the deploy and may
leave the controller stopped; correct the reported package issue and rerun.
No database restore/removal is attempted.

Java 17 and MongoDB 8 packages use presence semantics, preserving installed
patch versions rather than requesting upgrades. The MongoDB repository remains
Ubuntu noble/8.0. The role's logging settings are reconciled while retaining
storage, authorization, networking and other existing directives. Missing or
ambiguous required sections are refused. MongoDB restarts only for changed
configuration or a previous unapplied configuration write. Authentication and
loopback binding are checked before and after reconciliation.

Home Assistant reconciliation authenticates to MongoDB using the existing
secret, preserves the admin document ID, and creates or updates its SHA-512
crypt password and readonly default-site privileges. Both native string and
legacy ObjectId privilege foreign keys are handled without adding duplicate
records; matching records get empty permissions. The password is persisted as
`unifi:unifi 0600`. A missing default site is reported/skipped, matching the
role: complete the controller setup wizard and rerun. No other users, sites,
device adoption records or controller data are changed.

Fresh MongoDB/bootstrap and lifecycle backup/restore are outside this
initialized-install deployment contract; removal is the separate
[port of `unifi_remove`](#removal). The Linux fixture bootstraps its own
isolated database with authorization enabled; that fixture setup is not a
production bootstrap implementation.

## Removal

`remove_unifi(UnifiRemoveConfig(confirm=True, ...), secrets)` ports the
`unifi_remove` role at ops-library `d4039a71` (role files under
`tests/parity/unifi/remove`, digest in the drift manifest). Without `confirm`
it fails before any host probe. Every field is the role's `unifi_*` /
`unifi_remove_*` variable with its default, including the derived paths
(`home_dir` `/home/<user>`, `cache_dir`, `data_dir`, `logs_dir`,
`backup_dir`, unit and JVM argument file). The destructive choices stay
opt-in exactly as in the role: `delete_cache` defaults true;
`delete_logs`, `delete_data`, `delete_home`, `delete_backup_dir`,
`remove_user`, `remove_group`, `drop_mongodb_database` and
`drop_mongodb_user` default false. `trigger_backup` (the role's pre-removal
`unifi_backup`) is not ported and must stay false. Root, top-level or
traversing paths and a root account are refused.

`secrets` may hold `mongodb_password`. Without one (or empty) the database
and user drops are skipped, as the role skips them. With one, the role's
authenticated mongosh script (`mongodb_user`, default `unifi`, against
`mongodb_auth_db`, default `admin`) drops the `mongodb_database` (default
`unifi`) or the user; the payload travels on redacted stdin to a host helper
that runs mongosh with a private temporary HOME and prints only a status. A
failing drop is ignored (the role's `failed_when: false`).

The role's order: stop and disable `services` (ignored failures, the
`systemd` module's semantics); remove the unit, the JVM argument file and
the default `/etc/<service>-secrets` directory and reload systemd; remove
the Traefik route (behind the Traefik transaction guard); on a Debian-family
host with ufw, `ufw delete allow from any to any port <port> proto <proto>`
per `firewall_rules` (ignored failures); the drops; stop and disable
`mongod` (ignored); purge the UniFi, MongoDB and Java package lists (each
`apt-get --purge remove` of the listed packages dpkg knows in any state but
not-installed, so residual config-files packages are purged too, like the
apt module); remove the selected directories (cache, logs, backup, data,
install, home); `userdel` (`-r` with `delete_home`) and `groupdel`, both
fatal on failure.

Beyond the role, the removal also clears what the role's MongoDB purge
leaves behind. With `remove_packages`, a further purge between the MongoDB
and Java lists takes `mongodb_tool_packages` (`mongodb-database-tools`, `mongodb-mongosh`,
`mongodb-org-database-tools-extra`: dependencies of `mongodb-org` that its
list misses), with the same only-what-dpkg-knows semantics. With
`delete_data` and `remove_packages`, once the packages are purged,
`mongodb_state_dirs` (`/var/lib/mongodb`, mongod's data: every database of
that instance, the UniFi one included, and `/var/log/mongodb`) are removed; the purge leaves both. On a
host that has neither, both steps change nothing, so a rerun after an
earlier removal plans only these leftovers. Root, top-level or traversing
`mongodb_state_dirs` are refused like the other paths. The `mongodb` system
account and the MongoDB apt repository stay, as with the role.

## Shared configuration

Role templates remain byte-identical to ops-library: custom systemd unit,
private MongoDB Java argument file, Traefik route, MongoDB logrotate and daily
log monitor. The argfile is `root:unifi 0640` under a `root:unifi 0750`
directory. Credentials travel in redacted stdin and are never in commands,
unit environment variables or logs. MongoDB passwords must be nonempty,
non-placeholder URI-unreserved text (`A-Z a-z 0-9 . _ ~ -`); HA passwords
must be nonempty and non-placeholder.

### Private logs

UniFi 9.5 writes its MongoDB connection URI, password included, to
`server.log` on every start, so its logs must not be readable by other
users. The controller logs through logback, which has no file-permission
setting: new files get the process umask. The shared unit therefore sets
`UMask=0027` (new files 0640, new directories 0750; the vendor's own
`postinst` uses the same umask). The deploy locks the vendor log directory
`/var/log/unifi` (`/usr/lib/unifi/logs` links to it) to `unifi:unifi 0750`
before the rollout. After the rollout, if a plan-time probe found an entry
that is too open (or the probe failed), it removes group write and other
access from existing entries: directories at most 0750, files at most 0640.
That `find`/`chmod` runs from `/` as `unifi` (`runuser`), which owns the
directory and its files, so a symlink swapped in after `find` cannot redirect a root
`chmod`; symlinks are never followed and ownership is not changed. A
root-owned entry that is too open fails that step. A final read-only probe
requires `750 unifi:unifi` and no entry readable by others. Adding the
`UMask` changes the unit, so the first deploy with it restarts the
controller.

The unit/argfile and package changes trigger controller rollout. Pending unit
reload/restart state is recovered after an interrupted run. The local
self-signed HTTPS `/status` endpoint must return 200 with JSON `meta.rc=ok` and
`meta.up=true`. Optional UFW rules
preserve the role's five ports/comments without enabling UFW or removing
other rules. Traefik uses its watched dynamic route and is not restarted.

| Setting | Default | Behavior |
|---|---|---|
| `routine` | `None` | explicit artifact selection enables routine reconciliation |
| `installed_package_version` | required | compatibility mode exact assertion `9.5.21-31260-1` |
| `controller_bind_address`, `external_hostname` | required | IPv4 backend and route hostname |
| `jvm_min_heap_mb`, `jvm_max_heap_mb` | `1024`, `2048` | positive heap limits, min ≤ max |
| `traefik_enabled`, `manage_firewall` | `True` | false leaves existing settings untouched |
| `traefik_entrypoints`, `traefik_certresolver` | `("web-secure",)`, `"letsencrypt"` | `None` resolver emits `tls: {}` |
| `traefik_ip_allowlist` | `()` | source networks; empty leaves controller login protection |
| `create_homeassistant_user`, `homeassistant_username` | `False`, `"homeassistant"` | routine reconciliation; assertion only in compatibility mode |
| `mongodb_logrotate_enabled`, `mongodb_monitor_script_enabled` | `True`, `True` | false leaves existing files untouched |
| `mongodb_log_max_size_mb` | `500` | daily monitor threshold |
| `healthcheck_timeout` | `120` | total readiness deadline in seconds; each request is bounded by the remaining time |

## Validation and evidence

Check mode performs authenticated database reads. Its mongosh client creates
and removes a unique 0700 HOME with a non-secret 0600 configuration disabling
logging, telemetry and update checks. All child output stays in memory;
credential hashes are not printed. This ephemeral client footprint also
exists in compatibility mode.

Unit tests cover compatibility, selection validation, Mongo config preservation,
HA identity/privilege reconciliation and secret-safe failures. The manual
`UniFi routine integration` workflow selects an immutable implementation SHA
on a disposable GitHub Ubuntu x86 VM. Its harness provisions authenticated MongoDB 8, then uses the production API to install
Java 17 and UniFi 9.4.19 with a zero-mutation repeat, before exercising the selected 9.5.21 package update,
startup, true zero-mutation repeats, private logs (`/var/log/unifi` 0750, no entry readable by others) after each repeat, Mongo/HA drift repair and refusal paths.
The workflow result, not merely the presence of the harness, is qualification
evidence. Live host qualification and dispatcher routing are recorded by the
private control plane.

Readiness requires HTTP200 with JSON `meta.rc=ok` and `meta.up=true`. UniFi
serves HTTP200 with `up=false` and HTML API startup pages before it is ready;
deployment waits for the explicit ready signal before HA reconciliation. The
configured health timeout bounds the whole wait, and redirects are rejected.

HA privileges use the controller's string-valued account/site references. When
only legacy ObjectId references exist, routine reconciliation repairs one
privilege in place, preserving its ID and the account ID. An already-working
canonical record leaves harmless legacy duplicates intact; no records are
deleted or broader roles granted.

The full disposable Linux chain passed on 2026-10-26 in
[run 40347259878](https://github.com/ephes/ops-deploy/actions/runs/40347259878),
using implementation `b5dc1143641ea41fe479c5b32c2164940c115147` and harness
`d0ddbd84602020d4840f74578c0474e5e0dba557`. Install, update and Mongo/HA repair
had 17, 5 and 3 mutating operations respectively, each followed by a zero-mutation
repeat. Authenticated HA API access matched the external database
site identity; only the system Mongo process ran. The actual Temurin17 JVM
executable/version remained unchanged across update. Nonempty-database,
insufficient-permission and wrong-authentication admission faults ran zero
operations; a bad artifact digest preserved the running controller. This
qualifies an initialized authenticated MongoDB prerequisite, not fresh MongoDB
bootstrap or an unrelated live host.
