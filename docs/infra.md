# PostgreSQL and Redis

`ops_deploy.infra` ports the shared host services of ops-library:
`postgres_install` and `redis_install` (and `docker_install`, `vector_apt_install`,
`certbot_dns` and `encrypted_volume`, below). Like the [base deploys](base.md) each is
a frozen, strict config plus a `@deploy` function, outside the size-capped
helpers/ops/core layer. Passwords are deploy arguments, never config fields,
so a config can be printed and compared without exposing anything.

```python
from pydantic import SecretStr
from ops_deploy.infra import (
    DatabaseSpec,
    PostgresInstallConfig,
    RedisInstallConfig,
    deploy_postgres_install,
    deploy_redis_install,
)

deploy_postgres_install(
    PostgresInstallConfig(),
    databases=(DatabaseSpec(name="app", owner="app", password=SecretStr(pw)),),
)
deploy_redis_install(RedisInstallConfig(requirepass_enabled=True), SecretStr(redis_pw))
```

Field names follow the role variables without the role prefix; defaults are
the role defaults unless noted.

## Coexistence with the roles

Both deploys write the same bytes the roles write: `pg_hba.conf`, the
`conf.d/20-ops-library.conf` drop-in, `redis.conf` (including the `Managed by
Ansible` header) and the `.sources` file `deb822_repository` writes (fields in
its order). `tests/test_infra_parity.py` renders the vendored role templates
and compares, and checks the default files against macmini's sizes and its
PGDG `.sources` file. A host set up by one tool therefore shows no change when
the other runs, and no restart.

Existing data is never dropped or recreated. Databases and login roles go
through [`postgres_database`](concepts/helpers.md): it creates what is missing,
changes a database's owner or a role's password in place, and has no drop path.
The Redis data directory is only created and its owner and mode set.

Directories get the role's owner and mode, and setuid, setgid and sticky bits
are cleared as Ansible's `file` module does (the Ubuntu Redis package creates
`/etc/redis` and `/var/log/redis` setgid; `chmod 755` alone keeps that bit on
a directory).

## postgres_install

`deploy_postgres_install(cfg, databases=(), extensions=())`

| Field | Default | |
|---|---|---|
| `version` | `"17"` | major version, digits only |
| `cluster_name` | `main` | config in `/etc/postgresql/<version>/<cluster>` |
| `service_name` | `postgresql` | |
| `use_pgdg_repo` | `True` | `False` removes the `.sources` file and `/etc/apt/keyrings/<repo_name>.{asc,gpg}`, as the role's `state: absent` does |
| `repo_name`, `repo_url`, `repo_components`, `repo_key_url`, `repo_keyring` | the role's | |
| `repo_codename` | `None` | `None`: the host's `VERSION_CODENAME`; the suite is `<codename>-pgdg` |
| `packages` | `None` | `None`: `postgresql-`, `postgresql-client-`, `postgresql-contrib-<version>`, `libpq-dev` |
| `extra_packages` | `("python3-psycopg2",)` | |
| `listen_addresses` | `("localhost",)` | tuple (joined with `,`) or one string |
| `port` | `5432` | |
| `manage_conf_d`, `conf_d_filename` | `True`, `20-ops-library.conf` | |
| `config_overrides` | `{}` | strings are quoted, other values written as Python prints them (the template's behaviour) |
| `manage_pg_hba`, `pg_hba_rules` | `True`, the role's four rules | `PgHbaRule(type, database, user, address, auth_method, auth_options, comment)` |
| `admin_user` | `postgres` | SQL runs as this user over peer authentication, against `port` (which selects the cluster) |
| `service_enabled` | `True` | |
| `restart_on_change` | `True` | restart when the drop-in or `pg_hba.conf` changed |
| `manage_cluster_service` | `True` | also keep `postgresql@<version>-<cluster>` running |

`DatabaseSpec(name, owner, password)`: a database and its owner, a login role
with that password (non-empty ASCII). `ExtensionSpec(name, database)`:
`CREATE EXTENSION IF NOT EXISTS` when `pg_extension` does not list it.

Steps: PGDG key (downloaded once) and `.sources` file, `apt update` when the
file changed, otherwise a cache older than an hour is refreshed (a failure is
ignored, as in the role); the packages that are neither installed nor
provided by an installed package (`postgresql-contrib-<version>` is a virtual
package provided by `postgresql-<version>`, which Ansible's `apt` accepts);
config directory, drop-in, `pg_hba.conf`;
units running and enabled; one restart if a config file changed; databases;
extensions.

Differences from the role, on purpose:

- Users and databases come in pairs (`DatabaseSpec`); every caller of the role
  pairs one user with one database. `role_attr_flags` other than `LOGIN`,
  `state: absent`, `encoding`/`lc_*`/`template` and `admin_password` are not
  ported (no caller uses them). Two specs for one owner must use the same
  password.
- `service_state` is not ported: the service is always running.
- On a config change only `service_name` is restarted; its clusters restart
  with it (`PartOf=`). The role restarts both units, so the cluster twice.
- `python3-debian` is not installed: only Ansible's `deb822_repository`
  module needs it, and the role installs it itself when it runs.
- No `daemon_reload` on every run (nothing here writes unit files).

## redis_install

`deploy_redis_install(cfg, password=None)`

| Field | Default | |
|---|---|---|
| `package_name` | `redis-server` | `redis-tools` is always installed too |
| `add_official_repo` | `False` | adds `redis-official.sources` with `apt_repo`, `apt_suite` (`None`: the host's codename), `apt_components`, `repo_key_url`, `repo_keyring_path` |
| `bind_addresses` | `("127.0.0.1", "::1")` | at least one |
| `port`, `protected_mode`, `supervised_mode`, `databases` | `6379`, `True`, `systemd`, `16` | |
| `requirepass_enabled` | `False` | needs `password` |
| `save_rules` | `("900 1", "300 10", "60 10000")` | empty: `save ""` |
| `appendonly`, `appendfilename`, `appendfsync` | `False`, `appendonly.aof`, `everysec` | |
| `maxmemory`, `maxmemory_policy` | `"0"`, `noeviction` | `0`/`0b`/`0B`: unlimited |
| `tcp_backlog`, `timeout`, `tcp_keepalive`, `stop_writes_on_bgsave_error` | `511`, `0`, `300`, `True` | |
| `loglevel`, `log_dir`, `logfile` | `notice`, `/var/log/redis`, `None` (`<log_dir>/redis-server.log`) | |
| `config_path`, `data_dir`, `user`, `group`, `service_name` | the role's | |
| `restart_on_change` | `True` | |
| `check_host` | `None` | address of the final `PING`; `None`: the first bind address |
| `validate_config` | `False` | `True` is refused (see below) |

The password must not be a placeholder (`changeme`, `password`) and, since it
is written unquoted into `redis.conf`, must not contain whitespace, quotes or
control characters.

Steps: optional official repository; packages; data directory (`0750`), log
directory (`0755`) and config directory; when `redis.conf` differs, the old
file is copied to `redis.conf.<pid>.<date>@<time>~` (the role's `backup: true`
name; created private, then `root:redis 0640`) and the new one installed with `secret_file` (`root:redis 0640`, never in
a diff or on a command line); earlier backups not `root:redis 0640` are
restricted; restart if the file changed; service running and enabled; a
restart if the server still answers `PING` without a password while one is
configured, or started before the current `redis.conf` was written; finally a
read-only `PING` (with the password on stdin), as the ops-control playbook's
post task does.

Differences from the role, on purpose:

- The role re-checks a running server by trying the configured password. That
  needs the password in a probe; this deploy compares `redis.conf`'s time with
  the service's start time instead. Both catch a server left running an older
  configuration.
- The apt cache is refreshed when older than an hour, not on every run.
- With `add_official_repo` the armored key is stored dearmored at the `.gpg`
  path (the role stores it armored, which apt does not read there).
- `validate_config` (try a candidate in a throwaway `redis-server` first) is
  not ported; it is off in every inventory.
- Whether to back up is decided from the file before the run, so on a fresh
  host the package's default `redis.conf` is not kept.

## docker_install

`deploy_docker_install(cfg)`: Docker Engine, CLI, containerd, buildx and the
Compose plugin from Docker's apt repository (Ubuntu only, like the role). Fields
follow the role (`repo_url`, `repo_suite` (`None`: the release codename),
`repo_components`, `repo_key_url`, `repo_keyring_path`, `prerequisite_packages`,
`packages`, `remove_conflicting_packages` and its list, `service_name`,
`enable_service`/`start_service`/`manage_service`, `users`, `configure_daemon`
with `daemon_config_path`/`daemon_config`, `verify`, `verify_docker_info`).

Steps: prerequisites (including `python3-debian`, which only Ansible needs, so an
Ansible run afterwards finds them), conflicting distribution packages purged,
the key (downloaded once) and `docker.sources` (with `Architectures:`, byte for
byte what `deb822_repository` writes), `apt update` when the file changed,
packages, `daemon.json` as `to_nice_json` (restarting Docker when it changed),
the `docker` group and its members, the service, then read-only checks
(`docker --version`, `docker compose version`, the unit, `docker info`).
Containers, images, volumes and networks are never touched.

## vector_apt_install

`deploy_vector_apt_install(cfg)`: the key is downloaded once to
`repo_key_tmp`, converted with `gpg --dearmor` into `repo_keyring_path` (when
the key was just downloaded or the keyring is missing), `vector.list` holds the
role's single line, and the unpinned package comes from the `vector-0`
channel. Fields are the role's (`package_name`, `repo_url`, `repo_channel`,
`repo_version`, `repo_key_url`, `repo_key_tmp`, `repo_keyring_path`,
`repo_list_file`).


## certbot_dns

`deploy_certbot_dns(cfg, secret)`: port of the `certbot_dns_deploy` role
(ops-library 2.51.0 and later, checked against `540ede2b`, 2.56.0): certbot
with the DNS-01 plugin, one lineage (apex and wildcard by default), its deploy
hook and `certbot.timer`. `secret` is the provider credential, a Gandi LiveDNS
API key or the base64 TSIG secret; it is written with
[`secret_file`](concepts/operations.md) and never put on a command line, in a
diff or in an error.

```python
from pydantic import SecretStr
from ops_deploy.infra import CertbotDnsConfig, deploy_certbot_dns

deploy_certbot_dns(
    CertbotDnsConfig(
        provider="rfc2136",
        domain="home.example.org",
        email="admin@example.org",
        rfc2136_server="192.0.2.53",
        rfc2136_key_name="acme-key",
        renewal_hooks=("systemctl restart traefik",),
        consumer_units=("traefik",),
        single_lineage=True,
    ),
    SecretStr(tsig_secret),
)
```

| Field | Default | |
|---|---|---|
| `provider` | `gandi` | `gandi` or `rfc2136` |
| `domain`, `email` | required | lowercase DNS name (the lineage's `--cert-name`); one address. The role's defaults are one site's values, so there are none here |
| `rfc2136_server`, `rfc2136_port` | `None`, `53` | an IP address (the plugin does not resolve names); required for `rfc2136` |
| `rfc2136_key_name`, `rfc2136_key_algorithm` | `None`, `HMAC-SHA256` | TSIG key name (required for `rfc2136`); `HMAC-SHA256/384/512`, any case |
| `wildcard`, `include_base`, `additional_domains` | `True`, `True`, `()` | the requested names: base, `*.<domain>`, extras (duplicates dropped) |
| `key_type`, `staging`, `propagation_seconds` | `ecdsa`, `False`, `120` | |
| `config_dir` | `/etc/letsencrypt` | the only value accepted: the role's certbot commands pass no `--config-dir` |
| `credentials_file`, `rfc2136_credentials_file` | `<config_dir>/dns-credentials.ini`, `<config_dir>/dns-rfc2136-credentials.ini` | one file per provider, `root:root 0600` |
| `renewal_hook_path`, `renewal_hooks` | `<config_dir>/renewal-hooks/deploy/reload-services.sh`, `()` | the role's hook script, one isolated block per item |
| `reconfigure_on_provider_change` | `True` | `certbot reconfigure` when the lineage's authenticator differs |
| `remove_unused_credentials` | `True` | delete the other provider's file once no renewal configuration names it |
| `stray_config_dirs` | `()` | leftover certbot trees to delete (see below) |
| `package_state` | `present` | or `latest` |
| `single_lineage` | `False` | read-only check: `renewal/*.conf` (every entry, symlinks included, as certbot's glob) is only `<domain>.conf` |
| `consumer_units` | `()` | read-only check: each unit is loaded and active |

`single_lineage` and `consumer_units` are not role variables: they port the
post-task assertions a consumer's playbook runs after the role (a host-wide
deploy hook is only safe for one lineage; the certificate's readers must be
running).

### Steps

1. A read-only probe (`files/certbot_dns_host.py probe`, `python3 -I` as root)
   reads the lineage's `renewal/<domain>.conf`, its live links and archive,
   the live certificate's dates, names and key type (`openssl x509 -dates
   -text`; the private key is never read), the other provider's credentials
   file with the role's `grep -l` scan, and which stray dirs exist. It
   contacts nothing but the local `openssl` and `grep`.
2. With the lineage in place and `stray_config_dirs` set, the role's vendored
   `certbot_stray_guard.py` runs read-only; any refusal fails the deploy here,
   before any change (the role refuses after it requested the certificate).
3. `certbot` and the plugin package; `<config_dir>` `root:root 0755`; the
   credentials file, byte-identical to the role's template.
4. `certbot certonly` with the role's argv, byte for byte (including each
   domain as one `-d <name>` word), **only when certbot would act** (below).
5. `certbot reconfigure` when the probe saw another authenticator; the step
   reads the authenticator again when it runs and does nothing if `certonly`
   already switched it, as the role's later task does.
6. Cleanup (`remove_unused_credentials`): the other providers'
   `dns_<provider>_*` lines leave the managed lineage once its authenticator
   is the configured one (written through a symlink, owner and mode kept,
   like `lineinfile`), then the other provider's file is removed when the
   role's scan, run again at that point, exits 1. Exit 0 (in use) and 2 (scan
   error, for example no `*.conf`) keep it; anything else fails. The step is
   planned only when the file exists and either the scan already exits 1 (or
   fails otherwise) or an earlier step of this run can change the answer.
7. Stray dirs: the guard runs again and only its decision is applied (the
   role's assertion, then `rmtree` of each removable dir).
8. The hook directory `root:root 0755`, the hook `root:root 0755`
   byte-identical to the role's template, `certbot.timer` enabled and started.
9. Read-only checks: the hook is a regular file with mode 0755, then
   `single_lineage` (every non-hidden `renewal/*.conf` entry counts, a
   symlink too, since certbot's glob renews it) and each consumer unit
   (`LoadState=loaded` and `ActiveState=active` as whole lines).

### When certonly runs

The role runs `certonly --keep-until-expiring --expand` on every run and lets
certbot decide; certbot fetches the ACME directory each time, even when
nothing is due. Here the probe makes certbot 2.9's decision while planning,
and `certonly` runs only for:

- no `renewal/<domain>.conf` yet, or one whose `archive_dir`, `cert`,
  `chain`, `fullchain` or `privkey` is not the standard path, or one configobj
  might read otherwise or reject (a duplicate key or section, a line that is
  no comment, `[section]` or `key = value`, an inline comment, an unbalanced
  or triple-quoted value; certbot ignores such a lineage);
- a missing live certificate;
- certificate names (CN and SANs, compared as sets, case-insensitive) other
  than the requested ones (`--expand`);
- another key type than `key_type` (certbot renews at once when
  `--key-type` and `--cert-name` are both given);
- live links that are broken, point at another kind or are not on the latest
  complete archive version (certbot relinks);
- otherwise a certificate inside its renewal window, unless the lineage sets
  `autorenew = False`. The window is the lineage's `renew_before_expiry` (a
  number of days or weeks; another form counts as due) or, when unset, the
  longer of 30 days (certbot 2.x) and a third of the lifetime (newer
  certbot), so it errs towards running `certonly`.

Anything the probe cannot read exactly (a failed probe, an unknown
`autorenew` value) counts as due: `certonly` then decides, as in the role,
and a probe that failed is run again at the end and fails the deploy if it
still fails. A converged host gets no certbot command and no mutating
operation. Not modelled: OCSP revocation and ACME renewal information (ARI);
`certbot.timer` (`certbot renew`, twice a day) still acts on both. When
`certonly` runs but certbot finds nothing to do, the step is still reported
as changed (the role keys its changed state on certbot's "not yet due"
output).

### Stray certbot dirs

`stray_config_dirs` lists certbot trees outside `config_dir` to delete (for
example `/letsencrypt` an earlier restore extracted into `/`). As in the role,
each path must be absolute and normalized (letters, digits, `.`, `_`, `-`,
`/`, no `.`/`..` segments, no `//`, no trailing slash) and must not be equal
to, inside or above `config_dir`, `/etc/letsencrypt`, `/var/lib/letsencrypt`
or `/var/log/letsencrypt`; both are checked when the config is built. The
guard, vendored byte for byte from the role (`infra/files/certbot_stray_guard.py`,
checked by `tests/test_ops_library_drift.py`), also checks after resolving
symlinks, requires a real directory with a real `renewal/`, and refuses
everything unless the live trees use only literal paths (no symlinks besides
certbot's lineage links, plain paths inside the live dirs in every renewal
configuration) and are readable. A missing path is skipped; a removed tree
gives no operation on the next run.

### Differences from the role, on purpose

- `certonly` runs only when certbot would act (above); the role contacts the
  ACME server on every run.
- A guard refusal fails before any change instead of after `certonly`.
- `config_dir` must be `/etc/letsencrypt` (the role accepts another value but
  its certbot commands would still use the default tree).
- `single_lineage` counts symlinked `renewal/*.conf` entries; the playbook's
  `find` (`file_type: file`) skipped them although certbot renews them.
- `domain` and `email` have no defaults; `domain`, extra names, `email`, the
  TSIG key name and server are checked strictly (the server with Python's
  `ipaddress`), the credential must not be empty, `CHANGEME` or contain
  control characters (a newline would add settings to the file), and a hook
  must not contain NUL.
- A directory or other special file at the other provider's credentials path
  is refused (the role would delete it recursively once unused).
- Debian-family hosts with systemd only (the role's `package` module would
  also take other package managers).
- The consumer check requires the exact `ActiveState=active` line; the
  playbook's substring test also accepted `activating`.

### Tests

`tests/test_infra_certbot_dns.py` renders the vendored role templates
(`tests/parity/ansible/certbot_dns_deploy__*`) and compares, pins the
`certonly` and `reconfigure` argv, and runs the deploy on the fake connector:
fresh host, converged host (no certbot command, credentials only on stdin),
due certificate, provider switch, the cleanup scan's exit codes, stray
removal, refusal and first-run cases, a failed probe, and the read-only
checks. `tests/test_infra_certbot_dns_host.py` runs the host script and the
guard for real on temp trees with `openssl`-made certificates.
`tests/test_infra_certbot_dns_docker.py` runs against real certbot 2.9,
openssl and systemd in an owned Docker container and is skipped unless
`CERTBOT_DNS_DOCKER_CONTAINER` holds its full ID. The container must be named
`ops-deploy-certbot-dns-20261020`, carry the labels
`ops-deploy.fixture=certbot-dns` and
`ops-deploy.run=pyinfra-certbot-dns-20261020`, and run systemd as PID 1 with
`--network none` (no ACME server is reachable), no binds, ports or devices, a
private cgroup namespace and `SYS_ADMIN` as its only added capability (an
Ubuntu 24.04 image with `systemd systemd-sysv certbot
python3-certbot-dns-rfc2136 openssl python3`, `/sbin/init` after remounting
`/sys/fs/cgroup` writable; `--security-opt apparmor=unconfined --tmpfs /run
--tmpfs /run/lock`). It checks that the planned `certonly` agrees with
certbot's own decision (`_find_lineage_for_domains_and_certname` and
`has_pending_deployment` on the same tree) for not-due, due, renamed,
key-type, relinked and `autorenew = False` lineages; that a first run writes
the credentials and hook and removes an unused old file and a stray tree,
and a second run changes nothing and starts no certbot (certbot writes its
log on every start); the leftover-settings cleanup on the real file; an old
file another lineage uses is kept; a guard refusal changes nothing; and the
final checks fail on a second lineage (also a symlinked one) or a missing
consumer.

## Mail database foundation

`ops_deploy.services._mail_database` supplies the narrow shared foundation for
mail applications: `MailDatabaseConfig`, `ensure_mail_database` and read-only
`require_mail_database`. It creates only missing roles/databases, retains
PostgreSQL's default database owner, and preserves existing owners and grants.
Matching SCRAM credentials retain their verifier; a login-only repair does not
rotate it. Unsupported, malformed or inconsistent verifier state refuses before
reconciliation. Passwords and verifiers travel through protected stdin.

The requirement operation can check DATABASE-level CONNECT, CREATE and TEMPORARY
privileges. It never grants privileges or checks application tables/schemas.
PostgreSQL installation, application schemas and mail catalog rows are outside
this API. Applications with planning-time admission require foundation/password
convergence in a prior run. See the [module contract](https://github.com/ephes/ops-deploy/blob/main/src/ops_deploy/services/_mail_database/README.md)
for signatures and qualification limits.

Existing roles with NULL password verifiers are refused, like unsupported MD5;
this API does not interpret unknown credentials as permission to initialize them.
Passwords currently use the explicit nonempty ASCII contract (excluding CR, LF
and NUL). Non-ASCII inputs refuse before verification or mutation; no Unicode
normalization or SASLprep equivalence is claimed. Database-only requests contain
no password.

## encrypted_volume

`ops_deploy.infra.encrypted_volume` ports the configure path of
`encrypted_volume_prepare` for a LUKS volume that already exists: the
passphrase becomes the keyfile `cryptsetup open` and `/etc/crypttab` use, the
mapper is opened when it is closed, and the filesystem inside is mounted
through its `/etc/fstab` entry. Deploys whose data lives on the volume call it
first, as the Ansible plays import the role's playbook first.

```python
from pydantic import SecretStr
from ops_deploy.infra import EncryptedVolumeConfig, deploy_encrypted_volume

deploy_encrypted_volume(
    EncryptedVolumeConfig(device="/dev/sda", expected_luks_uuid="e301d851-3454-4b1b-a3a2-5e71f18af8d7"),
    SecretStr(passphrase),
)
```

Never done, by construction: format a device or mapper (`allow_format`),
close a mapper, unmount, read or change the LUKS header or keyslots, or
switch the device path (`device_by_id`; `device` is resolved with `realpath`
and recorded in `/etc/crypttab` as the role does without `device_by_id`).
Passphrase mode (`use_keyfile: false`), `validate_only`, `fs_label` and
`no_log` are not ported.

| Field | Default | Notes |
|---|---|---|
| `device`, `expected_luks_uuid` | required | the device must be a block device whose LUKS header has this UUID |
| `mapper_name`, `mount_point` | `cryptdata`, `/mnt/cryptdata` | |
| `fs_type`, `mount_opts`, `fstab_dump`, `fstab_passno` | `ext4`, `defaults,noatime`, `0`, `0` | the fstab entry's fields |
| `keyfile_path` | `None` | `None`: `/root/.luks-key-<mapper_name>`; never on the volume itself |
| `keyfile_owner`, `keyfile_group`, `keyfile_mode` | `root`, `root`, `0400` | |
| `crypttab_options` | `luks` | |
| `mount_owner`, `mount_group`, `mount_mode` | `root`, `root`, `0755` | the mount point (the filesystem's root once mounted) |
| `packages` | `cryptsetup`, `cryptsetup-initramfs` | installed only while `cryptsetup` is missing |

### Admission, then at most one step

While planning, one read-only host program (`files/encrypted_volume_host.py`,
run as `python3 -I -B`, source and config base64 so fish passes them through)
looks at the host with `blkid -p` (no cache), `lsblk` and `findmnt` only: no
`cryptsetup` call, so not even a LUKS lock file is created. It refuses, and
the deploy stops before any operation, when:

- the device is missing or not a block device, not a LUKS container, or its
  header UUID is not `expected_luks_uuid`;
- the device is already mapped under another name, or `mapper_name` is open
  on another device (the role's check for the first never fires: it compares
  `lsblk -p` paths with a basename);
- the open mapper holds no filesystem (this deploy never formats) or another
  type than `fs_type`;
- something else is mounted at `mount_point` (also while the mapper is
  closed), or the volume is mounted read-only;
- `/etc/fstab` has more than one entry for `mount_point` (also while the mapper
  is closed).

Otherwise it reports what is pending. Then: `cryptsetup` is installed when it
is missing; the keyfile directory `root:root 0700`; the keyfile with
`secret_file` (rewritten only when its SHA-256, owner or mode differ); the
mount point; and, only when something is pending, one step that re-runs the
admission and then

1. opens the mapper with the keyfile when it is closed (`udevadm settle`
   afterwards);
2. writes the crypttab line `<mapper> <device> <keyfile> <options>` with
   `lineinfile`'s semantics (the last line matching `^<mapper>\s` is
   replaced, otherwise the line is appended; other lines stay);
3. writes the fstab entry with `ansible.posix.mount`'s semantics (matched by
   mount point; source `UUID=<filesystem UUID>`; a differing entry is
   rewritten as `src name fstype opts dump passno`, a missing dump/passno
   counts as differing; otherwise the entry is appended);
4. mounts the volume when it is not mounted, or runs `mount -o remount` when
   an existing entry was rewritten (an added entry leaves the mount as it is).
   Unlike the role, a failed remount fails the deploy instead of falling back
   to unmount and mount.

Both files are written through a sibling temporary file and renamed, keeping
an existing file's owner and mode. Afterwards `/etc/crypttab` is enforced
`root:root 0640` and `/etc/fstab` `root:root 0644` (as the role does), and a
final read-only probe must find nothing pending.

On a converged host nothing is written and nothing is remounted. Equal
inputs give the files the role writes, so the role run after this deploy
changes nothing (the owned native fixture checks it with the role).

### Tests

`tests/test_encrypted_volume.py` covers the crypttab and fstab edits, every
refusal and the plan; the owned native fixture
[`tests/integration/linux_apps`](https://github.com/ephes/ops-deploy/tree/main/tests/integration/linux_apps)
runs it on a real LUKS loop device: fresh, repeat, closed mapper, lost lines,
changed options, keyfile drift, the refusals, recovery and the role run after
it.

## Persistent network and Tailscale

`ops_deploy.infra.netplan` exposes `NetplanConfig` and `deploy_netplan` for the
original networkd route-guard and NetworkManager configuration. The four original
role templates remain byte-identical. Healthy repeats do not reconfigure or
exercise recovery. Declared drift uses native merged-input validation before
publication and one bounded transient activation job observed through the
existing SSH connection; queued jobs are not cancelled as if already complete.
Unknown outcome or uncertain owned-job cleanup requires retaining writer
ownership and inspecting the saved failure, without automatic replay/repair.
Physical LAN and boot/initramfs recovery require separate evidence.

`ops_deploy.infra.tailscale` provides the native core, cached endpoint, dedicated
Nyxmon SQL and explicit backup/manual-LAN-restore/remove APIs. Current native
component qualification binds Tailscale1.104.2. Running nodes retain identity;
only selected CorpDNS/RouteAll drift invokes `set`. Public repository key refresh
still checks upstream on every ordinary run and compares validated bytes before
replacement. `latest` retains the original package-present semantics.

Cached metrics retain their original Python/pinned-Rust policy, timer and
cgroup-BPF controls. Fresh compatible error telemetry stays visible; missing,
stale, incompatible or changed collector inputs cause an explicitly managed
refresh. Dry plans never collect. Dedicated Tailscale SQL changes only original
configuration fields and preserves disabled/status/processing/schedule columns,
including during a configuration edit. SQLite check uses read-only database
mode; this is not a claim of global zero filesystem I/O or absence of SQLite
coordination metadata.

Backups intentionally copy identity material using the original layout, archive
and optional controller fetch. The declared operator directory defaults to
`~/backups/tailscale`, with directory0700/archive0600 and a private remote handoff;
there is no agent-workspace restriction. The original hot-rsync consistency
limit remains. The legacy default backup prefix is `manual`, while restore
requires the inventory-host prefix: `just backup tailscale macmini macmini`
creates the appropriate archive for `just restore-tailscale-manual latest macmini`.
A newer foreign-prefix archive still makes legacy `latest` refuse; automatic
host-filtered latest selection is a separate follow-up. Ordinary metadata restore stays excluded: explicit manual restore
requires a LAN/out-of-band connection and validates before stopping/replacing
state. A failed restore never silently repairs or retries. Removal preserves
original stop-before-best-effort-logout ordering (online revocation unattested).
Because the actual1.104.2 vendor purge script deletes state, `purge_state=False`
removes without dpkg purge; true explicitly purges. Inventory adoption, complete
composite/lifecycle and hardware qualification remain separate from these APIs.

At the API level, create the backup with `TailscaleBackupConfig(prefix=<inventory_name>)`
so the strict restore host prefix matches `TailscaleManualRestoreConfig(inventory_name=...)`.
The `just backup` and `just restore-tailscale-manual` examples above are recipes in
the external **ops-control** consumer, not this package’s justfile.

The root `ops_deploy.infra` namespace resolves its Tailscale exports when requested,
so an existing Fractal monitoring component can initialize first without a circular
model import. Direct Tailscale subpackage APIs and typed root imports are unchanged.

## Retired software-estate tools

`ops_deploy.infra.software_estate_remove` provides
`SoftwareEstateRemoveConfig` and `remove_software_estate`. It preserves the
original two-task removal role: the installation path must be exactly
`/usr/local/lib/software-estate`, then that leaf is absent. A directory and its
contents, a regular file, or a symbolic link are removed without a backup;
removing a link does not remove its target. An already absent path is unchanged.
No service, account, package, inventory data or unrelated path is managed.

The private removal command retains its existing confirmation and macmini scope.
This is a lifecycle-only component, not a new deployable service or restored
software-estate pilot. Tests exercise the standard operation with real local
facts and execution in a temporary owned directory, including strict unchanged
peer metadata and zero-change repeats; the fixed real installation path is
never touched by those tests. Both Ubuntu24.04 CI legs passed these twelve tests,
including four actual LocalConnector first/repeat cases (directory, file, link,
absent), in [run40758861268](https://github.com/ephes/ops-deploy/actions/runs/40758861268).
All 792 previously qualified package resources were preserved byte-for-byte;
the actual noneditable controller artifact's full 793-file set matched Git.
This qualifies the owned Linux primitive, not removal of an inventory installation.
Private routing adoption and a bounded real dry plan remain separate.

## Declared ZFS storage and scheduled backup configuration

`ops_deploy.infra.zfs_storage` provides `ZfsPoolConfig`, `ZfsDatasetConfig`,
`ZfsStorageConfig` and their `deploy_zfs_pool`, `deploy_zfs_dataset` and
`deploy_zfs_storage` functions. The bundle retains pool order and sorts datasets
by path depth, then name. Supply encryption material separately as `SecretStr`
values keyed by pool name; config models contain no credentials.

```python
from pydantic import SecretStr
from ops_deploy.infra.zfs_storage import (
    ZfsPoolConfig,
    ZfsDatasetConfig,
    ZfsStorageConfig,
    deploy_zfs_storage,
)

pool = ZfsPoolConfig(
    name="example",
    vdevs=("/dev/disk/by-id/replace-with-declared-device",),
    allow_create=True,
    filesystem_properties={"compression": "lz4"},
)
config = ZfsStorageConfig(
    pools=(pool,),
    datasets=(ZfsDatasetConfig(name="example/data"),),
)
# Obtain this value from the normal secret store; never put a real key in source.
deploy_zfs_storage(cfg=config, credentials={"example": SecretStr(source_key)})
```

The original explicit `allow_create` input remains required unless
`validate_only=True`; `force_create` defaults to false. Unknown pool/dataset
errors refuse creation rather than count as absence. For an existing encrypted
root, native `zfs load-key -n` validates the desired source key from stdin before
any key-file publication, including when its key is already loaded. Deployment
does not rotate keys, unload them, export pools, recreate datasets, scrub or
prune. It repairs declared properties and key metadata only when needed. The
original boot unlock unit remains enabled/started, with its boot/stop lifecycle;
a changed unit does not restart it during deployment. Validation-only retains
the original package/module prerequisites but performs no pool/dataset/key writes.

A separately deployed dataset can declare `parent_pool=pool` when an earlier
pool operation will create its parent. Only that exact absent parent can be
deferred during planning; actual execution still requires it. This does not add
implicit `zfs create -p`. The original `mounted=False` policy does not unmount an
existing filesystem. `casesensitivity` is creation-only, with a warning for
existing macOS-policy mismatches. The source's `inherit_encryption` flag was
unused by its create task: retaining it does not introduce `encryption=off`.
Binary size comparisons use Decimal multiplication and truncation, including
`none` versus zero. The source's `refreservation=auto` exception still performs
an ordinary managed `zfs set` on each invocation; it is not a read-only no-op.

`ops_deploy.infra.backup` provides `SyncoidConfig`, `UsbReplicationConfig`,
`MinioArchiveConfig`, `MailReplicationConfig` and their four `deploy_*`
functions. `SyncoidJob`, `UsbDrive` and `SnapshotRetention` retain explicit
rollback, force-delete, partial-receive, bookmark-rotation and managed-prefix
retention policies. The original scripts/templates are preserved; Sanoid stays
its separate existing API. Deploy configures packages, declared directories,
private keys, scripts and timers; it never explicitly invokes replication,
mail staging, snapshot pruning, attestation or spindown. Timers retain their
original `Persistent=true` behavior, so normal scheduling or a missed scheduled
job can run independently of deployment.

SSH private keys and USB pool keys are separate `SecretStr` deploy arguments.
On-host private-file equality stays in RAM and produces no credential digest or
file export; Linux OpenSSH validates private keys through a private anonymous
RAM descriptor. Existing content is preserved when only mode/ownership changes. Mail-role and
macmini restore-client private keys retain the original `regex_replace` literal
newline transformation; MinIO private-key bytes remain unmodified.
Known-host management performs a fresh ordinary peer keyscan every invocation,
compares before writing and preserves unrelated entries, aliases, comments and
other key types. It retains the original keyscan trust policy; it does not add
an authentication channel or suppress future peer key changes.

`ops_deploy.infra.backup.source` provides `BackupSourceConfig`,
`BackupRestoreAccessConfig`, `deploy_backup_source`,
`deploy_backup_restore_access` and `deploy_backup_restore_client` for the original delegated source scripts and
the Fractal mail-restore forced-command key. They install the existing mail staging/restore programs;
deploy never runs them or reads mail. The source play does not authorize keys on macmini; its existing SSH-key management retains that ownership. Existing unrelated Fractal root authorizations
are retained in memory without exporting their file contents. The control
plane preserves the exact original interleave: call `deploy_backup_source`
with `restore_client=False` on macmini for its wrapper files, then
`deploy_backup_restore_access` on Fractal for its restore wrapper/key, then
`deploy_backup_restore_client` on macmini for its private restore key and fresh
peer keyscan. Run the Fractal backup roles next, followed by its original
backup dataset subset. Direct single-host `deploy_backup_source` calls retain
`restore_client=True` by default. The original pre-task key assertions still
run before wrapper preparation even when client preparation is deferred.

Owned ARM Ubuntu/ZFS2.2.2 fixtures cover encrypted file-vdev pools, a mirror,
ordered datasets, source-key failures, native systemd/SSH configuration and
strict repeats. Synthetic runtime fixtures exercise real syncoid/bookmark
continuity and retention; physical USB/spindown efficacy is not attested.
The unchanged retention helper relies on native ZFS hold refusal and can fail
on a held candidate; it does not silently skip all held snapshots. Corrupt
anchor JSON refuses before mutation, with the original JSON decoder exception.
These component results do not constitute a production deployment receipt.
