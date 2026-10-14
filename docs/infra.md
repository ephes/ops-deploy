# PostgreSQL and Redis

`ops_deploy.infra` ports the shared host services of ops-library:
`postgres_install` and `redis_install`. Like the [base deploys](base.md) each is
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
