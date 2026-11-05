# Daybook Operations API

`services.daybook_operations_api` ports the original Operations API deployment,
including its PostgreSQL and uv dependencies, exported or Git source, separate
Python3.14 environment, protected configurations, genuine Django management,
systemd units and private Traefik router. Fresh installations are disabled.
Select enabled state explicitly; the public backend does not infer desired
state from an existing process or remember an earlier enable operation.

```python
from pathlib import Path
from ops_deploy.infra.postgres_install import PostgresInstallConfig
from ops_deploy.services.daybook_operations_api import (
    OperationsApiConfig,
    OperationsApiPins,
    OperationsProfile,
    deploy_daybook_operations_api,
)

cfg = OperationsApiConfig(
    source_path=Path("/prepared/daybook-export"),
    deploy_method="rsync",
    enabled=False,
    domain="operations.home.example.com",
    postgres=PostgresInstallConfig(manage_conf_d=False, manage_pg_hba=False),
)
pins = OperationsApiPins(
    secret_key=secrets["django_secret_key"],
    database_password=secrets["postgres_password"],
    signing_key_id="v1",
    signing_keys=signing_keys,
    profiles=(
        OperationsProfile(
            name="worker",
            host="worker",
            profile="operations-worker",
            enabled=True,
            tokens=(secrets["worker_token"],),
        ),
    ),
)
deploy_daybook_operations_api(cfg=cfg, pins=pins)
```

For Git, select `deploy_method="git"`, an exact40-character `git_revision`,
and optional `git_repo`. Rsync requires a prepared source directory and retains
the original excludes for Git, virtual environments, environment files, Python
caches, nested site/cache and experiments. It also excludes `*.egg-info`,
which the role does not: the frozen `uv sync` installs the project editable and
writes `src/daybook.egg-info` into the site, and the role's `--delete` removes it
again, so every Ansible run reports a source change and restarts both units.
Here a converged repeat (also right after an Ansible deploy) leaves it and plans
no source sync. The private caller resolves current
Daybook Main and owns the exported tree for the complete operation lifetime.
An existing exported tree must remain explicitly rsync in desired inventory;
changing it to Git is not an automatic migration strategy.
The site directory gets the mode the original role leaves behind: `0700` for
rsync (the role creates it `0750`, but its archive-mode `synchronize` then copies
the mode of the playbook's `0700` export directory onto it on every run) and
`0750` for Git. `sync_tree` keeps an existing directory's mode, so the port sets
the final mode itself, and a deploy after the role changes nothing there.

The original defaults include user/home `daybook-operations` and
`/home/daybook-operations`, site and separate `venv` underneath that home,
configuration `/etc/daybook-operations`, backups
`/opt/backups/daybook_operations`, loopback port10063, PostgreSQL17 and
`daybook_operations` database/owner. `site`, `venv`, `storage_path`, configuration,
backup, uv and router paths remain configurable. Record and capacity thresholds,
profile identities and purposes, allowed networks and signing-key selection
retain the original validations and defaults. Shared PostgreSQL listener/access
policy can be left unmanaged through `PostgresInstallConfig` as shown.

The four0600 configurations use the original templates: systemd environment,
quoted management shell companion, schema4 profiles and lifecycle metadata.
Profiles contain only principal identity and executor/monitor credentials;
source bindings, schedules and machine offers are not deployment inputs.
Management sources the companion inside the service-user shell. Secret values
never enter the controller's command arguments, and failure output is replaced
with the original bounded failure categories. An application failure stops the
remaining operations; it is not evidence that no preceding database write ran.

`migrate --noinput` and `provision_operations` execute as managed operations on
every normal deployment. Provisioning may save unchanged principal/credential
enabled values and disable omitted credentials. A semantic repeat therefore
still performs genuine management and database I/O. It does not edit source
bindings or machine offers. Determine pending migrations and source/dependency
effects before a production update, including changes in imported shared
Daybook modules even when the direct API files are unchanged.

A read-only `uv sync --check` determines dependency drift. A real frozen sync
runs for drift or changed source. Service restart follows source, dependency,
configuration or unit changes only when explicitly enabled; disabled installs
remain stopped. The enabled `/healthz` check establishes database readiness,
not successful source work or end-to-end client behavior.

The API and reconciliation processes share the installed source tree. An update
can change imported code before the restart; no transactional rollout or
application rollback is claimed. After partial management failure, inspect the
retained outcome and schema state before retrying or selecting another source.

The private playbook also has an original loopback-port ownership preflight.
`operations_api_port_preflight(cfg)` queues that read-only check before the
backend; it allows listeners belonging to `daybook-operations.service` and
refuses another owner. The standalone role did not contain this preflight, so
it is separate from the public backend rather than an added mandatory policy.

## Exact Git revision and original source ownership

The Git option runs under the dedicated service identity through the shared
`runuser` helper. A fresh clone keeps a valid index so a failed later fetch can resume. It fetches the exact
40-character revision, checks out detached, and verifies HEAD. A clean detached
repeat queues no Git mutation; tracked local changes are refused without force
or reset. The pyinfra SDK branch argument cannot represent a commit SHA and its
global become arguments are deliberately not used.

Rsync uses the established checksum/omit-directory-times helper with the original
exclusions and SDK tooling markers. On the original root connection the remote
binary is `/usr/bin/rsync`; no redundant `sudo rsync` shell wrapper is needed.
Transferred files get the service identity and a metadata-only inspection finds
remaining descendant ownership mismatches. Only mismatches are chowned, so a
converged repeat does not change unrelated inode timestamps. This is source
metadata enumeration, not a promise of globally zero read I/O.

## Backup, restore and removal

`services.daybook_operations_api.lifecycle` ports the
`daybook_operations_api_backup`, `_restore` and `_remove` roles. The archive
format belongs to Daybook: the installed `services/operations_api/lifecycle.py`
writes and reads it, and these deploys only call it as the service account
(`runuser -u daybook-operations`), exactly as the roles do (`become_user`). Either
tool therefore restores the other's archives.

```python
from ops_deploy.services.daybook_operations_api import (
    OperationsApiBackupConfig,
    OperationsApiRemoveConfig,
    OperationsApiRestoreConfig,
    deploy_daybook_operations_api_backup,
    deploy_daybook_operations_api_remove,
    deploy_daybook_operations_api_restore,
)

deploy_daybook_operations_api_backup(OperationsApiBackupConfig(required_mount="/opt/backups"))
deploy_daybook_operations_api_restore(
    OperationsApiRestoreConfig(
        archive="/opt/backups/daybook_operations/20261103T101500123456Z.tar",
        confirmed=True,
        clients_quiesced=True,
    )
)
deploy_daybook_operations_api_remove(OperationsApiRemoveConfig(confirmed=True, clients_quiesced=True))
```

| Role step | pyinfra |
|---|---|
| backup: `0700` backup root owned by the service account | same (`files.directory`) |
| backup: archive `<root>/<UTC %Y%m%dT%H%M%S%fZ>.tar`, or `daybook_operations_api_backup_archive` | same (`archive`); the name is taken on the controller, as `now(utc=true)` is |
| backup: `lifecycle.py backup --config … --archive …` as the service account | same |
| backup: report the archive path | printed by the run |
| backup: no fetch, no pruning | same |
| — | `required_mount`: the backup root must lie on that mount (ops-control: macmini's `/opt/backups`), checked before the first write |
| restore: assert confirmed, clients quiesced, absolute archive | same; `confirmed`/`clients_quiesced` are strict booleans |
| restore: `lifecycle.py validate` before any unit change | same |
| restore: stop and disable both units | disable, then stop, read from `ActiveState` (a unit waiting in `auto-restart` is stopped too); a unit already stopped and disabled is left alone |
| restore: `lifecycle.py restore --clients-quiesced`; units stay stopped | same |
| — | `validate_only`: guards and validation only, no unit change (`just pyinfra-restore … DRY_RUN=true`) |
| remove: assert confirmed and clients quiesced | same |
| remove: stop and disable the units that exist | same |
| remove: delete both unit files and the Traefik route | same; the route only while no Traefik transaction holds its lock |
| remove: `daemon-reload` on every run | only after a unit file was removed, so a repeat changes nothing |
| remove: keep database, account, site, configuration and backups | same |
| backup `tasks_from: register_echoport` (Echoport target, root bridge, FastDeploy token) | not ported; ops-control keeps `register-daybook-operations-backup.yml` on Ansible |

`tests/test_daybook_operations_api_lifecycle.py` checks the commands and the
guards on the fake connector. `tests/test_daybook_operations_api_lifecycle_docker.py`
runs all three against a Debian 12 container with systemd as PID 1, with a
synthetic stand-in for Daybook's private lifecycle tool (same command line, same
owner and unit checks): two backups, a refused restore, a validate-only
restore, a restore and its repeat, a removal and its repeat (no change). Build
the image and run it with:

```bash
docker build -t ops-deploy-daybook-ops-lifecycle:local tests/integration/daybook_operations_api_lifecycle
DAYBOOK_OPERATIONS_API_LIFECYCLE_DOCKER_IMAGE=ops-deploy-daybook-ops-lifecycle:local \
  uv run --locked pytest -q tests/test_daybook_operations_api_lifecycle_docker.py
```

The real dump/restore of the database is Daybook's own and is covered by its
suite, not here.
