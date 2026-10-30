# work_app

Port of the `work_app_deploy` Ansible role (rsync method) and of the
operations wiring in ops-control's `deploy-work-app.yml`: the work ledger, a
Django app on one SQLite database served by gunicorn, behind Traefik with
basic auth, plus its Echoport backup target and Nyxmon health check.

```python
from ops_deploy.services.work_app import WorkAppConfig, deploy_work_app

cfg = WorkAppConfig(
    source_path=Path("~/projects/work-ledger").expanduser(),
    secrets=SecretRef("secrets/prod/work_app.yml"),
)
deploy_work_app(cfg, store.load(cfg.secrets))
```

ops-control registers it with secrets from two SOPS files (see its
`docs/PYINFRA.md`).

## Secrets

| Key | Required | Used for |
|---|---|---|
| `django_secret_key` | yes | `.env` (`DJANGO_SECRET_KEY`); at least 50 characters from `[A-Za-z0-9_-]`, as the role asserts |
| `basic_auth_password` | yes | Traefik route (bcrypt hash only) |
| `basic_auth_user` | no | Traefik user; falls back to `basic_auth_user` in the config |

Values must be single lines; `CHANGEME` is refused. Errors name keys, never
values. `.env` reaches the host only on stdin; migrations and `collectstatic`
read it on the host (`. .env`), so no secret is on a command line.

## Configuration (`WorkAppConfig`)

Defaults follow the role's `defaults/main.yml`.

| Field | Default | Notes |
|---|---|---|
| `source_path` | required | work-ledger checkout (`src/`, `ledger/`, `manage.py`, `pyproject.toml`, `uv.lock`) |
| `user`, `group` | `work` | login shell `/usr/sbin/nologin` |
| `home`, `site_path`, `database_path` | `/home/work`, `.../site`, `.../site/db.sqlite3` | static files go to `site/staticfiles` |
| `python_version` | `3.14` | `uv sync --python`; a venv of another Python is removed first |
| `app_host`, `app_port`, `workers` | `127.0.0.1`, `10011`, `2` | gunicorn, `wsgi_module` `src.config.wsgi:application` |
| `django_settings_module`, `django_debug`, `django_admin_url`, `evidence_base_url` | role defaults | `.env` |
| `django_allowed_hosts`, `django_csrf_trusted_origins` | `127.0.0.1` / none | allowed hosts must not be empty |
| `healthcheck_path`, `health_retries`, `health_delay` | `/accounts/login/`, `20`, `3` | the role's final check: status 200 |
| `traefik_host`, `traefik_cert_resolver`, `traefik_middlewares`, `basic_auth_user` | role defaults | |
| `internal_ip_ranges` | the role's list (RFC1918, `100.64.0.0/10`, two IPv6 ranges) | clients that skip basic auth |
| `echoport_target`, `echoport_schedule` | `None`, `10 2 * * *` | Echoport `BackupTarget` name; `None` skips the wiring |
| `nyxmon_check` | `false` | upsert the "Work app health" check |

Values that end up unquoted in `.env` (the role sources it with a shell) may
only use `A-Za-z0-9._:/@%+~*-`.

## What the deploy does

1. Checks the secrets and renders `.env` (fails before any operation).
2. Port preflight (read-only; fails when `ss` fails): nothing but
   `work-app.service` may listen on `app_port` at a loopback or wildcard
   address, as the playbook's `preflight_ports` (`bind: loopback`). It cannot
   be skipped.
3. `system_user` (`/usr/sbin/nologin`); `home`, `site` and `staticfiles` are
   `0750`.
4. `sync_tree` of `src/` and `ledger/` into `site/`, each with `--delete`
   inside it and the role's excludes (`__pycache__`, `*.pyc`, caches, `.env`,
   `.vault_password`, `*.sqlite3`, `*.sqlite3-*`), owned by the service user;
   `manage.py`, `pyproject.toml` and `uv.lock` copied `0644`. The database,
   `.env`, `.venv` and `staticfiles` are never part of a synced tree.
5. A venv of another Python version than `python_version` is removed.
6. `uv sync --frozen --no-dev --no-install-project --python 3.14` if a source
   changed, the venv is missing, or a read-only `uv sync --check` says the
   venv does not match `uv.lock` (a sync that failed in an earlier run).
7. `.env` through `secret_file`, `0600`.
8. `manage.py migrate --noinput` if the source, dependencies or `.env` changed
   (it may name another database) or a
   read-only `migrate --check` finds unapplied migrations (so a failed run is
   retried). The check only runs when `db.sqlite3` and `.env` exist, since
   Django would create an empty SQLite file otherwise.
9. `db.sqlite3` is set to `0600 work:work`.
10. `manage.py collectstatic --noinput` if the source, dependencies or `.env`
    changed or `staticfiles` is empty.
11. Unit file and `service_rollout`: restart on a source, dependency, `.env`,
    migration or static change, or when a deployed file is newer than the
    service's start (a run that failed after the sync, before the restart; the
    app's own `__pycache__` is ignored). A failed run whose only change was
    deleting files is not seen this way (directories are not compared, since
    the app touches them); restart `work-app` by hand or change a file.
12. Traefik route with the role's own template (dual router, HTTP router with
    its redirect middleware). The role has no Traefik restart handler (Traefik
    watches the directory), so none is issued here.
13. Read-only check of `healthcheck_path`: status 200.
14. Wiring, when configured: each upsert first runs read-only in a "check"
    mode and only applies when something differs.
    - Echoport (`/home/echoport/site`): the `BackupTarget` `work_app` with the
      playbook's fields, the schedule included.
    - Nyxmon (`/home/nyxmon/site`, `.env` sourced): service "Work app", check
      "Work app health" on `http://<app_host>:<app_port>/healthz`; a check
      still called "Work app login page" is reused and renamed.
    - Fails when the app is not installed on the host, as the playbook does.

## Parity with the role and playbook

`tests/test_work_app_parity.py` renders the vendored role templates
(`tests/parity/ansible/work_app_deploy__*`) the way Ansible does and requires
**byte-identical** `.env`, unit and Traefik route (which is why the route
still says "Managed by Ansible"). With the route hash reused, Ansible and
ops-deploy take turns on a host without rewriting these files or restarting
work-app or Traefik.

Differences:

- The role's migrations, `collectstatic`, recursive `chown` of the site and
  the playbook's upserts run on every deploy; the upserts always report a
  change. Here they run only when needed, so a converged deploy changes
  nothing.
- Ansible's `synchronize` compares file times, ops-deploy file contents (no
  times are synced). The first Ansible run after an ops-deploy run therefore
  rewrites the source files once and restarts work-app; later runs are quiet.
- `uv sync` is given `--python 3.14` and runs only on a change; the role runs
  it every time.
- `apache2-utils` is not installed (the bcrypt hash is computed on the
  controller); the playbook's `uv_install` role is not run (uv must be at
  `/usr/local/bin/uv`, see `deploy_uv_install`). A new user's home is created
  without the skeleton files `useradd -m` copies.
- Not ported: switching off Traefik or basic auth, other deploy methods, other
  source directories or files, `work_app_uv_path`.

## Backup, restore and remove

`deploy_work_app_backup`, `deploy_work_app_restore` and
`deploy_work_app_remove` port the `work_app_backup`, `work_app_restore` and
`work_app_remove` roles (configs `WorkAppBackupConfig`, `WorkAppRestoreConfig`,
`WorkAppRemoveConfig`). They take no secrets; all three share the paths of the
deploy (`user`, `group`, `home`, `site_path`, `database_path`, `service_name`,
`traefik_config_path`) with the same defaults, so pass the values the deploy
used. Either tool restores the other's archives and removes the other's
deploy.

```python
run(deploy_work_app_backup, WorkAppBackupConfig(ops_library_version="2.31.40"))
run(deploy_work_app_restore, WorkAppRestoreConfig(ops_library_version="2.31.40"))
run(deploy_work_app_remove, WorkAppRemoveConfig(confirm=True))
```

### Backup

Writes `<root>/<prefix>-<timestamp>/` (default root `/opt/backups/work_app`,
prefix `manual`, timestamp the host's local `%Y%m%dT%H%M%S`) with
`database/db.sqlite3`, `static/`, `env/.env`, `configs/work-app.service`,
`configs/traefik.yml`, `metadata.yml` and `manifest.sha256`, packs it as
`<dir>.tar.gz` and fetches the archive to `~/backups/work_app` (`0700`) on the
controller. Directories are `0700 root`, copied files and archives `0600 root`.
Every backup restricts existing regular archives directly in the root to
`0600`, including when no new archive is requested. Symlinks and nested
snapshots are left alone. New archives use `umask 077` and an explicit final
chmod.

- The database is copied with `sqlite3 .backup` (up to `sqlite_retries`
  attempts, 2 s apart) while the service runs. Like ops-library's SQLite
  runners (2.53.0), each attempt passes `.timeout 30000` first, so a
  committing writer is waited for (up to 30 s) instead of failing the attempt
  with "database is locked", and a copy counts only when
  `PRAGMA integrity_check` prints exactly `ok`; a failed copy is removed. If
  every attempt fails on the backup itself, or with `force_stop`, the service
  is stopped for a plain copy and started again however the copy ends; that
  copy is checked the same way once the service runs again. A hot copy that
  fails its integrity check fails the backup without the offline copy (the
  database itself is damaged; stopping the service would not help).
  `metadata.yml` records `sqlite_mode` (`hot`, `offline` or `missing`).
- `include_static`, `include_env`, `include_systemd`, `include_traefik`,
  `manifest`, `create_archive`, `fetch_local` switch the parts as the role's
  variables do. A part whose source is missing is skipped.
- `ops_library_version` is written to `metadata.yml` and compared by restore.
  Ansible writes the `version` of the installed collection's `galaxy.yml`, or
  `unknown` when the collection copy has none; pass the same value so the two
  tools accept each other's archives. `inventory_name` (default `macmini`) is
  the `host` field.
- Differences: the archive is packed with `umask 077` (it holds `.env`); only
  `tar.gz`.
- `required_mount` checks, before the first directory is made, that the mount
  is there and `root` resolves below it; `retain_count`/`retain_days` record
  the snapshot and prune the recorded ones after packing, before the fetch
  ([Local backups](../concepts/local-backups.md)).

### Restore

Selects the newest `*.tar.gz` under `root` (`archive: latest`), an archive
name below `root` or an absolute path. While planning, from the archive's
listing and `metadata.yml` (nothing is unpacked yet), it refuses before any
change: a missing archive, no payload directory, unreadable metadata, another
slug, a missing `slug`/`timestamp`/`host`, and an `ops_library_version`
different from the config's (unless `allow_version_mismatch`). Then, as the
role does: check `required_mount` (when set), reset and fill `staging_dir`
(default `/tmp/work-app-restore`, `0700`), check
`manifest.sha256`, stop work-app (a failing stop aborts), copy the site to
`<site>.pre-restore-<timestamp>`, restore static files (`rsync --delete`),
remove stale `-wal`/`-shm`/`-journal` files, restore the database (`0600
work`) and `.env`, restore the unit and the Traefik config when they differ
(`daemon-reload`, `reload traefik`), fix ownership of the static files, run
`check --deploy` and `showmigrations` when `.env` exists, check
`PRAGMA integrity_check`, restart work-app and check its login page. The
staging directory is removed right after the Traefik config, the last step
that reads it. The pre-restore copy (database
and `.env` included) is kept and its path reported, as the role does since
ops-library a811bc16; nothing prunes these copies, so delete old ones by hand.
`safe_snapshot_delete=True` deletes it after a success instead. `dry_run`
stops after the checks. `restore_env`, `rebuild_static`, `verify_http` and the
other role switches are config fields too.

With `cleanup` (the default), a step that fails while the staging directory
exists removes it before the run stops, as the role's `always` block does; the
safety snapshot stays, as in the role. `cleanup=False` keeps the staging
directory in both cases; the next restore resets it.

### Remove

Destructive by default, like the role: requires `confirm`, then stops and
disables work-app, removes the unit (and reloads systemd), the Traefik config,
the database files, the home directory and the user and group. Keeping the
database means keeping home and user (`remove_database=False` together with
`remove_home` or `remove_user` is refused). `remove_home` removes the home directory itself
when the user is kept or already gone (`userdel -r` takes it otherwise, and
the removal fails if it is still there). Where the role pauses for
ENTER before deleting a database, this asks on the controller's terminal
before the first change; without a terminal it refuses unless
`auto_confirm`. A second run finds nothing left and changes nothing.

## Tests

- `tests/test_work_app.py` (fake connector): first run, converged second run
  (no mutating change), source and top-level file change, `.env` rotation,
  basic-auth rotation, unapplied migrations, empty static root, outdated venv,
  database permissions, wiring drift and opt-out, port collision, failed
  health check, leak checks (no secret in commands, op names/args or uploads;
  `.env` only on stdin), validation.
- `tests/smoke/test_work_app_smoke.py` (`just smoke`, needs `WORK_LEDGER_SOURCE`
  or `PROJECTS_ROOT`): two real deploys of the committed `HEAD` and one of a
  fresh export; second and fresh runs converged; service active and answering,
  modes and owners, Traefik route, no secret on disk outside its files; the
  port preflight refuses another listener. The wiring is off on the VM.
- `tests/test_work_app_lifecycle.py` (fake connector): the backup layout,
  metadata and archive; the offline fallback and the optional parts; the
  restore sequence, the plan-time refusals (slug, fields, version, missing
  archive), dry run, flags and failure; remove with every flag combination,
  the refusals and an already removed app.
- `tests/smoke/test_work_app_smoke.py` also runs a backup, deletes the data,
  restores it (data back, snapshot and staging removed, a deploy over it has
  nothing to do) and removes the app twice (the second run changes nothing).
  The VM needs the `sqlite3` CLI (installed by the test; macmini has it).
- Ansible coexistence (deploys, backups, restores and removals taken across
  the tools, data kept) runs from ops-control: `just smoke-work-app-coexistence`.
