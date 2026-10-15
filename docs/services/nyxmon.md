# nyxmon

Port of the `nyxmon_deploy` Ansible role (rsync method only): the Django
dashboard `nyxmon` and the monitoring agent `nyxmon-monitor`, both on one
SQLite database, behind Traefik with basic auth.

```python
from ops_deploy.services.nyxmon import NyxmonConfig, deploy_nyxmon

cfg = NyxmonConfig(source_path=Path("~/projects/nyxmon").expanduser(), secrets=SecretRef("secrets/prod/nyxmon.yml"))
deploy_nyxmon(cfg, store.load(cfg.secrets))
```

ops-control registers it with secrets from three SOPS files (see its
`docs/PYINFRA.md`).

## Secrets

| Key | Required | Used for |
|---|---|---|
| `django_secret_key` | yes | `.env` |
| `telegram_bot_token`, `telegram_chat_id` | yes | `.env` |
| `basic_auth_password` | yes | Traefik route (bcrypt hash only) |
| `basic_auth_user` | no | Traefik user; falls back to `basic_auth_user` in the config |
| `opsgate_submit_token` | when `opsgate_submit_base_url` is set | `.env`; at least 20 characters |

Values must be single lines; `CHANGEME` and the role's development placeholders are refused. Errors name keys, never values.

## Configuration (`NyxmonConfig`)

Defaults follow the role's `defaults/main.yml`.

| Field | Default | Notes |
|---|---|---|
| `source_path` | required | nyxmon checkout; must contain `src/django`, `src/nyxmon`, `src/nyxboard`, `pyproject.toml`, `uv.lock`, `README.md` |
| `service_name`, `monitor_service_name` | `nyxmon`, `nyxmon-monitor` | |
| `user` / `site_path` | `nyxmon` / `/home/nyxmon/site` | home is `/home/<user>` |
| `persistent_excludes` | see below | host-side state the syncs never delete |
| `source_excludes` | `.vault_password`, `*.pyc`, caches, `node_modules` | never shipped |
| `python_version` | `3.13` | `uv sync --python` |
| `app_host`, `app_port`, `workers` | `127.0.0.1`, `10017`, `4` | granian |
| `django_settings_module` | `config.settings.production` | |
| `django_allowed_hosts`, `django_admin_url`, `django_debug` | `127.0.0.1`, `admin/`, `false` | |
| `require_login` | `false` | `NYXBOARD_REQUIRE_LOGIN` |
| `notify_*`, `processing_lease_seconds`, `check_batch_size` | `2`, `21600`, `86400`, `900`, `5` | ranges as in the role, lease ≥ (batch + 5) min |
| `opsgate_submit_base_url` | `""` | empty disables the OpsGate producer and its check |
| `opsgate_approval_base_url` | `""` | empty: the submit URL |
| `opsgate_ticket_expires_seconds`, `opsgate_submit_timeout_seconds`, `opsgate_submit_include_warnings` | `14400`, `10`, `false` | |
| `traefik_host`, `traefik_cert_resolver`, `traefik_middlewares`, `internal_ip_ranges` | role defaults | |

### Host-side state (`persistent_excludes`)

`cache`, `.env*`, `db.sqlite3*`, `*.sqlite3`, `media/`, `staticfiles/`, and the
site-root paths this deploy writes after the sync: `/src/`, `/venv`,
`/.env.shell`, `/pyproject.toml`, `/uv.lock`, `/README.md`. The same list as
the role's `nyxmon_rsync_excludes`/`nyxmon_rsync_django_excludes` (with `.env*` for `.env`) plus its
root-anchored excludes, so the database survives `--delete`.

## What the deploy does

1. Checks secrets and renders both env files (fails before any operation).
2. `system_user`: user, group, `/home/nyxmon`, `site`, `site/cache`, `logs`,
   `site/src`, `site/src/nyxmon`, `site/src/nyxboard`.
3. `sync_tree`: `src/django/` to `site/`, `src/nyxmon/` and `src/nyxboard/` to
   `site/src/...`, owned by the service user; copies `pyproject.toml`,
   `uv.lock`, `README.md` (`0644`).
4. `.env` (systemd format) and `.env.shell` (double-quoted for `sh`) through
   `secret_file`, `0600`.
5. `uv sync --frozen --no-dev --no-default-groups --python 3.13` if the source
   changed or the venv is missing; `site/venv` symlink to `.venv`.
6. `migrate` and `collectstatic` if the sync ran or the source changed.
7. Traefik route (dual router, basic auth).
8. For each unit: unit file, `sqlite-privacy.conf` drop-in (`UMask=0077`),
   `service_rollout` (daemon-reload on unit/drop-in change; restart on code,
   dependency or `.env` change).
9. Database and sidecars `0600 nyxmon:nyxmon` (only when a file is exposed or
   the database is new; fails if `db.sqlite3` is missing).
10. Read-only checks: port, HTTP (200/301/302), and with OpsGate enabled, that
    `nyxmon-monitor`'s live environment carries the rendered OpsGate URLs.

## Parity with the role

`tests/test_nyxmon_parity.py` renders the vendored role templates
(`tests/parity/ansible/nyxmon_deploy__*`) the way Ansible does and requires
**byte-identical** `.env`, `.env.shell` and unit files. That is why the env
file still says "Managed by Ansible": identical bytes let Ansible and
ops-deploy take turns on a host without rewriting files or restarting nyxmon.
The only file that differs is the Traefik route (comments; see
[helpers](../concepts/helpers.md#parity-differences-from-the-ansible-roles)).

Not ported (production uses none of them): the git deploy method, pip
instead of uv, a templated `pyproject.toml`, switching off Traefik, basic
auth or the monitor, `nyxmon_service_restart_on_change: false`, and the
`uv_install` role (uv must already be at `/usr/local/bin/uv`). A Python
version change is left to `uv sync --python` on the next dependency change;
the role removes a mismatched venv on every run.

## Backup, restore and removal

`ops_deploy.services.nyxmon` also ports `nyxmon_backup`, `nyxmon_restore` and
`nyxmon_remove`. None of them needs secrets. Backups written by either tool
restore with the other.

| Function | Config | Role |
|---|---|---|
| `deploy_nyxmon_backup` | `NyxmonBackupConfig(host_name=...)` | `nyxmon_backup` |
| `deploy_nyxmon_restore` | `NyxmonRestoreConfig(host_name=...)` | `nyxmon_restore` |
| `deploy_nyxmon_remove` | `NyxmonRemoveConfig(confirm=True)` | `nyxmon_remove` |

`host_name` is the inventory name. The backup writes it into
`metadata.yml`, and the restore uses it in its error messages. The other
fields are the roles' defaults under shorter names: `prefix`, `root`,
`include_logs`, `include_cache`, `include_static`, `use_sqlite_backup`,
`fetch_local` and `local_dir` for the backup; `archive`, `dry_run`,
`create_safety_backup`, `verify_http` and `health_url` for the restore.

**Backup.** It refuses to start when the site directory, `.env`, the
database, `staticfiles` (when `include_static` is set) or the logs (when
`include_logs` is set) are missing. It installs `sqlite3`, then stops
`nyxmon-monitor` and `nyxmon` and copies the database and the media, static,
cache and log directories, the config files, units and Traefik route into
`/opt/backups/nyxmon/<prefix>-<timestamp>/`. Everything there is
`root:root 0700/0600`, as are the parent directories it creates. Whatever the
copy does, the services are started again (the role's `always`). Then the
backup writes the role's `metadata.yml` (`to_nice_yaml`) and
`manifest.sha256`, packs `<dir>.tar.gz` and fetches the archive into
`~/backups/nyxmon` (`0700`).

**Restore.** One bash script on the host runs the role's phases in order:

1. Validate. Pick `latest` (the newest `*.tar.gz` under the root) or a name
   below the root, unpack it under `/tmp/nyxmon-restore/<timestamp>`, check
   the metadata fields and `manifest.sha256`.
2. Check disk space (twice the archive size).
3. With `dry_run`, stop here.
4. Take a safety copy of the site directory (`<site>.pre-restore-<timestamp>`).
5. Stop both services. Put back the database (`nyxmon 0600`) and run its
   integrity check, then the directories (`rsync --delete`), config files and
   units. Fix ownership and start both services.
6. Verify: `nyxmon.service` enabled and started, then the HTTP probe on
   `/admin/login/` with `X-Forwarded-Proto: https`.

If step 5 fails, the safety copy is synced back, the services are started
and the run fails (the role's `rescue`). The staging directory and the
safety copy are always removed.

Like the role, the restore does not put the Traefik route back. The role's
condition (`is exists`) is evaluated on the Ansible controller, where the
staging path never exists, so the route is never restored there either. The
route on the host is not changed by a restore.

**Removal.** It needs `confirm`. It stops and disables both units, then
removes the unit files, the route and `/home/nyxmon` (with the database). It
ends every process of the `nyxmon` user (SIGTERM, then SIGKILL, then
`systemd-run pkill`), removes the user and group, the `/tmp/*nyxmon*` entries
and the runtime drop-ins in `/run/systemd/system`. Like the role, it keeps
the `sqlite-privacy.conf` drop-ins the deploy installs in
`/etc/systemd/system/nyxmon*.service.d/`. It only acts on what exists, so a
second run changes nothing.

## Tests

- `tests/test_nyxmon.py` (fake connector): first run, converged second run
  (no mutating change), code change, lockfile change, `.env` secret rotation,
  basic-auth rotation, monitor unit change, missing drop-in, exposed database,
  OpsGate disabled, leak checks (no secret in commands, op names/args or
  uploads; env files only on stdin), validation.
- `tests/smoke/test_nyxmon_smoke.py` (`just smoke`, needs `NYXMON_SOURCE` or
  `PROJECTS_ROOT`): two real deploys of the committed `HEAD` of a nyxmon
  checkout; second run converged, units active with `UMask=0077`, database and
  env files private, migrations applied, Traefik 401 without auth, no secret
  outside its files.
- `tests/test_nyxmon_lifecycle.py` (fake connector): backup settings,
  metadata, archive and fetch, refusals before any change; the restore
  script's settings; removal order, a second removal without change, the
  confirmation.
- `tests/smoke/test_nyxmon_lifecycle_smoke.py`: backup with a marker account
  and media file, a dry-run restore (nothing restored), the restore (both
  back, no staging or safety copy left), removal twice (the second without
  change), then a fresh deploy.
- Ansible coexistence runs from ops-control: `just smoke-nyxmon-coexistence`.
  Deploys take turns with this deploy, and backup, restore and removal run
  across the tools (Ansible backup with pyinfra restore, pyinfra backup with
  Ansible restore, pyinfra removal with Ansible removal).
