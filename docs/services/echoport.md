# echoport

Port of the `echoport_deploy` Ansible role (rsync method, uv) and of the steps
ops-control's `playbooks/deploy-echoport.yml` runs around it: the loopback
listener check and the Nyxmon health check. Echoport is the backup
orchestrator: a Django app (granian) on one SQLite database, behind Traefik,
with three cron jobs of the service user (scheduled backups, retention cleanup,
nightly staging database refresh).

```python
from ops_deploy.services.echoport import EchoportConfig, NyxmonCheck, deploy_echoport

cfg = EchoportConfig(
    source_path=Path("~/projects/echoport").expanduser(),
    secrets=SecretRef("secrets/prod/echoport.yml"),
    traefik_host="echoport.example.com",
    django_allowed_hosts=("127.0.0.1", "echoport.example.com"),
    minio_url="http://127.0.0.1:9001",
    nyxmon=NyxmonCheck(),
)
deploy_echoport(cfg, store.load(cfg.secrets))
```

ops-control registers it with secrets from three SOPS files (see its
`docs/PYINFRA.md`).

## Secrets

| Key | Required | Used for |
|---|---|---|
| `django_secret_key` | yes | `.env` (`SECRET_KEY`) |
| `fastdeploy_base_url`, `fastdeploy_service_token` | yes | `.env` |
| `admin_username`, `admin_password` | yes | admin account (stdin only) |
| `admin_email` | no (empty: not enforced) | admin account |
| `basic_auth_password` | with Traefik and `basic_auth_enabled` | the route's bcrypt hash (computed on the controller) |
| `basic_auth_user` | no (`admin`) | the route's basic auth user |
| `minio_access_key`, `minio_secret_key` | with `cleanup_enabled` | the cleanup user's `mc` alias (stdin only) |

Values must be single lines. `django_secret_key` must not be `CHANGEME` or the
role's development key; `minio_secret_key` and `basic_auth_password` must not
be `CHANGEME`. Errors name keys, never values.

## Configuration (`EchoportConfig`)

Defaults follow the role's `defaults/main.yml`.

| Field | Default | Notes |
|---|---|---|
| `source_path` | required | echoport checkout; needs `src/django/manage.py`, `pyproject.toml`, `uv.lock` and every `rsync_additional_paths` entry |
| `service_name` | `echoport` | |
| `user`, `group`, `home`, `site_path` | `echoport`, `echoport`, `/home/echoport`, `/home/echoport/site` | the site is below the home |
| `rsync_additional_paths` | `("src/backups/",)` | synced below the site (the package the venv installs from); each must be `src/<name>...` without `.` or `..` components, so it can never reach the site root or its state |
| `python_version` | `3.13` | `uv sync --python`; a venv on another Python is removed first |
| `app_host`, `app_port`, `workers` | `127.0.0.1`, `10018`, `2` | the host must stay on loopback (Echoport answers unauthenticated monitoring requests) |
| `allowed_path_prefixes` | `/home/ /opt/ /var/lib/ /mnt/cryptdata/` | `ECHOPORT_ALLOWED_PATH_PREFIXES` |
| `stale_run_grace_seconds`, `late_result_window_seconds`, `health_overdue_grace_minutes` | none | left out of `.env` unless set |
| `django_settings_module`, `django_allowed_hosts`, `django_debug` | `config.settings.production`, `127.0.0.1`, `false` | |
| `traefik_enabled`, `traefik_host`, `traefik_cert_resolver`, `traefik_middlewares` | `true`, `echoport.example.com`, none, none | |
| `basic_auth_enabled`, `basic_auth_user`, `internal_ip_ranges` | `true`, `admin`, five private ranges | dual router: no auth from the internal ranges, basic auth from everywhere else |
| `scheduler_enabled`, `scheduler_interval` | `true`, `*/5` | crontab minute field |
| `cleanup_enabled`, `cleanup_hour` | `true`, `3` | needs `minio_url` |
| `minio_mc_path`, `minio_alias`, `minio_url`, `minio_verify_bucket` | `/usr/local/bin/mc`, `minio`, none, `backups` | the cleanup user's alias and the bucket it must reach |
| `staging_db_refresh_*` | off | `enabled`, `hour` (`2`), `minute` (`20`), `targets`, `triggered_by` |
| `nyxmon` | `None` | `NyxmonCheck(...)`: the playbook's Nyxmon check (see below) |

Not ported: the pip/venv branch (`echoport_use_uv: false`), a pyproject other
than the checkout's (`echoport_use_source_pyproject: false`),
`echoport_rsync_extra_files`, `echoport_skip_django_manage`, the unused
`echoport_django_admin_url`, `echoport_service_restart_on_change: false`, and
the `uv_install` role (uv must already be at `/usr/local/bin/uv`, see
`deploy_uv_install`).

## What the deploy does

1. Checks secrets and renders the env file; fails before any operation.
2. `system_user`: group, user, `/home/echoport`, `site`, `site/cache`,
   `logs`. An existing user is not modified (on macmini it is a non-system
   user with group `users`, which the role created without a system flag);
   differences are logged as warnings.
3. `sync_tree` of `src/django/` to `site/` (`--delete`, files owned by the
   service user; the role's excludes, so `db.sqlite3*`, `media/`,
   `staticfiles/`, `cache`, `src/` and the files the deploy writes itself
   survive), then `src/backups/` to `site/src/backups/`, then
   `pyproject.toml` and `uv.lock` next to `manage.py`. If anything below the
   site is not owned by the service user, the role's recursive `chown` runs
   (the owner only: processes started by `runuser` or cron have the user's
   primary group, so group drift would reappear after every run).
4. A venv whose Python does not run, or is not `python_version`, is removed.
   `uv sync --frozen --no-dev --no-default-groups --python <version>` runs if
   a source file changed or the venv is missing; `site/venv` links to `.venv`.
5. `.env` (`0600`) through `secret_file`.
6. `manage.py migrate --noinput` when anything above changed or a probe
   (`migrate --check`, read-only) finds pending migrations (also after an
   earlier run that synced but failed; the service is then restarted, since its
   workers still run the old code); `collectstatic --noinput` when
   anything changed or the manifest `staticfiles/staticfiles.json` is missing.
   Both run as the service user in the site root with only
   `DJANGO_SETTINGS_MODULE` in the environment; the settings read `.env`.
7. Admin account: a read-only probe (`manage.py shell`) prints digests of
   each staff or superuser account (name, email, password hash) and the hash's
   algorithm, iterations and salt. The deploy rehashes the configured password
   (pbkdf2_sha256) and runs `ensure_superuser` only if the account is missing
   or differs. Name, email and password travel on stdin.
8. The unit (`service_rollout`: reload on unit change, restart on code,
   dependency, `.env`, migration or unit change, not right after this run started it).
9. The Traefik route `/etc/traefik/dynamic/echoport.yml` from the role's
   template. The bcrypt hash is computed on the controller; the hash in the
   deployed file is reused while it still verifies against the password, so
   the route (and Traefik) stay untouched. Traefik restarts only if it changed.
10. The crontab of the service user, in the format of Ansible's `cron` module
    (`#Ansible: <name>` above the job): `Echoport scheduled backups`,
    `Echoport cleanup old backups`, `Echoport staging DB refresh`, each present
    or absent as configured, with their log files (`0640`) and, for the staging
    refresh, `staging-db-refresh.sh` (`0750`). A script reads the crontab,
    changes only the job's two lines (a header-less identical job line is
    adopted, as Ansible does) and writes it back only if something differs, so
    other entries survive and neither tool adds a second copy.
11. With `cleanup_enabled`: the service user's `mc` alias. A read-only probe
    prints a digest of the stored URL and credentials; if it differs from the
    configured ones, `mc alias import` is run with the credentials on stdin
    (the role's `mc alias set` puts them in the host's process list). Then a
    read-only `mc ls <alias>/<bucket>` proves the bucket is reachable.
12. Read-only checks: Echoport listens on the app port and only on
    `127.0.0.1` (15 tries, 2 s apart).
13. With `nyxmon`: if `/home/nyxmon/site/db.sqlite3` exists, a dry run of the
    playbook's upsert (as `nyxmon`, SQLite opened read-only) and, only if it
    reports a difference, the upsert itself (service `echoport` and the
    `json-metrics` check on `/api/health/` with the four target freshness
    conditions and the backup-window suppression). Without the database it
    warns and skips, like the playbook.

## Parity with the role

The deploy ships the role's four templates unchanged and renders them with
Ansible's template options (including its `quote` filter), so `.env`, the
unit, the Traefik route (given the same hash) and `staging-db-refresh.sh` are
**byte-identical** to what Ansible writes (`tests/test_echoport_parity.py`,
against the vendored copies in `tests/parity/ansible/echoport_deploy__*`).

Differences, all on the "change only what differs" side:

- migrate, collectstatic, the admin account, the `mc` alias, the crontab and
  the Nyxmon check run only when needed (the role and playbook run migrate,
  collectstatic and `ensure_superuser` on every deploy and rewrite the route
  with a fresh bcrypt hash, so Traefik restarts on every Ansible run);
- the recursive `chown` of the site runs only when a file is not owned by the
  service user (the role also resets the group on every run, which Ansible
  reports as a change every time);
- the venv is removed and recreated only when it is broken or on the wrong
  Python, as in the role;
- `db.sqlite3-*` (journal, WAL, SHM) is excluded from the sync as the role's
  `db.sqlite3-*` exclude does, and the role's file-time comparison is a
  checksum comparison here: after pyinfra installed a tree (or synced changed
  files), the next Ansible run resyncs the same content once and restarts.

## Tests

- `tests/test_echoport.py` (fake connector): first run, converged second run,
  code change, package source change, lockfile change, secret rotation, admin
  password rotation, unit and route drift, basic auth rotation, each cron job,
  disabled jobs, missing log files and staging script, `mc` alias drift and an
  unreachable bucket, pending migrations, missing static manifest, a venv on
  the wrong Python, foreign-owned files, the Nyxmon check (differs, missing
  database, payload), a listener failure, validation, leak checks.
- `tests/test_echoport_parity.py`: byte parity with the role's templates.
- `tests/test_echoport_scripts.py`: the host scripts run against a stand-in
  `crontab` and a real SQLite file (Ansible's header format, adoption, removal,
  the Nyxmon upsert and its dry run).
- `tests/smoke/test_echoport_smoke.py` (`just smoke`, needs `ECHOPORT_SOURCE`
  or `PROJECTS_ROOT`): real deploys of the committed `HEAD` (first, converged,
  a fresh clone, a code change); no secret outside its files, the database
  kept across the code change, units, loopback listener, the route's basic
  auth, the crontab. No MinIO and no Nyxmon.
- MinIO, Nyxmon and Ansible coexistence run from ops-control:
  `just smoke-echoport-coexistence`.
