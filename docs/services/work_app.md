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
- Ansible coexistence (deploys taking turns, data kept) runs from
  ops-control: `just smoke-work-app-coexistence`.
