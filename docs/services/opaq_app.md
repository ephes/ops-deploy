# opaq_app

Port of the `opaq_app_deploy` Ansible role plus the steps ops-control's
`deploy-opaq-app.yml` runs around it. The app is daybook's `services/opaq_app`
(Django, SQLite, gunicorn on loopback): the company cash page behind a Traefik
tailnet allowlist **and** the app's own password login.

```python
from ops_deploy.services.opaq_app import OpaqAppConfig, deploy_opaq_app

cfg = OpaqAppConfig(
    source_path=Path("~/projects/daybook").expanduser(),
    secrets=SecretRef("secrets/prod/opaq_app.yml"),
    traefik_host="opaq.example.com",
    allowed_networks=("100.64.0.0/10",),
)
deploy_opaq_app(cfg, store.load(cfg.secrets))
```

ops-control registers it (see its `docs/PYINFRA.md`).

## Secrets

| Key | Used for |
|---|---|
| `django_secret_key` | environment file; 50 or more of `[A-Za-z0-9_-]` |
| `upload_token` | only its SHA-256 digest reaches the host (environment file); 32 or more characters |

Errors name keys, never values. The digest is treated as a secret as well.

## Configuration (`OpaqAppConfig`)

Defaults follow the role's `defaults/main.yml`.

| Field | Default | Notes |
|---|---|---|
| `source_path` | required | daybook checkout; needs `services/opaq_app/manage.py` and `src/daybook/opaq_site.py` |
| `source_dirs`, `source_files` | `src`, `services/opaq_app`; `pyproject.toml`, `uv.lock` | synced with `--delete` / copied `0600` |
| `rsync_excludes` | caches, `*.sqlite3`, `*.sqlite3-*`, `staticfiles`, `.env` | never shipped, kept across `--delete` |
| `service_name`, `user` | `opaq-app` | home is `/home/<user>`; `data/`, `static/`, `venv/`, `opaq-app.env` are in it |
| `site_path` | `/home/opaq-app/site` | |
| `app_port`, `workers` | `10065`, `2` | gunicorn on `127.0.0.1` |
| `python_version`, `dependency_group` | `3.14`, `opaq-app` | `uv sync --frozen --only-group ... --no-install-project` |
| `traefik_enabled` | `true` | needs `traefik_host` and a non-empty `allowed_networks` (CIDR ranges) |
| `traefik_entrypoint`, `traefik_http_entrypoint` | `web-secure`, `web` | |
| `refuse_while_exists` | none | the deploy fails before any change while this file exists (the static page's route) |
| `route_checks` | none | `controller_login`: the controller requests `https://<host>/` and must be redirected to the login (retried); `refused_address`: a request from the host to that address must get 403; `verify_tls` |
| `echoport` | none | Echoport backup target upsert (`name`, `schedule`, ...) |
| `nyxmon_check` | none | Nyxmon health check upsert (`service_name`, `check_name`, `interval`, ...) |

## What the deploy does

1. Checks the secrets and renders the environment file (fails before any operation).
2. Port preflight (the playbook's `preflight_ports`, `bind: loopback`): fails
   if anything but `opaq-app.service` listens on the app port at a loopback or
   wildcard address. Read-only, before any change; `SKIP_PREFLIGHT_PORTS` has no
   effect on the pyinfra path.
3. With `refuse_while_exists`: fails while that file exists.
4. `system_user`: user (`nologin`), group, and `0700` home, `site`, `site/services`, `data`, `static`.
5. `sync_tree` of `src/` and `services/opaq_app/` into `site/` (`--delete`,
   owned by the service user), copies of `pyproject.toml` and `uv.lock`
   (`0600`), then the whole site tree owned by the user and `go-rwx` (only
   after a sync, or when something is exposed).
6. `uv sync` of the locked `opaq-app` group into `venv/` (Python under
   `<home>/python`, like the role) when the project files changed, the venv is
   missing, runs another Python than configured, or a read-only
   `uv sync --check` finds it out of sync with the lock (an earlier run died
   after the files were copied).
7. The environment file through `secret_file` (`0600`).
8. `migrate` and `collectstatic --clear` as the service user (`umask 077`, so
   bytecode caches and the database are private from the start) when the code,
   dependencies or environment changed, the database does not exist yet, or a
   read-only `migrate --check` (no bytecode written) finds unapplied migrations.
9. The database `0600`.
10. Unit file, Traefik route (written without restarting Traefik, as the role
   does: the file provider watches), `service_rollout` (daemon-reload on unit
   change; restart on a change of code, dependencies, environment or unit).
11. Read-only checks: port, `/healthz` answering `ok`; with `route_checks` the
    login redirect and the 403 for the host's own address.
12. With `echoport` / `nyxmon_check`: require the service, then upsert. Both are
    probed first (read-only) and written only when they differ.

The database is under `data/`, outside the synced tree, so no sync can remove
it; the migration/collectstatic step never runs on a converged host.

## Parity with the role

`tests/test_opaq_app_parity.py` renders the vendored role templates
(`tests/parity/ansible/opaq_app_deploy__*`) the way Ansible does and requires
byte-identical environment file, unit and Traefik route.

Known role quirk: `DJANGO_ALLOWED_HOSTS` is built with the `union` filter, a
set whose order depends on the controller's hash seed, so the role itself may
rewrite the file (and restart the app) on a converged host. This deploy always
writes the host name first, one of the two orders the role writes; the first
Ansible run after a pyinfra run may therefore rewrite it once.

Differences kept on purpose:

- Echoport: like the playbook, every deploy sets the target's fields and the
  schedule; a schedule changed by hand in Echoport is reset. A target already
  as wanted is not written.
- Not ported: the `uv_install` role (uv must already be at
  `/usr/local/bin/uv`), and the playbook's second play that writes the upload
  token on the Atlas workstation (macOS; it stays on Ansible).

## Tests

- `tests/test_opaq_app.py` (fake connector): first run, converged second run
  (no mutating change), code change, lockfile change, other Python, secret
  rotation, port in use, allowlist change (route only, no restart), unit change, exposed
  tree, exposed database, missing database, static route guard, Traefik off,
  Echoport and Nyxmon upserts (pending, unchanged, missing service), route
  checks, leak checks (no secret or digest in commands, op names, arguments or
  uploads; the environment file only on stdin), validation.
- `tests/test_opaq_app_parity.py`: byte parity with the role.
- `tests/smoke/test_opaq_app_smoke.py` (`just smoke`, needs `DAYBOOK_SOURCE` or
  `PROJECTS_ROOT`): two real deploys of the committed `HEAD` of a daybook
  checkout plus a fresh-clone run; second run converged, unit hardened,
  tree/database/environment private, migrations applied, allowlist and login
  behaviour, no secret outside its file.
- Ansible coexistence (the role and the playbook's upserts taking turns with
  this deploy, data kept) runs from ops-control: `just smoke-opaq-app-coexistence`.
