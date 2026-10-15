# chesslab

Port of the `chesslab_deploy` Ansible role (rsync method) and of the
operations wiring in ops-control's `deploy-chesslab.yml`: the Chesslab
trainer, a Django app served by granian on one SQLite database, behind
Traefik with basic auth, plus its Echoport backup target and Nyxmon health
check.

```python
from ops_deploy.services.chesslab import ChesslabConfig, deploy_chesslab

cfg = ChesslabConfig(source_path=Path("~/projects/chess").expanduser(), secrets=SecretRef("secrets/prod/chesslab.yml"))
deploy_chesslab(cfg, store.load(cfg.secrets))
```

ops-control registers it with secrets from two SOPS files (see its
`docs/PYINFRA.md`).

## Secrets

| Key | Required | Used for |
|---|---|---|
| `secret_key` or `session_secret` | one of them; `secret_key` wins | `.env` (`CHESSLAB_SECRET_KEY`); more than 20 characters |
| `users` | yes | JSON list of `{username, password, owner}` (`lichess_username` instead of `owner` works too); the Django admins and trainer owners `ensure_admin` keeps in place |
| `basic_auth_password` | yes | Traefik route (bcrypt hash only) |
| `basic_auth_user` | no | Traefik user; falls back to `basic_auth_user` in the config |

Values must be single lines; `CHANGEME` is refused. Errors name keys, never
values. User names count as secret too: they reach the host only on stdin.

## Configuration (`ChesslabConfig`)

Defaults follow the role's `defaults/main.yml`.

| Field | Default | Notes |
|---|---|---|
| `source_path` | required | chess checkout (`pyproject.toml`, `uv.lock`, `src/chesslab`); synced as the site root |
| `user`, `group` | `chesslab` | login shell `/usr/sbin/nologin` |
| `home`, `site_path`, `data_path`, `db_path` | `/home/chesslab`, `.../site`, `.../data`, `.../data/chess.db` | |
| `python_version` | `3.14` | `uv sync --python` |
| `app_host`, `app_port`, `workers` | `127.0.0.1`, `10019`, `2` | granian, `wsgi_module` `chesslab.djangoapp.wsgi:application` |
| `django_settings_module`, `django_debug`, `secure_cookies`, `limit` | role defaults | `.env` |
| `django_allowed_hosts`, `django_csrf_trusted_origins` | `127.0.0.1, localhost` / none | |
| `run_migrations` | `true` | |
| `traefik_host`, `traefik_cert_resolver`, `traefik_middlewares`, `basic_auth_user` | role defaults | |
| `internal_ip_ranges` | the role's list (`127.0.0.1/32`, RFC1918, `100.64.0.0/10`) | clients that skip basic auth |
| `health_retries`, `health_delay` | `20`, `3` | `/healthz` check, as the role's |
| `echoport_target` | `None` | Echoport `BackupTarget` name; `None` skips the wiring |
| `echoport_schedule`, `echoport_update_schedule` | `50 2 * * *`, `false` | see below |
| `nyxmon_check` | `false` | upsert the "Chesslab trainer health" check |

## What the deploy does

1. Checks secrets and the users list, renders `.env` (fails before any
   operation).
2. Port preflight (read-only; fails when `ss` fails): nothing but `chesslab.service` may listen on
   `app_port` at a loopback or wildcard address, as the playbook's
   `preflight_ports` (`bind: loopback`). It cannot be skipped.
3. `system_user` (`/usr/sbin/nologin`), `home`, `site`, `data`.
4. Database check (read-only): `db_path` must exist and be read/writable by
   the service user. The deploy never creates the database; without it, it
   stops before the site changes.
5. `sync_tree` of the checkout to `site/` with the role's excludes (`.git`,
   `.venv`, caches, `.env`, `chess.db`, `*.db`, `*.db-*`), owned by the
   service user.
6. Runtime packages (`python3`, `python3-venv`, `sqlite3`, `rsync`).
7. `uv sync --frozen --no-dev --python 3.14` if the source changed or the venv
   is missing.
8. `.env` through `secret_file`, `0600`.
9. `python -m django migrate` if the source or dependencies changed or a
   read-only `migrate --check` (debug key, no secret) finds unapplied
   migrations, so a failed run is retried. A migration restarts chesslab. The
   Django environment goes over stdin, never on a command line.
10. `ensure_admin` for each user, called in-process by the venv's Python
    (password, user name and owner over stdin, never in a process's arguments), only when a user or its trainer profile is missing or
    differs in the database (a read-only SQLite query, compared as digests) or
    the `users` secret changed since the last run. The last ensured set is
    recorded as an HMAC (keyed with the Django secret) in
    `/home/chesslab/.ops-deploy-users` (`0600 root`).
11. Unit file and `service_rollout`: restart on code, dependency or `.env`
    change.
12. Traefik route with the role's own template (dual router, the HTTP router
    with its redirect middleware, `X-Forwarded-Host`), restart Traefik on
    change.
13. Read-only `/healthz` check: 200 and `{"ok": true}`.
14. Wiring, when configured: each upsert first runs read-only in a "check"
    mode and only applies when something differs.
    - Echoport (`/home/echoport/site`): the `BackupTarget` with the
      playbook's fields; a schedule set in the Echoport UI is kept unless
      `echoport_update_schedule`; refuses a model/database without
      `schedule_required`.
    - Nyxmon (`/home/nyxmon/site`, `.env` sourced): service "Chesslab", check
      "Chesslab trainer health" on `http://<app_host>:<app_port>/healthz`.
    - Fails when the app is not installed on the host, as the playbook does.

## Parity with the role and playbook

`tests/test_chesslab_parity.py` renders the vendored role templates
(`tests/parity/ansible/chesslab_deploy__*`) the way Ansible does and requires
**byte-identical** `.env`, unit and Traefik route (which is why the route
still says "Managed by Ansible"). With the route hash reused, Ansible and
ops-deploy take turns on a host without rewriting files or restarting
chesslab or Traefik.

Differences:

- The role's `ensure_admin`, migrations and the playbook's upserts run on
  every deploy; the playbook's upserts always report a change. Here they run
  only when needed, so a converged deploy changes nothing. A password changed
  by hand in Django is reset by the next Ansible deploy, but by ops-deploy
  only when the `users` secret changes or a user is missing.
- `uv sync` uses `--frozen` (the role runs plain `uv sync --no-dev`, which may
  rewrite `uv.lock` on the host).
- `apache2-utils` is not installed (the bcrypt hash is computed on the
  controller); the playbook's `uv_install` role is not run (uv must be at
  `/usr/local/bin/uv`, see `deploy_uv_install`); the playbook's warn-only
  clock check is not ported.
- Not ported (production uses none of them): switching off Traefik or basic
  auth, other deploy methods.

## Tests

- `tests/test_chesslab.py` (fake connector): first run, converged second run
  (no mutating change), code change, `.env` rotation, user password change,
  missing user, basic-auth rotation, wiring drift and opt-out, port
  collision, missing database, leak checks (no secret or user name in
  commands, op names/args or uploads; secrets only on stdin), validation.
- `tests/smoke/test_chesslab_smoke.py` (`just smoke`, needs `CHESSLAB_SOURCE`
  or `PROJECTS_ROOT`): refuses a host without the database, then two real
  deploys of the committed `HEAD` and one of a fresh export; second and fresh
  runs converged; service healthy, `.env` and stamp private, users and
  profiles in the database, Traefik route; the port preflight refuses another
  listener. The wiring is off on the VM.
- Ansible coexistence (deploys taking turns, data kept) runs from
  ops-control: `just smoke-chesslab-coexistence`.
