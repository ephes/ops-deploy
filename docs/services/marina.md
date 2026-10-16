# marina

Port of the `marina_deploy` Ansible role (rsync method, uv): the Marina
portfolio site, a Django/Wagtail app on SQLite served by gunicorn behind
Traefik.

```python
from ops_deploy.services.marina import MarinaConfig, deploy_marina

cfg = MarinaConfig(
    source_path=Path("~/projects/marina").expanduser(),
    secrets=SecretRef("secrets/prod/marina.yml"),
    fqdn="marina-adler.de",
    traefik_host_rule="Host(`marina-adler.de`) || Host(`www.marina-adler.de`)",
)
deploy_marina(cfg, store.load(cfg.secrets))
```

ops-control registers it per host (production `marina`, `staging`) with the
secrets of that environment (see its `docs/PYINFRA.md`).

## Secrets

| Key | Required | Used for |
|---|---|---|
| `django_secret_key` | yes | `.env` (`DJANGO_SECRET_KEY`), unquoted; only letters, digits and `_ @ % + = : , . / -` (the role's `.env` is sourced by `sh` and read by django-environ without quotes) |
| `admin_username`, `admin_email`, `admin_password` | yes | the Django superuser `ensure_superuser` keeps in place |

Values must be single lines; `CHANGEME` is refused. Errors name keys, never
values. The admin name, email and password reach the host only on stdin.

## Configuration (`MarinaConfig`)

Defaults follow the role's `defaults/main.yml`.

| Field | Default | Notes |
|---|---|---|
| `source_path` | required | marina checkout (`manage.py`, `pyproject.toml`, `uv.lock`, `config/wsgi.py`); synced as the site root |
| `source_commit` | `None` | the commit `source_path` is a checkout of (a [git source](../concepts/git-source.md)); recorded on the host, `None` (a local working tree) removes the record |
| `fqdn`, `traefik_host_rule` | required | Traefik router names and rule (`marina_fqdn`, `marina_traefik_host_rule`) |
| `user`, `group` | `marina` | login shell `/usr/bin/fish`; the systemd unit and the Traefik file are named after the user |
| `home`, `site_path` | `/home/marina`, `/home/marina/site` | cache dir `site/cache`, venv `site/.venv` |
| `python_version` | `3.13` | `uv sync --python` |
| `app_port`, `gunicorn_workers`, `gunicorn_timeout` | `10019`, `4`, `3600` | `gunicorn.sh` binds `127.0.0.1` |
| `django_settings_module`, `django_admin_url` | `config.settings.production`, `marina_admin/` | `.env` |
| `django_allowed_hosts` | `<fqdn>,localhost` | |
| `systemd_hardening` | `false` | the role's optional sandboxing options |
| `source_excludes` | the role's list plus `/.env`, `/staticfiles`, `/cache` | never shipped, never touched |
| `health_retries` | `30` | wait for the port |

## What the deploy does

1. Checks the secrets and renders `.env` (fails before any operation).
2. `system_user` (shell `/usr/bin/fish`, an existing user is left alone), home,
   `site`, `site/cache`, `~/.config/fish/config.fish`.
3. `sync_tree` of the checkout to `site/` with the role's excludes (database,
   media, backups, `.venv`, `.git`, caches), owned by the service user.
   **Without `--delete`**, like the role (`delete: false`): files only on the
   host (database, uploads, collected static files) are never removed.
4. A recursive `chown` of the site tree, only when a read-only `find` sees a
   file with the wrong owner (the role's `file: recurse` on every run).
5. `uv sync --frozen --no-dev --python 3.13` if the source changed, the venv
   is missing or a read-only `uv sync --dry-run` does not report "Would make no
   changes" (an earlier run stopped after the source sync, or `python_version`
   changed); the `venv` symlink to `.venv`.
6. `.env` through `secret_file`, `0600`.
7. `manage.py migrate` if the source or dependencies changed or a read-only
   `migrate --check` finds unapplied migrations (a failed earlier run is
   retried); `collectstatic --noinput` if the source or dependencies changed or
   `staticfiles/staticfiles.json` is missing. As in the role, neither restarts
   the service.
8. `ensure_superuser` when the account is missing, inactive or not
   staff/superuser or has another email (a read-only SQLite query compared as
   digests), or the admin secrets changed since the last run. The last ensured
   set is recorded as an HMAC (keyed with the Django secret) in
   `/home/marina/.ops-deploy-admin` (`0600 root`). Like the role it fails on an
   inactive account.
9. `gunicorn.sh`, the unit and `service_rollout`: restart on a code,
   dependency, `.env`, launcher or unit change.
10. The Traefik route with the role's own template (`/etc/traefik/dynamic/<user>.traefik.yml`,
    redirect, csrf and www-redirect middlewares). Traefik is not restarted: the
    role does not either, its file provider watches the directory.
11. Read-only checks: the port opens, `http://127.0.0.1:<port>/` answers 200,
    301 or 302 with the site's Host header.
12. Records `source_commit` in `/home/marina/site/.ops-deploy-source`, or
    removes that file for a local working tree (`record_source`, see
    [Git source](../concepts/git-source.md)). Last, so only a deploy that came
    up healthy records its commit; the same commit again is no change.

## Parity with the role

`tests/test_marina_parity.py` renders the vendored role templates
(`tests/parity/ansible/marina_deploy__*`) the way Ansible does and requires
**byte-identical** `.env`, `gunicorn.sh`, unit, fish config and Traefik route.
Ansible and ops-deploy take turns on a host without rewriting files or
restarting marina.

Differences:

- The role's migrations, `collectstatic` and `ensure_superuser` run on every
  deploy; here only when needed (above), so a converged deploy changes nothing.
  A password changed by hand in Django is reset by the next Ansible deploy, but
  by ops-deploy only when the admin secrets change or the account is off.
- `uv sync` uses `--frozen` (the role runs plain `uv sync --no-dev`, which may
  rewrite `uv.lock` on the host).
- `.env`, `staticfiles/` and `cache/` of a developer checkout are not shipped
  (the role would copy them over the host's).
- The role's `uv_install` step and the pip/venv branch (`marina_use_uv: false`)
  are not ported: uv must be at `/usr/local/bin/uv` (see `deploy_uv_install`).
- The health checks are new; the role has none.

A run that fails after the source sync is retried for the dependencies, the
migrations and the admin account (each is probed read-only), not for a restart
or a half-finished `collectstatic`; the role has the same gap (its handlers do
not run after a failure and the next rsync finds nothing to change). Rerun
after fixing the cause, and restart the service by hand if the failed run had
changed code.

## Tests

- `tests/test_marina.py` (fake connector): first run, converged second run (no
  mutating change), code change, `.env` rotation, admin secret change, account
  drift, retried migrations, missing static manifest, ownership repair,
  launcher/unit/route changes (Traefik not restarted), leak checks (no secret
  in commands, op names/args or uploads; secrets only on stdin), the deployed
  commit record (written once, unchanged on a re-run, removed for a local
  source, after the health checks), validation.
- `tests/smoke/test_marina_smoke.py` (`just smoke`, needs `MARINA_SOURCE` or
  `PROJECTS_ROOT`): two real deploys of the committed `HEAD` and one of a fresh
  export; second and fresh runs converged; service active, answering, files
  with the role's owners and modes, the admin account, the route file, no
  secret on disk outside its files.
- Ansible coexistence (deploys taking turns, data kept) runs from ops-control:
  `just smoke-marina-coexistence`.
