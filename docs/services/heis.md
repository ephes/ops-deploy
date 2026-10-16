# heis

Port of the `heis_deploy` Ansible role (rsync method, uv): the Heis
Wagtail site, a Django app on SQLite served by gunicorn behind Traefik. The
SQLite database and uploaded media are host state the deploy never ships or
deletes; production content changes only through Wagtail or ops-control's
promotion playbook.

```python
from ops_deploy.services.heis import HeisConfig, deploy_heis

cfg = HeisConfig(
    source_path=Path("~/projects/heis").expanduser(),
    secrets=SecretRef("secrets/prod/heis.yml"),
    fqdn="fabian-heis.de",
    traefik_host_rule="Host(`fabian-heis.de`) || Host(`www.fabian-heis.de`)",
    # Production: never run the content reconcilers.
    setup_default_pages=False,
    seed_content=False,
)
deploy_heis(cfg, store.load(cfg.secrets))
```

ops-control registers it per host (production `heis`, `staging`) with the
secrets of that environment (see its `docs/PYINFRA.md`).

## Secrets

| Key | Required | Used for |
|---|---|---|
| `django_secret_key` | yes | `.env` (`DJANGO_SECRET_KEY`), shell-quoted like the role's `quote` filter |
| `django_admin_url` | yes | `.env` (`DJANGO_ADMIN_URL`); the inventory keeps the admin path secret |
| `admin_username`, `admin_email`, `admin_password` | yes | the Django superuser `ensure_superuser` keeps in place |

Values must be single lines; the role's placeholders (`CHANGEME`, and
`CHANGE_ME` for the admin password) are refused. Errors name keys, never
values. The admin name, email and password reach the host only on stdin.

## Configuration (`HeisConfig`)

Defaults follow the role's `defaults/main.yml`.

| Field | Default | Notes |
|---|---|---|
| `source_path` | required | heis checkout (`manage.py`, `pyproject.toml`, `uv.lock`, `config/wsgi.py`); synced as the site root |
| `source_commit` | `None` | the commit `source_path` is a checkout of (a [git source](../concepts/git-source.md)); recorded on the host, `None` (a local working tree) removes the record |
| `fqdn`, `traefik_host_rule` | required | Traefik router names and HTTP rule (`heis_fqdn`, `heis_traefik_host_rule`) |
| `traefik_tls_host_rule` | `None` (the HTTP rule) | the HTTPS router's rule (`heis_traefik_tls_host_rule`) |
| `traefik_canonical_redirect_regex`, `_replacement` | `""` | both set: a permanent `redirect-canonical-host` middleware on the HTTPS router |
| `serve_media` | `false` | `DJANGO_SERVE_MEDIA` |
| `wagtailadmin_base_url` | `None` (`https://<fqdn>`) | `WAGTAILADMIN_BASE_URL` |
| `setup_default_pages`, `seed_content` | `true` | the role's Wagtail content reconcilers; production sets both `false` |
| `user`, `group` | `heis` | login shell `/usr/bin/fish`; the systemd unit and the Traefik file are named after the user |
| `home`, `site_path` | `/home/heis`, `/home/heis/site` | cache dir `site/cache`, venv `site/.venv` |
| `python_version` | `3.13` | `uv sync --python` |
| `app_port`, `gunicorn_workers`, `gunicorn_timeout` | `10020`, `4`, `3600` | `gunicorn.sh` binds `127.0.0.1` |
| `django_settings_module` | `config.settings.production` | `.env`, the unit |
| `django_allowed_hosts` | `<fqdn>,localhost` | |
| `source_excludes` | the role's list (with `venv` and `heis-buehne-bilder.zip`) plus `/.env`, `/staticfiles`, `/cache` | never shipped, never touched |
| `health_retries` | `30` | wait for the port |

## What the deploy does

1. Checks the secrets and renders `.env` (fails before any operation).
2. Installs the role's prerequisites (`fish`, `rsync`, `sqlite3`) with apt,
   then `system_user` (shell `/usr/bin/fish`, an existing user is left alone), home,
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
   retried). Then, when enabled, `setup_default_pages --hostname <fqdn> --port
   443`, `seed_home_content` and `seed_subpages_content`, each only if the
   source, the dependencies or the schema changed (always on a first deploy).
   `/home/heis/.ops-deploy-content-pending` is created before them and removed
   after all succeeded, so a run that failed half-way retries them.
   `collectstatic --noinput` if the source or dependencies changed or
   `staticfiles/staticfiles.json` is missing. As in the role, neither restarts
   the service.
8. `ensure_superuser` when the account is missing, inactive or not
   staff/superuser or has another email (a read-only SQLite query compared as
   digests), or the admin secrets changed since the last run. The last ensured
   set is recorded as an HMAC (keyed with the Django secret) in
   `/home/heis/.ops-deploy-admin` (`0600 root`). Like the role it fails on an
   inactive account.
9. `gunicorn.sh`, the unit and `service_rollout`: restart on a code,
   dependency, `.env`, launcher or unit change.
10. The Traefik route with the role's own template (`/etc/traefik/dynamic/<user>.traefik.yml`,
    TLS rule, redirect, csrf, www-redirect and the optional canonical redirect). Traefik is not restarted: the
    role does not either, its file provider watches the directory.
11. Read-only checks: the port opens, `http://127.0.0.1:<port>/` answers 200,
    301 or 302 with the site's Host header.
12. Records `source_commit` in `/home/heis/site/.ops-deploy-source`, or
    removes that file for a local working tree (`record_source`, see
    [Git source](../concepts/git-source.md)). Last, so only a deploy that came
    up healthy records its commit; the same commit again is no change.

## Parity with the role

`tests/test_heis_parity.py` renders the vendored role templates
(`tests/parity/ansible/heis_deploy__*`) the way Ansible does and requires
**byte-identical** `.env`, `gunicorn.sh`, unit, fish config and Traefik route.
Ansible and ops-deploy take turns on a host without rewriting files or
restarting heis.

Differences:

- The role's migrations, content reconcilers, `collectstatic` and
  `ensure_superuser` run on every deploy; here only when needed (above), so a converged deploy changes nothing.
  A password changed by hand in Django is reset by the next Ansible deploy, but
  by ops-deploy only when the admin secrets change or the account is off.
  Staging content removed by hand is put back by the next code deploy here,
  by every deploy with the role. With the production switches off neither
  tool runs the reconcilers.
- The role skips `ensure_superuser` when no admin variables are set; here the
  admin secrets are required (every inventory host sets them).
- `uv sync` uses `--frozen` (the role runs plain `uv sync --no-dev`, which may
  rewrite `uv.lock` on the host).
- `.env`, `staticfiles/` and `cache/` of a developer checkout are not shipped
  (the role would copy them over the host's).
- The role's `uv_install` step and the pip/venv branch (`heis_use_uv: false`)
  are not ported: uv must be at `/usr/local/bin/uv` (see `deploy_uv_install`).
- The health checks are new; the role has none.

A run that fails after the source sync is retried for the dependencies, the
migrations and the admin account (each is probed read-only), not for a restart
or a half-finished `collectstatic`; the role has the same gap (its handlers do
not run after a failure and the next rsync finds nothing to change). Rerun
after fixing the cause, and restart the service by hand if the failed run had
changed code.

## Tests

- `tests/test_heis.py` (fake connector): first run, converged second run (no
  mutating change), code change, `.env` rotation, admin secret change, account
  drift, retried migrations, the content reconcilers (order, production
  switches), missing static manifest, ownership repair,
  launcher/unit/route changes (Traefik not restarted), leak checks (no secret
  in commands, op names/args or uploads; secrets only on stdin), the deployed
  commit record (written once, unchanged on a re-run, removed for a local
  source, after the health checks), validation.
- `tests/smoke/test_heis_smoke.py` (`just smoke`, needs `HEIS_SOURCE` or
  `PROJECTS_ROOT`): two real deploys of the committed `HEAD` and one of a fresh
  export; second and fresh runs converged; service active, answering, files
  with the role's owners and modes, the admin account, the reconcilers' pages, the route file, no
  secret on disk outside its files.
- Ansible coexistence (deploys taking turns, data kept) runs from ops-control:
  `just smoke-heis-coexistence`.
