# villakunterbunt

Port of the Villa Kunterbunt project's own Ansible playbook: a Django/Wagtail
site on SQLite served by gunicorn, plus a standalone Next.js server for a set
of paths, behind one Traefik route.

```python
from ops_deploy.services.villakunterbunt import UrlCheck, VillakunterbuntConfig, deploy_villakunterbunt

cfg = VillakunterbuntConfig(
    source_path=tree,  # the application tree, for example a git source
    secrets=SecretRef("secrets/staging/villakunterbunt.yml"),
    fqdn="villakunterbunt.example.com",
    mailgun_api_url="https://mailgun.example.com/v3",
    bootstrap_admin_email="admin@example.com",
    next_path_prefixes=("/cms", "/_next"),
    public_checks=(UrlCheck(path="/"), UrlCheck(path="/cms/login")),
)
deploy_villakunterbunt(cfg, store.load(cfg.secrets))
```

The module knows the shape every such deploy has (two apps in one tree, the
units, the route, the `.env`, the build); everything specific to the
application is config. The private deploy repository supplies the real values
and checks that the files match the old playbook byte for byte.

## Secrets

All ten keys are required; the deploy refuses any that is missing or empty.
Values must be single lines. Errors name keys, never values.

| Key | Used for |
|---|---|
| `django_secret_key` | `.env` (`DJANGO_SECRET_KEY`); at least 50 characters |
| `bootstrap_admin_password` | the bootstrap superuser (stdin only); `CHANGEME` refused |
| `django_admin_url_path`, `wagtail_admin_url_path` | `.env`; URL paths (letters, digits, `. _ ~ / -`), distinct, not in `refused_admin_url_paths` and not under a Next.js prefix or a `reserved_admin_url_paths` entry |
| `django_mailgun_api_key` | `.env`; `CHANGEME` refused |
| `mailgun_api_url` | `.env`; must equal the config's `mailgun_api_url` |
| `mailgun_sender_domain`, `django_default_from_email`, `django_server_email`, `django_email_subject_prefix` | `.env` |

`.env` quotes every value (`'...'`, a `'` inside as `'\''`), so
`set -a; source .env` reads quotes, `$` and backticks literally.

## Configuration (`VillakunterbuntConfig`)

| Field | Default | Notes |
|---|---|---|
| `source_path` | required | the tree (`package.json`, `package-lock.json`, `django/manage.py`, `django/pyproject.toml`, `django/uv.lock`); synced as the site root |
| `source_commit` | none | the commit of a git source, recorded in `site/.ops-deploy-source` after a healthy deploy ([Git source](../concepts/git-source.md)); none for a local tree (the record is removed) |
| `fqdn` | required | router names, `ALLOWED_HOSTS`, CSRF origin, `WAGTAILADMIN_BASE_URL`, `NEXT_PUBLIC_FQDN` |
| `traefik_host_rule` | ``Host(`<fqdn>`)`` | grouped in parentheses before the Next.js paths when it has `||` |
| `next_path_prefixes` | `/_next` | routed to Next.js (priority 200) as ``Path(p) || PathPrefix(p/)``, in this order; no trailing slash; also reserved for admin paths |
| `mailgun_api_url`, `bootstrap_admin_email` | required | |
| `user`, `home`, `site_path` | `villakunterbunt`, `/home/villakunterbunt`, `.../site` | login shell `/usr/bin/fish`; units `<user>-django`, `<user>-next`; route `/etc/traefik/dynamic/<user>.traefik.yml` |
| `deploy_environment` | `staging` | `staging` or `production` (`DJANGO_DEPLOY_ENVIRONMENT`) |
| `django_port`, `next_port`, `gunicorn_workers` | `10025`, `10026`, `3` | both bind `127.0.0.1` |
| `django_settings_module` | `config.settings.production` | |
| `extra_django_allowed_hosts`, `extra_django_csrf_trusted_origins` | none | aliases; extra hosts are smoke-checked too |
| `refused_admin_url_paths`, `reserved_admin_url_paths` | none | see the secrets |
| `bootstrap_admin_username` | `admin` | |
| `extra_source_excludes` | none | added to `/.git`, `node_modules`, `.venv`, `.next` and what the deploy writes (`/.env`, the launchers, `/cache`, `/django/staticfiles`) |
| `middleware_from` | none | a file under `nextjs/` installed as `nextjs/middleware.ts` after each sync |
| `content_import_command` | none | a management command run on a source change |
| `private_media_moves` | none | `media/<name>` moved into `private_media/<name>` once (names never `.` or `..`, here and in `purged_public_dirs`) |
| `purged_public_dirs` | none | `nextjs/public/<name>` whose files are never synced (`/nextjs/public/<name>/***` is excluded) and are removed from the tree and the standalone copy |
| `legacy_guard` | none | `LegacyGuard(tokens, dirs, search)`: code that must never be served |
| `next_check_path` | `/` | local Next.js check |
| `csrf_check_path` | none | session endpoint for the CSRF smoke check |
| `public_checks` | `UrlCheck(path="/")` | `UrlCheck(path, status, follow, contains, retries, delay)` per public host |
| `skip_public_smoke_checks` | `false` | |

Persistent state lives in `~/data` (`db.sqlite3`, `media/`,
`private_media/`, the bootstrap marker, the health-check rehearsal file),
outside the synced site.

## What the deploy does

1. Checks the secrets and renders `.env` (fails before any operation); a
   read-only check that `/usr/bin/node` and `/usr/local/bin/uv` exist
   (host-level, not installed here).
2. `system_user` (shell `/usr/bin/fish`; an existing user is left alone),
   `site/`, and `~/data`, `~/data/media`, `~/data/private_media` (`0750`);
   the `private_media_moves`, only while pending.
3. Markers in `site/`, each written **before** the change it stands for and
   removed together once a run completed (after the checks), so a run that
   fails halfway leaves its work to the next one: `.ops-deploy-pending`
   before a source change (sync or middleware), which repeats every source
   step and both restarts; `.ops-deploy-restart-<unit>` before anything the
   unit reads changes (`.env`, a launcher, its unit file, the dependencies,
   `collectstatic`, the Next.js build), which repeats that restart after a
   `systemctl daemon-reload`; `.ops-deploy-collectstatic` before a dependency
   change, which repeats `collectstatic`.
4. `sync_tree` of the tree to `site/` **with `--delete`**, like the
   playbook's `synchronize`; excluded paths are never deleted on the host.
   `middleware_from` installed as `nextjs/middleware.ts`.
5. `.env` through `secret_file` (`0600`, owner the service user, group left as
   is), `~/.config/fish/config.fish`.
6. `uv sync --locked --no-dev` in `site/django` (venv `site/django/.venv`) on
   a source change, a missing venv or when a read-only `uv sync --dry-run`
   does not report "Would make no changes".
7. `gunicorn.sh`, `site/cache`; `migrate` on a source or dependency change or
   when a read-only `migrate --check` finds unapplied migrations;
   `collectstatic --noinput --clear` on a source or dependency change or
   without `staticfiles.json`; the content import on a source change.
8. `createsuperuser` when the bootstrap account is missing (read-only
   SQLite query); the bootstrap password once, recorded by the marker
   `~/data/.bootstrap-admin-password-applied`.
9. `npm ci` and `next build` (standalone; `NODE_ENV=production`,
   `WAGTAIL_BASE_URL`, `NEXT_PUBLIC_FQDN`), then `.next/static` and `public`
   copied into the standalone output, on a source change or when the stamp
   `site/.ops-deploy-next-build` does not hold this build environment (or
   `server.js` is missing). The stamp is removed before and written after a
   complete build.
10. The `purged_public_dirs` cleanup (when files are present, or after a
    sync or build that may have brought some) and its read-only check; the
    `legacy_guard` check (read-only, before any restart; `node_modules`
    directories are not searched).
11. `next.sh` (a change in comments only restarts nothing), the Traefik route
    (no Traefik restart: its file provider watches the directory), both units.
    `<user>-django` restarts on a source, dependency, `.env`, `gunicorn.sh`,
    unit or `collectstatic` change; `<user>-next` on a build, `next.sh` or unit
    change.
12. Read-only checks: both ports, Django on `http://127.0.0.1:<django_port>/`
    (200/301/302), Next.js on `next_check_path` (200/301/302/307), then for
    every public host (unless `skip_public_smoke_checks`) the `public_checks`
    and the CSRF check.
13. `record_source`, then the markers are cleared.

## Differences from the playbook

- The playbook runs every step and restarts both services on every deploy;
  here only what changed or what a probe finds missing (above). The content
  import therefore does not overwrite CMS edits on a deploy without a source
  change.
- `uv sync --locked` instead of plain `uv sync` (which may rewrite `uv.lock` on
  the host); the playbook's `uv venv` before it is not ported: `uv sync`
  creates the venv with the project's Python.
- `createsuperuser` runs only when the account is missing, and fails the
  deploy if it fails (the playbook ignores its errors).
- Management commands load `.env` instead of getting the same values as
  environment variables.
- On a new host the user is a system user without skeleton files.
- Only SQLite: the playbook's optional PostgreSQL branch is not ported.
- A host rule with several hosts is grouped before the Next.js paths (the
  playbook leaves it ungrouped, which sends all traffic of the other hosts to
  Next.js). A single `Host()` rule renders as the playbook's.
- The comments in `next.sh` and the route are this module's own.
- The legacy guard matches tokens as fixed strings and skips `node_modules`
  directories entirely; the playbook dropped every matching line that named
  `node_modules` (hiding a token on such a line) and searched dependencies for
  the forbidden directory names.
- A smoke check retries until status and content both match, and only counts
  a transfer curl completed.
- The media move checks everything before it copies or removes anything: it
  fails, keeping the source, on a symlink or special file in the source, or a
  path in both places that is not the same regular file (the playbook's
  `rsync --ignore-existing` kept the private copy and deleted the other one).
  Both units are stopped while it moves files (uploads would race it; a
  failed stop moves nothing) and the ones that ran or were (re)starting are
  started again afterwards; only verified copies are removed from the source.
  Purged directories lose every symlink too (a symlinked purge root and a
  symlinked `.gitkeep` included), not only regular files.

## Tests

`tests/test_villakunterbunt.py` (fake connector), with an application config
of made-up names: first run, converged second run (no mutating change), source
change, a repeated run after a failure (pending, restart and collectstatic
markers), middleware drift, `.env` rotation, stale builds, a build URL change,
migrations, static files and dependencies repaired without a source change,
bootstrap account and password, media moves and purged files,
launcher/unit/route changes (Traefik not restarted, a comment-only launcher
change restarts nothing), sync excludes and `--delete`, leak checks (no secret
in commands, op names or uploads; secrets only on stdin), secret and config
validation, the generic defaults, and the URL, CSRF and legacy-guard scripts
run through bash and fish.
