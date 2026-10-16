# django_site

One deploy for the Django/Wagtail sites: gunicorn behind Traefik, SQLite and
local media, uv, an optional admin account and optional management-command
groups. Each site is a typed `DjangoSiteConfig`; the step code never branches
on the site. It replaces the per-site modules (`marina` first; `heis`,
Villa Kunterbunt and the `wagtail_deploy` sites follow in later slices) and
writes **one canonical file set** for every site.

```python
from ops_deploy.services.django_site import (
    AppSpec,
    DjangoSiteConfig,
    EnsureSuperuser,
    EnvSpec,
    Route,
    SourceSpec,
    deploy_django_site,
)

cfg = DjangoSiteConfig(
    service_name="marina",
    title="Marina",
    user="marina",
    home="/home/marina",
    site_path="/home/marina/site",
    shell="/usr/bin/fish",
    fish=True,
    secrets=SecretRef("secrets/prod/marina.yml"),
    source=SourceSpec(path=checkout, required_files=("manage.py", "pyproject.toml", "uv.lock", "config/wsgi.py")),
    app=AppSpec(settings_module="config.settings.production", port=10019, python="3.13"),
    env=EnvSpec(admin_url="marina_admin/"),
    admin=EnsureSuperuser(),
    route=Route(
        fqdn="marina.example.com",
        host_rule="Host(`marina.example.com`) || Host(`www.marina.example.com`)",
        public_reason="Public portfolio website",
    ),
)
deploy_django_site(cfg, store.load(cfg.secrets))
```

The operations are named `Deploy <service_name> | ...`, like the old
per-site modules. ops-control builds the config per host from a `SiteSpec`
(`pyinfra_support/django_sites.py`, see its `docs/PYINFRA.md`).

## The canonical file set

| File | Owner, mode | Content |
|---|---|---|
| `<app>/.env` | user, `0600` | a header comment, then `KEY='value'` per entry |
| `<site>/gunicorn.sh` | user, `0755` | sources `.env`, `cd <app>`, `exec gunicorn` |
| `/etc/systemd/system/<unit>.service` | root, `0644` | runs the launcher; `Restart=always`, `RestartSec=5` |
| `/etc/traefik/dynamic/<unit>.traefik.yml` | root, `0644` | HTTP and HTTPS routers of a public website |
| `~/.config/fish/config.fish` (with `fish`) | user, `0644` | venv on `PATH`, `cd` to the site |

`<site>` is `site_path`, `<app>` the app directory in it (`app.app_dir`, the
site itself by default), `<unit>` is `unit` (default: `service_name` with `-`
for `_`). Every file starts with the comment `# Managed by ops-deploy
(django_site). Local changes are overwritten by the next deploy.` (after the
shebang in the launcher).

### Why this set

The three Ansible origins (`marina_deploy`/`heis_deploy`, `wagtail_deploy`,
Villa Kunterbunt's playbook) write different files. The owner decided for one
set instead of one profile per origin: each site gets one planned rewrite and
one restart when it moves to django_site, and Ansible no longer deploys it.
The set is the classic one (marina/heis) with these choices:

- **`.env` single-quoted.** It is read by four parsers: `sh` (`set -a; .
  .env`: the launcher, every management command, the promotion and backup
  playbooks), systemd `EnvironmentFile=` (wagtail units), django-environ's
  `read_env` (marina's settings) and python-dotenv. Inside single quotes all
  four take the characters as they are, so a secret can hold spaces, `$`,
  single backslashes or `;` (the classic unquoted file had to refuse those).
  A value is refused, naming its key, when it contains `'`, a line break or
  NUL; starts with `$` (django-environ resolves that as a reference to
  another variable); contains `${` (python-dotenv expands it) or `\\`, or
  ends with `\` (python-dotenv reads them as escapes); or is wrapped in `"`
  (django-environ strips a second pair of quotes).
  `tests/test_django_site_env_parsers.py` reads every accepted value of
  length up to three over the tricky characters back through `sh`,
  django-environ and python-dotenv.
- **The launcher sources `.env` and `exec`s gunicorn.** The web process and
  the management commands get their environment from the same file through
  the same parser; the settings no longer have to read `.env` themselves.
  gunicorn becomes the unit's main process (signals and `MainPID` reach it
  directly). The gunicorn arguments are the classic ones; the `%` access-log
  format stays in the launcher, out of systemd's specifier expansion.
- **The classic unit**, plus `Group=` and `RestartSec=5`: a crashing app is
  retried every 5 s instead of every 100 ms, which would hit systemd's start
  limit (5 starts in 10 s) and leave the unit failed. `DJANGO_SETTINGS_MODULE`
  comes from `.env` only. `hardening` adds the classic/wagtail sandbox
  (`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ReadWritePaths`
  = the site, the cache and a database or media directory outside the site).
- **The classic route.** Router names (`<fqdn>-router`,
  `<fqdn>-secure-router`), service name (`<fqdn>`) and the middlewares
  (`redirect`, `csrf`, `sslHeaders`, `gzip-compress`, `redirect-www`) stay as
  they are: Traefik's file provider shares one namespace, and other route
  files may refer to these middlewares as `<name>@file`. The second header
  line states `route.public_reason`, the reason the route has no Basic Auth
  (a required field).
- **The classic fish config**, unchanged apart from the header.

### Differences from the marina_deploy role's files

What the first django_site deploy of marina rewrites (the old module wrote the
role's bytes). Everything else (paths, owners, modes, unit and route names,
port, gunicorn arguments, env keys and values) stays.

| File | Old line | New line | Why |
|---|---|---|---|
| `.env` | – | `# Managed by ops-deploy (django_site). ...` | marks the file as pyinfra's |
| `.env` | `KEY=value` | `KEY='value'` | one quoting all four parsers read alike (above); same keys and values |
| `gunicorn.sh` | – | `# Managed by ...` (line 2) | as above |
| `gunicorn.sh` | – | `set -a; . /home/marina/site/.env; set +a` (after `set -euo pipefail`) | the web process gets the same environment as the management commands |
| `gunicorn.sh` | `/home/marina/site/.venv/bin/gunicorn \` | `exec /home/marina/site/.venv/bin/gunicorn \` | gunicorn is the main process |
| unit | – | `# Managed by ...` | as above |
| unit | – | `RestartSec=5` | no fast restart loop into the start limit |
| unit | `Environment="DJANGO_SETTINGS_MODULE=config.settings.production"` | – | the settings module comes from `.env` (same value) |
| unit | – | `Group=marina` | explicit; it was the user's primary group, `marina` |
| route | – | `# Managed by ...` and `# Public website, no Basic Auth: <public_reason>` | ownership and the documented exception |
| fish config | – | `# Managed by ...` | as above |

The equivalence test (below) shows that nothing else differs: the same
commands, facts, uploads (paths) and stdin, apart from the markers.

### Ansible after the switch

An Ansible deploy of a switched site (`playbooks/deploy-<site>.yml` with the
frozen role) writes its own files back and restarts the site, and the next
django_site deploy switches it again (one more restart). Deploy switched sites
only with `just deploy-one <site>`; ops-control documents the other entry
points per site. Ansible stays the last-resort rollback.

## Secrets

`required_secret_keys` follows from the config: every `Secret(secret=...)` in
it, in order of first use (`env.secret_key`, `env.admin_url` and
`env.extra` values, the admin account). For marina:

| Key | Used for |
|---|---|
| `django_secret_key` | `DJANGO_SECRET_KEY`; also keys the admin stamp |
| `admin_username`, `admin_email`, `admin_password` | `EnsureSuperuser` (stdin only) |

Every referenced secret must be set, a single line and no `CHANGEME`; secrets
in `.env` follow its value rules. Errors name keys, never values. Secrets
reach the host only through `secret_file` (`.env`, the stamp) or stdin.

## Configuration (`DjangoSiteConfig`)

| Field | Default | Notes |
|---|---|---|
| `service_name`, `title` | required | operation names; `Description=<title> web application` |
| `unit` | `service_name` (`_` → `-`) | unit and route file name |
| `user`, `group` | required, `user` | |
| `home`, `site_path` | required | absolute, letters, digits and `_ . -` only |
| `shell` | `/bin/bash` | `/usr/bin/fish` for classic sites |
| `fish` | `false` | fish config and the `<app>/venv` link to `.venv` |
| `source` | required | `SourceSpec`: `path`, `commit` ([git source](../concepts/git-source.md)), `excludes`, `delete` (default `false`), `required_files` (checked in the app directory), `repair_ownership` (default `true`). The sync always also excludes, anchored at the site root, `.env`, the cache, `staticfiles`, the SQLite database with everything SQLite keeps next to it (`<db>*`: `-wal`, `-shm`, `-journal`) and the media root when they are inside the site: rsync neither overwrites nor deletes them |
| `app` | required | `AppSpec`: `app_dir`, `settings_module`, `wsgi_app` (`config.wsgi`), `port`, `workers` (4), `timeout` (3600), `python` (`uv sync --python`), `uv_args` (`--frozen --no-dev`) |
| `database` | `SqliteDb()` | `path` (default `<app>/db.sqlite3`) |
| `media` | `LocalMedia()` | `root` (default `<app>/media`) |
| `env` | `EnvSpec()` | `secret_key` (`Secret("django_secret_key")`), `admin_url` (literal or `Secret`), `allowed_hosts` (default `<fqdn>,localhost`), `extra` (ordered `EnvEntry(key, value)`) |
| `steps` | `Steps()` | `collectstatic_args` (`--noinput`), `restart_after_collectstatic`, `extra` (`StepGroup`s) |
| `admin` | `None` | `EnsureSuperuser(command="ensure_superuser", username/email/password secrets)` |
| `route` | required | `Route`: `fqdn`, `host_rule`, `tls_host_rule` (default `host_rule`), `cert_resolver` (`letsencrypt`), `public_reason` (required) |
| `checks` | `Checks()` | `port_retries` (30), `path` (`/`), `statuses` (200, 301, 302) |
| `hardening` | `false` | the systemd sandbox above |

`.env` holds `DJANGO_SETTINGS_MODULE`, `DJANGO_SECRET_KEY`, `DJANGO_ADMIN_URL`
(when set), `DJANGO_ALLOWED_HOSTS`, `DJANGO_CACHE_LOCATION` (`<app>/cache`),
then `env.extra` in order; `env.extra` may not repeat a key.

A `StepGroup` is a list of `ManageStep(name, argv)` run as `manage.py <argv>`
in order. `when="changes"` runs it when one of its `triggers` happened in this
run (`source`: the source changed; `deps`: `uv sync` ran; `migrate`:
migrations ran), `"always"` on every deploy. With `marker` (a file name
`.ops-deploy-<x>` in the home directory) the group is marked pending before it
runs and the marker is removed after every step succeeded; while it is there,
the next deploy runs the group again. The deploy's own file names
(`.ops-deploy-pending`, `.ops-deploy-restart-*`, `.ops-deploy-admin`,
`.ops-deploy-source`) cannot be markers.

## What the deploy does

1. Checks the secrets and renders every file (fails before any operation).
2. `system_user` (an existing user is left alone), `site`, the cache
   directory; with `fish` the fish config (a missing `~/.config` is created,
   an existing one is never touched).
3. Reads the markers an earlier run left (one fact).
4. `~/.ops-deploy-pending` is written when the sync will change something,
   `uv sync` is owed, or a marker is left over. Then `sync_tree` (`--delete`
   only with `source.delete`), and a recursive `chown` of the site only when a
   read-only `find` sees another owner.
5. `uv sync` when the source changed, the venv is missing or a read-only
   `uv sync --dry-run` does not say "Would make no changes"; the `venv` link.
6. `~/.ops-deploy-restart-<unit>` is written when `.env`, the launcher or the
   unit will change, or one is left over. Then `.env` through `secret_file`.
7. `migrate` when the source or the dependencies changed or a read-only
   `migrate --check` finds unapplied migrations; `collectstatic` when the
   source or the dependencies changed or the manifest is missing; the step
   groups; `ensure_superuser` when the account is missing, inactive, not
   staff/superuser, has another email, or the admin secrets changed since the
   last run (an HMAC keyed with the Django secret in `~/.ops-deploy-admin`,
   `0600 root`).
8. Launcher, unit, `service_rollout`: systemd is reloaded when the unit
   changed (or a restart marker was left over); the unit restarts once when
   the source or the dependencies changed, something it reads changed, or a
   marker says a restart is owed (and after `collectstatic` with
   `restart_after_collectstatic`; then `collectstatic` writes the restart
   marker before it changes any file).
9. The route. Traefik is never restarted: its file provider watches the
   directory.
10. Read-only checks: the port opens, `http://127.0.0.1:<port><path>` answers
    one of `statuses` with the site's Host header.
11. `record_source` (the deployed commit), then the markers are removed. Only
    a run that came up healthy gets here; a failed run leaves its markers, and
    the next run repeats the source steps and the restart it owes.

The markers live in the home directory: no sync of either tool touches it,
also not one with `--delete`. A converged deploy reads them and changes
nothing.

## Tests

- `tests/test_django_site.py` (fake connector): the rendered files, first run,
  converged run (no mutating change), code change and its markers, leftover
  markers (pending, restart), a failed run that keeps them, `.env` rotation,
  the switch from marina's old files (one restart, then nothing), step groups
  (triggers, marker, `always`), `restart_after_collectstatic`, `fish` off,
  secret and config validation, leak checks.
- `tests/test_django_site_equivalence.py` (transitional, removed with
  `services/marina`): every scenario of `test_marina.py` through both modules;
  the normalized transcripts are equal apart from the markers and the
  documented file contents, and `.env` carries the same keys and values.
- `tests/test_django_site_env_parsers.py`: `.env` values read back by `sh`,
  django-environ and python-dotenv (dev dependencies), accepted ones
  unchanged, refused ones changed by at least one of them.
- `tests/test_remote_shell_execution.py`: the management command reads `.env`
  values with quotes, backslashes, `$` and backticks, through bash and fish;
  the launcher passes them and the gunicorn arguments unchanged; the marker
  fact lists only markers.
- `tests/smoke/test_django_site_smoke.py` (`just smoke`, needs `MARINA_SOURCE`
  or `PROJECTS_ROOT`): marina deployed by the old module, then switched: only
  the documented files change, one restart, `.env` values, database, media,
  cache and admin kept; later runs (same tree, fresh clone) change nothing; a
  code change restarts once; no secret on disk outside its files.
- ops-control: `just smoke-marina-coexistence` switches from the Ansible role.
