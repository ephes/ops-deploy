# django_site

One deploy for the Django/Wagtail sites: gunicorn behind Traefik, SQLite and
local media, uv, an optional admin account, optional management-command
groups and an optional Next.js standalone frontend with its own unit. Each
site is a typed `DjangoSiteConfig`; the step code never branches on the site.
It replaced the per-site modules of marina and heis (both on django_site since
2026-10-16; `services/marina` and `services/heis` are gone) and, in slice 3,
an unmerged module for one site with a Next.js frontend (the "split site"
below); the `wagtail_deploy` sites follow in later slices. It writes **one
canonical file set** for every site.

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
| `<env>/.env` | user, `0600` | a header comment, then `KEY='value'` per entry |
| `<site>/gunicorn.sh` | user, `0755` | sources `.env`, `cd <app>`, `exec gunicorn` |
| `/etc/systemd/system/<unit>.service` | root, `0644` | runs the launcher; `Restart=always`, `RestartSec=5` |
| `/etc/traefik/dynamic/<route>.traefik.yml` | root, `0644` | HTTP and HTTPS routers of a public website |
| `~/.config/fish/config.fish` (with `fish`) | user, `0644` | venv on `PATH`, `cd` to the site |
| `<site>/next.sh` (with `frontend`) | user, `0755` | `NODE_ENV`, `PORT`, `HOSTNAME`, `runtime_env`; `exec node <standalone>/server.js` |
| `/etc/systemd/system/<frontend unit>.service` (with `frontend`) | root, `0644` | the same unit shape, running `next.sh` in the site, `After=<unit>.service` |

`<site>` is `site_path`, `<app>` the app directory in it (`app.app_dir`, the
site itself by default), `<env>` the directory of `.env` and the cache
(`app.env_dir`, the app directory by default), `<unit>` is `unit` (default:
`service_name` with `-` for `_`), `<route>` is `route.name` (default: the
unit). Every file starts with the comment `# Managed by ops-deploy
(django_site). Local changes are overwritten by the next deploy.` (after the
shebang in the launchers).

With a `frontend`, the route has two more routers, `<fqdn>-<router>-router`
(HTTP: `redirect`) and `<fqdn>-<router>-secure-router` (HTTPS: `csrf`,
`sslHeaders`, `gzip-compress`), with the rule `<host rule> && (Path(p) ||
PathPrefix(p/) ...)` over `frontend.path_prefixes` (the HTTPS one with the
TLS host rule; a host rule with `||` in parentheses) and priority 200; the site's routers get priority 100 and their
service is `<fqdn>-django`, the frontend's `<fqdn>-next`. `route.backend`
(`localhost` or `127.0.0.1`) is the address in the service URLs.

### Why this set

The three Ansible origins (`marina_deploy`/`heis_deploy`, `wagtail_deploy`,
the split site's own playbook) write different files. The owner decided for one
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
  (`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
  `ProtectHome=false`, `ReadWritePaths` = the site, the cache and the directories
  outside the site the database and the media live in, the home included, a
  directory inside another one not repeated); `hardening: "strict"` (the split site's) makes the home
  read-only (`ProtectHome=read-only`) and adds `ProtectKernelTunables`,
  `ProtectKernelModules`, `ProtectControlGroups`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `LockPersonality`,
  `RestrictRealtime` and `SystemCallArchitectures=native`. The frontend's
  unit has the same sandbox.
- **The classic route.** Router names (`<fqdn>-router`,
  `<fqdn>-secure-router`), service name (`<fqdn>`) and the middlewares
  (`redirect`, `csrf`, `sslHeaders`, `gzip-compress`, `redirect-www`) stay as
  they are: Traefik's file provider shares one namespace, and other route
  files may refer to these middlewares as `<name>@file`. The second header
  line states `route.public_reason`, the reason the route has no Basic Auth
  (a required field).
- **The classic fish config**, unchanged apart from the header.

### Differences from the marina_deploy and heis_deploy roles' files

What the first django_site deploy of marina or heis rewrites (the old modules
wrote the roles' bytes); shown with marina's paths, heis's are the same with
`heis`. Everything else (paths, owners, modes, unit and route names, port,
gunicorn arguments, env keys and values, heis's TLS rule and canonical
redirect) stays. heis's role quoted `.env` values with `quote` (`'...'` only
when needed); its values read the same as before.

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

The equivalence tests showed that nothing else differs: the same commands,
facts, uploads (paths) and stdin, apart from the markers (marina's while
`services/marina` existed, heis's now).

### Differences from the split-site module's files

What the first django_site deploy of the split site rewrites (its earlier,
unmerged module wrote the bytes of the site's own playbook), with
`<user>`, `<site>`, `<fqdn>` and the ports standing for the site's values.
Paths, owners and modes, unit names, the route file name, router, service
and middleware names, priorities, ports, gunicorn arguments, the build
command and stamp, and `.env` keys and values stay.

| File | Old line | New line | Why |
|---|---|---|---|
| all files | – | `# Managed by ops-deploy (django_site). ...` | marks the file as pyinfra's |
| `.env` | `KEY='value'` in the playbook's order | the base keys first (`DJANGO_SETTINGS_MODULE`, `DJANGO_SECRET_KEY`, `DJANGO_ALLOWED_HOSTS`, `DJANGO_CACHE_LOCATION`), then `env.extra` | one key order for every site; same keys and values (values with `'` are refused instead of escaped as `'\''`) |
| `gunicorn.sh` | `set -a; source <site>/.env; set +a` | `set -a; . <site>/.env; set +a` | the canonical launcher (same arguments: `-w 3`, `-t 3600`, the access-log format) |
| `gunicorn.sh` | `--access-logfile - --error-logfile - \`, `-b ... -t 3600 \` | one argument per line | as above |
| Django unit | `Description=<user> Django/Wagtail web application` | `Description=<title> web application` | the canonical unit |
| Django unit | `Environment="DJANGO_SETTINGS_MODULE=..."` | – | `.env` has it (same value) |
| both units | – | `Group=<user>` | explicit; it was the user's primary group |
| Django unit | `ReadWritePaths=<home>/data <site> <site>/cache` | `ReadWritePaths=<site> <site>/cache <home>/data` | the canonical order |
| Next.js unit | `Description=<user> Next.js admin (/cms)` | `Description=<title> Next.js server` | generic |
| Next.js unit | `ReadWritePaths=<home>/data <site>` | `ReadWritePaths=<site> <site>/cache <home>/data` | the same paths as the Django unit (the cache is in the site) |
| `next.sh` | four comment lines about `WAGTAIL_BASE_URL` | – | the build environment is config (`build_env`) |
| `next.sh` | `export DJANGO_BASE_URL="http://127.0.0.1:<django port>"` | `export DJANGO_BASE_URL=http://127.0.0.1:<django port>` | `runtime_env` values are plain (no quotes needed) |
| route | the playbook's comment on priorities | django_site's comment | – |
| route | – | a blank line after each `rule:` | the canonical route's layout |
| route | HTTPS Django router: `csrf`, `sslHeaders`, `gzip-compress` | the same plus `redirect-www` | the canonical route; the host rule matches no `www.` host, so it never fires |
| fish config | `set -x PATH $PATH ~/.local/bin`, `.../.venv/bin`, `VIRTUAL_ENV ".../.venv"`, `cd site/django` | the classic config: `alias bat`/`fd`, `<home>/.local/bin`, `<app>/venv/bin`, `VIRTUAL_ENV "<app>/venv"`, `cd <app>` | the canonical config; django_site links `<app>/venv` to `.venv` (excluded from the sync) |

The switch also changes owners, not content: files the old module wrote with
group `root` (`.env`, the launchers, the cache, `~/.config/fish` and its
config) get the service group, and the site's recursive ownership repair
runs once. Both units restart once (their unit files changed); the
migrations, `collectstatic`, the content import and the build do not run
(the same tree, the same dependencies, the build stamp matches), and the
next run changes nothing (`tests/test_django_site_split_equivalence.py`).

Behaviour that differs from the old module, apart from the files:

- The markers live in the state directory (`/var/lib/ops-deploy/<service>/`)
  instead of the site; the old module's `.ops-deploy-collectstatic` is gone
  (a dependency change writes `.ops-deploy-pending`, and the
  `staticfiles.json` probe finds an incomplete collection). A deploy stops
  before any change while the site holds such an old marker
  (`.ops-deploy-pending`, `.ops-deploy-collectstatic`,
  `.ops-deploy-restart-*` in `<site>`): finish that run with the old module
  first.
- systemd is reloaded when a unit file changed or a restart marker is left
  over, not whenever a restart marker is written (`.env` or `next.sh`).
- Management commands also export `DJANGO_SETTINGS_MODULE` (the same value
  `.env` has).
- The local check of the Django port sends the site's Host header.
- The old module's one-time move of `media/<name>` into private storage
  (`private_media_moves`) is not ported: the split site's move is done.

### Ansible after the switch

An Ansible deploy of a switched site (`playbooks/deploy-<site>.yml` with the
frozen role) writes its own files back and restarts the site, and the next
django_site deploy switches it again (one more restart). Deploy switched sites
only with `just deploy-one <site>`; ops-control documents the other entry
points per site. Ansible stays the last-resort rollback.

## Secrets

`required_secret_keys` follows from the config: every required `Secret(secret=...)` (excluding explicit `allow_empty` references) in
it, in order of first use (`env.secret_key`, `env.admin_url` and
`env.extra` values, `env.url_paths`, the admin account). For marina:

| Key | Used for |
|---|---|
| `django_secret_key` | `DJANGO_SECRET_KEY`; also keys the admin stamp |
| `admin_username`, `admin_email`, `admin_password` | `EnsureSuperuser` (stdin only) |

Every required referenced secret must be set, a single line and no `CHANGEME`; secrets
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
| `apt_packages` | `()` | Debian packages installed first, before the user (heis: `fish`, `rsync`, `sqlite3`; no cache update) |
| `fish` | `false` | fish config and the `<app>/venv` link to `.venv` (excluded from the sync) |
| `source` | required | `SourceSpec`: `path`, `commit` ([git source](../concepts/git-source.md)), `excludes`, `delete` (default `false`), `required_files` (checked in the app directory), `repair_ownership` (default `true`). The sync always also excludes, anchored at the site root, `.env`, the cache, `staticfiles`, the SQLite database with everything SQLite keeps next to it (`<db>*`: `-wal`, `-shm`, `-journal`), the media root and `media.private_root`, the bootstrap admin's marker, the launchers (including worker launchers), the `venv` link and the frontend's installed middleware, purged public directories, `node_modules` (anywhere) and `<app_dir>/.next` when they are inside the site: rsync neither overwrites nor deletes them |
| `app` | required | `AppSpec`: `app_dir`, `env_dir` (`.env` and the cache, relative to the site; default the app directory), `settings_module`, `wsgi_app` (`config.wsgi`), `port`, `workers` (4), `timeout` (3600), `python` (`uv sync --python`), `uv_args` (`--frozen --no-dev`), `uv_env` (empty), `assert_python_version` (false) |
| `database` | `SqliteDb()` | `path` (default `<app>/db.sqlite3`) |
| `media` | `LocalMedia()` | `root` (default `<app>/media`), `private_root` (optional) |
| `env` | `EnvSpec()` | `secret_key` (`Secret("django_secret_key")`), `admin_url` (literal or `Secret`), `allowed_hosts` (default `<fqdn>,localhost`), `extra` (ordered `EnvEntry(key, value)`), `url_paths` (`PathSecrets`, below) |
| `steps` | `Steps()` | `migrate_args` (none), `collectstatic_args` (`--noinput`), `restart_after_collectstatic`, `extra` (`StepGroup`s) |
| `admin` | `None` | `EnsureSuperuser(command="ensure_superuser", username/email/password secrets)` or `BootstrapSuperuser(username="admin", email, password=Secret("bootstrap_admin_password"), marker)` |
| `workers` | `()` | `DbWorker` unit/backend/id/queue/interval/args, sharing app env and gated rollout |
| `repair_cache_ownership` | `false` | Repair cache entry owner/group recursively, preserving modes |
| `frontend` | `None` | `NextStandalone`, below |
| `route` | required | `Route`: `fqdn`, `name` (the route file; default the unit), `host_rule`, `tls_host_rule` (default `host_rule`), `cert_resolver` (`letsencrypt`), `backend` (`localhost`), `canonical_redirect_regex` and `canonical_redirect_replacement` (both or neither: a permanent `redirect-canonical-host` middleware on the HTTPS router, heis's), `public_reason` (required) |
| `checks` | `Checks()` | `port_retries` (30), `path` (`/`), `statuses` (200, 301, 302), `public` (`UrlCheck`s), `csrf_path` |
| `hardening` | `false` | `true` or `"strict"`: the systemd sandbox above |

`.env` holds `DJANGO_SETTINGS_MODULE`, `DJANGO_SECRET_KEY`, `DJANGO_ADMIN_URL`
(when set), `DJANGO_ALLOWED_HOSTS`, `DJANGO_CACHE_LOCATION` (`<env>/cache`),
then `env.extra` in order; `env.extra` may not repeat a key. A value is a
literal, a `Secret(secret, strip="", min_length=0, equals=None)` (`strip="/"`
removes slashes at both ends; `min_length` and `equals` are checked before
any operation, `equals` for a value kept with the secrets that must be the
configured one, such as a relay URL), or `Joined(parts)`: literals and
secrets concatenated (`https://<fqdn>/` and a path secret).

`PathSecrets(secrets, refused, reserved)`: secrets holding URL paths the site
serves (admin paths). Each must be a URL path (letters, digits and
`. _ ~ / -`, not only slashes), none of `refused`, not under `reserved` or a
frontend path prefix (Traefik would send it to the frontend), and no two the
same; paths compare as `/<path>/`.

Directories outside the site that hold data (the database's directory, the
media roots, never the home) are created as the user, `0750`.

`NextStandalone` (a Next.js app built with `output: "standalone"`;
`package.json` and `package-lock.json` at the site root):

| Field | Default | Notes |
|---|---|---|
| `unit`, `port` | required | the frontend's unit and port (both differ from the site's) |
| `app_dir` | required | the Next.js app in the site; `server.js` is in `<app_dir>/.next/standalone/<app_dir>` |
| `router` | `next` | the routers' middle name; not `secure` (that would collide with the site's `<fqdn>-secure-router`) |
| `path_prefixes` | required | routed to the frontend; segments without a trailing slash |
| `build_env` | `()` | `EnvLiteral(key, value)`s baked into the build after `NODE_ENV=production`; the stamp |
| `runtime_env` | `()` | exported by `next.sh` |
| `node` | `/usr/bin/node` | checked (with uv) before any change; Node.js is host-level |
| `middleware_from` | `None` | a file in `app_dir` installed as `<app_dir>/middleware.ts` after the sync; a content change counts as a source change, an owner or mode repair alone does not |
| `purged_public_dirs` | `()` | `<app_dir>/public/<name>`: never synced, files removed |
| `legacy_guard` | `None` | `LegacyGuard(tokens, dirs, search)`: code that must never be served |
| `check_path`, `check_statuses` | `/`, (200, 301, 302, 307) | the local check |

`UrlCheck(path, status=200, follow=True, contains=(), retries=1, delay=5)`:
`curl https://<fqdn><path>` on the host, through Traefik.

A `StepGroup` is a list of `ManageStep(name, argv)` run as `manage.py <argv>`
in order. `when="changes"` runs it when one of its `triggers` happened in this
run (`source`: the source changed; `deps`: `uv sync` ran; `migrate`:
migrations ran), `"always"` on every deploy. With `marker` (a file name
`.ops-deploy-<x>` in the site's state directory) the group is marked pending before it
runs and the marker is removed after every step succeeded; while it is there,
the next deploy runs the group again. The deploy's own file names
(`.ops-deploy-pending`, `.ops-deploy-restart-*`, `.ops-deploy-admin`,
`.ops-deploy-source`) cannot be markers. `after="migrate"` runs the group
right after the migrations (heis's content reconcilers), the default
`"collectstatic"` after the static files.

## What the deploy does

1. Checks the secrets and renders every file, and refuses a source `uv.lock`
   (the app directory's, or a workspace root's above it in the source) that
   locks certifi below 2026.10.19 or pip below 26.2.2 (`require_lock_floors`;
   fails before any operation).
2. `apt_packages`, then `system_user` (an existing user is left alone), `site`, the cache
   directory; with `fish` the fish config (a missing `~/.config` is created,
   an existing one is never touched).
3. Reads the markers an earlier run left (one fact) and stops when the site
   holds a marker of the old split-site module (one fact). When an existing user
   has another primary group than the service group (a user the Ansible
   roles created with `users`): the restart marker, the old group into
   `.ops-deploy-regroup` in the state directory, `usermod -g <group> <user>`, then
   `find <home> [<site>] -xdev -user <user> -group <old> -exec chgrp -h <group> {} +`
   (only the user's own files, only in its home and a site outside it) and
   the marker removed; a run that stopped in between finishes the move.
   Linux `usermod -g` itself also moves every file with the old group in the
   home, whoever owns it and across mounts, so the deploy stops before any
   change when such a file belongs to someone else or something is mounted
   below the home (fix those by hand). The running processes keep the old
   group until the unit restarts: the change folds into the run's one
   restart. A user with the right group costs two read-only facts.
4. `.ops-deploy-pending` is written when the sync will change something,
   `uv sync` is owed, or a marker is left over. Then `sync_tree` (`--delete`
   only with `source.delete`), and a recursive `chown` of the site only when a
   read-only `find` sees another owner.
5. `uv sync` when the source changed, the venv is missing or a read-only
   `uv sync --dry-run` does not say "Would make no changes"; then, on every
   run, the read-only `verify_trust` of the venv (certifi/pip floors, no
   distrusted root in their bundles); the `venv` link.
6. `.ops-deploy-restart-<unit>` is written when `.env`, the launcher or the
   unit will change, or one is left over. Then `.env` through `secret_file`.
7. `migrate` when the source or the dependencies changed or a read-only
   `migrate --check` finds unapplied migrations; `collectstatic` when the
   source or the dependencies changed or the manifest is missing; the step
   groups; `ensure_superuser` when the account is missing, inactive, not
   staff/superuser, has another email, or the admin secrets changed since the
   last run (an HMAC keyed with the Django secret in `~/.ops-deploy-admin`,
   `0600 root`).
   With a `frontend` (after the admin account): the build when the source
   changed (or a pending marker is left over) or the build stamp
   `<site>/.ops-deploy-next-build` differs from `NODE_ENV=production` plus
   `build_env` (also without a `server.js`): the frontend's restart marker,
   then as the user in the site `rm -f` the stamp, `npm ci --no-audit
   --no-fund`, `env <build env> npm run build`, the static files and
   `public` (when the app has one) copied into the standalone output when
   missing, the stamp written. A change of the Python dependencies alone does not rebuild. Then
   the purged public files are removed when a read-only `find` sees one (or
   the source or build changed) and checked absent (read-only); a purged
   directory under a symlinked parent (`public` linked elsewhere) is never
   followed: nothing is removed and the deploy fails. Then the legacy guard
   runs (read-only).
8. Launcher, unit, `service_rollout`: systemd is reloaded when the unit
   changed (or a restart marker was left over); the unit restarts once when
   the source or the dependencies changed, something it reads changed, or a
   marker says a restart is owed (and after `collectstatic` with
   `restart_after_collectstatic`; then `collectstatic` writes the restart
   marker before it changes any file). The frontend's unit restarts once
   when the build ran or what it reads changed (its unit file, the user's
   group, `next.sh` when a code line changed: a comment-only change is
   written without a restart).
9. The route. Traefik is never restarted: its file provider watches the
   directory.
10. Read-only checks: the port opens, `http://127.0.0.1:<port><path>` answers
    one of `statuses` with the site's Host header; the frontend's port and
    `check_path`; the `public` URL checks and the CSRF check (a session
    endpoint's token in a POST with the site's `Origin` must get 400, not
    Django's 403).
11. `record_source` (the deployed commit), then the markers are removed. Only
    a run that came up healthy gets here; a failed run leaves its markers, and
    the next run repeats the source steps and the restart it owes.

The markers live in the site's state directory `/var/lib/ops-deploy/<service_name>/`
(`root:root 0700`, created by the first marker a run writes): no sync of
either tool touches it, also not one with `--delete`, and the service user
cannot plant a symlink there that a root `touch` or write would follow. A
converged deploy reads it and changes nothing.

## Tests

- `tests/test_django_site.py` (fake connector): the rendered files, first run,
  converged run (no mutating change), code change and its markers, leftover
  markers (pending, restart), a failed run that keeps them, `.env` rotation,
  the switch from marina's old files (one restart, then nothing), step groups
  (triggers, marker, `always`, `after`), `apt_packages`, the canonical
  redirect, `restart_after_collectstatic`, `fish` off,
  secret and config validation, leak checks.
- The transitional equivalence tests ran every scenario of the old
  `services/marina` and `services/heis` tests through both modules (equal
  normalized transcripts apart from the markers and the documented file
  contents) until those modules were removed after the sites' cutovers.
- `tests/test_django_site_split.py` (fake connector and real shells): the
  frontend's files and route, first run, converged run, code change
  (one restart of each unit), a dependency change (no build, no import),
  leftover markers, stale builds, a build environment change, a
  comment-only `next.sh` change (no restart), the bootstrap admin, the
  purge, the sync excludes with real rsync, secret and config validation,
  leak checks, every command (also of skipped ops) unchanged through fish;
  the legacy guard, purge, URL and CSRF scripts in bash and fish.
- `tests/test_django_site_split_equivalence.py` (transitional): every
  scenario of the old split-site module's tests through the vendored old
  module (`tests/legacy_split_site/`, made-up names) and django_site: the
  same mutating operations (renamed ones mapped; the documented reload and
  marker differences listed per scenario), restarts, management, build and
  purge commands, uploads (the documented files carry django_site's render)
  and stdin (`.env` as the same keys and values; the read-only certifi/pip
  trust check is new in django_site and not a mutating operation); and the switch from the
  old module's host state: the documented rewrites, one restart per unit,
  then nothing. It goes with the vendored module once the site has run on
  django_site for a while.
- `tests/test_django_site_env_parsers.py`: `.env` values read back by `sh`,
  django-environ and python-dotenv (dev dependencies), accepted ones
  unchanged, refused ones changed by at least one of them.
- `tests/test_remote_shell_execution.py`: the management command reads `.env`
  values with quotes, backslashes, `$` and backticks, through bash and fish;
  the launcher passes them and the gunicorn arguments unchanged; the marker
  fact lists only markers.
- `tests/smoke/test_django_site_smoke.py` (`just smoke`, needs `HEIS_SOURCE`
  or `PROJECTS_ROOT`): heis in the staging shape, deployed from nothing; the
  next runs (same tree, fresh clone) change nothing; a code change restarts
  once and runs the reconcilers before `collectstatic`; `.env` values,
  database, media, cache, admin and the primary group kept, no marker left,
  no secret on disk outside its files.
- ops-control: `just smoke-marina-coexistence` and
  `just smoke-heis-coexistence SHAPE=production|staging` switch from the
  Ansible roles.


## PostgreSQL and Wagtail sites

`database=PostgresDb(name=..., user=..., password=Secret(...))` provisions only
an ASCII-password login role, database ownership and public-schema ownership.
The shared local PostgreSQL server must already answer `pg_isready` before any
mutation; installation, startup and server upgrades remain host operations.
Hyphenated database/user names are supported as quoted SQL identifiers.
`DATABASE_URL` is generated automatically with percent-encoded credentials.
SQLite remains the default, including existing untagged SQLite dictionaries.
The SQLite superuser helpers are rejected for PostgreSQL; use a management
step group for a site's idempotent bootstrap instead.

`ManageStep.stdin_env` is a tuple of `EnvEntry` values sent on stdin and
exported without shell expansion. Commands must never echo those values.
`StepGroup(when="first", marker=".ops-deploy-bootstrap", ...)` runs once after
a successful completion; the separate `-done` marker records completion.
Both markers are in the root-only state directory. A leftover pending marker
wins over completion, so interrupted work repeats. Completion-marker names and
pending-marker names cannot collide. Ordinary `when="changes"` groups can run
`update_index` on source/dependency/migration changes; their pending marker
makes failures resumable. `steps.required_static` checks each relative path
after collection and fails if it is missing.

`source.forbid_local_dependencies=True` rejects uv path/workspace sources in
`pyproject.toml` on the controller. This prevents a deployment from silently
using a developer's local dependency checkout.

`route.wagtail=True` retains Wagtail's externally referenced unit-based router,
service and middleware names and HSTS/security headers inside the canonical
route renderer. `route.extra_middlewares` adds existing file-provider
middlewares; `route.noindex` writes a companion `<route>-noindex.traefik.yml`.
Classic-only TLS rules and canonical redirects are rejected for Wagtail
routes instead of silently ignored. Noindex middleware is installed before the
route that references it. Disabling noindex leaves an inert companion file;
removing that file belongs to a separately reviewed routing cleanup.
An empty `cert_resolver` renders `tls: {}` for an existing certificate setup.
There is one environment/launcher/unit format for all sites.

| Origin file or behavior | Canonical change | Reason |
|---|---|---|
| Wagtail `.env`: double quotes/comments | Header and single quotes; same parsed keys/values; URL credentials encoded | Shared parser-safe format, reserved credential characters supported |
| Wagtail unit: inline gunicorn, EnvironmentFile, RestartSec=10 | Shared launcher sourcing `.env`, RestartSec=5, shared description | One unit format, same bind/worker/timeout/WSGI arguments |
| Wagtail gunicorn logging | Adds existing canonical stdout/stderr/access format | Consistent journal diagnostics |
| Wagtail route | Header only differs; names, headers, redirects, TLS and extra middleware preserved | External references and security policy remain contracts |
| noindex companion | Managed header changes | Same noindex response header |
| `update_index` every deployment | Changes-only group plus pending marker | Converged deployment does no work |
| bootstrap every deployment | First-success group plus pending/completion markers | Idempotent initialization with explicit resume |
| PostgreSQL role dependency installs server | Read-only availability preflight, then role/database only | Server lifecycle belongs to host infrastructure |

The first switch intentionally rewrites the canonical unit/env/launcher and
restarts the app once; its second run must be a no-op. Ansible fallback would
rewrite the old files and restart again. Do not alternate tools after a live
switch; the private control plane owns admission/entry-point guards.

Coverage: `test_django_site_postgres.py`, `test_django_site_wagtail_parity.py`
(object storage/Sentry on/off, mail URL empty/set, TLS resolver empty/set),
and `tests/smoke/test_django_site_postgres_smoke.py` (synthetic Linux/PostgreSQL
Django app, data retention, no-op rerun, pending-source resume).


### Existing environment aliases and controller caches

Source sync preserves an existing `<app>/venv` alias for every Django site,
including Wagtail accounts that do not use fish. Fish controls creation of the
alias and shell configuration, not protection of a host-managed alias left
by an older deploy. Source sync also excludes `.ruff_cache` directories at any
depth so local lint-cache files cannot create artificial source changes or
trigger migrations, static collection, indexing and restarts. These exclusions
preserve existing host files; they do not remove old caches already on a host.

Existing in-tree PostgreSQL media directories retain their permissions during
conversion. A missing directory is created as the app user/group with mode
`0755`, matching the Wagtail origin. Symlinks and other existing file types
are refused before execution. External `data_dirs` keep their existing `0750`
provisioning policy.

### Database workers and transport

`workers` declares Django Tasks `db_worker` units sharing the app's `.env`
and virtualenv. Each worker names its unit, backend, optional worker id/queue,
interval and argv tuple. A canonical shell launcher sources `.env` and execs
`python manage.py db_worker`; the unit keeps the origin's `RestartSec=10`.
The worker's own unit/launcher or shared source, dependencies, env and primary
group changes owe its restart. Root-owned restart markers are written before
changes and cleared only after all rollouts and checks succeed. Each worker
must remain active across a two-second settle window without an increase in
NRestarts; an immediate exit fails the deploy and retains its marker. This
is a process-liveness check, not proof of successful task processing. A worker-only
unit repair or leftover worker marker does not restart the web process.

`app.uv_env` supplies validated literal environment entries identically to
`uv sync --dry-run` and the actual sync (for example per-command Git HTTP/1.1).
It cannot override HOME or UV_PROJECT_ENVIRONMENT. `assert_python_version`
requires the controller source's `.python-version` to match `app.python`
before connecting. Both options default off/empty for existing sites.

`repair_cache_ownership` opt-in repairs recursively owned cache entries when
needed, without changing their modes. First-only `StepGroup`s can ensure an
application's default Site once; their completion marker remains outside the
source tree. Host-written worker launchers are excluded from source sync.

A `Secret(allow_empty=True)` is an explicit optional env reference: the
controller must still supply its value (including an empty default), and it
still rejects placeholders and unsafe env characters. Database/auth/admin
and the standard object-storage references cannot opt out of required values.
`EnvEntry(omit_empty=True)` omits that env line when resolved empty; the default
retains it. Optional/default resolution belongs in the private control plane;
this module adds no object-storage provider or lifecycle behavior.

## Optional Echoport backups

Set `DjangoSiteConfig.echoport` to an `EchoportTarget` (exported from
`ops_deploy.services.django_site`) or a mapping. The default is `None`:
no Echoport probe or operation runs. Echoport must already be deployed on the
same host at `/home/echoport/site`, using the `echoport` user. Registration
runs after the site's health checks, recording the source commit, and
clearing pending markers, so a registration failure does not repeat site steps
on retry. A matching target causes no write; a missing
Echoport installation fails registration.

For example, the mapping below can be included in an ops-control
`SiteSpec.config` once its pinned ops-deploy revision includes this feature:

```python
"echoport": {
    "name": "example-backup",
    "description": "Example site data",
    "db_path": "/home/example/site/db.sqlite3",
    "backup_files": (
        "/home/example/site/media",
        "/home/example/site/private",
    ),
    "schedule": "30 3 * * *",
    "update_schedule": False,
},
```

`name`, `description`, and the five-field numeric cron `schedule` are required;
`icon` defaults to `archive`. `db_path` is optional and uses SQLite's online
backup; `backup_files` defaults to an empty tuple and copies files or whole
directories as-is. Supply at least one path. PostgreSQL sites can use a
files-only target; this integration does not dump PostgreSQL databases.
Paths must be absolute under `/home/`, `/opt/`, `/var/lib/`, or
`/mnt/cryptdata/` (Echoport's default allowed prefixes), have unique basenames,
and must not overlap. Do not include SQLite sidecars or `manifest.json`.
Choose paths that source syncing already preserves; registering a target does
not change sync exclusions or create backups immediately.

`service_name` defaults to the site's resolved web unit plus `.service`;
`restore_owner` defaults to `user:group` using the site's resolved group.
Both can be overridden explicitly, for example `example-site.service` and
`example:webdata`. Echoport stops that one service during restore and chowns
restored paths to that owner; additional worker/frontend units need their own
restore coordination. Keep restore contents limited to data suitable for that
owner. `update_schedule=False` preserves an existing schedule edited in
Echoport; `True` resets it on each deploy. Removing this config stops managing
the target; it does not delete an existing Echoport target.

ops-control's builder accepts this nested mapping directly, and inventory
fields may use dotted destinations such as `echoport.name`,
`echoport.db_path`, `echoport.backup_files`, and `echoport.schedule` in
`SiteSpec.fields`.
