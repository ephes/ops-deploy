# haushalt

The family finance dashboard: daybook's `services/haushalt` (Django, SQLite,
gunicorn on loopback) behind a Traefik tailnet allowlist **and** the app's
own password login. Until 2026-11-18 it lived in its own repository with its
own pyinfra deploy, shaped after [opaq_app](opaq_app.md); this service takes
it over with the same host layout, so the first run on such a host moves no
path, port, user or database.

```python
from ops_deploy.services.haushalt import HaushaltConfig, RouteChecks, deploy_haushalt

cfg = HaushaltConfig(
    source_path=Path("~/projects/daybook").expanduser(),
    secrets=SecretRef("secrets/prod/haushalt.yml"),
    traefik_host="haushalt.example.com",
    allowed_networks=("100.64.0.0/10", "fd7a:115c:a1e0::/48"),
    route_checks=RouteChecks(controller_login=True),
)
deploy_haushalt(cfg, store.load(cfg.secrets))
```

ops-control registers it (see its `docs/PYINFRA.md`).

## Secrets

| Key | Used for |
|---|---|
| `django_secret_key` | environment file; 50 or more of `[A-Za-z0-9_-]` |
| `upload_token` | only its SHA-256 digest reaches the host (environment file); 32 or more characters |

Errors name keys, never values. The digest is treated as a secret as well.

## Configuration (`HaushaltConfig`)

| Field | Default | Notes |
|---|---|---|
| `source_path` | required | daybook checkout; needs `services/haushalt/web/manage.py`, `pyproject.toml`, `uv.lock` and `.python-version` in `services/haushalt` (its own uv project) |
| `rsync_excludes` | caches, `*.sqlite3`, `*.sqlite3-*`, `staticfiles`, `.env`, `.DS_Store` | never shipped, kept across `--delete` |
| `service_name`, `user` | `haushalt` | home is `/home/<user>`; `data/`, `static/`, `venv/`, `<service>.env` are in it |
| `site_path` | `/home/haushalt/site` | directly in the user's home |
| `app_port`, `workers` | `10067`, `2` | gunicorn on `127.0.0.1` |
| `python_version`, `dependency_group` | `3.14`, `web` | must equal the project's `.python-version`; `uv sync --frozen --only-group web --no-install-project` |
| `traefik_enabled` | `true` | needs `traefik_host` and a non-empty `allowed_networks` (CIDR ranges) |
| `traefik_entrypoint`, `traefik_http_entrypoint` | `web-secure`, `web` | |
| `route_checks` | none | as for opaq_app: `controller_login`, `refused_address`, `verify_tls` |

## What the deploy does

1. Checks the secrets and renders the environment file (fails before any operation).
2. Port preflight: fails if anything but `haushalt.service` listens on the
   app port at a loopback or wildcard address. Read-only, before any change.
   Then the database guard (root, read-only): the database must be a
   regular file, not a link, in rollback-journal mode (empty, or at least
   100 bytes with header bytes 18/19 equal to 1: Django's default and the
   app's; read without a pipe under `timeout 10`), and the
   file an unfinished migrate step of an earlier run recorded (below). On an
   installed host (its environment file exists) a missing database fails the
   deploy before any change, so a lost or half-restored database is never
   replaced by an empty one. Only a fresh host gets a new database: the
   service user creates the empty file exclusively (`noclobber`) right after
   step 3, before the environment file exists.
3. `system_user`: user (`nologin`), group, and `0700` home, `site`, `data`, `static`.
4. `sync_tree` of `services/haushalt/web/` into `site/web` (`--delete`, owned
   by the service user); copies of `services/haushalt/pyproject.toml`,
   `uv.lock` and `.python-version` into `site/` (`0600`); then the whole site
   tree owned by the user and `go-rwx` (only after a sync, or when something
   is exposed). The collector (`services/haushalt/src`) is never shipped.
5. `uv sync` of the locked `web` group into `venv/` when the project files
   changed, the venv is missing, runs another Python, or a read-only
   `uv sync --check` finds it out of sync. The host installs Django, gunicorn
   and whitenoise from PyPI and never needs the collector's private package.
6. The environment file through `secret_file` (`0600`).
7. The database handed back to the service user and `0600` when its owner
   or mode differ, before any management command (a database restored as
   root would make them fail): through file descriptors only, every
   directory and the file opened with `O_NOFOLLOW` (a FIFO cannot block), and
   only a regular file changed, so no link in the service user's home can
   redirect it.
8. `migrate` and `collectstatic --clear` in `site/web` as the service user
   (`umask 077`) when the code, dependencies or environment changed, the
   database or venv is new, or a rollout is pending (below). There is no
   migration probe: it would open the live database read-write (SQLite's
   journal recovery included) while planning, before the guard. After
   restoring a database older than a schema-changing deploy, run `migrate`
   by hand (below). Around the step, root records the database's device and
   inode in its state directory (`/var/lib/ops-deploy/<service>/database-identity`,
   resolved first and published atomically) and compares them afterwards. A
   mismatch (a restore moved the file while `migrate` ran, and SQLite may
   have created a new one) fails the run before the restart and keeps the
   record; the guard then refuses every later run until an operator has
   checked the database and removed the record. A step that died keeps the
   record too, and the next run's guard compares it. The migrate script
   itself refuses to start without the database file.
9. The unit (gunicorn with `--forwarder-headers=`), the Traefik route
   `/etc/traefik/dynamic/<service>.yml` with the shared edge-header deletion
   (written without restarting Traefik: the file provider watches), and the
   rollout: daemon-reload on a unit change (or for a pending rollout),
   restart on a change of code, dependencies, environment or unit.
10. Read-only checks: port, `/healthz` answering `ok`; with `route_checks`
    the login redirect and the 403 for the host's own address. Then the
    pending-rollout marker is removed.

**Pending rollouts.** Before the first change of a run (code, project
files, dependencies, environment or unit, a synced tree with an entry not
owned by the service user and group, or a non-link entry with any group or
other mode bit set, or a new database or venv) the marker
`/var/lib/ops-deploy/<service>/.ops-deploy-pending` is written (root's `0700`
directory, as django_site's, so the service user cannot plant a link a root
`touch` would follow); it is removed only after the restarted service has
passed every check. A run that died in between leaves it; the next run then
reloads systemd, runs `migrate` and `collectstatic` and restarts the service
even though its files already match. A failed check keeps it.

The database is under `data/`, outside the synced tree, so no sync can remove
it; the migration/collectstatic step never runs on a converged host.

After restoring an older database, apply its migrations by hand, once the
restore is complete and with the database handed back to the service user
(for a database restored as root, run `just deploy-one haushalt macmini`
first: its step 7 hands it back through descriptors, without following
links; do not `chown` it by hand).
The command stops unless the environment loads, the directory exists and
the database is a regular file when it starts. Nothing may move the
database while it runs (SQLite opens the path itself and would create a
new, empty file if it were gone), so run it only when no restore or other
maintenance is under way:

```bash
runuser -u haushalt -- env HOME=/home/haushalt bash -c 'set -euo pipefail; umask 077; set -a; . /home/haushalt/haushalt.env; set +a; if [ ! -f "$HAUSHALT_DATABASE_PATH" ] || [ -L "$HAUSHALT_DATABASE_PATH" ]; then echo "no regular database file" >&2; exit 1; fi; cd /home/haushalt/site/web; exec /home/haushalt/venv/bin/python manage.py migrate --noinput'
```

Not covered here: `sync_tree` (the code sync, with `--delete`), the
`files.put` uploads of the project files, `system_user`'s directories and the
recursive `chown`/`chmod` of the site write as root beneath the service
user's own home, as they do for every app service in this repository
(opaq_app, django_site, work_app, ...). No race is needed: a link the service
user plants in `site/` at any time before a deploy is followed by those
writes. Only an account already running code as the service user can do
that; the fix belongs to the shared helpers (a run-as-user mode for
`sync_tree`, a descriptor-walking installer for plain files like the one
`secret_file` already has), tracked as the work item
`ops-deploy-root-writes-in-service-homes`. The environment file is not
affected: `secret_file` walks from `/` with `O_NOFOLLOW`. The
database's Echoport backup target is not part of this deploy (ops-control
registers it on Echoport's generic runner).

## Taking over the old deploy

Against the files the old deploy wrote, the first run rewrites the
environment file, the unit and the route (header comments; the route's
`haushalt-edge-headers` middleware; `--forwarder-headers=`), runs `migrate`
(nothing to apply) and `collectstatic`, and restarts the service once. The
environment file's values are unchanged when the secrets are the old ones.
`tests/test_haushalt.py::test_host_of_the_old_deploy_is_taken_over_in_place`
keeps that so.

## Tests

- `tests/test_haushalt.py` (fake connector): first run, converged second run,
  takeover of the old deploy (against independent copies of its files,
  `tests/haushalt_legacy.py`), the missing-database guard, the fresh-host
  database, a root-owned restored database, the rollout marker (set before
  any change, finished by the next run, kept by a failed check), the
  database identity recorded before and checked after migrate (a mismatch
  stops the run before the restart), the guard's journal-mode check run by
  `sh` against real files (empty, rollback journal, WAL, short, truncated
  header) and its identity check, no probe opening the database while
  planning, the database hand-back run for real
  (regular file, link, linked directory, FIFO), code change, lockfile change, other Python,
  secret rotation, allowlist change (route only, no restart), exposed tree,
  exposed database, missing database, port in use, Traefik off, route checks,
  leak checks (no secret or digest in commands, op names, arguments or
  uploads; the environment file only on stdin), validation.
- `tests/test_haushalt_golden.py`: the host files against their goldens.

The preflight, health and route checks are shared with opaq_app
(`ops_deploy.services._login_app`).
