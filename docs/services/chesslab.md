# chesslab

Port of the `chesslab_deploy` Ansible role (rsync method) and of the
operations wiring in ops-control's former deployment playbook: the Chesslab
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
| `trusted_proxy_hops` | `0` (not rendered) | `1` renders `CHESSLAB_TRUSTED_PROXY_HOPS="1"` into `.env`: the app then takes the client address for its login address window from Traefik's right-most `X-Forwarded-For` entry when the peer is loopback. Opt in only where Traefik is the only path in, trusts no incoming forwarded headers and drops header-name aliases (`aliasHeadersStrategy = "delete"`, see `docs/traefik.md`); the per-host opt-in belongs in ops-control's `chesslab_config` (`pyinfra_support/services.py`), and until a host has it, its clients share one loopback address window |
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
3. `trusted_home_check`, `system_user` (`/usr/sbin/nologin`) and
   `user_directories`
   ([service homes](../concepts/helpers.md#service-homes-ops_deployservices_service_home)):
   a read-only check that only root can replace a directory on the way to the
   home, then the home by root and `site` and `data` by the service user
   itself. A `site` or `data` that is a symlink or belongs to someone else
   fails the deploy; root does not repair it by path.
4. Database check (read-only): `db_path` must exist and be read/writable by
   the service user. The deploy never creates the database; without it, it
   stops before the site changes.
5. `sync_tree_as_user` of the checkout to `site/` with the role's excludes
   (`.git`, `.venv`, caches, `.env`, `chess.db`, `*.db`, `*.db-*`): the remote
   rsync runs as the service user (no `--chown`), so the files are the
   service's because it creates them.
6. Runtime packages (`python3`, `python3-venv`, `sqlite3`, `rsync`).
7. `uv sync --frozen --no-dev --python 3.14` if the source changed or the venv
   is missing.
   Before any operation, a `uv.lock` in the source that locks certifi or pip
   below the [security floors](../concepts/helpers.md#certifipip-security-floors-ops_deployhelperspython_security)
   fails the deploy; after this step `verify_trust` checks the venv read-only
   on every run, also when nothing was synced.
8. `.env` through `secret_file`, `0600`.
9. `python -m django migrate` if the source or dependencies changed or a
   read-only `migrate --check` (debug key, no secret) finds unapplied
   migrations, so a failed run is retried. The check opens the database
   through the SQLite URI `file:<db>?mode=ro` and without writing bytecode: a
   normal connection can checkpoint the log or roll back a hot journal just by
   reading. A migration restarts chesslab. The Django environment goes over
   stdin, never on a command line.
10. `ensure_admin` for each user, called in-process by the venv's Python
    (password, user name and owner over stdin, never in a process's arguments), only when a user or its trainer profile is missing or
    differs in the database (a read-only SQLite query as the service user,
    `sqlite3 -readonly -init /dev/null`, compared as digests) or
    the `users` secret changed since the last run. The last ensured set is
    recorded as an HMAC (keyed with the Django secret) in
    `/home/chesslab/.ops-deploy-users` (`0600 root`). Root reads it back
    without following a link or blocking, and only accepts a small regular
    file of its own with mode `0600`; anything else counts as no stamp.
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
    - Fails when the app is not installed on the host, as the former playbook did.

Every command in the site, and every wiring command in a neighbour's site,
has the form `cd / && runuser -u <user> -- env ... sh -c 'cd "$1" && shift && exec "$@"' sh <dir> ...`:
the service user enters the directory, not root.

A probe that *fails* (the migration check, the user query, a wiring check)
stops the deploy while it plans, before any operation. While the service
account does not exist yet (a first deploy, also with a database that was
provisioned beforehand), the two probes of chesslab's own database are not run
at all and answer "no users" and "pending": nobody can run as that user yet. "Pending" is an answer;
a crash is not, and it must not schedule the migration, the user update or the
upsert it gates.

## Root writes in the service's home

chesslab is the pilot of
[root writes in service homes](../plans/root-writes-in-service-homes.md): the
sync, the directories below the home and all commands and probes run as the
service user. Still written by root into the service's directories, through
`secret_file`: `.env` and the users stamp (step 3 of that plan moves them).

### `verify_only`

`verify_only=True` is stage A of the pilot's rollout. The deploy then queues
only read-only operations:

| Operation | What it checks |
|---|---|
| Check the path to /home/chesslab | every ancestor is a real root-owned directory closed to group and others; the home is a real directory of the service user |
| Audit ownership below the chesslab home | nothing in `site` or `data` has another owner or group, and no directory is setgid |
| Show the identity of chesslab | `runuser -u chesslab -- id`, the credentials every command gets |
| Check chesslab database | as in a normal deploy |

and decides while planning, with the predicates a normal deploy uses, that
nothing is pending: `site` and `data` are the service's own directories with
mode `0755` (a symlink or a foreign owner stops the run as it stops a deploy),
the sync's dry run (as the service user) itemizes no change, the venv has an
interpreter, the migrations are current, the users and their stamp match the
secrets. The dry run is asked directly, not through the sync operation: no
operation of such a run can transfer anything, whatever changes on the host
while it executes. Anything pending, or a failing probe, stops the
run with `verify_only: chesslab is not converged: ...` before any operation.
No account, directory, package, dependency, `.env`, migration, unit, route,
wiring or stamp step exists in such a run, and the neighbours are not asked.

### What a converged run reports

pyinfra counts every shell command as "changed". On a converged host these
read-only operations run and nothing else: the port preflight, the path
check, the database check, the certifi/pip trust check and the `/healthz`
check. Listed as conditional (decided while executing, "No changes" when the
condition is false): the dependency sync, the migrations, the daemon reload
and the restarts of chesslab and Traefik.

## Parity with the role and playbook

The unit is **byte-identical** to the retired role's output, and the Traefik
route was too (which is why it still says "Managed by Ansible"), so hosts the
role set up were taken over without rewriting files or restarting chesslab or
Traefik. Since then two renders differ from the role on purpose: the route's
headers middleware deletes client-sent identity, address and path-prefix
headers (`fa7fcc52`, `_edge.j2`; the first deploy after it rewrites the route
and restarts Traefik), and `.env` gains `CHESSLAB_TRUSTED_PROXY_HOPS` when
`trusted_proxy_hops` is `1` (rewrites `.env` and restarts chesslab once).
`tests/test_chesslab_golden.py` pins the renders: it compares them with the
goldens in `tests/golden/chesslab`, recorded from the role and updated only for
the route difference above (the golden cases keep `trusted_proxy_hops` at `0`).

Differences:

- The role's `ensure_admin`, migrations and the playbook's upserts ran on
  every deploy. The upserts always reported a change. Here they run
  only when needed, so a converged deploy changes nothing. The former role reset passwords changed by hand in Django on every deploy.
  Pyinfra resets them only when the `users` secret changes or a user is missing.
- `uv sync` uses `--frozen` (the role ran plain `uv sync --no-dev`, which may
  rewrite `uv.lock` on the host).
- `apache2-utils` is not installed (the bcrypt hash is computed on the
  controller); the playbook's `uv_install` role is not run (uv must be at
  `/usr/local/bin/uv`, see `deploy_uv_install`); the playbook's warn-only
  clock check is not ported.
- Not ported (production uses none of them): switching off Traefik or basic
  auth, other deploy methods.

## Backup (`ChesslabBackupConfig`)

`deploy_chesslab_backup(ChesslabBackupConfig(prefix=...))` is the port of
the former `playbooks/chesslab/backup.yml` (removed 2026-11-16). It refuses with the
play's message ("echoport-backup must be registered before Chesslab backups
can run.") unless `/usr/local/libexec/fastdeploy/echoport-backup/backup.py`
exists, then runs the play's shell task unchanged: a private `mktemp
/tmp/chesslab-backup-XXXXXX.json` (removed by an `EXIT` trap) with the target's
Echoport environment (`ECHOPORT_DB_PATH=/home/chesslab/data/chess.db`, `ECHOPORT_SERVICE_NAME=chesslab.service`, `ECHOPORT_RESTORE_OWNER=chesslab:chesslab`),
handed to the runner with `--config`. The runner uploads the backup to the
object store; nothing is kept on the host or fetched. The run id is
`<prefix>-<UTC %Y-%m-%dT%H-%M-%S>`, the key prefix `<target>/<run id>`. Shared with the Chesslab and Archive
backups: `ops_deploy.services._lifecycle.echoport_runner`
(`tests/test_echoport_runner_backup.py` runs the script through bash).

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
