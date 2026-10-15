# weeknotes_home

Port of the `weeknotes_home_deploy` Ansible role (rsync method) and of the
operations wiring in ops-control's `deploy-weeknotes-home.yml`: the daybook
weeknotes.home steering inbox, a Django app served by gunicorn on PostgreSQL,
behind Traefik with basic auth, plus the playbook's FastDeploy service row,
Echoport backup target (with its FastDeploy service token) and Nyxmon checks.

```python
from ops_deploy.services.weeknotes_home import WeeknotesHomeConfig, deploy_weeknotes_home

cfg = WeeknotesHomeConfig(
    source_path=Path("~/projects/daybook").expanduser(),
    secrets=SecretRef("secrets/prod/weeknotes_home.yml"),
    traefik_host="weeknotes.home.example.com",
)
deploy_weeknotes_home(cfg, store.load(cfg.secrets))
```

ops-control registers it with secrets from three SOPS files (see its
`docs/PYINFRA.md`).

## Secrets

| Key | Required | Used for |
|---|---|---|
| `django_secret_key` | yes | env file (`DJANGO_SECRET_KEY`); more than 20 characters |
| `postgres_password` | yes | database role (as a SCRAM verifier) and `DATABASE_URL`; ASCII |
| `api_token` | yes | env file (`WEEKNOTES_HOME_API_TOKEN`); 32 to 256 characters of `A-Za-z0-9._~-` |
| `basic_auth_password` | yes | Traefik route (bcrypt hash only); printable ASCII |
| `basic_auth_user` | no | Traefik user; falls back to `basic_auth_user` in the config |
| `fastdeploy_token_user` | with `operations_wiring` | FastDeploy user the Echoport token is issued for |

Values must be single lines; `CHANGEME` is refused. Errors name keys, never
values. The FastDeploy user name counts as secret too: it reaches the host
only on stdin.

## Configuration (`WeeknotesHomeConfig`)

Defaults follow the role's `defaults/main.yml`.

| Field | Default | Notes |
|---|---|---|
| `source_path` | required | daybook checkout (`pyproject.toml`, `uv.lock`, `services/weeknotes_home/manage.py`, `src/daybook/cli.py`); synced as the site root |
| `service_name`, `user`, `group` | `weeknotes-home` | login shell `/bin/bash`, as the role |
| `home`, `site_path` | `/home/weeknotes-home`, `.../site` | the service lives in `site/services/weeknotes_home`, the venv in `site/.venv-weeknotes-home`, the env file is `site/.env.weeknotes-home`, cache and static in `site/cache/weeknotes-home` and `site/static/weeknotes-home` |
| `python_version` | `3.14` | `uv sync --python` |
| `app_host`, `app_port`, `workers`, `timeout` | `127.0.0.1`, `10062`, `2`, `120` | gunicorn, `wsgi_module` `weeknotes_home.wsgi:application` |
| `django_settings_module`, `django_debug`, `db_conn_max_age`, `cast_base_url` | role defaults | env file |
| `django_allowed_hosts`, `django_csrf_trusted_origins` | `127.0.0.1, localhost` / none | |
| `postgres_database`, `postgres_user` | `weeknotes_home` | `postgres_host` is `localhost` or `127.0.0.1` (the deploy manages the local cluster) |
| `run_migrations`, `collectstatic` | `true` | |
| `traefik_host`, `traefik_entrypoints`, `traefik_cert_resolver`, `traefik_middlewares`, `basic_auth_user` | role defaults | |
| `internal_ip_ranges` | the approved private and Tailnet ranges | clients that skip basic auth; must be canonical CIDRs inside those ranges (the role's `validate_auth.yml`) |
| `health_retries`, `health_delay` | `20`, `3` | `/healthz` check, as the role's |
| `operations_wiring` | `false` | the playbook's post tasks, see below |
| `fastdeploy_site_root`, `echoport_*`, `fastdeploy_token_*`, `nyxmon_*`, `backup_window_*` | the playbook's values | Echoport target and FastDeploy service names and schedule, token lifetime (at most 90 days) and rotate window, Nyxmon service name and interval, backup-window policy of the freshness check |

## What the deploy does

1. Checks the secrets and renders the env file (fails before any operation).
2. Port preflight (read-only): nothing but `weeknotes-home.service` may listen
   on `app_port` at a loopback or wildcard address, as the playbook's
   `preflight_ports` (`bind: loopback`). It cannot be skipped.
3. PostgreSQL service running, login role (SCRAM verifier computed on the
   controller; the password never reaches the host) and database owned by it.
   The server itself stays with the PostgreSQL deploy.
4. `system_user`, `home`, `site`.
5. `sync_tree` of the checkout to `site/` with the role's excludes (`.git`,
   `.venv`, `.envrc`, `.cache`, `/cache`, `/static`, `/site`, the env file,
   the venv, caches), owned by the service user, plus
   `/src/daybook.egg-info` (see below).
6. Cache and static directories.
7. `uv sync --frozen --group weeknotes-home --python 3.14` if the source
   changed or the venv is missing.
8. The env file through `secret_file`, `0600`, and the env loader
   `files/env_exec.py` as `/home/weeknotes-home/env-exec.py` (`root:root`,
   `0644`). Every `manage.py` call runs
   `python -I env-exec.py <env file> manage.py ...`: it reads the env file
   (undoing the template's escapes) and replaces itself by `manage.py`, so no
   secret is on a command line. It is a file, not `python -c <source>`,
   because its regex needs backslash pairs, which root's fish login shell
   would halve on the way (the first live deploy failed on exactly that).
9. `migrate --noinput` if the source, dependencies or env file changed or a
   read-only `migrate --check --plan` finds unapplied migrations (so a failed
   run is retried); `collectstatic --noinput` likewise, with `collectstatic
   --dry-run` (read-only). Both probes are strict
   ([strict probes](../concepts/helpers.md#strict-probes-ops_deployhelpersprobes)):
   before the venv, `manage.py`, env file and loader exist they answer
   "pending"; an error is not read as "pending" but runs the step and then
   the probe again ("Probe again: ..."), which fails the deploy if it still
   fails.
   On a host deployed by Ansible (no loader yet) the first run therefore runs
   both once and restarts the service once; Ansible leaves the loader alone.
10. Unit file and `service_rollout`: restart on code, dependency or env
    change, and when migrations run (a retry after a failed run must not leave old code on the new schema; the role restarts on neither).
11. Traefik route with the role's own template (dual router, the HTTP router
    with its redirect, `X-Forwarded-Host`), restart Traefik on change.
12. Read-only `/healthz` check (200).
13. Wiring, with `operations_wiring` (the playbook's post tasks):
    - Read-only guards: Echoport (`/home/echoport/site/manage.py`), the
      FastDeploy service config (`.../services/weeknotes-home-backup/config.json`;
      "run just register-weeknotes-home-backup") and Nyxmon's database must
      exist, else the run fails.
    - FastDeploy `service` row: the row of the backup service mirrors its
      `config.json`; written (through `psql` on stdin) only when it differs.
    - FastDeploy token and Echoport target in one remote script: a read-only
      "check" run in the Echoport shell decides whether anything is to do (the
      target's fields, or a token that is missing, undecodable, scoped to
      another service, a legacy token without `jti` or within the rotate
      window, or `fastdeploy_token_force_rotate`). If so, an apply pass
      stores the target; when it needs a token, `issueservicetoken` runs
      (FastDeploy's CLI is called in-process, the user name read from stdin, so it is in no process's arguments) and the token goes through a pipe into the
      second apply pass. It never reaches the controller, a file or a command
      line; the script's stderr is dropped. A target named
      `weeknotes-home` (legacy) is renamed.
    - Nyxmon checks ("local health" and "backup freshness") by direct SQLite
      upsert as the `nyxmon` user, after a read-only check pass, same SQL as
      the playbook.
    - The service-row query and both check passes are strict probes: an
      error applies and probes again instead of passing as "differs".

## Parity with the role and playbook

`tests/test_weeknotes_home_parity.py` renders the vendored role templates
(`tests/parity/ansible/weeknotes_home_deploy__*`) the way Ansible does and
requires **byte-identical** env file, unit and Traefik route (which is why the
route says "Managed by Ansible" and `removeHeader: True`; the vendored
templates are compared with ops-library by `test_traefik_parity`). The
`DATABASE_URL` expression of the role defaults is evaluated by Jinja and
compared too. With the route hash reused, Ansible and ops-deploy take turns
on a host without rewriting files or restarting weeknotes-home or Traefik.

Differences:

- `src/daybook.egg-info` is excluded from the sync. `uv sync` builds the
  project and leaves it; the role's `--delete` removes it, so every Ansible
  run reports a sync change, reruns `uv sync` and restarts the service. Here
  nothing changes on a converged host. (A matching exclude in the role would
  stop that; the role is frozen.)
- The role runs migrations and `collectstatic` on every deploy; here they run
  when needed (see 9), so a converged deploy changes nothing.
- The playbook's upserts always report a change; here they run only when
  something differs.
- `uv sync` uses `--frozen` as the role does, but only when needed.
- `apache2-utils` is not installed (the bcrypt hash is computed on the
  controller); the role's `uv_install` and `postgres_install` dependencies
  are not run (uv must be at `/usr/local/bin/uv`, see `deploy_uv_install`;
  PostgreSQL must be installed, see `deploy_postgres_install`).
- Not ported (the playbook uses none of them): the `git` deploy method,
  `traefik_enabled`, `basic_auth_enabled`, a precomputed password hash,
  `service_restart_on_change`. The backup and restore playbooks
  (`wagtail_backup`) stay on Ansible.

## Tests

- `tests/test_weeknotes_home.py` (fake connector): first run, converged second
  run (no mutating change), code change, env rotation, PostgreSQL password
  rotation, basic-auth rotation, pending migrations and collectstatic,
  wiring drift and opt-out, token issue through a pipe, missing dependencies,
  port collision, shell syntax of the generated scripts, leak checks (no
  secret in commands, op names/args or uploads), validation, failing probes
  (the step runs, then "Probe again").
- `tests/test_remote_shell_execution.py`: the `manage.py` command, sent as
  pyinfra sends it through bash and through fish, starts `manage.py` with an
  env value full of quotes, backslash pairs, `$` and backticks intact.
- `tests/smoke/test_weeknotes_home_smoke.py` (`just smoke`, needs
  `DAYBOOK_SOURCE` or `PROJECTS_ROOT`; resets weeknotes-home on a lima VM):
  the port preflight refuses another listener, then real deploys of the
  committed `HEAD`: second and fresh-export runs have no mutating change, a
  code change runs migrations and `collectstatic` and restarts once, and a
  row in the database and files in cache and static survive; root's login
  shell is fish and `manage.py`, run as pyinfra sends it, sees a secret key
  with quotes and backslash pairs exactly. The service is healthy, the env file private, the database
  owned by the role, the Traefik route requires basic auth. The wiring runs
  against stand-ins for Echoport, FastDeploy and Nyxmon (their real
  interfaces: `manage.py shell -c`, `commands.py issueservicetoken`, the
  SQLite database, the `service` table): applied once and settled, an
  unusable token is replaced and a legacy target adopted, no secret on disk.
- Ansible coexistence (deploys taking turns, data kept) runs from
  ops-control: `just smoke-weeknotes-home-coexistence`.
