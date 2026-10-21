# homelab

Port of the `homelab_deploy` Ansible role (with the `homelab_shared` defaults
it reads) as a playbook runs it with the rsync method: the home dashboard, a
Django app on one SQLite database served by gunicorn (`uv run gunicorn`),
behind Traefik with basic auth outside the internal networks. Deploy only:
backup, restore and remove stay with the Ansible roles.

```python
from ops_deploy.services.homelab import HomelabConfig, deploy_homelab

cfg = HomelabConfig(
    source_path=Path("~/projects/homelab").expanduser(),
    secrets=SecretRef("secrets/prod/homelab.yml"),
    traefik_host="home.example.com",
    django_allowed_hosts="127.0.0.1,home.example.com",
)
deploy_homelab(cfg, store.load(cfg.secrets))
```

ops-control registers it with secrets from two SOPS files (see its
`docs/PYINFRA.md`).

## Secrets

| Key | Required | Used for |
|---|---|---|
| `django_secret_key` | yes | `.env` (`DJANGO_SECRET_KEY`) |
| `basic_auth_password` | yes | Traefik route (bcrypt hash only) |
| `basic_auth_user` | no | Traefik user; falls back to `basic_auth_user` in the config |

Empty values and `CHANGEME` are refused, as the role asserts; values must be
single lines. The role writes `.env` unquoted, systemd reads it and the
role's `manage.py` steps source it with bash, so `django_secret_key` must also
be printable ASCII without whitespace, quotes, backslashes or
`` $ ` ; & | < > ( ) ~ `` (a value both read the same way). Errors name keys,
never values. `.env` reaches the host only on stdin.

## Configuration (`HomelabConfig`)

Defaults follow `homelab_shared/defaults/main.yml`
(`tests/test_homelab_parity.py` compares them with the role when
`OPS_LIBRARY_PATH` is set).

| Field | Default | Notes |
|---|---|---|
| `source_path` | required | a homelab checkout with `src/`, `manage.py`, `pyproject.toml`, `uv.lock` (the role's checks); `media/` is synced when present |
| `service_name`, `user`, `group` | `homelab` | `service_name` must equal `user` (the role names the unit after one and starts the other); login shell `/bin/bash` |
| `home`, `site_path` | `/home/homelab`, `.../site` | `.venv`, `.env`, `db.sqlite3`, `staticfiles`, `media`, `cache` below the site |
| `media_subdirs` | `services`, `services/logos` | created below `media` |
| `app_host`, `app_port`, `workers` | `127.0.0.1`, `10010`, `4` | gunicorn |
| `django_settings_module`, `django_admin_url`, `django_debug` | `config.settings.production`, `admin/`, `false` | `.env` |
| `django_allowed_hosts` | `127.0.0.1` | one comma-separated string, as the role's variable |
| `uv_path`, `python_version` | `/usr/local/bin/uv`, `3.14` | the venv's interpreter version |
| `uv` | `None` | a [`UvInstallConfig`](../base.md#uv_install): run the role's `uv_install` first; its `install_dir` must be `uv_path`'s directory |
| `traefik_host`, `traefik_cert_resolver`, `basic_auth_user` | role defaults | |
| `internal_ip_ranges` | the role's list | clients that skip basic auth |

Not ported, as the playbook uses none of them: `homelab_use_uv: false` (the
role refuses it too), `homelab_service_restart_on_change`,
`homelab_traefik_enabled` and `homelab_basic_auth_enabled` (always on), and
another `homelab_traefik_config_path` (always
`/etc/traefik/dynamic/<service_name>.yml`).

## What the deploy does

1. Checks the secrets and renders `.env` and the route inputs (fails before
   any operation).
2. `system_user` (`/bin/bash`; an existing user is not modified); `home`,
   `site`, `staticfiles`, `cache` and the media subdirectories `0755`.
3. `sync_tree` of `src/` into `site/src` **without `--delete`** and with the
   role's excludes (`__pycache__`, `*.pyc`, `.pytest_cache`, `.coverage`,
   `htmlcov`, `.mypy_cache`), owned by the service user; `manage.py` (`0755`),
   `pyproject.toml` and `uv.lock` (`0644`) copied. With a `media/` directory
   in the checkout it is synced into `site/media` the same way (no
   `--delete`, `.gitkeep` excluded; no restart).
4. The role's recursive owner fix of the site, when a read-only `find` finds
   a path not owned by the service user (or a directory was created this run).
5. `uv_install` when `uv` is set; then a read-only check that `uv_path` is an
   executable (fails before anything Python-related otherwise).
6. The venv: if `.venv/bin/python --version` fails or reports another
   `python_version`, `.venv` is removed; a missing venv is created with
   `uv venv --python <version> .venv`. The `venv -> .venv` link is created
   when nothing is at `venv` (an existing one is left alone).
7. `uv sync --frozen` (with `VIRTUAL_ENV=.venv`, as the role) if the venv was
   created, the source or the copied files changed, or a read-only
   `uv sync --frozen --check` finds the venv out of step with `uv.lock`.
8. `.env` through `secret_file`, `0600`, owned by the service user.
9. `manage.py migrate --noinput` (the role's `. .env` in bash) if the code,
   copied files, venv, dependencies or `.env` changed, or a read-only
   `migrate --check --plan` finds unapplied migrations. The check runs only
   when `db.sqlite3`, `.env` and the venv exist.
10. `db.sqlite3` to `homelab:homelab 0644`, the role's mode (not tightened),
    when a read-only `stat` shows otherwise or the database appeared this run.
11. `manage.py collectstatic --noinput` after the same changes as migrate, or
    when a read-only `collectstatic --dry-run` would copy files.
12. `manage.py add_default_services` after a code change, or when the
    read-only probe `files/default_services_check.py` says it would write.
    The probe runs the command itself through `manage.py shell -c`, with every
    SQL `INSERT`/`UPDATE`/`DELETE`/`REPLACE`/`CREATE`/`DROP`/`ALTER` and every
    file-storage save or delete refused before it happens, inside a
    transaction that is rolled back: "pending" when the command tried to
    write (a missing default service or logo), "current" otherwise.
13. Unit file and `service_rollout`: restart on a code, copied file, venv,
    dependency, `.env`, unit or migration change.
14. Traefik route with the role's own template (dual router, the HTTP router
    on `web`). The deployed bcrypt hash is kept while it matches the password,
    as the role does since ops-library 2.49.1; Traefik is not restarted (its file provider watches the directory, and the
    role has no handler either).

A probe that fails (rather than answering) does not stop planning: its step
runs, and the probe then runs again as a read-only operation that fails the
deploy if it still fails. The probes that run Python as the service user
(`.venv/bin/python --version`, `uv sync --check`, `migrate --check --plan`,
`collectstatic --dry-run` and the default-services probe, in planning and
when probed again) run with `PYTHONDONTWRITEBYTECODE=1`; see
[Ownership and the service user's group](#ownership-and-the-service-users-group). A run that failed after the source sync but before
the restart leaves the old code running: the next run finds the sync current
and does not restart (as chesslab); restart `homelab` by hand then.

## Ownership and the service user's group

The role creates the user with `group` as primary group, but an existing user
only gets `group` appended. A user from before (on one host the primary group
is `users`) writes every new file with its primary group: the venv and
packages from `uv venv`/`uv sync`, bytecode caches (`__pycache__/*.pyc` in
`src` and in the venv) from any Python run, the files `collectstatic` and
`add_default_services` write. The unit runs the service with
`Group=<group>`, so the service itself writes files with `group`.

Planning runs the ownership `find` (step 4) before the probes. A probe that
writes bytecode would leave a file with the wrong group after the run, and
the next run's `find` would plan the `chown` again: a converged host would not
stay converged. So the planning probes run with
`PYTHONDONTWRITEBYTECODE=1`. Only probes get it; the steps that change the host, the unit and `.env` are as in
the role.

Order of the steps that run: as in the role, the owner fix comes before
`uv venv`, `uv sync`, `migrate`, `collectstatic`, `add_default_services` and
the restart. When a run executes one of them (a code, dependency, `.env` or
venv change), files they create may carry the user's primary group until the
next run fixes them, which is then that run's only change (the role leaves
the same files and fixes them on its next run too). A run that only fixes
ownership, the database mode or the route executes no Python as the service
user, so the run after it plans no mutating operation. Making the primary
group `group` (as the `django_site` port does) is not part of this port.

## Parity with the role and playbook

`tests/test_homelab_parity.py` renders the vendored role templates
(`tests/parity/ansible/homelab_deploy__*`, last checked against ops-library
main `540ede2b`, 2.56.0) the way Ansible does and requires **byte-identical**
`.env`, unit and Traefik route; the templates the deploy ships are the same
files. `tests/parity/ops_library_roles.json` records `homelab_deploy`,
`homelab_shared` and `uv_install`.

Differences:

- The role runs `uv sync`, migrations, `collectstatic`,
  `add_default_services` and the recursive `chown` on every deploy; here they
  run only when needed, so a converged deploy changes nothing.
- A migration run also restarts homelab (a retry after a failed run must not
  leave old code on a new schema); the role restarts only on code, file,
  venv, dependency, `.env` and unit changes.
- `add_default_services` is judged by its effect (any write attempt) rather
  than by its output; the role reports a change only for "Created service" or
  "Updated service", not for a logo it filled in.
- Ansible's `synchronize` compares file times, ops-deploy file contents (no
  times are synced). The first Ansible run after an ops-deploy run may
  rewrite source files once and restart homelab; later runs are quiet.
- The bcrypt hash is computed on the controller; the role's
  `apache2-utils` package (`htpasswd`) is not installed.
- `uv_install` runs only when `uv` is set. The role pins uv (0.13.4 today)
  and replaces any other version on every run; with `uv` unset the deploy
  uses the uv it finds at `uv_path` and refuses before any Python step when
  there is none (as the graphyard port).
- A new user is a system user (`useradd -r`); an existing one is untouched.
- The read-only probes run Python with `PYTHONDONTWRITEBYTECODE=1`. The
  role has no such probes: it runs `migrate`, `collectstatic` and
  `add_default_services` on every deploy, after its owner fix, so its runs
  leave new bytecode caches with the user's primary group behind.
