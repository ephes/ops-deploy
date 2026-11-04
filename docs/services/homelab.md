# homelab

Port of the `homelab_deploy` Ansible role (with the `homelab_shared` defaults
it reads) as a playbook runs it with the rsync method: the home dashboard, a
Django app on one SQLite database served by gunicorn (`uv run gunicorn`),
behind Traefik with basic auth outside the internal networks. Backup,
restore ([below](#backup-and-restore)) and removal ([Removal](#removal)) are
ported too.

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
- `uv_install` runs only when `uv` is set. The role pins uv (0.13.5 today)
  and replaces any other version on every run; with `uv` unset the deploy
  uses the uv it finds at `uv_path` and refuses before any Python step when
  there is none (as the graphyard port).
- A new user is a system user (`useradd -r`); an existing one is untouched.
- The read-only probes run Python with `PYTHONDONTWRITEBYTECODE=1`. The
  role has no such probes: it runs `migrate`, `collectstatic` and
  `add_default_services` on every deploy, after its owner fix, so its runs
  leave new bytecode caches with the user's primary group behind.

## Removal

`remove_homelab(HomelabRemoveConfig(confirm=True))` ports the
`homelab_remove` role at ops-library `44a532ba` (the role files and
`homelab_shared`'s defaults are recorded under
`tests/parity/homelab/remove`). The defaults are the role's and destructive:
`remove_user`, `remove_home`, `remove_database`, `remove_media` and
`remove_traefik_config` are all `True`; the paths are `homelab_shared`'s
(`/home/homelab`, `/home/homelab/site/db.sqlite3`, `/home/homelab/site/media`,
`/etc/systemd/system/homelab.service`, `/etc/traefik/dynamic/homelab.yml`).

Before any host probe it refuses without `confirm`, and it refuses keeping the
database or media (`remove_database=False` / `remove_media=False`) while the
home or the user goes, because both live inside the home directory, as the
role does. A root account, `/`, a top-level directory or a traversal as a path
is refused.

In the role's order:

1. when the database or the media directory exists and goes, the role's
   pause: this port asks on the controller's terminal (type `yes`) before the
   first change and refuses without a terminal unless `auto_confirm=True`
   (the role's `homelab_remove_auto_confirm`). This is stricter than the
   role: Ansible's `pause` goes on without waiting when stdin is not a
   terminal;
2. only when the unit file exists (a dangling link counts, as for `stat`):
   stop, then disable the unit (failures ignored, as `failed_when: false`),
   remove the unit file and reload systemd;
3. remove the Traefik route (behind the Traefik transaction guard);
4. remove the database with `-wal` and `-shm`, the media directory, the home
   directory (only when it exists and the user stays) and the account
   (`userdel`, with `-r` when the home goes; a failure stops the removal).

The role's plan, warning and summary messages are not printed; the role's
informational re-check of the route is not run. No secrets are read; Echoport
archives stay.

## Backup and restore

`ops_deploy.services.homelab` also ports `homelab_backup` and
`homelab_restore` (with the `homelab_shared` defaults). Neither needs
secrets. Archives written by either tool restore with the other.

| Function | Config | Role |
|---|---|---|
| `deploy_homelab_backup` | `HomelabBackupConfig(host_name=...)` | `homelab_backup` |
| `deploy_homelab_restore` | `HomelabRestoreConfig(host_name=...)` | `homelab_restore` |

The fields are the roles' variables without the `homelab_`,
`homelab_backup_` or `homelab_restore_` prefix (in the backup config `owner`
and `group` are the archive's, `homelab_backup_owner`/`_group`;
`homelab_restore_root` is `search_root` and
`homelab_restore_metadata_required_fields` is `required_fields`) (`site_path`, `root`,
`include_*`, `force_stop`, `archive`, `dry_run`, `create_safe_snapshot`,
`safe_snapshot_delete`, `healthcheck_url`, ...). `host_name` is the
inventory name written into `metadata.yml`; `ops_library_version` is the
controller's ops-library version, written by the backup and compared by the
restore (a mismatch stops it unless `allow_version_mismatch`), as the roles
read it from `galaxy.yml`. Pass the same value as the roles' `galaxy.yml`
for archives of the other tool to restore without
`allow_version_mismatch`. `required_mount` and `retain_count`/`retain_days`
work as for the other ports ([Local backups](../concepts/local-backups.md)).

**Backup.** It refuses to start without the site directory. It records the
site's git commit (`unknown` without a repository), then one host script
creates `/opt/backups/homelab/<prefix>-<timestamp>/` with `database`,
`static`, `media`, `cache`, `configs` and `env` (`root:root 0700`),
restricts older archives in the root to `0600`, and copies the database with
`sqlite3 .backup` (4 attempts, 2 s apart). When every attempt fails, or with
`force_stop`, it stops `homelab`, copies the file and starts `homelab` again
whatever the copy did. It then copies static and media (cache only with
`include_cache`) with `rsync -a --delete`, `.env`, the unit and the Traefik
route (`0600`), writes the role's `metadata.yml` (`sqlite_mode` `hot`,
`offline` or `missing`) and `manifest.sha256`, packs `<dir>.tar.gz`
(`0600`) and fetches it into `~/backups/homelab` (`0700`, the copy `0600`).

**Restore.** One host script, in the role's order:

1. Reset the staging directory, pick `latest` (the newest `*.tar.gz` by
   mtime directly in the search root) or a name below it, unpack it, check
   `slug: homelab`, the required fields (`slug`, `timestamp`, `host`), the
   ops-library version and `manifest.sha256`, and print the plan.
2. With `dry_run`, stop here.
3. When the archived route differs from the live one and a Traefik
   transaction holds its lock, stop here too (nothing changed yet). A lock
   taken later, during the copy, leaves the route as it is; the restore
   finishes, starts `homelab` and then fails, keeping the pre-restore copy.
4. Stop `homelab` (a failure stops the restore), copy the site to
   `<site>.pre-restore-<timestamp>`, put back static, media and cache
   (`rsync -a --delete`), the database (stale `-wal`/`-shm`/`-journal`
   removed first), `.env`, the unit and the route, fix ownership, reload systemd and
   Traefik when their files changed, run `manage.py check --deploy` and
   `showmigrations` as `homelab`, check the database's integrity, restart
   `homelab` and probe the health URL (6 tries, 3 s apart).

The staging directory always goes; it must not contain the search root, the
site or any restored path, nor lie inside the site or a restored path. As in
the role, an archived directory that is empty (the cache by default, static or
media when not included) empties the live one (`rsync --delete`); the
pre-restore copy still has it. As with the role, a failed restore does not roll
back: the pre-restore copy stays and is reported; it is removed only after a
successful restore with `safe_snapshot_delete`. `archive` is a name below the
search root, never an absolute path, and `static`, `media` and `cache` get
their modes back after the copy (`rsync -a` would leave the archived
directory's mode, `0700` for one that was empty at backup time; that pass also
gives the three directories back to `homelab`). The systemd and Traefik
reloads follow content changes only. `sqlite3`, the controller directory's
`0700` and the `*.tar.gz` pattern of `latest` are fixed, not configurable.

Tests: `tests/test_homelab_backup_restore.py` (planned settings, and both
scripts end to end in a temporary tree with stubbed `systemctl`, `runuser`
and `curl`).

