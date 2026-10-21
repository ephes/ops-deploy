# fastdeploy

Port of the `fastdeploy_deploy` Ansible role (rsync method only): the
FastDeploy API (uvicorn) with its Vue frontend, on PostgreSQL, behind Traefik
with basic auth. FastDeploy keeps deploying *other* services with Ansible;
this only replaces the deploy of FastDeploy itself from a local checkout.

```python
from ops_deploy.services.fastdeploy import FastdeployConfig, deploy_fastdeploy

cfg = FastdeployConfig(
    source_path=Path("~/projects/fastdeploy").expanduser(), secrets=SecretRef("secrets/prod/fastdeploy.yml")
)
deploy_fastdeploy(cfg, store.load(cfg.secrets))
```

ops-control registers it with secrets from two SOPS files (see its
`docs/PYINFRA.md`).

## Secrets

| Key | Required | Used for |
|---|---|---|
| `secret_key` | yes | `.env` (`SECRET_KEY`, signs tokens) |
| `postgres_password` | yes | `.env` (`DATABASE_URL`, unencoded as in the role) and the database role (as a SCRAM verifier); only `A-Z a-z 0-9 . _ ~ -` |
| `initial_user_name` | yes | initial FastDeploy user and the rollout check (stdin only) |
| `initial_user_password_hash` | yes | initial user's bcrypt hash (stdin only) |
| `basic_auth_password` | yes | Traefik route (bcrypt hash only) |
| `basic_auth_user` | no | Traefik user; falls back to `basic_auth_user` in the config |

Values must be single lines; `CHANGEME` is refused. Errors name keys, never
values. The user name, the hash and the rollout request reach the host on a
command's stdin (`secret_stdin`), the env files through `secret_file`.

## Configuration (`FastdeployConfig`)

Defaults follow the role's `defaults/main.yml`.

| Field | Default | Notes |
|---|---|---|
| `source_path` | required | FastDeploy checkout; must contain `commands.py`, `pyproject.toml`, `uv.lock`, `src/deploy`, `frontend/package.json` |
| `service_name`, `user`, `deploy_user` | `fastdeploy`, `fastdeploy`, `deploy` | `deploy` runs registered services' `deploy.sh` via sudo |
| `site_path` | `/home/fastdeploy/site` | home is `/home/<user>`, services in `<site>/services` |
| `source_excludes` | the role's `fastdeploy_rsync_excludes` | never shipped |
| `persistent_excludes` | see below | host-side state the sync never deletes |
| `environment` | `production` | `DEPLOY_ENV` |
| `python_version` | `3.14` | `uv sync --frozen --python` |
| `nodejs_version` | `24` | NodeSource major installed when `node` is missing or older |
| `app_host`, `app_port` | `127.0.0.1`, `9999` | uvicorn |
| `forwarded_allow_ips` | `("127.0.0.1",)` | literal addresses only |
| `restart_on_failure`, `restart_sec` | `true`, `5` | unit `Restart=` |
| `api_url`, `websocket_url` | `https://deploy.example.com`, `wss://.../deployments/ws` | `.env` and the frontend build |
| `postgres_database`, `postgres_user`, `postgres_host`, `postgres_port` | `fastdeploy`, `fastdeploy`, `localhost`, `5432` | host only `localhost` or `127.0.0.1`, port only `5432`: the deploy manages the local cluster |
| `legacy_service_tokens_accepted_until` | `""` | ISO 8601 with offset; empty: not rendered |
| `service_token_max_expire_days`, `service_token_retention_days` | `None` | positive days; `None`: not rendered |
| `legacy_token_users` | `()` | temporary users for legacy service tokens |
| `service_token_admin_users`, `service_token_admin_initial_user` | `()`, `false` | `SERVICE_TOKEN_ADMIN_USERS`; the flag puts the secret `initial_user_name` first; empty: not rendered (API token issuance gets 403) |
| `restore_policies` | `{}` | `RESTORE_POLICIES`: FastDeploy service name to `{bucket, prefixes}` (each prefix ends in `/`); empty: not rendered (every restore gets 422) |
| `create_initial_user`, `sync_services` | `true`, `true` | |
| `rollout_validation` and `rollout_validation_*` | `true`, `/users/me`, initial user, 300 s, 15 x 2 s | |
| `traefik_host`, `traefik_cert_resolver`, `traefik_middlewares`, `internal_ip_ranges`, `basic_auth_user` | role defaults | |

### Token issuance admins and restore policies

FastDeploy main `8faa9bd` and later fail closed without `SERVICE_TOKEN_ADMIN_USERS`
(no user may issue service tokens through the API, which also stops the web
UI's deploy button) and `RESTORE_POLICIES` (every Echoport restore is refused).
Each is written only when set, as compact JSON (keys sorted, list order kept)
in single quotes, in `.env` and `.env.shell` alike: systemd's
`EnvironmentFile=`, dotenv and `sh` all read it literally. The config refuses
anything that could contain a quote or that FastDeploy's `RestorePolicy`
rejects (a non-lowercase bucket, an empty prefix list, a prefix that is
absolute, has `..` or an empty component, or lacks the trailing `/`). The
bytes match the role's `fastdeploy_service_token_admin_users` and
`fastdeploy_restore_policies` (ops-library 2.57.0); the role takes the initial
user by name, so a playbook lists `{{ secrets.initial_user_name }}` where the
config sets `service_token_admin_initial_user`.

### Host-side state (`persistent_excludes`)

`/.env.shell`, `/bin/`, `/logs/`, `/services/` (where
`fastdeploy_register_service` writes registrations) and `/db.sqlite3` (left by
early deploys). Together with the source excludes (`.env`, `venv`,
`databases`, `frontend/node_modules`, `frontend/dist`, ...) and `sync_tree`'s
own (`.git`, `.venv`, ...) nothing the host keeps in the site tree is deleted.
Unlike the role's `synchronize` (no `--delete`), files removed from the source
are removed from the host.

## What the deploy does

1. Checks secrets and renders both env files (fails before any operation).
2. `postgres_database`: `postgresql` enabled and running, login role
   `fastdeploy` with the password, database `fastdeploy` and its `public`
   schema owned by it.
3. Groups and users `deploy` (also in group `fastdeploy`) and `fastdeploy`,
   `/home/fastdeploy` and `site`, `site/bin`, `site/logs` (`0755`). The
   services root `site/services` is `root:root 0755` (FastDeploy only reads
   it); anything below it not owned by root gets owner root, and the
   `fastdeploy` group becomes root (other groups stay), as
   `fastdeploy_deploy`'s `runner_layout.yml` does since ops-library 2.49.0.
   `/usr/local/libexec/fastdeploy` (`root:root 0755`) holds the scripts
   FastDeploy runs through sudo (ops-library `fastdeploy_runner`); the
   services root is inside the fastdeploy-owned site, so no sudoers rule may
   name a script there. The retired wildcard rule `/etc/sudoers.d/fastdeploy`
   (`fastdeploy` could run any `services/*/deploy.sh` as `deploy`) is removed,
   as `fastdeploy_deploy` does since ops-library 2.35.0; each registered
   service installs its own narrow rule for its script.
4. `sync_tree`: the checkout to `site/`, owned by the service user.
5. `.env` (systemd format) and `.env.shell` (double-quoted for `sh`) through
   `secret_file`, `0600`.
6. `uv sync --frozen --python 3.14` if the source changed, the venv is missing,
   or its interpreter is another Python version (probed as the service user).
7. Node.js from NodeSource if `node` is missing or too old; then `npm ci` (or
   `npm install` without a lockfile) and `npm run build` with `NODE_ENV` and
   the `VITE_*` URLs if the build inputs changed (see below).
8. Initial user and legacy token users that do not exist yet
   (`commands.py createuser`, the role's `ensure_token_user.py`);
   `commands.py syncservices` if the source or the dependencies changed.
9. Unit file, Traefik route (dual router, basic auth, `/` redirected to
   `/static/index.html`), then `service_rollout(always_restart=True)`.
   Traefik is not restarted: its file provider watches
   `/etc/traefik/dynamic` and loads a changed route itself (the role since
   ops-library 2.31.47; it used to restart Traefik on every run).
10. Read-only checks: the port, then a token minted with FastDeploy's own
    `create_access_token` must get the user back from `/users/me`.

### Frontend build stamp

The role builds the frontend on every deploy. Here the controller hashes the
build inputs (every file under `frontend/` except `node_modules`, `dist` and
`.DS_Store`, plus the build environment) and compares the digest with
`frontend/dist/.ops-deploy-build`, written after each build. A changed source
file, lockfile or URL triggers a build; nothing else does. The role's build
empties `dist/`, so the first ops-deploy run after an Ansible deploy builds
once.

### Users in the database

Which users exist is read as SHA-256 digests of the names (`psql` as
`postgres`), so the initial user's name never shows in pyinfra's output. Only
missing users are created; the role runs `createuser` on every deploy and
relies on the duplicate-key error. Both commands' output is judged on the
host and withheld, because `createuser` can print the password hash.

### Rollout check

`files/rollout_check.py` runs with FastDeploy's interpreter as the service
user: it mints the token and makes the request in one process, so the token
never appears on a command line, in output or on the controller. Only the last
line of its output (the verdict or the exception) is shown. It retries until
it gets HTTP 200 with the right user name; the role's list of accepted interim
status codes is not needed.

## Parity with the role

`tests/test_fastdeploy_parity.py` renders the vendored role templates
(`tests/parity/ansible/fastdeploy_deploy__*`) the way Ansible does and requires
**byte-identical** `.env`, `.env.shell` and unit files, so Ansible and
ops-deploy can take turns without rewriting them. With `OPS_LIBRARY_PATH` set,
`tests/test_ops_library_drift.py` also checks the vendored
`ensure_token_user.py` and `sudoers_blanket_check.py` and the digests of the
`fastdeploy_*` roles against ops-library (see
[Testing](../concepts/testing.md#drift-from-ops-library)). The
Traefik route differs in comments only (see
[helpers](../concepts/helpers.md#parity-differences-from-the-ansible-roles)).

Differences, all intended:

- **Restart**: unconditional, as in the role (owner decision); the build,
  `uv sync`, `syncservices` and user creation are change-gated instead of
  running on every deploy. A converged run changes nothing but the restart.
- **Ownership**: the role chowns the whole site tree after every sync; here
  the sync sets the owner of what it transfers (`--chown`).
- **Deletion**: the sync deletes files that are gone from the source
  (protected host state aside); the role never deletes.
- **Node.js**: when an upgrade is needed, `nodesource.list` is replaced
  rather than extended with a second line.
- **PostgreSQL**: the role pulls in `postgres_install` (repository, packages,
  `conf.d`, `pg_hba.conf`). Here PostgreSQL must already be installed; only
  the role, database and schema owner are managed.

Not ported (production uses none of them): the git deploy method,
`fastdeploy_install_uv` (uv must be at `/usr/local/bin/uv`), switching off
Traefik or basic auth, `fastdeploy_rollout_restart_enabled: false` and
`fastdeploy_build_frontend: false`.

## Backup, restore and removal

`ops_deploy.services.fastdeploy` also ports `fastdeploy_backup`,
`fastdeploy_restore` and `fastdeploy_remove`. Backups and snapshot
directories written by either tool restore with the other.

| Function | Config | Role |
|---|---|---|
| `deploy_fastdeploy_backup(cfg, secrets)` | `FastdeployBackupConfig(host_name=...)` | `fastdeploy_backup` |
| `deploy_fastdeploy_restore(cfg, secrets)` | `FastdeployRestoreConfig(host_name=...)` | `fastdeploy_restore` |
| `deploy_fastdeploy_remove(cfg)` | `FastdeployRemoveConfig(confirm=True)` | `fastdeploy_remove` |

`secrets` may carry `postgres_password`; ops-control passes the service's
password, as the playbooks do. Backup and restore run one bash script on the
host (`files/lifecycle.sh`), and the password reaches it on stdin only. The
backup exports it as `PGPASSWORD` for `pg_dump`. The restore writes it to a
private passfile (`mktemp -d` as `postgres`, removed afterwards). A password
with a line break is refused before anything runs.

**Backup.** It needs the site directory, `.env` and `services/`, and also the
runner root and the workspace when `require_runner_root` or
`include_workspace` is set. It creates
`/opt/backups/fastdeploy/<prefix>-<timestamp>/` as `root:postgres 0750`, with
`database/` as `postgres:postgres` (parent directories it creates get the
same owner and mode, as with Ansible's `file`). It checks free space (the
services, runners and workspace times 1.5) and reads FastDeploy's version
as `fastdeploy`. Then:

- `pg_dump --clean --if-exists --no-owner` runs as `postgres`;
- the services, the deploy runners (without `.config/sops/age/keys.txt`) and
  optionally the workspace are copied with `rsync -a --delete`;
- the env file, the unit, the Traefik route and `/etc/sudoers.d/fastdeploy_*`
  are copied (`0640`, rules `0440`), plus the journal when `include_logs` is
  set;
- the backup writes the role's `metadata.yml` (service and runner counts) and
  `manifest.sha256`, packs `.tar.gz` or `.tar.zst` and fetches it into
  `~/backups/fastdeploy` (`0700`).

**Restore.** It follows the role and `restore_pilot_internal`:

- **Validate.** `latest` is the newest `.tar.gz`/`.tar.zst` under the root,
  skipping `pre-restore-*` safety backups while others exist. A name is
  tried as given, below the root, and with each suffix; a directory is used
  as a snapshot. An archive is unpacked into
  `/tmp/fastdeploy-restore/fastdeploy-restore-<timestamp>`. The metadata and
  `manifest.sha256` are required.
- **Safety backup.** A full backup with prefix `pre-restore`, not fetched.
- **Restore.** Stop the service, `dropdb`/`createdb --owner=fastdeploy` and
  replay the dump as `fastdeploy` (`SET ROLE`). Sync `services/`, the runners
  and (when backed up) the workspace with `--delete` and fix their owners.
  Put back the env file (`0600`), units, the Traefik route and sudoers rules,
  then reload, enable and start. Like the role since ops-library 2.35.0, what
  the FastDeploy privilege reduction retired stays out even when the archive
  has it: the top-level entries `retired_entries` (`fastdeploy-self`,
  `fastdeploy-self-playbook.yml`, `apt_upgrade_local`, `apt_upgrade_staging`)
  are excluded from the services and runner syncs, the sudoers files
  `retired_sudoers` (`fastdeploy`, `fastdeploy_fastdeploy-self`,
  `fastdeploy_self_deploy_users`) are not copied back, and any other sudoers
  file is restored only when the role's `files/sudoers_blanket_check.py`
  (vendored) passes it: nothing but blank lines, comments and narrow
  `<user> ALL=(<runas>) NOPASSWD:[NOSETENV:] <script>[ *| --config *]` rules
  for root-owned scripts (`/usr/local/libexec/fastdeploy/<service>/<file>`,
  `/usr/local/libexec/<file>`) or, for a rule that runs as `deploy`,
  `/home/deploy/runners/<service>/<file>`. Older rules naming scripts below
  `/home/fastdeploy/site/services/` and an older register rule
  `deploy ALL=(root) NOPASSWD: ALL` are skipped (rerun that service's register
  playbook). The services root is restored `root:root`. Each
  skipped file is named in the output.
- **Verify.** The service is active and `/docs` answers 200. The service
  table counts as many rows as the metadata recorded, when that count is
  above zero.

If any phase fails, the safety backup is restored and verified the same way,
and the run still fails (the role's `rescue`). The unpacked archive is
always removed. `dry_run` stops after validation.

**Removal.** It needs `confirm`. It stops and disables the unit and removes
the unit file, the route and `/etc/sudoers.d/fastdeploy_*`. It drops the
`fastdeploy` database and role, ends the processes of `fastdeploy` and
`deploy`, and removes both homes, users and groups. Failures there do not
stop the removal, as with the role's `ignore_errors`. Like the role, it
leaves `/etc/sudoers.d/fastdeploy` (outside `fastdeploy_*`) alone; the deploy
removes that retired rule. It only acts
on what exists, so a second run changes nothing. One difference from the
role: the database is dropped with `dropdb`. The role uses
`community.postgresql`, which needs `python3-psycopg2` on the host and fails
(ignored) without it.

## Tests

- `tests/test_fastdeploy.py` (fake connector): first run, converged second run
  (only the restart), code change (sync, `uv sync`, `syncservices`, no build),
  frontend and build-URL changes (build), old Node.js, secret and database
  password rotation, role without login or with a non-SCRAM password, wrong
  owners, missing initial and legacy users, unit drift, the retired wildcard
  sudoers rule removed and no sudoers rule installed, basic-auth rotation
  without a Traefik restart, protected host state, leak checks (no secret in commands, op names/args or uploads),
  validation.
- `tests/test_postgres.py`: `postgres_database` and `sudoers_file` (no longer
  used by this deploy).
- `tests/smoke/test_fastdeploy_smoke.py` (`just smoke`, needs
  `FASTDEPLOY_SOURCE` or `PROJECTS_ROOT`): a real deploy of the committed
  `HEAD`, a converged rerun and a fresh-export rerun (only the restart), the
  initial user logs in, the database role logs in with its password, a
  registered service and runner survive, a pre-seeded retired wildcard rule is
  removed and FastDeploy cannot run a registered `deploy.sh` without that
  service's own rule, Traefik answers 401 without auth, no secret outside its
  files (including the PostgreSQL logs). Last, a basic-auth rotation is
  served by Traefik within seconds without a Traefik restart (same PID).
- `tests/test_fastdeploy_lifecycle.py` (fake connector): the password only
  on stdin, backup and restore settings (the safety backup's overrides, the
  retired lists, the vendored check), the restore phase run through local bash
  on a snapshot with retired entries and blanket rules, archive names, a password with a line break refused, removal order, a
  second removal without change, the confirmation.
- `tests/smoke/test_fastdeploy_lifecycle_smoke.py`: a backup with a marker
  table, the registered service and the runner. The restore after losing the
  marker and the registration brings both back and passes the service count
  check. An archive with retired services and runners, the wildcard rule and
  a `deploy ALL=(root) NOPASSWD: ALL` rule restores without them and with the
  narrow rule (`visudo -c` passes). A broken archive (no env file) fails the
  restore, which rolls back to its safety backup. Removal twice (the second without change), then a fresh
  deploy.
- Ansible coexistence runs from ops-control: `just smoke-fastdeploy-coexistence`.
  Deploys take turns with this deploy, and backup, restore and removal run
  across the tools.
