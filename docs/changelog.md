# Changelog

## Unreleased

- `traefik_deploy`: the log rotation file follows ops-library 2.39.2: Traefik
  gets `SIGUSR1` after `access.log` is rotated (the old
  `systemctl reload traefik || true` did nothing, so the renamed file kept
  growing), and `traefik.log` is rotated with `copytruncate`. The role's
  template is vendored and compared byte for byte for several configs, and
  `traefik_deploy` joins the roles `tests/test_ops_library_drift.py` watches.
- Ports caught up with ops-library main (fd6b4cf1), ops-control main and the
  live hosts:
  - `fastdeploy`: the deploy removes the retired wildcard rule
    `/etc/sudoers.d/fastdeploy` instead of installing it (`fastdeploy_deploy`
    2.35.0); `templates/sudoers.j2` and its vendored role template are gone.
    The restore never brings back retired services and runners
    (`fastdeploy-self`, `fastdeploy-self-playbook.yml`, `apt_upgrade_local`,
    `apt_upgrade_staging`) or retired sudoers files, and restores another
    sudoers file only when the role's `sudoers_blanket_check.py` (vendored
    under `files/`) passes it, so no `deploy ALL=(root) NOPASSWD: ALL` rule
    comes back from an older archive (`fastdeploy_restore` 2.35.0).
  - `fastdeploy` and `nyxmon`: a changed Traefik route no longer restarts
    Traefik (ops-library 2.31.47); its file provider loads the change.
  - `nyxmon`: `agent_impl` (only `python`) mirrors the role's
    `nyxmon_agent_impl`: the Rust agent drop-in `agent-impl.conf` is removed
    and a read-only check proves the monitor runs the venv's `start-agent`
    (the role's `agent_verify.yml`). Installing and selecting the Rust agent
    is not ported.
  - `work_app` restore: `safe_snapshot_delete` defaults to `False`; the
    pre-restore copy is kept and its path reported (ops-library a811bc16).
  - `tests/test_ops_library_drift.py`: with `OPS_LIBRARY_PATH` set, fails
    when a vendored role file or a mirrored role changes in ops-library
    (digests in `tests/parity/ops_library_roles.json`). See
    [Testing](concepts/testing.md#drift-from-ops-library).
- echoport and archive no longer use the MinIO root credentials, following
  ops-control's `deploy-echoport.yml` and `deploy-archive.yml`.
  `EchoportConfig.minio_account` (`MinioAccount`, default `echoport-retention`)
  ports `minio_deploy`'s `backup_account` include: the policy
  `backup-echoport-retention` (the role's template, vendored for parity:
  list, read and delete in the whole bucket, no writes) and the user
  `bk-<sha256(name)[:17]>` are created or updated through root's MinIO admin
  alias `local` (required: `mc admin info local` must succeed first), only
  when a probe finds them missing or different; the cleanup user's `mc` alias
  then uses that account (`minio_access_key` is refused with an account,
  `minio_secret_key` needs 32 to 40 characters). archive's `MinioBootstrap`
  drops `root_env_file` for `admin_alias` (`local`): probe and bootstrap make
  their admin calls through it after the same required check, the app secret
  and the app's alias (JSON for `mc alias import` into a temporary mc
  configuration) reach the bootstrap and the media migration on stdin, and
  `minio_root_user`/`minio_root_password` are refused. No script puts
  credentials into `MC_HOST_*` any more. `minio_deploy` joins the roles
  `tests/test_ops_library_drift.py` watches.
- Commands no longer depend on the SSH user's login shell. Root's on macmini
  and staging is fish, which halves backslash pairs inside single quotes, so
  the weeknotes_home env loader (`python -c` with a regex) crashed live with
  `re.PatternError`. The loader is now a file the deploy installs
  (`/home/weeknotes-home/env-exec.py`, run with `python -I`), and the
  FastDeploy restore builds its pgpass escapes without backslashes in the
  script. `run_deploy_fake` fails any deploy test that would send a command
  fish reads differently (`fish_unsafe` on the exact `wire_command`, also for
  `_if`-gated operations), and `tests/test_remote_shell_execution.py` runs
  generated commands through real bash and fish. The smoke VM gives root the
  fish login shell (`smoke/provision.sh`); smoke checks go through `sh`
  (`SmokeHost.run`).
- Strict probes (`ops_deploy.helpers.probes`): migrations, static files,
  dependency (`uv sync --check`/`--dry-run`), admin, wiring, MinIO, Nyxmon and
  FastDeploy probes of archive, chesslab, echoport, fastdeploy, heis, logyard,
  marina, nyxmon, opaq_app, weeknotes_home and work_app no longer read an
  error as "not current". States normal before a first deploy are explicit
  answers; a failed probe runs the step it gates and then probes again
  ("Probe again: ..."), failing the deploy if the probe still fails. See
  [Deploy helpers](concepts/helpers.md#strict-probes-ops_deployhelpersprobes).

- `ops_deploy.services.nyxmon` and `ops_deploy.services.fastdeploy`: backup,
  restore and removal, ports of the `nyxmon_backup`/`_restore`/`_remove` and
  `fastdeploy_backup`/`_restore`/`_remove` roles. Archives and snapshot
  directories have the roles' layout and metadata, so either tool restores
  the other's backups. Backup and restore each run as one bash script on the
  host, which keeps the roles' structure: services always restart after a
  backup, and a failed restore puts back the safety copy or safety backup and
  still fails. The FastDeploy database password reaches the host on stdin
  only. Removals need `confirm`, only act on what exists and change nothing
  on a second run. Shared pieces live in `ops_deploy.services._lifecycle`,
  outside the size-capped layer. Fake connector tests and two lifecycle smoke
  tests; see [nyxmon](services/nyxmon.md) and
  [fastdeploy](services/fastdeploy.md).

- `ops_deploy.services.echoport`: `deploy_echoport`, a port of the
  `echoport_deploy` role (rsync method, uv) plus the steps ops-control's
  `deploy-echoport.yml` runs around it (loopback listener check, Nyxmon
  health check upsert). Ships the role's templates unchanged, so the env file,
  unit, Traefik route and staging refresh script are byte-identical. The
  service user's crontab is edited in Ansible's `cron` format, so the two
  tools never add a second copy of a job. migrate runs when code changed or a
  migration is pending; the admin account, the cleanup user's `mc` alias
  (credentials on stdin, not the role's `mc alias set` arguments), the
  crontab and the Nyxmon check are probed read-only and written only when
  they differ. Fake connector, parity, host script and smoke tests; see
  [echoport](services/echoport.md).

- `ops_deploy.services.logyard`: `deploy_logyard`, `deploy_logyard_core`,
  `deploy_logyard_ingress` and `deploy_logyard_vector`, ports of the
  `logyard_deploy`, `logyard_ingress_deploy` and `logyard_vector_deploy` roles
  and the playbook steps around them (Nyxmon checks upsert). Templates shipped
  unchanged, files byte-identical to the roles'; Grafana is restarted only
  when its datasource, dashboards or network changed. See
  [logyard](services/logyard.md).

- `ops_deploy.infra`: `deploy_docker_install` and `deploy_vector_apt_install`,
  ports of the `docker_install` and `vector_apt_install` roles (the repository
  files are the ones the roles write). See [infra](infra.md).

- `ops_deploy.services.work_app`: `deploy_work_app_backup`,
  `deploy_work_app_restore` and `deploy_work_app_remove`, ports of the
  `work_app_backup`, `work_app_restore` and `work_app_remove` roles. The
  archive layout and `metadata.yml` match the roles', so either tool restores
  the other's archives. Restore checks the archive (slug, metadata, version)
  from its listing before it changes anything. Fake connector and smoke
  tests; see [work_app](services/work_app.md).

- `ops_deploy.services.work_app`: `deploy_work_app`, a port of the
  `work_app_deploy` role (rsync method) and of the port preflight, Echoport
  backup target and Nyxmon health check in ops-control's
  `deploy-work-app.yml`. `.env`, unit and Traefik route are byte-identical to
  the role's (parity tests against the vendored templates). `src/` and
  `ledger/` are synced with `--delete` inside each, the SQLite database,
  `.env`, venv and static files never are. Migrations, `collectstatic` and the
  upserts run only when needed (the upserts probe read-only first), so a
  converged deploy changes nothing. Fake connector tests and
  `tests/smoke/test_work_app_smoke.py`; see [work_app](services/work_app.md).

- `ops_deploy.services.heis`: `deploy_heis`, a port of the `heis_deploy`
  role (rsync method). `.env`, unit, launcher, fish config and the Traefik
  route (TLS rule, canonical redirect) are byte-identical to the role's
  (parity tests against the vendored templates, including production's
  shape). The Wagtail content reconcilers follow the role's switches
  (production: off) and run only when the source, dependencies or schema
  changed; the SQLite database and media are never shipped or deleted. Fake
  connector, parity and smoke tests; see [heis](services/heis.md).

- `ops_deploy.services.archive`: `deploy_archive`, a port of the
  `archive_deploy` role (rsync method) plus the steps ops-control's
  `deploy-archive.yml` runs around it (MinIO bucket and service account,
  local media migration, Echoport backup target). Ships the role's templates
  unchanged, so env files, units and the Traefik route are byte-identical.
  migrate/collectstatic, the admin account, MinIO and Echoport are probed
  read-only and written only when they differ; credentials travel on stdin
  only. Fake connector, parity and smoke tests; see
  [archive](services/archive.md).

- `ops_deploy.services.chesslab`: `deploy_chesslab`, a port of the
  `chesslab_deploy` role (rsync method) and of the Echoport backup target and
  Nyxmon health check upserts in ops-control's `deploy-chesslab.yml`.
  `.env`, unit and Traefik route are byte-identical to the role's (parity
  tests against the vendored templates). Like the playbook, it checks the app
  port before any change and stops when the SQLite database is missing.
  Migrations, `ensure_admin` and the upserts run only when something needs
  them (the upserts probe read-only first), so a converged deploy changes
  nothing. App users (a JSON list secret) reach the host only on stdin. Fake
  connector tests and `tests/smoke/test_chesslab_smoke.py`; see
  [chesslab](services/chesslab.md).

- `ops_deploy.services.delve`: `deploy_delve` and `build_delved`, a port of
  the `delve_deploy` role (the Delve backend Go binary behind Traefik, plus
  the Discovery collector oneshot and timer). The binary is cross-compiled on
  the controller as the playbook does; reproducible builds keep an unchanged
  checkout a no-op. A new binary is staged next to the old one and renamed
  in, since writing into the running executable fails. Env file, units and
  route are byte-identical to the role's; Traefik picks the route up through
  its file watcher (the role's reload handler is a no-op). Optional
  `public_health_check` checks `/health` through Traefik on the host. Fake
  connector, parity and smoke tests; see [delve](services/delve.md).

- `ops_deploy.services.recorder`: `deploy_recorder`, port of the
  `recorder_deploy` role plus the controller build (`npm ci`, `npm run build`,
  `go build` for linux/`goarch`) and the external-URL smoke gate of
  ops-control's recorder playbook. Env file, unit and Traefik route are
  byte-identical to the role's (parity tests against the vendored
  templates); recorder restarts only when the binary, env file or unit
  changed, and Traefik is never restarted (the role's reload is a no-op).
  Fake connector tests and `tests/smoke/test_recorder_smoke.py`; see
  [recorder](services/recorder.md).

- `ops_deploy.services.static_site`: `deploy_static_site`, port of the
  `static_site_deploy` role. Controller-side source validation (regular files
  only, no symlinks, optional exact file allowlist), rsync publish, hardened
  loopback HTTP server unit and Traefik route; server script, unit and route
  are byte-identical to the role's (parity tests against the vendored
  templates). The service restarts only when the server script or unit
  changed; Traefik is never restarted. Fake connector tests and
  `tests/smoke/test_static_site_smoke.py`; see
  [static_site](services/static_site.md).

- `sync_tree` takes `chmod` (rsync `--perms --chmod=...`): modes are enforced
  on existing files too and a mode-only difference counts as a change. Used
  for the static site's `D0755,F0644` / private `D0750,F0640` publication.

- `ops_deploy.services.marina`: `deploy_marina`, a port of the `marina_deploy`
  role (rsync method, uv). `.env`, `gunicorn.sh`, unit, fish config and Traefik
  route are byte-identical to the role's (parity tests against the vendored
  templates). The source sync never deletes, as in the role, so the database,
  media and collected static files stay. Migrations, `collectstatic` and
  `ensure_superuser` run only when something needs them, so a converged deploy
  changes nothing; the admin account travels on stdin only. Fake connector tests
  and `tests/smoke/test_marina_smoke.py`; see [marina](services/marina.md).

- `ops_deploy.services.opaq_app`: `deploy_opaq_app`, port of the
  `opaq_app_deploy` role together with the steps of `deploy-opaq-app.yml`
  around it (the guard against taking over a name a static page routes, the
  login and allowlist checks, the Echoport backup target and the Nyxmon
  health check) and the playbook's port preflight (nothing but opaq-app
  may listen on the app port). Environment file, unit and Traefik route are byte-identical
  to the role's (parity tests against the vendored templates); the route is
  written without a Traefik restart, as the role does. The database lives
  outside the synced tree and is never touched by a sync. The Echoport and
  Nyxmon entries are probed first and written only when they differ. Fake
  connector tests and `tests/smoke/test_opaq_app_smoke.py`; see
  [opaq_app](services/opaq_app.md).

- `ops_deploy.services.weeknotes_home`: `deploy_weeknotes_home`, a port of the
  `weeknotes_home_deploy` role (rsync method) and of the FastDeploy service
  row, Echoport backup target (with its FastDeploy service token, issued only
  when the stored one is unusable and piped, never written) and Nyxmon check
  upserts in ops-control's `deploy-weeknotes-home.yml`. Env file, unit and
  Traefik route are byte-identical to the role's (parity tests against the
  vendored templates). Like the playbook, it checks the app port before any
  change. Migrations and `collectstatic` run only when needed, and
  `src/daybook.egg-info` is not removed by the sync, so a converged deploy
  changes nothing (the role restarts the service on every run). Fake
  connector tests and `tests/smoke/test_weeknotes_home_smoke.py`; see
  [weeknotes_home](services/weeknotes_home.md).

- `ops_deploy.infra`: `deploy_traefik`, `deploy_traefik_backup`,
  `deploy_traefik_restore` and `deploy_traefik_remove`, ports of the
  `traefik_deploy` (full deploy), `traefik_backup`, `traefik_restore` and
  `traefik_remove` roles. Static config, unit, certificate list and log
  rotation are byte-identical to the role's (parity tests against the
  vendored templates). Deploy, restore and remove refuse transaction-managed
  hosts before any change, as the role's guard does. The static config and
  certificate list are validated before anything is written, a new binary
  must report its version before Traefik restarts, and Traefik restarts only
  on a real change (also a new binary, which the role leaves running old).
  A release checksum is required. Fake connector tests and
  `tests/smoke/test_traefik_smoke.py`; see [Traefik](traefik.md). PyYAML is
  now a runtime dependency (certificate list validation).
- The vendored-template check accepts templates in role subdirectories
  (`<role>__<dir>__<file>`).

- `ops_deploy.infra` (outside the size-capped layer): `deploy_postgres_install`
  and `deploy_redis_install`, ports of the `postgres_install` and
  `redis_install` roles. `pg_hba.conf`, the `conf.d` drop-in, `redis.conf` and
  the PGDG `.sources` file are byte-identical to what the roles write (parity
  tests against the vendored templates and macmini's files). Databases go
  through `postgres_database`, which never drops or recreates; `redis.conf`
  (it may hold `requirepass`) is written with `secret_file` and the old file
  kept as a backup like the role's; a server that answers without its
  password or started before its current `redis.conf` is restarted. Fake
  connector tests and `tests/smoke/test_infra_smoke.py`; see
  [PostgreSQL and Redis](infra.md).
- `postgres_database`: while the server is not installed or not running at
  planning time (the same deploy sets it up) the plan treats the role and
  database as new instead of failing; new `port` (cluster) and `enabled`
  arguments; psql now always passes `-p`.

- Base deploys in `ops_deploy.base` (outside the size-capped layer), ported
  from the ops-library base roles: `hostname`, `headless_mode`,
  `systemd_unit_masks`, `ssh_authorized_keys` (whole file, byte-identical to
  the role's template, installed atomically), `uv_install` and
  `shell_basics` (pinned, checksum-verified downloads renamed into place),
  `nodejs_install` (NodeSource line, apt pin, read-only version check).
  Fake connector tests for each and `tests/smoke/test_base_smoke.py` (two
  runs per deploy, the second without change); see [base deploys](base.md).

- Size cap: `just size-cap` (`scripts/size_cap.py`, also a CI step and a
  test) fails when helpers + ops + core exceed 1,500 code lines; see
  [development](development.md#size-cap-on-the-shared-layer).
- `BaseServiceConfig` no longer imports pydantic's private
  `ModelMetaclass`; `Config(...)` and the `model_validate*` methods still
  raise `ConfigValidationError`. Constructor calls on config classes are
  now type-checked against the field types (previously typed `Any`), so
  pass `SecretRef(...)` rather than a plain string in typed code.
- `systemd_unit` drops its unused `unit_dir` argument.

- `fastdeploy` service: port of the `fastdeploy_deploy` role (rsync method)
  with `FastdeployConfig`, byte-identical env, unit and sudoers files (parity
  tests against the vendored role templates), host-state
  `persistent_excludes` (registered services, env files, venv, build output),
  NodeSource Node.js, a frontend build gated on a digest of its inputs, change
  -gated `uv sync`/`syncservices`, initial and legacy token users created only
  when missing, the role's unconditional restart and a token-minting auth
  check; fake connector scenarios and a smoke test (`FASTDEPLOY_SOURCE`).
- `postgres_database` helper: login role, database and schema owner; the
  password goes to PostgreSQL as a SCRAM verifier computed on the controller.
- `sudoers_file` helper: sudoers drop-in validated with `visudo` before it
  replaces the installed rule.
- `secret_stdin` operation: run a command with a secret on stdin.
- Smoke VM: PostgreSQL 17 from PGDG and `build-essential` (asyncpg has no
  wheel for Python 3.14 on arm64).

- `sync_tree` compares files by checksum and no longer syncs times
  (`-rl --checksum` instead of `-rlt`): a fresh clone of unchanged code is a
  no-op. Real-rsync test for time-only differences; the nyxmon smoke deploys
  from a fresh export and expects no mutating change.
- `nyxmon` service: port of the `nyxmon_deploy` role (rsync method) with
  `NyxmonConfig`, byte-identical env and unit files (parity tests against the
  vendored role templates), host-state `persistent_excludes`, SQLite privacy
  (umask drop-ins, `0600` database), an OpsGate live-environment check, fake
  connector scenarios and a smoke test (`NYXMON_SOURCE`).
- Deploy helpers in `ops_deploy.helpers`: `system_user`, `systemd_unit`,
  `service_rollout` (daemon-reload and restart only on change; optional
  unconditional restart), `uv_sync` and `django_manage` (run as the service
  user via `runuser`, gated with `when_changed`), `traefik_route` with
  `TraefikRoute`/`BasicAuth` (controller-side bcrypt in `htpasswd -B` format,
  reusing a deployed hash that still matches), and the read-only checks
  `wait_port` and `http_check`.
- Test harness: `OpResult.read_only` and `FakeRun.mutating_changed_ops`, so a
  converged second run can be asserted while ignoring read-only checks.
- `system_user` leaves an existing user's home, shell and primary group
  unchanged, as the roles do, and logs a warning on any difference.
- `toyweb` service: a toy uv/Django app that uses every helper plus
  `sync_tree` and `secret_file`, with deploy-level scenarios.
- Parity tests against the nyxmon and fastdeploy Traefik role templates.
- New dependency `bcrypt`; new dev dependencies `pyyaml`, `types-pyyaml`.

## 0.1.0 (unreleased)

- Project skeleton: uv, ruff, mypy (strict), pytest, mkdocs, GitHub Actions CI.
  pyinfra pinned to `3.10.*`, Python 3.12+.
- `BaseServiceConfig` with `CHANGEME` rejection (input, defaults and
  validated values), sanitized `ConfigValidationError`, `ServiceName` and `UnixUser`
  field types, and `required_secret_keys`.
- `SecretRef`, `SecretValues` (redacted, unpicklable) and the `SecretStore`
  protocol.
- `ops_deploy.testing`: `run_deploy_fake` with recording of facts, shell
  commands, uploads and `FunctionCommand` callbacks; `RecordingRsyncRunner`.
- Injectable controller-side rsync runner (`ops_deploy.core.rsync`).
- `toy` service deploy with first-run, no-op and change-run tests.
- `ops_deploy.ops.sync_tree`: rsync a controller directory to the host,
  replacing `ansible.posix.synchronize`. Plan-time itemized dry run (cached, so
  it runs once per deploy), owner set with `--chown` and never preserved,
  mandatory excludes for VCS/tool state and deploy state markers. The toy
  service uses it.
- `ops_deploy.ops.secret_file` and `SecretContent`: install a secret sent over
  stdin with a host-side Python installer that never follows symlinks and
  works through descriptors: a private 0700 staging directory next to the
  destination (checked on its descriptor), a 0600 `O_EXCL` file inside it,
  `fchown`/`fchmod`/`fsync`, and a rename as the commit point (directory
  `fsync` and staging cleanup after it are best effort). Interrupted or failed
  writes leave the destination untouched and remove the staging directory;
  leftovers from a killed run are removed by the next run. Forces
  `_get_pty=False`. Hosts need `python3` 3.8+.
- Harness: `FakeRun.stdin` records command stdin (excluded from `all_text()`),
  and `OpResult.args` records pyinfra's operation argument strings (included
  in `all_text()`).
- Smoke target: `smoke/vm.sh` and `just smoke-up`/`smoke`/`smoke-ssh`/`smoke-down`
  manage a local lima Ubuntu 24.04 VM with root SSH (pinned host key), uv and
  Traefik. `just smoke` deploys toyweb twice over pyinfra's ssh connector
  (second run: no mutating changes) and runs `secret_file` fault and leak
  tests on the VM.
- `ops_deploy.testing.run_deploy_ssh` and `SshRun`; `DeployRun` is the shared
  base of `FakeRun` and `SshRun` (`succeeded`, `changed_ops`,
  `mutating_changed_ops`, `op`).
- `sync_tree` passes `--omit-dir-times`: an app writing into a synced
  directory no longer makes every later deploy resync and restart. It also
  passes `ssh_key`, `ssh_known_hosts_file` and `ssh_strict_host_key_checking`
  from host data to rsync's ssh.
