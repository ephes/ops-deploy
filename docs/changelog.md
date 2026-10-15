# Changelog

## Unreleased

- `ops_deploy.services.recorder`: `deploy_recorder`, port of the
  `recorder_deploy` role plus the controller build (`npm ci`, `npm run build`,
  `go build` for linux/`goarch`) and the external-URL smoke gate of
  ops-control's recorder playbook. Env file, unit and Traefik route are
  byte-identical to the role's (parity tests against the vendored
  templates); recorder restarts only when the binary, env file or unit
  changed, and Traefik is never restarted (the role's reload is a no-op).
  Fake connector tests and `tests/smoke/test_recorder_smoke.py`; see
  [recorder](services/recorder.md).

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
