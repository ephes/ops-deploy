# Changelog

## Unreleased

- `fastdeploy`: port of ops-library 2.49.0's root-owned runner layout. The
  services root is `root:root 0755` and fastdeploy-owned leftovers below it
  (older Ansible deploys chowned the whole site, root-run backup scripts
  included) get owner root and lose the `fastdeploy` group;
  `/usr/local/libexec/fastdeploy` is created `root:root 0755`. The restore
  writes the services root `root:root` and, with the re-vendored
  `sudoers_blanket_check.py`, no longer restores sudoers rules naming scripts
  below the FastDeploy site. `tests/parity/ops_library_roles.json` records the
  new `fastdeploy_restore`; `fastdeploy_deploy` keeps its old digest because
  the unrelated HSTS preload change (ops-library `abae172`) is not ported yet.

- Traefik backup now captures the whole dynamic route-config tree by default,
  matching ops-library 2.48.1 coverage and metadata flags. Source modes are kept
  under a private container; archives and fetched copies stay `0600`. Missing,
  overlapping, symlinked or special dynamic sources refuse, and copy failure cannot
  proceed to packing/fetching. Dynamic-route restore and dry-run validation are
  not implemented; existing ACME-only restore/transaction guards are unchanged.
  No private registration or live qualification is included.

- `zellij_ingress`: port of the `zellij_ingress_deploy` role. Writes only
  `/etc/traefik/dynamic/zellij.yml` (`root:root 0644`, directory ensured
  `0755`) from the role's template shipped unchanged, so the file is
  byte-identical to the role's: routers `zellij-secure` and `zellij-http`,
  both restricted to `Host` plus the `ClientIP` allowlist, the
  `zellij-redirect-target` temporary redirect (`permanent: false`) to a fixed
  URL and `noop@internal`, no backend. Disabled is a no-op (nothing is
  removed). Unlike the role, nothing reloads or restarts Traefik; its file
  provider watches the directory. Host name, target URL (http(s), no
  credentials, query, quotes or `$`), entry points, resolver, allowlist and
  route path (directly in the dynamic directory) are checked before any
  operation. `tests/parity/ops_library_roles.json` now records the role.

- Add a standalone read-only Native venv metadata inventory probe with bounded
  trust/classification and Docker fixture coverage. A matching metadata
  candidate does not authorize execution, adoption, installation or deletion;
  PyPI source dispatch, hooks, interpreter/content trust and liveness remain
  separate prerequisites. Mixed missing/extra/older inventory drift stays
  different even when another Python/package declaration is newer.

- `compose_app`: an `echoport` part registers the app's Echoport backup
  target (SQLite database plus listed files, directories and `HostSecret`
  files; default unit and owner from the app). Paths are checked before any
  operation; host secrets a restore handed to `restore_owner` go back to root
  `0600` on the next deploy. The five copies of `echoport_target.py`
  (archive, chesslab, opaq_app, weeknotes_home, work_app) are one shared
  script in `services/_echoport`. Behaviour changes for those services:
  `schedule_required` is now set on every registered target (Echoport
  migration 0008 is required; targets registered without it, such as
  opaq_app, weeknotes_home and work_app, update that one field on their next
  deploy, while archive and chesslab already set it), and archive and
  opaq_app pass their parameters as `PARAMS` instead of an environment
  variable.

- `delve`: Delve's server ad analysis, mirroring ops-library 2.48.0's
  `delve_deploy` (`delve_smart_skip_analysis`). New `DelveConfig` fields
  `smart_skip_analysis` (default off; off renders nothing new, so existing
  deploys are unchanged), the profile (`smart_skip_analysis_profile_src`,
  copied to `<config_dir>/smart-skip-analysis-profile.json`), the media
  directory (`delve:delve 0700`, an own `ReadWritePaths` line outside
  `data_dir`), disk cap, ffprobe/ffmpeg paths, apt `ffmpeg`, the voxhelm and
  detector origins with their secrets `voxhelm_token` and `detector_api_key`
  written to their own `root:delve 0640` files (never into `delve.env`), and
  the optional timeouts. The secrets must be single lines of at least 32
  characters and not `CHANGEME`, checked before any operation; the detector
  API key must also be at least 32 of `A-Z a-z 0-9 . _ ~ + / = -`
  (`DETECTOR_API_KEY_PATTERN`; llama-server skips key-file lines starting
  with `#`). The vendored `delve.env.j2` and `delve.service.j2` follow the
  role.

- Add the minimal native_app release/TOML/custom-unit and route-only runtime,
  with canonical rendering, restart/resume markers, stable routes and
  read-only preflight checks. Release preflight refuses unsafe ownership/write
  permissions before version execution and classifies undecodable tracked
  drift for verified repair. Package-manager sources remain deferred.

- Django-site database workers with resumable per-unit restart gates, uv
  transport environment, controller Python-pin assertions, optional env
  references and opt-in cache ownership repair. Existing site defaults stay
  unchanged; source sync preserves worker launchers.

- Preserve Django sites' existing `venv` aliases even without fish, and exclude
  controller Ruff caches from source sync. A canonical conversion no longer
  deletes the Wagtail-origin alias or deploys local lint-cache files. Preserve
  existing in-tree PostgreSQL media permissions; create missing media with
  the origin mode 0755 and refuse symlink/file substitutes.

- Add local PostgreSQL Django sites without shared-server management, Wagtail
  route/security preservation, required static paths, and resumable bootstrap
  step groups with secrets on stdin. SQLite defaults remain unchanged.

- `django_site`: an optional Next.js standalone frontend (`NextStandalone`:
  its own unit and `next.sh`, `npm ci` and `next build` gated on the source
  and a build-environment stamp, the middleware installed from a source file,
  purged public directories, a read-only legacy-code guard; the route sends
  its path prefixes to it at priority 200). Also: `BootstrapSuperuser`
  (`createsuperuser` when missing, the password set once), `app.env_dir`,
  `media.private_root` and data directories outside the site (`0750`),
  `steps.migrate_args`, `route.name` and `route.backend`, `hardening:
  "strict"`, typed public URL checks and a CSRF check (`checks.public`,
  `checks.csrf_path`), `Joined` env values, `Secret.strip`, `min_length` and
  `equals`, and `env.url_paths` (admin path secrets checked before any
  operation). A step group's `source` trigger now means the source changed
  (or a pending marker is left), not a dependency change alone. The launchers,
  the `venv` link and the frontend's middleware and purged directories are
  always excluded from the sync. A deploy stops before any change when the
  site holds markers of the old split-site module. marina's and heis's files
  render byte for byte as before. The split site's module (never merged) is
  replaced; its files and their differences are documented in
  [django_site](services/django_site.md), and an equivalence test runs its
  scenarios through the vendored old module and django_site.
- compose_app: typed steps `http_json_settings` and `http_json_items` for an
  app's JSON API (Servarr: host settings, root folders, download clients,
  Prowlarr applications and indexer proxies). Declarative: a read-only probe
  while planning, an apply only on drift, a verifying second read; items are
  created from a schema entry or corrected in place and never deleted;
  Servarr `fields` lists and tag labels are handled; masked write-only values
  are tracked by digest on the host. API keys may be `HostSecret` files read
  on the host. Config files may carry `{"env_var": NAME}` YAML leaves
  (`!env_var NAME`, for Recyclarr).

- New service `ops_deploy.services.compose_app`: one deploy for the Docker
  Compose apps, configured per app with a typed `ComposeAppConfig` (users,
  groups, directories with setgid modes, required mounts and paths, external
  networks, env files and config files with `Secret`, `HostId` and
  `HostSecret` values, `ComposeService`s with the keys the fleet uses and
  nothing passed through, a route, typed API steps, checks, legacy paths). It
  renders the compose file (long binds with `create_host_path: false`,
  loopback ports, `$` escaped, a provider's dependents with `depends_on`
  healthy and `restart: true`), single-quoted env files (completed on the host
  by `files/compose_host.py` when they hold a host secret or id; a host secret
  is created once and an existing one adopted unchanged) and a oneshot unit
  with `ExecReload` and `RequiresMountsFor=`. Images must be pinned by digest
  and are pulled only when missing. Every decision is made while planning
  from read-only probes and an applied stamp (`applied.json` and `pending` in
  `/var/lib/ops-deploy/<service>/`, root-only), so a converged host gets no
  mutating operation, an interrupted or failed run is finished by the next,
  only the services whose inputs changed are recreated (`systemctl reload`),
  the readers of a changed config file restart, a unit-only change touches no
  container, and a namespace provider's dependents are stopped before it can
  be replaced and start only once it is healthy. Typed steps:
  `qbittorrent_preferences` (qBittorrent 5.2's 204 login, the temporary
  password bootstrap, preferences by drift, no secret in the output) and
  `json_key_copy`. Read-only checks: the port preflight before any change,
  running and healthy services, shared network namespaces, ports listening on
  their address only. `remove_compose_app` (`ComposeAppRemoveConfig`) keeps
  the data. Its route has no router on the HTTP entrypoint. Documented in
  [compose_app](services/compose_app.md) with the
  torrent switch and a worked *arr example; torrent is its first consumer.
- New service `ops_deploy.services.shared_tree`: a group-writable setgid tree
  (ops-control's `media_storage`) with a plan-time-gated, idempotent repair.
- `helpers.traefik`: `TraefikRoute.internal_only` renders one internal
  router (`<name>-int`, ClientIP ranges; `-http` with the same rule) and no
  external one; compose_app's `access: internal`. Shared layer: 1,413 of
  1,500 code lines.
- `docker_install`: the apt cache update after a changed Docker repository
  is decided while planning, so a converged dry run (`pyinfra-check`) no
  longer lists it.

- `services/heis` is removed, with its tests, the vendored `heis_deploy`
  templates, its smoke and page, and `tests/test_django_site_equivalence_heis.py`:
  heis production and staging run django_site since 2026-10-16. The
  django_site smoke now deploys heis's shape from nothing.

- `django_site` makes the service group the primary group of an existing
  user that has another one (heis's user was created by the Ansible role
  with `users`, so the files it wrote had that group and every run repaired
  their ownership again): `usermod -g`, then a `chgrp` of the user's own
  files with the old group in its home and the site (`find -xdev`), with the
  old group kept in `~/.ops-deploy-regroup` until the move succeeded. The
  deploy stops before any change when `usermod`'s own move would touch
  files of other owners or other mounts in the home. Both steps are marked
  as owing the unit's restart and fold into the run's one restart; a user
  with the right group changes nothing.
- `django_site` keeps its markers (pending, restart, step groups, the
  regroup state) in `/var/lib/ops-deploy/<service_name>/` (`root:root 0700`,
  created with the first marker) instead of the service user's home, where
  the user could have planted a symlink that root's `touch` or write would
  follow. The usermod step also stops when the user's home in passwd is not
  the configured one.

- `django_site` takes heis's shape: `apt_packages` (installed before the
  user), `StepGroup.after` (`"migrate"` runs a group before `collectstatic`,
  like heis's content reconcilers; group markers are cleared by
  "Clear <group> marker") and the route's `canonical_redirect_regex`/
  `canonical_redirect_replacement` (heis's permanent redirect to the
  canonical host). `tests/test_django_site_equivalence_heis.py` runs every
  `test_heis.py` scenario, staging and production shape, through both
  modules. `services/marina` is removed (marina runs on django_site since
  2026-10-16), with its tests, parity templates, smoke and page; the
  django_site smoke now switches heis from `services/heis`.

- New service `ops_deploy.services.django_site`: one deploy for the
  Django/Wagtail sites, configured per site with a typed `DjangoSiteConfig`
  (source, app, SQLite database, local media, `.env` entries with `Secret`
  references, management-command `StepGroup`s with triggers and markers,
  `EnsureSuperuser`, the route with a required `public_reason`, local
  checks). It writes one canonical file set for every site: a single-quoted
  `.env`, a launcher that sources it and `exec`s gunicorn, the classic unit
  with `Group=` and `RestartSec=5`, the classic route and fish config, each
  with a "managed by" header. Markers in the home directory
  (`~/.ops-deploy-pending`, `~/.ops-deploy-restart-<unit>`) make the next run
  finish what a failed one left undone; a converged run changes nothing.
  `required_secret_keys` follows from the config. Switching marina from
  `services/marina` rewrites `.env`, `gunicorn.sh`, the unit, the route and the
  fish config once and restarts marina once; the differences are listed in
  [django_site](services/django_site.md). `services/marina` stays until the
  transitional equivalence test (every marina scenario through both modules)
  is removed. New dev dependencies python-dotenv and django-environ: the
  `.env` values are read back by the real parsers in the tests.

- `graphyard`: ports of `graphyard_deploy`, `graphyard_vector_deploy`,
  `graphyard_ingress_deploy` and `graphyard_auth_bootstrap_deploy` with the
  playbooks around them (`ops_deploy.services.graphyard`: core, Vector,
  ingress, auth bootstrap and the stack). Templates are shipped unchanged and
  byte-identical (`tests/test_graphyard_parity.py`; role digests recorded at
  ops-library 94047183). Secret files (env, compose, metric specs, Vector
  fragment) are written with `secret_file`; credentials reach the host on
  stdin only (the InfluxDB v1 login is created through InfluxDB's HTTP API,
  not `influx v1 auth create --password`; env-file secrets that bash would
  read differently are refused). Steps are skipped when the host already
  matches: the InfluxDB v1 login, bucket retention and static files are
  probed, the metric collection specs are compared by digest, and the auth
  bootstrap (a deploy-time reconcile) checks the Django user and Grafana's
  admin password on the controller and resets only on a difference (`grafana cli --password-from-stdin`). The core takes a
  git source (`source_commit`). `logyard.vector.env_line` (was `_env_line`)
  is shared by both Vector producers.
- Graphyard and Logyard share the Grafana tree in Graphyard's site under one
  ownership rule: Logyard owns its datasource file and `dashboards/logyard`
  (`root:root`), Graphyard everything else. Graphyard's ownership step skips
  Logyard's paths (`GraphyardConfig.foreign_paths`) and Logyard's deploy no
  longer sets the shared `datasources/` and `dashboards/` directories to
  root, which ended the role's ping-pong (an owner change and a Grafana
  restart after every deploy of the other). The Graphyard sync keeps
  Docker's `dashboards-json` mount point, which the role's sync deletes
  (detaching Grafana's dashboards until it restarts).

- `nyxmon`: the Rust monitoring agent is ported (the role's `agent_rust.yml`
  and `agent_verify.yml`, ops-library 2.32.0). `agent_impl` accepts `python`
  and `rust`. The new `agent_rust_version`, `agent_rust_sha256`,
  `agent_rust_release_url` (with a `{version}` placeholder),
  `agent_rust_local_archive` and `agent_rust_keep_versions` take the role's
  defaults and are checked like the role checks them. A pinned release is
  downloaded (or uploaded) and must have the pinned sha256 and hold only the
  regular files `nyxmon-agent` and `LICENSE`. It is installed root-owned to
  `/opt/nyxmon-agent/<version>/` and validated with `--version` and
  `--check-schema` as the service user. A rejected fresh install is removed
  again, and an installed version from another archive stops the deploy.
  `rust` writes the role's `agent-impl.conf` (vendored, compared byte for
  byte), `python` removes it; a switch restarts only `nyxmon-monitor`, and
  `.previous-version` keeps the rollback target. The agent check follows the
  selected implementation, and old versions are pruned after it. The host
  steps are `services/nyxmon/files/agent.sh`; the new smoke test
  `tests/smoke/test_nyxmon_agent_smoke.py` runs it on the smoke VM against
  bad archives, failing candidates and the pruning rules.
- Git source: `ops_deploy.core.git_source.fetch_source` fetches a service's
  code from its git remote at a branch, tag or full commit (default: the
  remote's default branch) on the controller, with the operator's own git and
  SSH setup, into a fresh directory that the deploy syncs like a checkout;
  hosts need no git credentials. It fails closed on a missing ref, a name
  that is both a branch and a tag, another commit than asked for or a file
  that is not byte for byte its committed blob (attributes and filters are
  switched off; LFS and submodules are refused), and refuses repository URLs
  with credentials. `MarinaConfig` and `HeisConfig` gain
  `source_commit`; their deploys end with `record_source` (new in
  `ops_deploy.helpers`), which keeps the commit in
  `<site>/.ops-deploy-source` (removed for a local working tree), so a re-run
  of the same ref changes nothing. See [Git source](concepts/git-source.md).

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
  - `nyxmon`: `agent_impl` mirrors the role's `nyxmon_agent_impl`: with
    `python` the Rust agent drop-in `agent-impl.conf` is removed and a
    read-only check proves the monitor runs the venv's `start-agent` (the
    role's `agent_verify.yml`). Installing and selecting the Rust agent
    followed later (see the `nyxmon` entry above).
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
  connector, parity and smoke tests; see heis (its page was removed with the module).

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
  and `tests/smoke/test_marina_smoke.py`; its page was removed with the module (see [django_site](services/django_site.md)).

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
