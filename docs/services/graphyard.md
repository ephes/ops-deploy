# graphyard

Ports of the `graphyard_deploy`, `graphyard_vector_deploy`,
`graphyard_ingress_deploy` and `graphyard_auth_bootstrap_deploy` Ansible roles
together with the steps ops-control's playbooks run around them. Graphyard is a
Django app (granian web unit and an agent unit) with InfluxDB 2 and Grafana in
Docker Compose under one systemd unit, a Traefik route for the app and
Grafana, a Vector host-metrics producer per host, and a reconcile of the login
credentials.

```python
from ops_deploy.services.graphyard import (
    GraphyardAuthConfig,
    GraphyardConfig,
    GraphyardIngressConfig,
    GraphyardStackConfig,
    GraphyardVectorConfig,
    deploy_graphyard,
)

cfg = GraphyardStackConfig(
    core=GraphyardConfig(
        source_path=tree.path, source_commit=tree.commit, secrets=SecretRef("secrets/prod/graphyard.yml")
    ),
    vector=GraphyardVectorConfig(host_id="macmini", ingest_url="http://127.0.0.1:8051/v1/metrics"),
    ingress=GraphyardIngressConfig(graphyard_host="graphyard.example.com", grafana_host="grafana.example.com"),
    auth=GraphyardAuthConfig(grafana_shared_network_name="graphyard-monitoring"),
)
deploy_graphyard(cfg, secrets)  # core, Vector, ingress, auth: deploy-graphyard.yml's order
```

Five entry points, as there are five playbooks: `deploy_graphyard` (stack),
`deploy_graphyard_core(cfg, secrets)`, `deploy_graphyard_vector(cfg, secrets)`,
`deploy_graphyard_ingress(cfg, secrets)` and `deploy_graphyard_auth(cfg, secrets)`.
The roles' dependencies are the ported [`docker_install`, `vector_apt_install`](../infra.md)
and, on request, [`uv_install`](../base.md).

All files are byte-identical to the roles' (templates shipped unchanged,
`tests/test_graphyard_parity.py` renders the vendored copies independently),
so Ansible and ops-deploy can take turns on a host. Unlike the roles, steps
that would change nothing are skipped: a converged host sees no file written,
no command that writes run and nothing restarted.

## Secrets

| Key | Part | |
|---|---|---|
| `django_secret_key`, `influx_token` | core | the env file; the Influx token is also the InfluxDB init password and admin token (the role's defaults) |
| `grafana_admin_password`, `grafana_influx_password` | core (with a runtime), auth | compose file; Grafana's InfluxDB v1 login |
| `inventory_monitor_token` | core | must be present; empty disables machine access, else 32-128 URL-safe characters |
| `homeassistant_api_token`, `nyxmon_storage_metrics_password`, `homeassistant_unifi_password` | core | only when a metric collection spec refers to them |
| `vector_ingest_token` | Vector | |
| `basic_auth_password`, `basic_auth_user` (optional) | ingress | Traefik basic auth |
| `django_bootstrap_username`, `django_bootstrap_password` | auth | |

The env file, the compose file, the metric spec file and the Vector fragment
hold secrets and are written with `secret_file` (stdin, never a command line
or an upload). Commands that need a credential read it from stdin: the
InfluxDB v1 login check and creation, the Django user reconcile, the Grafana
password reset and the datasource health check. `django_secret_key` and
`influx_token` are written unquoted into the env file, which systemd reads and
bash sources (the role's `manage.py` commands), so values with whitespace,
quotes, backslashes or `` $ ` ; & | < > ( ) ~ `` are refused before any
connection.

## Core (`GraphyardConfig`)

| Field | Default | |
|---|---|---|
| `source_path` | required | a Graphyard tree with `src/django`, `src/graphyard`, `pyproject.toml`, `uv.lock` (the role's checks): a checkout or a [git source](../concepts/git-source.md) |
| `source_commit` | `None` | the git source's commit, recorded in `<site>/.ops-deploy-source` |
| `user`, `group`, `home`, `site_path`, `env_dir` | `graphyard`, `/opt/apps/graphyard`, `<home>/site`, `/etc/graphyard` | |
| `source_excludes` | the role's | plus `.inventory-releases.lock`, as the role adds; `agent-rs/target/` (the Rust agent's Cargo output) is one of the role's |
| `python_version`, `uv_sync_args`, `uv` | `3.12`, `--no-default-groups --no-dev`, `None` | `uv=UvInstallConfig()` runs `uv_install` as the role does; by default uv must be at `/usr/local/bin/uv` |
| `django` | `Django()` | settings module, allowed hosts, CSRF origins, admin/login URLs, cookie age |
| `influx` | `Influx()` | image `influxdb:2.7`, container, ports, data and config dirs with their numeric owners, org, bucket, measurement, `retention_apply`/`bucket_retention` |
| `grafana` | `Grafana()` | image `grafana/grafana-oss`, container, ports, data dir (`472:472`), provisioning and dashboards paths, admin user, InfluxDB login name, `base_url` |
| `runtime` | `Runtime()` | unit `graphyard-runtime`, Compose project, compose path, Docker network, `migrate_unmanaged_containers`, `docker`; `None` = no runtime |
| interval, heartbeat and SQLite fields | the role's | the env file's `GRAPHYARD_*` values |
| `web_*`, `agent_*` | the role's | unit names, bind address, workers, restart delays |
| `agent_impl` | `python` | the role's `graphyard_agent_impl`: `python` (the venv's `manage.py start_agent`) or `rust`; see [Agent](#agent-python-or-rust) |
| `agent_rust_version` | `""` | Rust release to install, e.g. `0.1.0`; empty installs, validates and prunes nothing. Required for `rust` |
| `agent_rust_sha256` | `""` | sha256 of the release archive (64 lowercase hex digits); required with a version unless `agent_rust_local_archive` is set |
| `agent_rust_release_url` | the GitHub release asset | download URL; `{version}` stands for the version |
| `agent_rust_local_archive` | none | controller path of an archive with the release layout, uploaded instead of the download; checked against `agent_rust_sha256` when both are set |
| `agent_rust_install_root` | `/opt/graphyard-agent` | versions go to `<root>/<version>/graphyard-agent`; absolute, not `/`, no trailing slash |
| `agent_rust_keep_versions` | `3` | newest installed versions the pruning keeps |
| `healthcheck` | `HealthCheck()` | `None` skips the health checks |
| `metric_specs` | `None` | `MetricSpecs(specs, prune)`: write and apply the declarative specs |
| `inventory_release_sources` | `None` | the weekly public release refresh; `None` stops an installed timer |
| `skip_django_manage` | `False` | no `manage.py` command (the role's emergency switch) |

`Influx.data_dir_mode` defaults to `"0755"` (the role's mode). Set `"0700"`
for an existing installation whose InfluxDB process keeps its data directory
private; convergence then preserves that mode instead of loosening it on
each deploy.

### What the core deploy does

1. Group and user `graphyard` (shell bash), home and site, `/etc/graphyard`
   (`root:graphyard 0750`).
2. The source sync (`--checksum`, `--delete`, owned by `graphyard`), then the
   role's recursive owner fix of the site, only when a file has another owner
   or group.
3. Docker Engine and Compose; `/var/lib/graphyard` and the InfluxDB and
   Grafana data directories with their numeric owners (compared by id); the
   Grafana provisioning assets must exist; the Docker network; containers with
   the runtime's names that Compose does not own are removed (the role's
   takeover); compose file (`root:root 0640`) and runtime unit; the unit is
   enabled and started and restarted only when one of them changed or a
   container was removed. InfluxDB must answer `influx ping`.
4. Grafana's InfluxDB v1 login: probed by name (`influx v1 auth list`),
   created only when missing, then checked with its password on every run
   (read-only). Creation and check go through InfluxDB's HTTP API on the
   published port (the endpoints `influx v1 auth create` calls) from a small
   Python script on the host, with the admin token and the password on stdin;
   the role passes the password on the `influx` command line.
5. `uv_install` when configured, the venv (created once), `uv sync` when its dry run finds
   work or the source sync or owner fix touched the site (uv decides whether
   to reinstall the project from file metadata both change).
6. The env file (`root:graphyard 0640`); migrate when one is pending or code,
   dependencies or the env file changed; collectstatic when its dry run
   (`--dry-run`, read-only) would copy something or code, dependencies or the
   env file changed; the database's owner and mode; the metric specs file
   and `apply_metric_collection_specs` when the file changed, a migration ran
   or Graphyard holds other specs (a read-only probe compares digests of the
   rows with the file's specs as the command normalises them).
7. With `agent_rust_version` set: the pinned Rust agent release is installed
   (once) and validated against the migrated database (see
   [Agent](#agent-python-or-rust)).
8. Bucket retention: read with `influx bucket list`, updated only when it
   differs.
9. The web and agent unit files and the agent drop-in `agent-impl.conf`
   (written for `rust`, removed for `python`). With a runtime, both units
   have `Wants=` and `After=` on it, not `Requires=`. A restart, a stop and
   start, or a failed start of `graphyard-runtime` leaves web and agent
   running. The container CA activation stops and starts that unit, and with
   `Requires=` web and agent stayed down afterwards. The role README's
   "Unit dependencies" section has the comparison and its systemd test. Release refresh: registry file,
   `--check` validation (read-only), units and timer.
10. Web and agent units started, restarted when code, venv, dependencies, the
    env file or their unit changed (the agent also when its drop-in changed). Then the
    check that the agent unit runs the selected agent, the pruning of old Rust
    agent versions (with a version set), the health checks (port,
    `/v1/health` with `X-Forwarded-Proto: https`, both units active) and the
    source record.

### Agent (Python or Rust)

The port of the role's `agent_rust.yml` and `agent_verify.yml` (ops-library
`08faab6a`; the contract is section 8.3 of graphyard's `agent-rs/PLAN.md`).
`graphyard-agent.service` runs the Python agent from the venv (`manage.py
start_agent`) or its Rust port `graphyard-agent`, a single binary published as
a graphyard GitHub release (`agent-rs-v<version>`). Both use the same
database, env file, user and working directory, so only one runs at a time.
The host-side steps are one script, `services/graphyard/files/agent.sh`
(`install`, `validate`, `prune`), ported from nyxmon's; nyxmon's module is
left as it is (a shared helper is a later decision).

1. **Install.** With `agent_rust_version` set and `<root>/<version>/` missing,
   after the migrations: the archive is downloaded on the host with `curl`
   (or `agent_rust_local_archive` is uploaded), its sha256 must be the pinned
   one, and `tar --list` must show exactly the regular files `graphyard-agent`
   and `LICENSE`, once each (links, devices, directories and other members are
   refused before anything is extracted). It is unpacked into
   `<root>/.staging/`, made root-owned (`graphyard-agent` `0755`), the
   checksum is recorded in `<root>/<version>/.archive-sha256`, and the
   directory is moved into place. A pinned version is installed with either
   implementation, so the binary can be in place before the switch.
2. **Validate.** As the service user, by the versioned path and without the
   env file: `graphyard-agent --version` must print `graphyard-agent <version>
   (<commit>)` and `graphyard-agent --check-schema --db <django>/db.sqlite3`
   must pass. A fresh install that fails is removed again and nothing is
   switched. An installed version is validated read-only on every deploy.
3. **Never in place.** An installed version whose `.archive-sha256` is not
   the pinned checksum (or is missing) stops the deploy before any change.
4. **Select.** `rust` writes
   `/etc/systemd/system/graphyard-agent.service.d/agent-impl.conf` (an
   `ExecStart=` override naming the versioned binary with `--db`; the role's
   template shipped unchanged, see `tests/test_graphyard_parity.py`); `python`
   removes it. The base unit (`User`, `EnvironmentFile`, `WorkingDirectory`,
   `Wants=`/`After=graphyard-runtime.service`) applies to both. The version is part
   of the file, so a switch or a version change reloads systemd and restarts
   the agent (not the web unit), and a deploy that changes neither restarts
   nothing for it. When the selection moves away from a Rust version whose
   directory still exists, that version is written to
   `<root>/.previous-version` (the rollback target).
5. **Check.** After the restarts, every run (read-only, 10 tries 3 s apart):
   for `rust`, `readlink /proc/<pid>/exe` is the versioned binary; for
   `python`, the argv holds `<venv>/bin/python`, `manage.py` and
   `start_agent` and the executable is not below the install root.
6. **Prune.** With a version set, after the check: version-shaped
   directories beyond the `agent_rust_keep_versions` newest (by mtime) are
   removed, except the pinned version, the one in `.previous-version` and the
   one the live process runs. Other entries are never touched. A dry run
   plans the pruning; it runs when that finds something, or when this deploy
   installed a version or changed the drop-in.

Rollback is a switch: `agent_impl="python"` removes the drop-in and restarts
the agent on the venv's `manage.py start_agent`. The binary stays installed,
so switching forward again downloads nothing. For a bad release, pin the
previous version and its checksum again; it is still installed. Emergency on
the host: remove the drop-in, `systemctl daemon-reload`, restart
`graphyard-agent`, then set `agent_impl` to `python` before the next deploy.

## Ingress (`GraphyardIngressConfig`)

`graphyard_host`, `grafana_host` (required, not the examples), backend URLs,
`traefik_cert_resolver`, middlewares, `basic_auth_enabled`/`basic_auth_user`,
`internal_ip_ranges`, `inventory_enabled` (the private inventory router).
Writes `/etc/traefik/dynamic/graphyard.yml`; the bcrypt hash already in the
file is reused while it matches, and Traefik is not restarted (file
provider). With `manage_graphyard_env` it sets `DJANGO_ALLOWED_HOSTS`,
`DJANGO_CSRF_TRUSTED_ORIGINS`, `GRAFANA_BASE_URL` and (when set)
`DJANGO_ADMIN_URL` in the env file like `lineinfile` does (the last matching
line replaced, else appended, owner and mode kept, a
`<file>.<pid>.<time>~` backup before a change) and restarts web and agent when
a line changed. Only those lines are read while planning; the file holds
secrets.

The core deploy renders the same keys from its own config, so the two must
agree (ops-control builds both from the same inventory values); otherwise
each run of one rewrites what the other wrote, as with the roles.

## Vector (`GraphyardVectorConfig`)

When the global and producer fragments already match the rendered content,
`root:vector` ownership and `0640` mode, validate the existing live directory
without staging files. This observational check preserves the existing
health-check policy. Any content or metadata drift uses staged validation
before replacing either live fragment. Staging creates and removes temporary
files and is counted as a mutating operation; a fully converged repeat uses
only the live-directory check.

`host_id` and `ingest_url` (required), `service_id`, `source_tag`,
collectors, metric prefixes, filesystem mountpoint excludes, sink tuning.
The default branch uses Linux apt and systemd. It installs Vector from apt,
creates the data and config
directories, validates the config directory with this fragment and the global
fragment swapped in (`vector validate --config-dir`, like the role without
`--skip-healthchecks`) before anything live changes, points
`/etc/default/vector` at `config.d`, removes the legacy `vector.yaml`, writes
the shared `00-global.yaml` (a different `data_dir` already there stops the
deploy) and the Graphyard fragment, and restarts Vector when one of them
changed. The Logyard producer shares the directory, the global fragment and
the service.


### Native macOS producer

Select the role's existing Homebrew/launchd branch with the nested typed
`darwin` configuration. No Linux logging or shell feature is invented for
macOS. The Graphyard fragment and global config use the same role templates.

Homebrew 6 requires its owner to trust third-party formulae before loading
them. For a fresh owner the role's declared formula can be selected with
`brew trust --formula vectordotdev/brew/vector`. That existing Homebrew trust
prerequisite is separate from deployment: this API does not manage the owner's
trust store or upgrade Homebrew. An already-installed producer keeps its
existing package, tap and trust selection.

```python
from ops_deploy.services.graphyard import (
    GraphyardVectorConfig,
    GraphyardVectorDarwinConfig,
    deploy_graphyard_vector,
)

cfg = GraphyardVectorConfig(
    host_id="workstation",
    service_id="workstation_host_metrics",
    ingest_url="https://graphyard.example.com/v1/metrics",
    filesystem_mountpoint_excludes=("/Volumes/Backups of workstation",),
    darwin=GraphyardVectorDarwinConfig(brew_user="operator"),
)
deploy_graphyard_vector(cfg, secrets)  # vector_ingest_token, as above
```

| Native field | Default/behavior |
|---|---|
| `brew_user` | Required existing Homebrew owner; commands use that owner's home and sudo context. |
| `brew_bin`, `binary_path` | Resolve `/opt/homebrew/bin/brew` then `/usr/local/bin/brew`; Vector defaults to `<brew prefix>/bin/vector`. |
| `brew_package`, `brew_service_name` | `vector`; ensures the `vectordotdev/brew` tap and installs an absent formula. Installed formulas are not upgraded. |
| `brew_update` | `false`; explicit `true` requests Homebrew metadata update, not formula upgrade. That requested update is a mutation. |
| `disable_brew_service` | `true`; stop a registered/running Homebrew Vector service to avoid duplicate producers. |
| `runtime_user`, `runtime_group`, `validation_group` | Existing `root`, `wheel`, `wheel`; the role does not create runtime accounts. |
| `launchd_label`, `launchd_plist_path` | `de.wersdoerfer.graphyard.vector`, `/Library/LaunchDaemons/<label>.plist`. |
| `launchd_keepalive`, `launchd_path` | `true`; `/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin`. Working directory is the main config's `data_dir`. |
| `log_dir`, `stdout_log_path`, `stderr_log_path` | `/var/log/vector`; derived `graphyard-vector.log` and `graphyard-vector.err.log` within it. |
| `newsyslog_conf_path`, `log_rotation_enabled` | `/etc/newsyslog.d/graphyard-vector.conf`, `true`. |
| `log_rotation_owner_group`, `log_rotation_mode` | `root:wheel`, `640`. |
| `log_rotation_count`, `log_rotation_size_kb` | `7`, `10240`. |
| `log_rotation_when`, `log_rotation_flags` | `*`, `ZN`. |

Darwin's default filesystem excludes are empty; Linux retains its Docker
excludes. Literal spaces in exclude paths are JSON-quoted; control characters
are rejected. The native branch retains shared fragments and buffer contents,
uses nonrecursive directory ownership/mode convergence and asserts the same
shared global `data_dir`. It validates a complete private candidate directory
before publishing configuration. The ingest token reaches apply only on
masked stdin, never argv, environment or debug host data; validation errors
never forward output that could quote credentials.

Intentional plist or pipeline changes restart the selected launchd job.
Missing/stopped jobs are recovered. Matching live configuration and a running
job retain their PID, even if a formula's installed binary changed separately.
A no-op creates no uploaded helper, staging directory or marker; its explicit
read-only verification validates the live directory. An active Vector process
may naturally append/rotate buffers or write logs: that daemon activity is
separate from deployment mutations. Do not freeze or hash large live buffers
to establish idempotence; compare config metadata, job identity and buffer
ownership/path/inode continuity.

The owned workflow `host-exceptions-native.yml` exercises both native hostname
and Vector branches on a disposable hosted macOS runner, with unique label,
paths and local ingest endpoint. It installs an absent real formula, exercises
present/update/config/fault/recovery/duplicate-service paths, and records actual
version/hash, source/installed resource parity and zero-repeat results. It
never uses an inventory machine as a fixture or reads private logs/buffers.
On the Homebrew 6 runner, setup trusts only the exact role formula using the
standard command above. The tap and formula remain absent until the API adds
and installs them. Evidence classifies this owned trust setup separately from
installer/configuration operations; it is not a production trust-policy change.

## Auth bootstrap (`GraphyardAuthConfig`)

A deploy-time reconcile, not a one-time bootstrap: `deploy-graphyard.yml`
runs the role after every stack deploy and each of its steps compares before
it writes. Here the comparisons happen while planning:

- the Django user (active, staff, superuser, the secret's password) through
  `manage.py shell` as the role reads it; the probe prints digests and the
  hash parameters, the password is checked on the controller (PBKDF2-SHA256);
  on a difference the role's own script runs with the credentials on stdin;
- Grafana's admin password (the role's PBKDF2 check, on the controller),
  datasource URL and lockout rows from Grafana's database (read-only); the
  datasource provisioning file with the role's rewrite logic in a dry mode.

Writes happen only on a difference: InfluxDB attached to the shared network,
the datasource URL in the database and the provisioning file (Grafana
restarts then), the admin password reset (`grafana cli ...
--password-from-stdin` instead of the role's argument; verified afterwards),
the lockout rows deleted. The InfluxDB ping from Grafana and the datasource
health through the API are checked on every run (read-only). Only the shared
network mode is ported (`grafana_shared_network_name` is required); the
role's container-IP fallback stays on Ansible.

## Living with Logyard

Logyard's Grafana files live in Graphyard's site. One rule, implemented in
both ports, decides who owns what below `/opt/apps/graphyard/site/deploy/grafana`:

| Path | Written by | Owner, mode |
|---|---|---|
| `provisioning/datasources/logyard.yaml` | Logyard | `root:root 0644` |
| `dashboards/logyard/` and everything in it | Logyard | `root:root 0755` / `0644` |
| everything else, the directories `provisioning/datasources/` and `dashboards/` included | Graphyard | `graphyard:graphyard` |

Graphyard's sync excludes Logyard's two paths (the role does too), and its
ownership step skips them (`foreign_paths`, default the two Logyard paths);
Logyard's deploy creates the two shared directories only when they are
missing and never changes their owner or mode. The roles still fight over
these paths (the Graphyard role chowns the whole site, the Logyard role sets
the shared directories to root), so an Ansible deploy of either brings the
old ping-pong back for one round; the next pyinfra deploy of Graphyard takes
the shared directories back once, and Logyard's pyinfra deploy, which only
reads them, does not react.

Docker creates `deploy/grafana/provisioning/dashboards-json/` in the site as
the mount point of the dashboards bind mount whenever Grafana starts. The
role's sync (`--delete`) removes it, which detaches the dashboards mount in
the running Grafana container (loaded dashboards stay, file changes are not
provisioned until Grafana restarts). The port excludes it from the sync, so
it survives; its owner becomes `graphyard` like the rest of the site.

## Differences from the roles

- The `graphyard` user is a system user created without a skeleton home
  (`system_user`); an existing user is left as it is.
- `rsync` is installed with apt when missing (the role assumes it).
- The sync excludes `deploy/grafana/provisioning/dashboards-json/`, and the
  ownership step skips Logyard's files (see above).
- `uv_install` does not run unless `uv` is set: the role installs its pinned
  uv (0.13.4) on every deploy and so replaces a newer uv on the host.
- In the stack, the auth step also plans the provisioning file rewrite when
  the file the source sync installs needs one (the role's sync and rewrite
  then take turns on every run, as here).
- On a fresh stack the auth steps cannot read Grafana while planning; they
  check on the host instead, and the datasource URL step restarts Grafana once.
- Services restart in the order of their steps, not all at the end.
- The Rust agent archive is downloaded on the host with `curl` (the role uses
  `get_url`), and the archive checks, staging and validation run as one host
  script.

## Tests

`tests/test_graphyard_parity.py`, `tests/test_graphyard.py`,
`tests/test_graphyard_parts.py` (fake connector: first runs, converged
no-ops, each kind of change and what it restarts, secrets never on a command
line) and `tests/test_graphyard_scripts.py` (the probes and host scripts run
through bash and fish). `tests/test_graphyard_agent.py` covers the agent
settings and every agent transition on the fake connector (pin without
switch, first Rust deploy, switch both ways, version change, refused
reinstall, local archive, pruning) and the `validate` step of
`files/agent.sh` through bash and fish with a fake binary;
`tests/smoke/test_graphyard_agent_smoke.py` runs `files/agent.sh` as root on
the smoke VM (install, refused archives and checksums, rejected candidates,
pruning against a live process). The Ansible/pyinfra coexistence smoke lives in
ops-control (`just smoke-graphyard-coexistence`).

## Per-container replacement CA store

`runtime.ca_store_root` optionally names an absolute host directory containing prepared
`<container-name>/bundle.pem` and `<container-name>/empty` stores. The
container retains its pinned application image and receives a read-only mount
at `/run/managed-ca`, with `SSL_CERT_FILE` and `SSL_CERT_DIR` pointing there.
Prepare from each image’s own trust material before deployment, verify the
specific runtime honors the overrides, and refresh preparation after image or
custom CA changes. The default is unset and preserves existing image behavior.
This option replaces default native trust paths; explicit application CA
overrides still require a separate audit.

Refreshing store files alone does not trigger compose change detection. Explicitly
restart/recreate affected containers to discard loaded trust contexts, then repeat
negative and positive TLS probes. The preparation role owns root:root 0755 for
the managed store root; LiveKit declares the same metadata for bind validation.

When replacement trust is enabled, preconditions require the prepared bundle, empty directory and manifest before any service changes. A missing store fails deployment; prepare the target image first rather than allowing Compose to create a missing source.
