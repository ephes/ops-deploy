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
| `source_excludes` | the role's | plus `.inventory-releases.lock`, as the role adds |
| `python_version`, `uv_sync_args`, `uv` | `3.12`, `--no-default-groups --no-dev`, `None` | `uv=UvInstallConfig()` runs `uv_install` as the role does; by default uv must be at `/usr/local/bin/uv` |
| `django` | `Django()` | settings module, allowed hosts, CSRF origins, admin/login URLs, cookie age |
| `influx` | `Influx()` | image `influxdb:2.7`, container, ports, data and config dirs with their numeric owners, org, bucket, measurement, `retention_apply`/`bucket_retention` |
| `grafana` | `Grafana()` | image `grafana/grafana-oss`, container, ports, data dir (`472:472`), provisioning and dashboards paths, admin user, InfluxDB login name, `base_url` |
| `runtime` | `Runtime()` | unit `graphyard-runtime`, Compose project, compose path, Docker network, `migrate_unmanaged_containers`, `docker`; `None` = no runtime |
| interval, heartbeat and SQLite fields | the role's | the env file's `GRAPHYARD_*` values |
| `web_*`, `agent_*` | the role's | unit names, bind address, workers, restart delays |
| `healthcheck` | `HealthCheck()` | `None` skips the health checks |
| `metric_specs` | `None` | `MetricSpecs(specs, prune)`: write and apply the declarative specs |
| `inventory_release_sources` | `None` | the weekly public release refresh; `None` stops an installed timer |
| `skip_django_manage` | `False` | no `manage.py` command (the role's emergency switch) |

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
7. Bucket retention: read with `influx bucket list`, updated only when it
   differs.
8. Release refresh: registry file, `--check` validation (read-only), units and
   timer.
9. Web and agent units, restarted when code, venv, dependencies, the env file
   or their unit changed. Then the health checks (port, `/v1/health` with
   `X-Forwarded-Proto: https`, both units active) and the source record.

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

`host_id` and `ingest_url` (required), `service_id`, `source_tag`,
collectors, metric prefixes, filesystem mountpoint excludes, sink tuning.
Linux only (apt and systemd); the role's Homebrew/launchd branch for macOS
stays on Ansible. Installs Vector from apt, creates the data and config
directories, validates the config directory with this fragment and the global
fragment swapped in (`vector validate --config-dir`, like the role without
`--skip-healthchecks`) before anything live changes, points
`/etc/default/vector` at `config.d`, removes the legacy `vector.yaml`, writes
the shared `00-global.yaml` (a different `data_dir` already there stops the
deploy) and the Graphyard fragment, and restarts Vector when one of them
changed. The Logyard producer shares the directory, the global fragment and
the service.

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

Logyard's deploy writes its datasource file and dashboards into Graphyard's
site (`deploy/grafana/...`, excluded from Graphyard's sync) and sets them to
`root:root`; Graphyard's deploy sets the whole site to `graphyard`. Both
roles do this today and both ports mirror it: whichever ran last wins, and a
Logyard deploy after a Graphyard deploy restarts Grafana once.

Docker creates `deploy/grafana/provisioning/dashboards-json/` in the site as
the mount point of the dashboards bind mount whenever Grafana starts. The
source sync (`--delete`, no exclude, as in the role) removes it, which
detaches the dashboards mount in the running Grafana container: dashboards
already loaded stay, file changes are not provisioned until Grafana restarts.
The port keeps this behaviour of the role.

## Differences from the roles

- The `graphyard` user is a system user created without a skeleton home
  (`system_user`); an existing user is left as it is.
- `rsync` is installed with apt when missing (the role assumes it).
- `uv_install` does not run unless `uv` is set: the role installs its pinned
  uv (0.13.0) on every deploy and so replaces a newer uv on the host.
- In the stack, the auth step also plans the provisioning file rewrite when
  the file the source sync installs needs one (the role's sync and rewrite
  then take turns on every run, as here).
- On a fresh stack the auth steps cannot read Grafana while planning; they
  check on the host instead, and the datasource URL step restarts Grafana once.
- Services restart in the order of their steps, not all at the end.

## Tests

`tests/test_graphyard_parity.py`, `tests/test_graphyard.py`,
`tests/test_graphyard_parts.py` (fake connector: first runs, converged
no-ops, each kind of change and what it restarts, secrets never on a command
line) and `tests/test_graphyard_scripts.py` (the probes and host scripts run
through bash and fish). The Ansible/pyinfra coexistence smoke lives in
ops-control (`just smoke-graphyard-coexistence`).
