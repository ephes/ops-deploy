# logyard

Ports of the `logyard_deploy`, `logyard_ingress_deploy` and
`logyard_vector_deploy` Ansible roles together with the steps ops-control's
playbooks run around them. Logyard is Loki in Docker Compose (data under
`/var/lib/logyard/loki`), wired into the shared Graphyard Grafana, with a
private Traefik route for producers and a Vector journald producer per host.

```python
from ops_deploy.services.logyard import (
    LogyardConfig,
    LogyardIngressConfig,
    LogyardStackConfig,
    LogyardVectorConfig,
    NyxmonChecks,
    deploy_logyard,
)

cfg = LogyardStackConfig(
    core=LogyardConfig(
        source_path=Path("~/projects/logyard").expanduser(),
        secrets=SecretRef("secrets/prod/nyxmon.yml"),
        nyxmon=NyxmonChecks(
            suppression_url="http://macmini:9106/.well-known/os-apt-maintenance", suppression_reason="macmini"
        ),
    ),
    ingress=LogyardIngressConfig(host="logyard.example.com"),
    vector=LogyardVectorConfig(host_id="macmini"),
)
deploy_logyard(cfg, secrets)  # core, ingress, Vector: deploy-logyard.yml's order
```

Four entry points, as there are four playbooks: `deploy_logyard` (stack),
`deploy_logyard_core(cfg, secrets)`, `deploy_logyard_ingress(cfg)` and
`deploy_logyard_vector(cfg)`. The roles' dependencies are ported as
[`deploy_docker_install` and `deploy_vector_apt_install`](../infra.md).

All files are byte-identical to the roles' (templates shipped unchanged,
`tests/test_logyard_parity.py` renders the vendored copies independently), so
Ansible and ops-deploy can take turns on a host without rewriting anything or
restarting anything.

## Secret

Only the core deploy needs one: `nyxmon_storage_metrics_password`, used as
the basic-auth password inside the Nyxmon checks' notification-suppression
block. It reaches the host on stdin only; the read-only probe compares
digests, never the stored password.

## Core (`LogyardConfig`)

| Field | Default | |
|---|---|---|
| `source_path` | required | Logyard checkout; needs `README.md`, `docs/operational-assumptions.md`, the home dashboard (the role's checks). The rsync method only; git follows after Phase 4 |
| `service_name`, `user`, `group` | `logyard` | |
| `home`, `site_path` | `/opt/apps/logyard`, `<home>/site` | compose file in `home`, config in `/etc/logyard` |
| `source_excludes` | the role's | `.git`, `.venv`, `__pycache__`, `*.pyc`, `.vault_password` |
| `docker_network_name` | `graphyard-monitoring` | shared with Grafana |
| `docker` | `DockerInstallConfig()` | |
| `loki` | `Loki()` | image `grafana/loki:3.5.11`, container, ports 3101/3100, data dir and its numeric owner `10001`, retention `336h`, schema, cache |
| `grafana` | `GrafanaWiring()` | `None` skips the wiring; container `graphyard-grafana`, datasource and dashboards paths in the Graphyard tree |
| `health` | `HealthEndpoint()` | `None` skips the endpoint; `127.0.0.1:9105/.well-known/logyard`, selector, freshness windows, `units` reported under `$.units.<id>`; `httpd_impl` (`python`), `httpd_rust_version`, `httpd_rust_sha256` select its HTTP server (the role's `logyard_health_impl` and the release pin, see [metrics-httpd switch](metrics_httpd.md)) |
| `ready_checks` | `ReadyChecks()` | 18 tries, 5 s; `None` skips |
| `nyxmon` | required | `NyxmonChecks`: database path/user, service name, health URL, interval, suppression URL and reason |

### What the core deploy does

1. Docker Engine and Compose (`docker_install`).
2. Group and nologin user `logyard`, `home` and `site_path`, `/etc/logyard`,
   Loki's data directory (`10001:10001 0755`; compared by numeric id, since
   `stat` prints `UNKNOWN` for ids without a name). Existing data is untouched.
3. `rsync` and the source sync (`--checksum`, `--delete`, owned by `logyard`).
4. Docker network (created if missing), Loki config, compose file, unit; the
   unit is enabled and started, and restarted only when one of the three
   changed (and not right after being started).
5. Grafana wiring: requires the container to exist (fails otherwise), joins
   it to the network, writes the datasource provisioning file and the
   dashboards below `<dashboards_root>/logyard` (`root:root`, `0755`/`0644`;
   files other than the dashboards keep their content and get the same
   owner and mode), starts the container if stopped. The datasource
   directory and the dashboards root are Graphyard's: they are created when
   missing, their owner and mode are left alone (see the ownership rule on
   the [graphyard](graphyard.md) page). The container restarts
   once, at the end, only if something above changed. The role copies the
   dashboards on the host after the sync; here they are put from the
   controller's checkout (the same bytes), so a change is known while
   planning.
6. Health endpoint script and unit, and the HTTP server switch's select
   step ([metrics-httpd switch](metrics_httpd.md); `metrics-httpd
   logyard-health --check-config` runs as `logyard` with exactly the unit's
   `Environment=` lines); restarted when the script, the unit or the drop-in
   changed. Then the switch's verify step: the unit runs the selected server
   and answers 200 with a JSON `status`; then the pin and the prune.
7. Read-only: Loki `/ready`, and the endpoint reporting `loki.ready`.
8. The playbook's post task: the three json-metrics checks in Nyxmon's SQLite
   database (skipped when `/home/nyxmon/site/db.sqlite3` is missing, as
   there). A read-only probe compares digests of what the database holds with
   what would be written; the upsert (the playbook's script, run as `nyxmon`)
   happens only when they differ, so a hand-edited check is repaired and a
   converged run writes nothing.

The playbook's Nyxmon checks read `$.units.vector.*`, so `health.units` should
name the `vector` unit on a host that runs the producer (the ops-control
registration does for macmini); the defaults, like the role's, report none.

Differences from the role: the apt `rsync` package is installed (the role
assumes it); `/var/lib/logyard` is created `root:root` by `mkdir -p` where
Ansible's `file` gives intermediate directories the leaf's owner; services
restart in the order of their steps instead of all at the end; the shared
Grafana directories keep Graphyard's owner (the role sets them to
`root:root`).

## Ingress (`LogyardIngressConfig`)

`host` (required, not the example), `backend_url`, `traefik_cert_resolver`,
`root_redirect_enabled`/`root_redirect_url`, `middlewares`, `allowed_paths`
(default: `POST /loki/api/v1/push`, `GET|HEAD /ready`; Loki has no auth, so
nothing else is routed), `internal_ip_ranges`. Writes
`/etc/traefik/dynamic/logyard.yml`; Traefik is not restarted (file provider).

## Vector (`LogyardVectorConfig`)

`host_id` (required), `ingest_endpoint`, `environment`, unit and match
filters, `current_boot_only`, sink tuning. Installs Vector from apt, writes the
shared `00-global.yaml` (`data_dir`; a different `data_dir` already on the host
stops the deploy) and the Logyard fragment, points `/etc/default/vector` at the
config directory, removes the legacy `/etc/vector/vector.yaml`, validates the
staged directory with `vector validate --skip-healthchecks` before replacing
either file (before the defaults file or the legacy config are touched), and restarts Vector when a file changed (also on the install
run: the package may have started it with the stock config).

The template-confinement opt-out is chosen from `vector --version` while
planning. On a host without Vector the configured default
(`supports_template_confinement`, `True`) applies; validation stops a wrong
guess before it reaches the running service, and the next run corrects it.

## Tests

`tests/test_logyard_parity.py`, `tests/test_logyard.py`,
`tests/test_logyard_ingress_vector.py` and `tests/test_infra_docker_vector.py`
(fake connector: first runs, converged no-ops, each kind of change and what it
restarts, secret handling, config validation). The Ansible/pyinfra coexistence
smoke lives in ops-control (`just smoke-logyard-coexistence`).

## Per-container replacement CA store

`loki.ca_store_root` optionally names an absolute host directory containing prepared
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
