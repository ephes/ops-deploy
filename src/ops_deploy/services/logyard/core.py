"""logyard core: Loki in Docker Compose, the shared Grafana wiring and the health endpoint.

Port of the ``logyard_deploy`` Ansible role (rsync method) together with the
steps around it in ops-control's ``playbooks/deploy-logyard-core.yml``: Docker
Engine (``docker_install``) before it, and the Nyxmon health checks after it.
The role's templates are shipped unchanged and rendered the way Ansible's
``template`` module renders them, so every file written is byte-identical to
the role's (``tests/test_logyard_parity.py``) and Ansible and ops-deploy can
take turns on a host without churn.

No data is touched: Loki's data directory only gets its owner and mode, the
Docker network and the Grafana container are only connected or restarted, and
the Nyxmon checks are upserted like the playbook does (one service, three
rows).
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import shlex
from collections.abc import Callable, Sequence
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar

from pydantic import Field, field_validator, model_validator
from pyinfra import host, logger
from pyinfra.api import deploy
from pyinfra.operations import apt, files, server
from pyinfra.operations.util import any_changed

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import mark_read_only, probes, service_rollout, system_user, systemd_unit
from ops_deploy.infra import DockerInstallConfig, docker_steps
from ops_deploy.infra._common import directory
from ops_deploy.ops import secret_stdin, sync_tree
from ops_deploy.services.logyard._common import (
    FILES,
    Hostname,
    ImageRef,
    Part,
    Port,
    Seconds,
    UnitValue,
    Url,
    Word,
    probe,
    render_role,
)

HEALTH_SCRIPT = (FILES / "logyard_health_httpd.py").read_text()
NYXMON_CHECKS = (FILES / "nyxmon_checks.py").read_text()
# The paths the role requires in the source tree before it syncs anything.
REQUIRED_SOURCE_PATHS = (
    "README.md",
    "docs/operational-assumptions.md",
    "deploy/grafana/dashboards/logyard/logyard-home.json",
)
DASHBOARD_SOURCE = PurePosixPath("deploy/grafana/dashboards/logyard")
NYXMON_SUPPRESSION_USER = "nyxmon"
SYSTEMD_UNIT_DIR = PurePosixPath("/etc/systemd/system")


def _absolute(value: PurePosixPath) -> PurePosixPath:
    if not value.is_absolute() or ".." in value.parts or value == PurePosixPath("/"):
        raise ValueError("paths must be absolute, without '..', and not '/'")
    return value


class Loki(Part):
    """The Loki container and its config (the role's ``logyard_loki_*`` and retention variables)."""

    image: ImageRef = "grafana/loki:3.5.11"
    container_name: Word = "logyard-loki"
    host_port: Port = 3101
    http_port: Port = 3100
    data_dir: PurePosixPath = PurePosixPath("/var/lib/logyard/loki")
    # The numeric ids of the container's user; the data directory is chowned to them.
    data_owner: Annotated[str, Field(pattern=r"^[0-9]+$")] = "10001"
    data_group: Annotated[str, Field(pattern=r"^[0-9]+$")] = "10001"
    schema_from: Annotated[str, Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")] = "2024-01-01"
    index_prefix: Annotated[str, Field(pattern=r"^[A-Za-z0-9_]+$")] = "logyard_index_"
    retention_period: Annotated[str, Field(pattern=r"^[0-9]+(ms|s|m|h|d|w|y)$")] = "336h"
    volume_enabled: bool = True
    query_cache_max_size_mb: int = Field(default=100, ge=1)

    @field_validator("data_dir")
    @classmethod
    def _data_dir_absolute(cls, value: PurePosixPath) -> PurePosixPath:
        return _absolute(value)


class GrafanaWiring(Part):
    """Connects the shared Graphyard Grafana container to Loki (datasource and dashboards)."""

    container_name: Word = "graphyard-grafana"
    datasource_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")] = "Logyard Loki"
    datasource_uid: Word = "logyard-loki"
    datasource_is_default: bool = False
    datasource_path: PurePosixPath = PurePosixPath(
        "/opt/apps/graphyard/site/deploy/grafana/provisioning/datasources/logyard.yaml"
    )
    dashboards_root: PurePosixPath = PurePosixPath("/opt/apps/graphyard/site/deploy/grafana/dashboards")

    @field_validator("datasource_path", "dashboards_root")
    @classmethod
    def _absolute_paths(cls, value: PurePosixPath) -> PurePosixPath:
        return _absolute(value)

    @property
    def dashboard_target_dir(self) -> PurePosixPath:
        return self.dashboards_root / "logyard"


class HealthEndpoint(Part):
    """The Nyxmon-facing health endpoint (a small Python HTTP server under systemd)."""

    service_name: ServiceName = "logyard-health-endpoint"
    bind_host: Annotated[str, Field(pattern=r"^[0-9.]+$")] = "127.0.0.1"
    port: Port = 9105
    path: Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~/-]*$")] = "/.well-known/logyard"
    script_path: PurePosixPath = PurePosixPath("/usr/local/bin/logyard_health_httpd.py")
    selector: UnitValue = '{host="macmini",source_type="journald"}'
    warning_window_seconds: Seconds = 900
    critical_window_seconds: Seconds = 3600
    timeout_seconds: Seconds = 10
    # Systemd units reported under ``$.units.<id>`` in the payload; ``id`` has no dot.
    units: tuple[dict[str, str], ...] = ()
    systemctl_timeout_seconds: Seconds = 5

    @field_validator("script_path")
    @classmethod
    def _script_absolute(cls, value: PurePosixPath) -> PurePosixPath:
        return _absolute(value)

    @field_validator("units")
    @classmethod
    def _units_shape(cls, value: tuple[dict[str, str], ...]) -> tuple[dict[str, str], ...]:
        for entry in value:
            if set(entry) != {"id", "unit"} or not all(isinstance(v, str) and v for v in entry.values()):
                raise ValueError("each health unit needs a non-empty id and unit")
            if "." in entry["id"]:
                raise ValueError("health unit ids must not contain a dot")
        return value


class ReadyChecks(Part):
    """Wait for Loki's ``/ready`` and the health endpoint after the rollout (the role's verify.yml)."""

    retries: int = Field(default=18, ge=1, le=1000)
    delay_seconds: int = Field(default=5, ge=0, le=3600)


class NyxmonChecks(Part):
    """The playbook's post-task: three json-metrics checks for the health endpoint in Nyxmon's database."""

    user: UnixUser = "nyxmon"
    db_path: PurePosixPath = PurePosixPath("/home/nyxmon/site/db.sqlite3")
    service_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 ()._-]*$")] = "Logyard (macmini)"
    health_url: Url = "http://127.0.0.1:9105/.well-known/logyard"
    poll_interval_seconds: Seconds = 60
    # Nyxmon's os-apt-maintenance endpoint, which silences notifications while apt runs.
    suppression_url: Url
    suppression_reason: Hostname

    @field_validator("db_path")
    @classmethod
    def _db_absolute(cls, value: PurePosixPath) -> PurePosixPath:
        return _absolute(value)


class LogyardConfig(BaseServiceConfig):
    """The role's variables without the ``logyard_`` prefix (defaults from its defaults/main.yml)."""

    required_secret_keys: ClassVar[tuple[str, ...]] = ("nyxmon_storage_metrics_password",)

    service_name: ServiceName = "logyard"
    user: UnixUser = "logyard"
    group: UnixUser = "logyard"
    home: PurePosixPath = PurePosixPath("/opt/apps/logyard")
    site_path: PurePosixPath = PurePosixPath("/opt/apps/logyard/site")
    # The Logyard checkout on the controller (the rsync method; git is not ported yet).
    source_path: Path
    source_excludes: tuple[str, ...] = (".vault_password", ".git/", ".venv/", "__pycache__/", "*.pyc")
    docker_network_name: Word = "graphyard-monitoring"
    docker: DockerInstallConfig = DockerInstallConfig()
    loki: Loki = Loki()
    # None: no Grafana wiring (the role's logyard_grafana_enabled: false).
    grafana: GrafanaWiring | None = GrafanaWiring()
    health: HealthEndpoint | None = HealthEndpoint()
    # None: no readiness checks at the end (logyard_healthcheck_enabled: false).
    ready_checks: ReadyChecks | None = ReadyChecks()
    nyxmon: NyxmonChecks

    @field_validator("home", "site_path")
    @classmethod
    def _absolute_paths(cls, value: PurePosixPath) -> PurePosixPath:
        return _absolute(value)

    @field_validator("source_path")
    @classmethod
    def _source_is_a_logyard_checkout(cls, value: Path) -> Path:
        value = value.expanduser().absolute()
        if not value.is_dir():
            raise ValueError("source_path must be a directory on the controller")
        missing = [path for path in REQUIRED_SOURCE_PATHS if not (value / path).exists()]
        if missing:
            raise ValueError(f"source_path is not a Logyard checkout (missing {', '.join(missing)})")
        return value

    @field_validator("source_excludes")
    @classmethod
    def _plain_excludes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not pattern or pattern.startswith("-") for pattern in value):
            raise ValueError("rsync excludes must not be empty or start with '-'")
        return value

    @model_validator(mode="after")
    def _unique_names(self) -> LogyardConfig:
        if self.health is not None and self.health.service_name == self.service_name:
            raise ValueError("the health endpoint needs its own service name")
        return self

    @property
    def compose_path(self) -> PurePosixPath:
        return self.home / "docker-compose.yml"

    @property
    def env_dir(self) -> PurePosixPath:
        return PurePosixPath("/etc/logyard")

    @property
    def config_path(self) -> PurePosixPath:
        return self.env_dir / "loki-config.yml"

    @property
    def ready_url(self) -> str:
        return f"http://127.0.0.1:{self.loki.host_port}/ready"

    @property
    def dashboard_source(self) -> Path:
        return self.source_path / DASHBOARD_SOURCE


def role_vars(cfg: LogyardConfig) -> dict[str, Any]:
    """The role's variables, as ``deploy-logyard-core.yml`` sets them."""

    grafana = cfg.grafana or GrafanaWiring()
    health = cfg.health or HealthEndpoint()
    return {
        "logyard_user": cfg.user,
        "logyard_group": cfg.group,
        "logyard_home": str(cfg.home),
        "logyard_service_name": cfg.service_name,
        "logyard_compose_path": str(cfg.compose_path),
        "logyard_config_path": str(cfg.config_path),
        "logyard_docker_network_name": cfg.docker_network_name,
        "logyard_loki_image": cfg.loki.image,
        "logyard_loki_container_name": cfg.loki.container_name,
        "logyard_loki_host_port": cfg.loki.host_port,
        "logyard_loki_http_port": cfg.loki.http_port,
        "logyard_loki_data_dir": str(cfg.loki.data_dir),
        "logyard_loki_schema_from": cfg.loki.schema_from,
        "logyard_loki_index_prefix": cfg.loki.index_prefix,
        "logyard_retention_period": cfg.loki.retention_period,
        "logyard_volume_enabled": cfg.loki.volume_enabled,
        "logyard_query_cache_max_size_mb": cfg.loki.query_cache_max_size_mb,
        "logyard_grafana_datasource_name": grafana.datasource_name,
        "logyard_grafana_datasource_uid": grafana.datasource_uid,
        "logyard_grafana_datasource_is_default": grafana.datasource_is_default,
        "logyard_health_script_path": str(health.script_path),
        "logyard_health_bind_host": health.bind_host,
        "logyard_health_port": health.port,
        "logyard_health_path": health.path,
        "logyard_health_selector": health.selector,
        "logyard_health_warning_window_seconds": health.warning_window_seconds,
        "logyard_health_critical_window_seconds": health.critical_window_seconds,
        "logyard_health_timeout_seconds": health.timeout_seconds,
        "logyard_health_systemctl_timeout_seconds": health.systemctl_timeout_seconds,
        "logyard_health_units": [dict(entry) for entry in health.units],
    }


def render_loki_config(cfg: LogyardConfig) -> str:
    return render_role("loki-config.yml.j2", role_vars(cfg))


def render_compose(cfg: LogyardConfig) -> str:
    return render_role("docker-compose.yml.j2", role_vars(cfg))


def render_service_unit(cfg: LogyardConfig) -> str:
    return render_role("logyard.service.j2", role_vars(cfg))


def render_datasource(cfg: LogyardConfig) -> str:
    return render_role("grafana-logyard-datasource.yml.j2", role_vars(cfg))


def render_health_unit(cfg: LogyardConfig) -> str:
    return render_role("logyard-health-endpoint.service.j2", role_vars(cfg))


# -- Nyxmon checks (the playbook's post_tasks) -------------------------------------


def nyxmon_checks(cfg: NyxmonChecks, password: str) -> list[dict[str, Any]]:
    """The three checks as the playbook's ``NYXMON_CHECKS_JSON`` lists them."""

    suppression = {
        "url": cfg.suppression_url,
        "timeout": 3.0,
        "reason": f"{cfg.suppression_reason}_os_apt_maintenance",
        "status_path": "$.last_status",
        "active_statuses": ["running"],
        "finished_epoch_path": "$.last_run_finished_epoch",
        "active_for_seconds": 900,
        "auth": {"username": NYXMON_SUPPRESSION_USER, "password": password},
    }

    def check(name: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "name": name,
            "check_type": "json-metrics",
            "url": cfg.health_url,
            "check_interval": cfg.poll_interval_seconds,
            "data": {
                "url": cfg.health_url,
                "timeout": 10.0,
                "retries": 1,
                "retry_delay": 2.0,
                "notification_suppression": suppression,
                "checks": checks,
            },
        }

    return [
        check(
            "Logyard API Health (JSON Metrics)",
            [
                {"path": "$.loki.ready", "op": "==", "value": True, "severity": "critical"},
                {"path": "$.status", "op": "!=", "value": "critical", "severity": "critical"},
            ],
        ),
        check(
            "Logyard Ingest Freshness (JSON Metrics)",
            [
                {"path": "$.ingest.warning_fresh", "op": "==", "value": True, "severity": "warning"},
                {"path": "$.ingest.critical_fresh", "op": "==", "value": True, "severity": "critical"},
            ],
        ),
        check(
            "Logyard Vector Producer (JSON Metrics)",
            [
                {"path": "$.units.vector.exists", "op": "==", "value": True, "severity": "critical"},
                {"path": "$.units.vector.active_state", "op": "==", "value": "active", "severity": "critical"},
            ],
        ),
    ]


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def nyxmon_checks_current(probe_output: str, checks: Sequence[dict[str, Any]]) -> bool:
    """Whether Nyxmon's database already holds these checks (compared by digest, see nyxmon_checks.py)."""

    lines = probe_output.splitlines()
    if "service present" not in lines:
        return False
    stored = {tuple(line.split()[1:]) for line in lines if line.startswith("check ")}
    for check in checks:
        state = json.dumps(
            [
                check["check_type"],
                check["url"],
                int(check["check_interval"]),
                json.dumps(check["data"], sort_keys=True),
            ]
        )
        if (_digest(check["name"]), _digest(state)) not in stored:
            return False
    return True


def _nyxmon_command(cfg: NyxmonChecks, mode: str) -> str:
    env = {"NYXMON_DB_PATH": str(cfg.db_path), "NYXMON_SERVICE_NAME": cfg.service_name}
    assignments = [f"{key}={value}" for key, value in env.items()]
    return shlex.join(
        ["runuser", "-u", cfg.user, "--", "env", *assignments, "python3", "-I", "-c", NYXMON_CHECKS, mode]
    )


def _nyxmon(cfg: LogyardConfig, secrets: SecretValues) -> None:
    nyxmon = cfg.nyxmon
    if probe(f"test -f {shlex.quote(str(nyxmon.db_path))} && echo present").strip() != "present":
        logger.info(f"{host.name}: no Nyxmon database at {nyxmon.db_path}, skipping the Logyard Nyxmon checks")
        return
    checks = nyxmon_checks(nyxmon, secrets["nyxmon_storage_metrics_password"])
    check = _nyxmon_command(nyxmon, "probe")
    stored = probes.probe(check, name="Nyxmon Logyard checks")
    current = stored is not None and nyxmon_checks_current(stored, checks)
    secret_stdin(
        name="Upsert Nyxmon Logyard json-metrics checks",
        command=_nyxmon_command(nyxmon, "apply") + " >/dev/null",
        content=SecretContent(json.dumps(checks)),
        _if=lambda: not current,
    )
    if stored is None:
        probes.verify_probe(check, name="Nyxmon Logyard checks")


# -- Grafana wiring (the role's grafana.yml) ----------------------------------------


def _source_files(root: Path, excludes: Sequence[str]) -> tuple[list[PurePosixPath], list[PurePosixPath]]:
    """(directories, files) below ``root`` as relative paths, minus what the source sync excludes."""

    def excluded(relative: PurePosixPath) -> bool:
        for pattern in excludes:
            bare = pattern.strip("/")
            if any(fnmatch.fnmatchcase(part, bare) for part in relative.parts):
                return True
        return False

    directories: list[PurePosixPath] = []
    found: list[PurePosixPath] = []
    for path in sorted(root.rglob("*")):
        relative = PurePosixPath(path.relative_to(root).as_posix())
        if excluded(relative):
            continue
        if path.is_symlink():
            raise ValueError(f"{path} is a symlink; dashboard assets must be plain files")
        (directories if path.is_dir() else found).append(relative)
    return directories, found


def _non_empty(listing: str) -> Callable[[], bool]:
    return lambda: bool(listing.strip())


def _grafana(cfg: LogyardConfig, grafana: GrafanaWiring) -> list[Any]:
    """The Grafana steps; returns the operations that make the container restart."""

    name = shlex.quote(grafana.container_name)
    network = shlex.quote(cfg.docker_network_name)
    running = probe(f"docker inspect --format '{{{{.State.Running}}}}' {name}").strip()
    attached = probe(f"docker inspect --format '{{{{json .NetworkSettings.Networks}}}}' {name}").strip()
    try:
        networks = set(json.loads(attached)) if attached else set()
    except json.JSONDecodeError:
        networks = set()
    mark_read_only(
        server.shell(
            name="Require the Graphyard Grafana container",
            commands=[
                f"docker inspect --format '{{{{.State.Running}}}}' {name} >/dev/null || "
                f"{{ echo 'container {grafana.container_name} not found' >&2; exit 1; }}"
            ],
        )
    )
    triggers: list[Any] = [
        server.shell(
            name="Connect Graphyard Grafana to the Logyard network",
            commands=[f"docker network connect {network} {name}"],
            _if=lambda: cfg.docker_network_name not in networks,
        )
    ]

    target = grafana.dashboard_target_dir
    # The shared Grafana tree belongs to Graphyard: its directories are only
    # created when missing (Graphyard's deploy owns them, see the logyard and
    # graphyard service pages); Logyard owns its datasource file and dashboards.
    datasource_dir = grafana.datasource_path.parent
    files.directory(name=f"Ensure {datasource_dir}", path=str(datasource_dir))
    triggers.append(
        files.put(
            name="Render Logyard datasource provisioning file",
            src=StringIO(render_datasource(cfg)),
            dest=str(grafana.datasource_path),
            user="root",
            group="root",
            mode="0644",
        )
    )
    files.directory(name=f"Ensure {grafana.dashboards_root}", path=str(grafana.dashboards_root))
    directory(str(target), user="root", group="root", mode="0755")

    # The role copies site/deploy/grafana/dashboards/logyard on the host, which
    # holds the controller's copy once the source sync ran; the files are put
    # from the controller instead, so a change is known while planning.
    directories, found = _source_files(cfg.dashboard_source, cfg.source_excludes)
    for relative in directories:
        triggers.append(directory(str(target / relative), user="root", group="root", mode="0755"))
    for relative in found:
        triggers.append(
            files.put(
                name=f"Copy Logyard dashboard {relative}",
                src=str(cfg.dashboard_source / relative),
                dest=str(target / relative),
                user="root",
                group="root",
                mode="0644",
            )
        )
    # Anything else below the target (files the sync no longer ships) keeps its
    # content but is made traversable and readable, as the role's find loops do.
    quoted = shlex.quote(str(target))
    for kind, mode in (("d", "0755"), ("f", "0644")):
        wrong = f"\\( ! -user root -o ! -group root -o ! -perm {mode} \\)"
        listing = probe(f"find {quoted} -type {kind} {wrong} -print")
        triggers.append(
            server.shell(
                name=f"Make Logyard dashboard {'directories' if kind == 'd' else 'files'} root-owned {mode}",
                commands=[f"find {quoted} -type {kind} {wrong} -exec chown root:root {{}} + -exec chmod {mode} {{}} +"],
                _if=_non_empty(listing),
            )
        )
    server.shell(
        name="Start Graphyard Grafana",
        commands=[f"docker start {name}"],
        _if=lambda: running != "true",
    )
    return triggers


def _loki_data_directory(loki: Loki) -> None:
    """The data directory, owned by the container's numeric ids (which have no name on the host).

    ``files.directory`` compares owner names, and ``stat`` prints ``UNKNOWN``
    for an id without one, so it would chown on every run; compare ids.
    """

    path = shlex.quote(str(loki.data_dir))
    wanted = f"{loki.data_owner} {loki.data_group} 755"
    current = probe(f"stat -c '%u %g %a' {path}").strip()
    files.directory(name="Ensure Loki data directory", path=str(loki.data_dir))
    server.shell(
        name="Set Loki data directory owner and mode",
        commands=[f"chown {loki.data_owner}:{loki.data_group} {path} && chmod 0755 {path}"],
        _if=lambda: current != wanted,
    )


def core_steps(cfg: LogyardConfig, secrets: SecretValues, rsync: RsyncRunner) -> None:
    secrets.require(cfg.required_secret_keys)
    if "\n" in secrets["nyxmon_storage_metrics_password"]:
        raise ValueError("secret nyxmon_storage_metrics_password must be a single line")

    docker_steps(cfg.docker)

    # The role's user.yml: a nologin system user whose home holds the compose
    # file; /etc/logyard and Loki's data directory belong to root and the container.
    system_user(cfg.user, group=cfg.group, home=cfg.home, shell="/usr/sbin/nologin", directories=[cfg.site_path])
    files.directory(name=f"Ensure {cfg.env_dir}", path=str(cfg.env_dir), user="root", group="root", mode="0755")
    _loki_data_directory(cfg.loki)

    apt.packages(name="Install rsync", packages=["rsync"], update=True, cache_time=3600)
    sync_tree(
        name="Sync Logyard source",
        src=cfg.source_path,
        dest=cfg.site_path,
        excludes=cfg.source_excludes,
        runner=rsync,
        user=cfg.user,
        group=cfg.group,
    )

    # runtime.yml
    network = shlex.quote(cfg.docker_network_name)
    network_exists = probe(f"docker network inspect {network} >/dev/null && echo present").strip() == "present"
    server.shell(
        name="Create the Logyard compose network",
        commands=[f"docker network create {network}"],
        _if=lambda: not network_exists,
    )
    loki_config = files.put(
        name="Render Loki config",
        src=StringIO(render_loki_config(cfg)),
        dest=str(cfg.config_path),
        user="root",
        group="root",
        mode="0644",
    )
    compose = files.put(
        name="Render Logyard compose file",
        src=StringIO(render_compose(cfg)),
        dest=str(cfg.compose_path),
        user="root",
        group="root",
        mode="0644",
    )
    unit = systemd_unit(cfg.service_name, render_service_unit(cfg))
    service_rollout(cfg.service_name, units=[unit], restart_when=[loki_config, compose])

    grafana_triggers: list[Any] = []
    if cfg.grafana is not None:
        grafana_triggers = _grafana(cfg, cfg.grafana)

    if cfg.health is not None:
        health = cfg.health
        script = files.put(
            name="Install Logyard health endpoint script",
            src=StringIO(HEALTH_SCRIPT),
            dest=str(health.script_path),
            user="root",
            group="root",
            mode="0755",
        )
        health_unit = systemd_unit(health.service_name, render_health_unit(cfg))
        service_rollout(health.service_name, units=[health_unit], restart_when=[script])

    if cfg.grafana is not None:
        # The role's handler, which runs after everything above.
        server.shell(
            name="Restart Graphyard Grafana",
            commands=[f"docker restart {shlex.quote(cfg.grafana.container_name)}"],
            _if=any_changed(*grafana_triggers),
        )

    if cfg.ready_checks is not None:
        _verify(cfg, cfg.ready_checks)
    _nyxmon(cfg, secrets)


@deploy("Deploy logyard core")
def deploy_logyard_core(
    cfg: LogyardConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner
) -> None:
    core_steps(cfg, secrets, rsync)


def _verify(cfg: LogyardConfig, checks: ReadyChecks) -> None:
    """The role's verify.yml: Loki answers ``/ready``, the health endpoint reports Loki ready."""

    def wait(url: str, test: str, label: str) -> str:
        script = (
            f"for i in $(seq 1 {checks.retries}); do "
            f"body=$(curl -sS --max-time 30 -w '\\n%{{http_code}}' {shlex.quote(url)} 2>/dev/null) && "
            f'code=$(printf %s "$body" | tail -n1) && body=$(printf %s "$body" | sed "$ d") && '
            f'[ "$code" = 200 ] && {test} && exit 0; sleep {checks.delay_seconds}; done; '
            f"echo '{label} did not become ready' >&2; exit 1"
        )
        return f"bash -c {shlex.quote(script)}"

    mark_read_only(
        server.shell(
            name="Wait for Loki /ready",
            commands=[wait(cfg.ready_url, 'printf %s "$body" | tr A-Z a-z | grep -q ready', "Loki")],
        )
    )
    if cfg.health is not None:
        health = cfg.health
        parse = "import json,sys; sys.exit(0 if json.load(sys.stdin).get('loki', {}).get('ready') else 1)"
        mark_read_only(
            server.shell(
                name="Wait for the Logyard health endpoint",
                commands=[
                    wait(
                        f"http://{health.bind_host}:{health.port}{health.path}",
                        f'printf %s "$body" | python3 -c {shlex.quote(parse)}',
                        "The Logyard health endpoint",
                    )
                ],
            )
        )
