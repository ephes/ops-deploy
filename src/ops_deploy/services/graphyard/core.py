"""graphyard core: the Graphyard Django app with its InfluxDB and Grafana runtime.

Port of the ``graphyard_deploy`` Ansible role (rsync method) and ops-control's
``playbooks/deploy-graphyard-core.yml``, including the roles it pulls in
(``docker_install``, ``uv_install``). The role's templates are shipped
unchanged and rendered the way Ansible's ``template`` module renders them, so
every file written is byte-identical to the role's
(``tests/test_graphyard_parity.py``) and Ansible and ops-deploy can take turns
on a host without rewriting or restarting anything.

Unlike the role, steps that would change nothing are skipped instead of run:
migrate, collectstatic and ``uv sync`` run when code, dependencies or the env
file changed (or a migration is pending), the metric collection specs are
applied when the file changed or the database holds something else, and the
InfluxDB v1 auth for Grafana and the bucket retention are probed before they
are written. Data is never touched: InfluxDB's and Grafana's data directories
only get their owner and mode, ``db.sqlite3*`` is excluded from the sync, and
the containers are recreated only when the compose file or the runtime unit
changed.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Sequence
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Literal

from pydantic import Field, field_validator, model_validator
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base import UvInstallConfig, deploy_uv_install
from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.git_source import CommitSha
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import mark_read_only, record_source, service_rollout, system_user, systemd_unit, wait_port
from ops_deploy.helpers.container_ca import require_container_ca_stores
from ops_deploy.helpers.probes import migrations_state, verify_probe, when_present
from ops_deploy.helpers.probes import probe as strict_probe
from ops_deploy.helpers.python import DEFAULT_UV
from ops_deploy.infra import DockerInstallConfig, docker_steps
from ops_deploy.ops import secret_file, secret_stdin, sync_tree
from ops_deploy.services.graphyard._common import (
    EnvValue,
    ImageRef,
    NumericId,
    Part,
    Port,
    Url,
    Word,
    absolute,
    gate,
    present,
    probe,
    render_role,
    runuser,
    to_nice_json,
)
from ops_deploy.services.graphyard.agent import RELEASE_URL, check_agent, install_agent, prune_agents, select_agent

# The paths the role requires in the source tree before it syncs anything.
REQUIRED_SOURCE_PATHS = ("src/django", "src/graphyard", "pyproject.toml", "uv.lock")
# The role's graphyard_rsync_excludes plus the lock file it always adds.
SOURCE_EXCLUDES = (
    ".vault_password",
    ".git",
    ".venv/",
    ".dev/",
    "__pycache__/",
    "*.pyc",
    ".pytest_cache/",
    ".coverage",
    "htmlcov/",
    ".tox/",
    ".mypy_cache/",
    "src/django/.env",
    "src/django/db.sqlite3",
    "src/django/db.sqlite3-wal",
    "src/django/db.sqlite3-shm",
    "src/django/staticfiles/",
    "src/django/media/",
    "deploy/grafana/dashboards/logyard/",
    "deploy/grafana/provisioning/datasources/logyard.yaml",
    # Cargo build output of the Rust agent port; never shipped from a local checkout.
    "agent-rs/target/",
    ".inventory-releases.lock",
    # Not in the role: Docker creates this as the mount point of the dashboards
    # bind mount when Grafana starts; deleting it detaches the mount in the
    # running container.
    "deploy/grafana/provisioning/dashboards-json/",
)
# Paths in the site that the Logyard deploy owns (root-owned files of its own);
# Graphyard's ownership step leaves them alone. Everything else in the site,
# the shared Grafana directories included, is Graphyard's.
LOGYARD_PATHS = (
    "deploy/grafana/provisioning/datasources/logyard.yaml",
    "deploy/grafana/dashboards/logyard",
)
PLACEHOLDERS = ("CHANGEME", "replace-me")
# The playbook's secret references inside metric collection specs, and the
# deploy secret each one names.
HOMEASSISTANT_TOKEN = "homeassistant_api_token"
SPEC_SECRET_REFS = {
    ("http_json_metric", "basic_password", "basic_password_secret_ref"): "nyxmon_storage_metrics_password",
    ("unifi_device_traffic", "password", "password_secret_ref"): "homeassistant_unifi_password",
}
HOMEASSISTANT_SPEC_TYPES = ("home_assistant_sensor", "home_assistant_env_scan")
INVENTORY_MONITOR_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
# The env file is read by systemd and sourced by bash (the role's manage.py
# commands): a value must mean the same to both, so nothing that quotes,
# expands, ends a word or starts a command.
ENV_SECRET = re.compile(r"^[^\s\"'\\$`;&|<>()~]+$")
ENV_SECRET_KEYS = ("django_secret_key", "influx_token")
DURATION = re.compile(r"^([0-9]+)(s|m|h|d|w)$")
DURATION_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
CONTAINER_LABELS = (
    "{{ if .Config.Labels }}"
    '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}'
    "{{ end }} @exists"
)

# Reads the metric collection specs Graphyard holds (stdlib only, read-only,
# no secrets in it); prints one digest pair per row, never the configs.
SPECS_PROBE = """\
import hashlib, json, sqlite3, sys
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
try:
    rows = db.execute(
        "select name, enabled, spec_type, interval_seconds, config from metric_collection_spec"
    ).fetchall()
except sqlite3.OperationalError as exc:
    # Not migrated yet: no specs. Any other database error fails the probe.
    if "no such table" not in str(exc):
        raise
    rows = []
digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
for name, enabled, spec_type, interval, config in rows:
    state = json.dumps([bool(enabled), spec_type, interval, json.loads(config)], sort_keys=True)
    print("spec", digest(name), digest(state))
"""
# Grafana's InfluxDB v1 login through the HTTP API (stdin: admin token, password).
# ``check`` only queries with the login; ``ensure`` creates it when that fails.
INFLUX_V1_AUTH = """\
import base64, json, sys, urllib.error, urllib.parse, urllib.request
base, org, bucket, user, mode = sys.argv[1:6]
token = sys.stdin.readline().rstrip("\\n")
password = sys.stdin.readline().rstrip("\\n")


def call(method, path, body=None, auth=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json", "Authorization": auth or "Token " + token}
    request = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        text = response.read()
    return json.loads(text) if text else None


def works():
    basic = base64.b64encode((user + ":" + password).encode()).decode()
    try:
        call("GET", "/query?q=SHOW+DATABASES", auth="Basic " + basic)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return False
        raise
    return True


if works():
    sys.exit(0)
if mode != "ensure":
    sys.exit("the InfluxDB v1 login for Grafana does not work")
org_id = call("GET", "/api/v2/orgs?" + urllib.parse.urlencode({"org": org}))["orgs"][0]["id"]
query = urllib.parse.urlencode({"name": bucket, "orgID": org_id})
buckets = call("GET", "/api/v2/buckets?" + query)["buckets"]
if len(buckets) != 1:
    sys.exit("expected exactly one bucket named %s, found %d" % (bucket, len(buckets)))
resource = {"type": "buckets", "id": buckets[0]["id"], "orgID": org_id}
permissions = [{"action": action, "resource": resource} for action in ("read", "write")]
created = call("POST", "/private/legacy/authorizations", {"orgID": org_id, "token": user, "permissions": permissions})
call("POST", "/private/legacy/authorizations/%s/password" % created["id"], {"password": password})
if not works():
    sys.exit("the new InfluxDB v1 login for Grafana does not work")
"""
# The bucket's retention in seconds, from ``influx bucket list --json`` on stdin.
BUCKET_RETENTION = """\
import json, sys
rows = json.load(sys.stdin)
if len(rows) != 1:
    sys.exit("expected exactly one bucket named %s, found %d" % (sys.argv[1], len(rows)))
rules = rows[0].get("retentionRules") or [{}]
print(rows[0]["id"], int(rules[0].get("everySeconds") or 0))
"""


def duration_seconds(value: str) -> int:
    """``community.general.to_time_unit('s')`` for the durations InfluxDB and the config accept."""

    found = DURATION.match(value)
    if found is None:
        raise ValueError("durations look like 180d, 12h or 0s")
    return int(found.group(1)) * DURATION_SECONDS[found.group(2)]


class Influx(Part):
    """InfluxDB 2 in the runtime and how the app reaches it (the role's ``graphyard_influx_*``)."""

    image: ImageRef = "influxdb:2.7"
    container_name: Word = "graphyard-influxdb"
    host_bind_address: Annotated[str, Field(pattern=r"^[0-9.]+$")] = "127.0.0.1"
    host_port: Port = 8086
    container_port: Port = 8086
    data_dir: PurePosixPath = PurePosixPath("/var/lib/graphyard/influxdb2")
    config_dir: PurePosixPath = PurePosixPath("/var/lib/graphyard/influxdb2-config")
    data_dir_owner: NumericId = "1000"
    data_dir_group: NumericId = "0"
    config_dir_owner: NumericId = "1000"
    config_dir_group: NumericId = "0"
    init_username: Word = "graphyard_admin"
    url: Url = "http://127.0.0.1:8086"
    org: Word = "graphyard"
    bucket: Word = "graphyard"
    measurement: Word = "graphyard_metrics"
    api_mode: Word = "v2"
    timeout_ms: int = Field(default=10000, ge=1)
    token_required: bool = True
    # Enforce ``bucket_retention`` on the bucket (``0s``: infinite).
    retention_apply: bool = False
    bucket_retention: str = "0s"

    @field_validator("data_dir", "config_dir")
    @classmethod
    def _absolute_dirs(cls, value: PurePosixPath) -> PurePosixPath:
        return absolute(value)

    @field_validator("bucket_retention")
    @classmethod
    def _duration(cls, value: str) -> str:
        duration_seconds(value)
        return value


class Grafana(Part):
    """Grafana in the runtime (the role's ``graphyard_grafana_*``)."""

    image: ImageRef = "grafana/grafana-oss"
    container_name: Word = "graphyard-grafana"
    host_bind_address: Annotated[str, Field(pattern=r"^[0-9.]+$")] = "127.0.0.1"
    host_port: Port = 3300
    container_port: Port = 3000
    data_dir: PurePosixPath = PurePosixPath("/var/lib/graphyard/grafana")
    data_dir_owner: NumericId = "472"
    data_dir_group: NumericId = "472"
    # None: ``<site_path>/deploy/grafana/provisioning`` and ``.../dashboards``.
    provisioning_path: PurePosixPath | None = None
    dashboards_path: PurePosixPath | None = None
    admin_user: Word = "admin"
    allow_sign_up: bool = False
    default_home_dashboard_path: PurePosixPath = PurePosixPath(
        "/etc/grafana/provisioning/dashboards-json/overview/graphyard-home.json"
    )
    influx_username: Word = "grafana"
    # None: the Influx bucket.
    influx_database: Word | None = None
    # The app's links to Grafana (``GRAFANA_BASE_URL``).
    base_url: EnvValue = ""

    @field_validator("data_dir", "provisioning_path", "dashboards_path", "default_home_dashboard_path")
    @classmethod
    def _absolute_paths(cls, value: PurePosixPath | None) -> PurePosixPath | None:
        return None if value is None else absolute(value)


class Runtime(Part):
    """The Compose project for InfluxDB and Grafana under a systemd unit (the role's runtime.yml)."""

    service_name: ServiceName = "graphyard-runtime"
    compose_project_name: Word = "graphyard-runtime"
    # None: ``<home>/docker-compose.yml``.
    compose_path: PurePosixPath | None = None
    ca_store_root: PurePosixPath | None = None
    docker_network_name: Word = "graphyard-monitoring"
    # Remove containers with the runtime's names that Compose does not own.
    migrate_unmanaged_containers: bool = True
    docker: DockerInstallConfig = DockerInstallConfig()

    @field_validator("compose_path", "ca_store_root")
    @classmethod
    def _absolute_compose(cls, value: PurePosixPath | None) -> PurePosixPath | None:
        return None if value is None else absolute(value)


class Django(Part):
    """The env file's Django settings (the role's ``graphyard_django_*``)."""

    settings_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.]+$")] = "config.settings.production"
    allowed_hosts: tuple[EnvValue, ...] = ("127.0.0.1", "localhost")
    csrf_trusted_origins: tuple[EnvValue, ...] = ()
    admin_url: EnvValue = "hidden_admin/"
    login_url: EnvValue = "/login/"
    login_redirect_url: EnvValue = "/"
    session_cookie_age_seconds: int = Field(default=86400, ge=1)


class HealthCheck(Part):
    """The role's health.yml: port, ``/v1/health`` (status ok/warning/critical), both units active."""

    # None: ``http://127.0.0.1:<web_bind_port>/v1/health``.
    url: Url | None = None
    timeout_seconds: int = Field(default=5, ge=1)
    retries: int = Field(default=12, ge=1)
    delay_seconds: int = Field(default=5, ge=0)


class MetricSpecs(Part):
    """Declarative metric collection specs, applied with ``manage.py apply_metric_collection_specs``.

    ``specs`` as the inventory lists them. The playbook's secret references
    are filled in from the deploy secrets: ``access_token`` of Home Assistant
    specs (``homeassistant_api_token``), and ``basic_password_secret_ref`` /
    ``password_secret_ref`` (the named secret); the ``*_secret_ref`` keys are
    dropped from what is written.
    """

    specs: tuple[dict[str, Any], ...] = ()
    prune: bool = False


class GraphyardConfig(BaseServiceConfig):
    """The role's variables without the ``graphyard_`` prefix (defaults from its defaults/main.yml)."""

    required_secret_keys: ClassVar[tuple[str, ...]] = ("django_secret_key",)

    service_name: ServiceName = "graphyard"
    user: UnixUser = "graphyard"
    group: UnixUser = "graphyard"
    home: PurePosixPath = PurePosixPath("/opt/apps/graphyard")
    site_path: PurePosixPath = PurePosixPath("/opt/apps/graphyard/site")
    env_dir: PurePosixPath = PurePosixPath("/etc/graphyard")
    # A Graphyard tree on the controller (a checkout or a fetched git source).
    source_path: Path
    # The commit ``source_path`` was checked out at (a git source), recorded on
    # the host; None: a local working tree, and the host's record is removed.
    source_commit: CommitSha | None = None
    source_excludes: tuple[str, ...] = SOURCE_EXCLUDES
    # Below the site, relative: left to another deploy (owner and content).
    foreign_paths: tuple[Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")], ...] = LOGYARD_PATHS
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.12"
    uv_sync_args: tuple[Annotated[str, Field(pattern=r"^--[a-z-]+$")], ...] = ("--no-default-groups", "--no-dev")
    # Optional pinned uv/uvx convergence; newer installed versions fail closed.
    # By default uv must already be at /usr/local/bin/uv.
    uv: UvInstallConfig | None = None
    django: Django = Django()
    influx: Influx = Influx()
    grafana: Grafana = Grafana()
    # None: no InfluxDB/Grafana runtime (``graphyard_runtime_enabled: false``).
    runtime: Runtime | None = Runtime()

    metric_collection_interval_seconds: int = Field(default=60, ge=1)
    condition_eval_interval_seconds: int = Field(default=60, ge=1)
    ingest_heartbeat_min_interval_seconds: int = Field(default=15, ge=1)
    heartbeat_warning_seconds: int = Field(default=900, ge=1)
    heartbeat_critical_seconds: int = Field(default=3600, ge=1)
    condition_data_stale_warning_seconds: int = Field(default=600, ge=1)
    sqlite_timeout_seconds: int = Field(default=30, ge=1)
    sqlite_busy_timeout_ms: int = Field(default=30000, ge=1)
    sqlite_journal_mode: Word = "WAL"
    sqlite_synchronous: Word = "NORMAL"

    web_service_name: ServiceName = "graphyard-web"
    agent_service_name: ServiceName = "graphyard-agent"
    web_bind_host: Annotated[str, Field(pattern=r"^[0-9.]+$")] = "127.0.0.1"
    web_bind_port: Port = 8051
    web_workers: int = Field(default=1, ge=1, le=64)
    web_restart_sec: int = Field(default=5, ge=0)
    agent_restart_sec: int = Field(default=5, ge=0)
    # The role's graphyard_agent_impl and graphyard_agent_rust_*: which agent
    # the agent unit runs, and the pinned Rust release installed (with either
    # implementation) below the install root. Empty version: nothing installed.
    agent_impl: Literal["python", "rust"] = "python"
    agent_rust_version: Annotated[str, Field(pattern=r"^([0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?)?$")] = ""
    # sha256 of the release archive; required with a version unless a local archive is set.
    agent_rust_sha256: Annotated[str, Field(pattern=r"^([0-9a-f]{64})?$")] = ""
    # ``{version}`` stands for the version.
    agent_rust_release_url: str = RELEASE_URL
    # A controller-side archive with the release layout replaces the download.
    agent_rust_local_archive: Path | None = None
    agent_rust_install_root: Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/+-]*[A-Za-z0-9._+-]$")] = (
        "/opt/graphyard-agent"
    )
    agent_rust_keep_versions: Annotated[int, Field(ge=1)] = 3

    # None: no health verification (``graphyard_healthcheck_enabled: false``).
    healthcheck: HealthCheck | None = HealthCheck()
    # None: specs are neither written nor applied (``..._specs_apply: false``).
    metric_specs: MetricSpecs | None = None
    # The weekly public release refresh; None: off (and its units stopped).
    inventory_release_sources: tuple[dict[str, Any], ...] | None = None
    # Emergency rollback: no manage.py commands (migrate, collectstatic, specs, releases).
    skip_django_manage: bool = False

    @field_validator("home", "site_path", "env_dir")
    @classmethod
    def _absolute_paths(cls, value: PurePosixPath) -> PurePosixPath:
        return absolute(value)

    @field_validator("source_path")
    @classmethod
    def _source_is_a_graphyard_tree(cls, value: Path) -> Path:
        value = value.expanduser().absolute()
        if not value.is_dir():
            raise ValueError("source_path must be a directory on the controller")
        missing = [path for path in REQUIRED_SOURCE_PATHS if not (value / path).exists()]
        if missing:
            raise ValueError(f"source_path is not a Graphyard tree (missing {', '.join(missing)})")
        return value

    @field_validator("source_excludes")
    @classmethod
    def _plain_excludes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not pattern or pattern.startswith("-") for pattern in value):
            raise ValueError("rsync excludes must not be empty or start with '-'")
        return value

    @field_validator("agent_rust_release_url")
    @classmethod
    def _release_url_takes_the_version(cls, value: str) -> str:
        try:
            url = value.format(version="0.0.0")
        except (IndexError, KeyError, ValueError):
            raise ValueError("agent_rust_release_url may hold no placeholder but {version}") from None
        if not re.fullmatch(r"https?://[^\s'\"$`\\{}]+", url):
            raise ValueError("agent_rust_release_url must be an http(s) URL without whitespace, quotes, $, ` or \\")
        return value

    @field_validator("agent_rust_keep_versions", mode="before")
    @classmethod
    def _keep_versions_is_a_whole_number(cls, value: object) -> object:
        # The role refuses booleans and anything but digits; pydantic would take True or 1.0 as 1.
        if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
            raise ValueError("agent_rust_keep_versions must be a whole number")
        return value

    @model_validator(mode="after")
    def _agent_settings(self) -> GraphyardConfig:
        """The role's "Validate agent implementation settings"."""

        version, local = self.agent_rust_version, self.agent_rust_local_archive
        if self.agent_impl == "rust" and not version:
            raise ValueError("agent_impl rust needs agent_rust_version")
        if version and not self.agent_rust_sha256 and local is None:
            raise ValueError("agent_rust_version needs agent_rust_sha256 (or agent_rust_local_archive)")
        if (self.agent_rust_sha256 or local is not None) and not version:
            raise ValueError("agent_rust_sha256 and agent_rust_local_archive need agent_rust_version")
        if local is not None and not local.is_file():
            raise ValueError("agent_rust_local_archive is not a file")
        return self

    @model_validator(mode="after")
    def _distinct_units(self) -> GraphyardConfig:
        names = [self.web_service_name, self.agent_service_name]
        if self.runtime is not None:
            names.append(self.runtime.service_name)
        if len(set(names)) != len(names):
            raise ValueError("the web, agent and runtime units need distinct names")
        if self.metric_specs is not None and self.metric_specs.prune and not self.metric_specs.specs:
            raise ValueError("pruning metric collection specs needs at least one spec")
        return self

    @property
    def django_path(self) -> PurePosixPath:
        return self.site_path / "src" / "django"

    @property
    def venv_path(self) -> PurePosixPath:
        return self.site_path / ".venv"

    @property
    def venv_bin(self) -> PurePosixPath:
        return self.venv_path / "bin"

    @property
    def env_path(self) -> PurePosixPath:
        return self.env_dir / "graphyard.env"

    @property
    def db_path(self) -> PurePosixPath:
        return self.django_path / "db.sqlite3"

    @property
    def specs_path(self) -> PurePosixPath:
        return self.env_dir / "metric-collection-specs.json"

    @property
    def releases_path(self) -> PurePosixPath:
        return self.env_dir / "inventory-releases.json"

    @property
    def compose_path(self) -> PurePosixPath:
        configured = self.runtime.compose_path if self.runtime is not None else None
        return configured or self.home / "docker-compose.yml"

    @property
    def provisioning_path(self) -> PurePosixPath:
        return self.grafana.provisioning_path or self.site_path / "deploy/grafana/provisioning"

    @property
    def dashboards_path(self) -> PurePosixPath:
        return self.grafana.dashboards_path or self.site_path / "deploy/grafana/dashboards"

    @property
    def agent_rust_binary(self) -> str:
        return f"{self.agent_rust_install_root}/{self.agent_rust_version}/graphyard-agent"

    @property
    def agent_rust_url(self) -> str:
        return self.agent_rust_release_url.format(version=self.agent_rust_version)

    @property
    def health_url(self) -> str:
        configured = self.healthcheck.url if self.healthcheck is not None else None
        return configured or f"http://127.0.0.1:{self.web_bind_port}/v1/health"


# -- secrets and rendering ------------------------------------------------------------


def _placeholder(value: str) -> bool:
    return not value or value in PLACEHOLDERS


def check_secrets(cfg: GraphyardConfig, secrets: SecretValues) -> None:
    """The role's and the playbook's asserts, plus single-line values. Errors name keys only."""

    wanted = ["django_secret_key"]
    if cfg.influx.token_required:
        wanted.append("influx_token")
    if cfg.runtime is not None:
        wanted += ["influx_token", "grafana_admin_password", "grafana_influx_password"]
    for key in wanted:
        if _placeholder(secrets.get(key, "")):
            raise ValueError(f"secret {key} must be set and not a placeholder")
    if "inventory_monitor_token" not in secrets:
        raise ValueError("secret inventory_monitor_token must be present (empty disables machine access)")
    token = secrets["inventory_monitor_token"]
    if token and not INVENTORY_MONITOR_TOKEN.match(token):
        raise ValueError("secret inventory_monitor_token must be empty or 32-128 URL-safe characters")
    if any(c in value for value in secrets.values() for c in "\r\n"):
        raise ValueError("secret values must be single lines")
    for key in ENV_SECRET_KEYS:
        value = secrets.get(key, "")
        if value and not ENV_SECRET.match(value):
            raise ValueError(
                f"secret {key} goes into the env file unquoted (bash sources it): "
                "no whitespace, quotes, backslashes or $ ` ; & | < > ( ) ~"
            )


def resolve_specs(specs: Sequence[dict[str, Any]], secrets: SecretValues) -> list[dict[str, Any]]:
    """The playbook's ``graphyard_metric_collection_specs_resolved``: references filled, refs dropped."""

    def secret(key: str) -> str:
        value = secrets.get(key, "")
        if not value or value in ("CHANGEME", "CHANGE_ME"):
            raise ValueError(f"secret {key} is needed by a metric collection spec")
        return value

    resolved = []
    for spec in specs:
        config = dict(spec.get("config") or {})
        kind = spec.get("spec_type")
        if kind in HOMEASSISTANT_SPEC_TYPES and not config.get("access_token"):
            config["access_token"] = secret(HOMEASSISTANT_TOKEN)
        for (spec_type, field, ref_key), key in SPEC_SECRET_REFS.items():
            ref = config.get(ref_key) or ""
            if kind == spec_type and not config.get(field) and ref:
                if ref != key:
                    raise ValueError(f"unsupported {ref_key} in metric collection spec {spec.get('name')!r}")
                config[field] = secret(key)
        for ref_key in ("basic_password_secret_ref", "password_secret_ref"):
            config.pop(ref_key, None)
        resolved.append({**spec, "config": config})
    return resolved


def role_vars(cfg: GraphyardConfig, secrets: SecretValues) -> dict[str, Any]:
    """The role's variables, as ``deploy-graphyard-core.yml`` sets them (secrets included)."""

    runtime = cfg.runtime or Runtime()
    influx, grafana = cfg.influx, cfg.grafana
    token = secrets.get("influx_token", "")
    return {
        "graphyard_user": cfg.user,
        "graphyard_group": cfg.group,
        "graphyard_home": str(cfg.home),
        "graphyard_django_path": str(cfg.django_path),
        "graphyard_venv_bin": str(cfg.venv_bin),
        "graphyard_env_dir": str(cfg.env_dir),
        "graphyard_env_path": str(cfg.env_path),
        "graphyard_django_settings_module": cfg.django.settings_module,
        "graphyard_django_secret_key": secrets["django_secret_key"],
        "graphyard_django_allowed_hosts": list(cfg.django.allowed_hosts),
        "graphyard_django_csrf_trusted_origins": list(cfg.django.csrf_trusted_origins),
        "graphyard_django_admin_url": cfg.django.admin_url,
        "graphyard_django_login_url": cfg.django.login_url,
        "graphyard_django_login_redirect_url": cfg.django.login_redirect_url,
        "graphyard_django_session_cookie_age_seconds": cfg.django.session_cookie_age_seconds,
        "graphyard_inventory_monitor_token": secrets["inventory_monitor_token"],
        "graphyard_influx_url": influx.url,
        "graphyard_influx_token": token,
        "graphyard_influx_org": influx.org,
        "graphyard_influx_bucket": influx.bucket,
        "graphyard_influx_measurement": influx.measurement,
        "graphyard_influx_timeout_ms": influx.timeout_ms,
        "graphyard_influx_api_mode": influx.api_mode,
        "graphyard_grafana_base_url": grafana.base_url,
        "graphyard_metric_collection_interval_seconds": cfg.metric_collection_interval_seconds,
        "graphyard_condition_eval_interval_seconds": cfg.condition_eval_interval_seconds,
        "graphyard_ingest_heartbeat_min_interval_seconds": cfg.ingest_heartbeat_min_interval_seconds,
        "graphyard_heartbeat_warning_seconds": cfg.heartbeat_warning_seconds,
        "graphyard_heartbeat_critical_seconds": cfg.heartbeat_critical_seconds,
        "graphyard_condition_data_stale_warning_seconds": cfg.condition_data_stale_warning_seconds,
        "graphyard_sqlite_timeout_seconds": cfg.sqlite_timeout_seconds,
        "graphyard_sqlite_busy_timeout_ms": cfg.sqlite_busy_timeout_ms,
        "graphyard_sqlite_journal_mode": cfg.sqlite_journal_mode,
        "graphyard_sqlite_synchronous": cfg.sqlite_synchronous,
        "graphyard_runtime_enabled": cfg.runtime is not None,
        "graphyard_runtime_service_name": runtime.service_name,
        "graphyard_compose_project_name": runtime.compose_project_name,
        "graphyard_compose_path": str(cfg.compose_path),
        "graphyard_docker_network_name": runtime.docker_network_name,
        "graphyard_ca_store_root": str(runtime.ca_store_root) if runtime.ca_store_root is not None else "",
        "graphyard_influx_image": influx.image,
        "graphyard_influx_container_name": influx.container_name,
        "graphyard_influx_host_bind_address": influx.host_bind_address,
        "graphyard_influx_host_port": influx.host_port,
        "graphyard_influx_container_port": influx.container_port,
        "graphyard_influx_init_username": influx.init_username,
        # The role's defaults: both are the Influx token.
        "graphyard_influx_init_password": token,
        "graphyard_influx_init_admin_token": token,
        "graphyard_influx_data_dir": str(influx.data_dir),
        "graphyard_influx_config_dir": str(influx.config_dir),
        "graphyard_grafana_image": grafana.image,
        "graphyard_grafana_container_name": grafana.container_name,
        "graphyard_grafana_host_bind_address": grafana.host_bind_address,
        "graphyard_grafana_host_port": grafana.host_port,
        "graphyard_grafana_container_port": grafana.container_port,
        "graphyard_grafana_admin_user": grafana.admin_user,
        "graphyard_grafana_admin_password": secrets.get("grafana_admin_password", ""),
        "graphyard_grafana_allow_sign_up": grafana.allow_sign_up,
        "graphyard_grafana_default_home_dashboard_path": str(grafana.default_home_dashboard_path),
        "graphyard_grafana_influx_database": grafana.influx_database or influx.bucket,
        "graphyard_grafana_influx_username": grafana.influx_username,
        "graphyard_grafana_influx_password": secrets.get("grafana_influx_password", ""),
        "graphyard_grafana_provisioning_path": str(cfg.provisioning_path),
        "graphyard_grafana_dashboards_path": str(cfg.dashboards_path),
        "graphyard_grafana_data_dir": str(grafana.data_dir),
        "graphyard_web_bind_host": cfg.web_bind_host,
        "graphyard_web_bind_port": cfg.web_bind_port,
        "graphyard_web_workers": cfg.web_workers,
        "graphyard_web_restart_sec": cfg.web_restart_sec,
        "graphyard_agent_restart_sec": cfg.agent_restart_sec,
    }


def render(template: str, cfg: GraphyardConfig, secrets: SecretValues) -> str:
    return render_role(template, role_vars(cfg, secrets))


def render_specs(cfg: GraphyardConfig, secrets: SecretValues) -> str:
    specs = resolve_specs(cfg.metric_specs.specs if cfg.metric_specs else (), secrets)
    return render_role("metric-collection-specs.json.j2", {"graphyard_metric_collection_specs": specs})


def render_releases(sources: Sequence[dict[str, Any]]) -> str:
    """The role's ``copy`` content: ``to_nice_json`` and a newline."""

    return to_nice_json(list(sources)) + "\n"


# -- plan-time probes -----------------------------------------------------------------


def specs_current(probe_output: str, rendered: str, *, prune: bool) -> bool:
    """Whether Graphyard's specs already equal the rendered file's (as the command normalises them)."""

    def digest(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    stored = {}
    for line in probe_output.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "spec":
            stored[parts[1]] = parts[2]
    wanted = {}
    for spec in json.loads(rendered)["metric_collection_specs"]:
        state = [spec.get("enabled", True), spec["spec_type"], spec.get("interval_seconds", 60), spec.get("config", {})]
        wanted[digest(str(spec["name"]).strip())] = digest(json.dumps(state, sort_keys=True))
    if prune and set(stored) != set(wanted):
        return False
    return all(stored.get(name) == state for name, state in wanted.items())


def _numeric_directory(path: PurePosixPath, owner: str, group: str, mode: str) -> None:
    """A directory owned by a container's numeric ids (``stat`` shows ``UNKNOWN`` for them by name)."""

    quoted = shlex.quote(str(path))
    current = probe(f"stat -c '%u %g %a' {quoted}").strip()
    created = files.directory(name=f"Ensure {path}", path=str(path))
    wanted = f"{owner} {group} {mode.lstrip('0') or '0'}"
    if (kwargs := gate(current != wanted, [created])) is not None:
        server.shell(
            name=f"Set owner and mode of {path}",
            commands=[f"chown {owner}:{group} {quoted} && chmod {mode} {quoted}"],
            **kwargs,
        )


# -- the role: runtime.yml ------------------------------------------------------------


def _runtime(cfg: GraphyardConfig, runtime: Runtime, compose: SecretContent, secrets: SecretValues) -> None:
    influx, grafana = cfg.influx, cfg.grafana
    files.directory(name="Ensure /var/lib/graphyard", path="/var/lib/graphyard", user="root", group="root", mode="0755")
    _numeric_directory(influx.data_dir, influx.data_dir_owner, influx.data_dir_group, "0755")
    _numeric_directory(influx.config_dir, influx.config_dir_owner, influx.config_dir_group, "0775")
    _numeric_directory(grafana.data_dir, grafana.data_dir_owner, grafana.data_dir_group, "0755")
    provisioning, dashboards = shlex.quote(str(cfg.provisioning_path)), shlex.quote(str(cfg.dashboards_path))
    mark_read_only(
        server.shell(
            name="Require the Grafana provisioning assets",
            commands=[
                f"test -d {provisioning} && test -d {dashboards} || "
                "{ echo 'Graphyard Grafana provisioning assets are missing' >&2; exit 1; }"
            ],
        )
    )

    network = shlex.quote(runtime.docker_network_name)
    network_exists = probe(f"docker network inspect {network} >/dev/null && echo present").strip() == "present"
    if not network_exists:
        server.shell(name="Create the Graphyard monitoring network", commands=[f"docker network create {network}"])
    removed: list[OperationMeta] = []
    for container, service in ((influx.container_name, "influxdb"), (grafana.container_name, "grafana")):
        labels = probe(f"docker inspect --format {shlex.quote(CONTAINER_LABELS)} {shlex.quote(container)}").strip()
        unmanaged = labels.endswith("@exists") and labels.removesuffix("@exists").strip() != (
            f"{runtime.compose_project_name}|{service}"
        )
        if runtime.migrate_unmanaged_containers and unmanaged:
            removed.append(
                server.shell(
                    name=f"Remove unmanaged container {container} before the Compose takeover",
                    commands=[f"docker rm -f {shlex.quote(container)}"],
                )
            )

    compose_file = secret_file(
        name="Render Graphyard compose file",
        path=cfg.compose_path,
        content=compose,
        user="root",
        group="root",
        mode="0640",
    )
    unit = systemd_unit(runtime.service_name, render("graphyard-runtime.service.j2", cfg, secrets))
    service_rollout(runtime.service_name, units=[unit], restart_when=[compose_file, *removed])

    container = shlex.quote(influx.container_name)
    mark_read_only(
        server.shell(
            name="Wait for the InfluxDB API",
            commands=[
                f"for i in $(seq 1 20); do docker exec {container} influx ping >/dev/null 2>&1 && exit 0; sleep 3; "
                "done; echo 'InfluxDB did not answer' >&2; exit 1"
            ],
        )
    )
    _grafana_influx_auth(cfg, secrets)


def _if_container(container: str, command: str, *, otherwise: str) -> str:
    """``command`` when the container exists, else ``echo <otherwise>`` (before a first deploy)."""

    return f"if docker inspect {container} >/dev/null 2>&1; then {command}; else echo {otherwise}; fi"


def _grafana_influx_auth(cfg: GraphyardConfig, secrets: SecretValues) -> None:
    """The InfluxDB v1 user Grafana's datasource reads with; created only when missing.

    Probed by name (no credentials). The role checks the password instead and
    creates the user when the check fails, which fails for a user that exists
    with another password; here the final check fails then. The login is
    created and checked through InfluxDB's HTTP API on the published port
    (what ``influx v1 auth create`` calls), with the admin token and the
    password on stdin, so neither is in any process's arguments.
    """

    influx, grafana = cfg.influx, cfg.grafana
    container = shlex.quote(influx.container_name)
    user = shlex.quote(grafana.influx_username)
    listing = (
        f"out=$(docker exec {container} influx v1 auth list --username {user} --json 2>&1) && echo present || "
        '{ case "$out" in *"authorization not found"*) echo missing ;; *) exit 1 ;; esac; }'
    )
    state = strict_probe(_if_container(container, listing, otherwise="missing"), name="InfluxDB v1 auth for Grafana")
    host = "127.0.0.1" if influx.host_bind_address == "0.0.0.0" else influx.host_bind_address
    base = f"http://{host}:{influx.host_port}"
    stdin = SecretContent(f"{secrets['influx_token']}\n{secrets['grafana_influx_password']}\n")

    def api(mode: str) -> str:
        args = [base, influx.org, influx.bucket, grafana.influx_username, mode]
        return shlex.join(["python3", "-I", "-c", INFLUX_V1_AUTH, *args])

    if state != "present":
        secret_stdin(name="Create Grafana InfluxDB v1 auth when missing", command=api("ensure"), content=stdin)
    mark_read_only(secret_stdin(name="Verify Grafana InfluxDB v1 auth", command=api("check"), content=stdin))


# -- the role: influx_retention.yml ---------------------------------------------------


def _retention(cfg: GraphyardConfig) -> None:
    influx = cfg.influx
    container = shlex.quote(influx.container_name)
    bucket = shlex.quote(influx.bucket)
    desired = duration_seconds(influx.bucket_retention)
    mark_read_only(
        server.shell(
            name="Require the InfluxDB container to be running",
            commands=[
                f'[ "$(docker inspect --format {{{{.State.Running}}}} {container})" = true ] || '
                f"{{ echo 'Graphyard InfluxDB container {influx.container_name} is not running' >&2; exit 1; }}"
            ],
        )
    )
    current = (
        f"docker exec {container} influx bucket list --name {bucket} --json | "
        f"python3 -I -c {shlex.quote(BUCKET_RETENTION)} {bucket}"
    )
    found = strict_probe(_if_container(container, current, otherwise="none"), name="InfluxDB bucket retention")
    drift = found is None or found.split()[-1:] != [str(desired)]
    update = (
        f'set -e; row=$({current}); [ "${{row#* }}" = {desired} ] && exit 0; '
        f'docker exec {container} influx bucket update --id "${{row%% *}}" '
        f"--retention {shlex.quote(influx.bucket_retention)} >/dev/null"
    )
    if drift:
        server.shell(name="Update bucket retention when it drifts", commands=[update])


# -- the role: python.yml and django.yml ----------------------------------------------


def _home_env(cfg: GraphyardConfig) -> dict[str, str]:
    return {"HOME": str(cfg.home)}


def _in(directory: PurePosixPath, command: str) -> str:
    return f"cd {shlex.quote(str(directory))} && {command}"


def _manage(cfg: GraphyardConfig, *args: str) -> str:
    """The role's ``set -a; . <env>; set +a; python manage.py ...`` (bash), as the service user."""

    script = (
        f"set -a; . {shlex.quote(str(cfg.env_path))}; set +a; "
        f"exec {shlex.join([str(cfg.venv_bin / 'python'), 'manage.py', *args])}"
    )
    return _in(cfg.django_path, runuser(cfg.user, ["bash", "-c", script], env=_home_env(cfg)))


def _python(
    cfg: GraphyardConfig, synced: Sequence[OperationMeta | None]
) -> tuple[OperationMeta | None, OperationMeta | None]:
    """The venv (created once, like the role's ``creates``) and ``uv sync`` when something changed.

    ``uv sync`` runs when its dry run finds work, and after ``synced`` changed
    the site: uv decides whether to reinstall the project from file metadata
    that the source sync and the ownership step both touch, so a dry run
    before them cannot tell.
    """

    if cfg.uv is not None:
        deploy_uv_install(cfg=cfg.uv)
    uv = str(DEFAULT_UV)
    for name in ("pyproject.toml", "uv.lock"):
        path = shlex.quote(str(cfg.site_path / name))
        mark_read_only(
            server.shell(
                name=f"Require {name} in the site",
                commands=[
                    f"test -e {path} || {{ echo 'Missing required file at {cfg.site_path / name}' >&2; exit 1; }}"
                ],
            )
        )
    interpreter = shlex.quote(str(cfg.venv_bin / "python"))
    venv_missing = probe(f"test -e {interpreter} && echo present").strip() != "present"
    venv = None
    if venv_missing:
        create = runuser(cfg.user, [uv, "venv", "--python", cfg.python_version, str(cfg.venv_path)], env=_home_env(cfg))
        venv = server.shell(name="Create virtual environment", commands=[_in(cfg.site_path, create)])
    env = {**_home_env(cfg), "UV_PROJECT_ENVIRONMENT": str(cfg.venv_path)}
    sync = runuser(cfg.user, [uv, "sync", *cfg.uv_sync_args], env=env)
    dry_run = runuser(cfg.user, [uv, "sync", *cfg.uv_sync_args, "--dry-run"], env=env)
    check = (
        f"out=$( {_in(cfg.site_path, dry_run)} 2>&1 ) || {{ printf '%s\\n' \"$out\" >&2; exit 1; }}; "
        "if printf '%s\\n' \"$out\" | grep -qx 'Would make no changes'; then echo current; else echo pending; fi"
    )
    check = when_present([cfg.site_path / "uv.lock", cfg.venv_bin / "python"], check, otherwise="pending")
    deps_state = strict_probe(check, name="graphyard dependencies")
    deps = None
    if (kwargs := gate(deps_state != "current", synced)) is not None:
        deps = server.shell(name="Sync runtime dependencies with uv", commands=[_in(cfg.site_path, sync)], **kwargs)
    if deps_state is None:
        verify_probe(check, name="graphyard dependencies", expect="current")
    return venv, deps


def _django(
    cfg: GraphyardConfig, secrets: SecretValues, changed: list[OperationMeta | None], specs: str | None
) -> OperationMeta:
    """django.yml: env file, migrate, collectstatic, database ownership, metric specs. Returns the env op."""

    env = secret_file(
        name="Render Graphyard environment file",
        path=cfg.env_path,
        content=SecretContent(render("graphyard.env.j2", cfg, secrets)),
        user="root",
        group=cfg.group,
        mode="0640",
    )
    db = shlex.quote(str(cfg.db_path))
    db_missing = probe(f"test -e {db} && echo present").strip() != "present"
    migrate: OperationMeta | None = None
    if not cfg.skip_django_manage:
        needed = (cfg.db_path, cfg.env_path, cfg.venv_bin / "python")
        plan = _manage(cfg, "migrate", "--check", "--plan")
        check = when_present(needed, migrations_state(plan), otherwise="pending")
        migrations = strict_probe(check, name="graphyard migrations")
        # The env file too: new settings may need migrations the old ones did not.
        if (kwargs := gate(migrations != "current", [*changed, env])) is not None:
            migrate = server.shell(
                name="Run Django migrations", commands=[_manage(cfg, "migrate", "--noinput")], **kwargs
            )
        if migrations is None:
            verify_probe(check, name="graphyard migrations", expect="current")
        # ``--dry-run`` copies nothing; "0 static files copied" means current.
        dry_run = _manage(cfg, "collectstatic", "--noinput", "--dry-run")
        static_check = when_present(
            needed[1:],
            f"out=$( {dry_run} ) || exit 1; "
            "if printf '%s\\n' \"$out\" | grep -Eq '(^|[^0-9])0 static files copied'; "
            "then echo current; else echo pending; fi",
            otherwise="pending",
        )
        static = strict_probe(static_check, name="graphyard static files")
        if (kwargs := gate(static != "current", [*changed, env])) is not None:
            server.shell(name="Collect static files", commands=[_manage(cfg, "collectstatic", "--noinput")], **kwargs)
        if static is None:
            verify_probe(static_check, name="graphyard static files", expect="current")
    # The role sets the database's owner and mode when it exists after migrate.
    owner = f"{cfg.user}:{cfg.group}"
    db_state = probe(f"stat -c '%U:%G %a' {db}").strip()
    wrong = not db_missing and db_state != f"{owner} 640"
    if (kwargs := gate(wrong, [migrate] if db_missing else [])) is not None:
        server.shell(
            name="Ensure sqlite database ownership",
            commands=[f"if [ -e {db} ]; then chown {owner} {db} && chmod 0640 {db}; fi"],
            **kwargs,
        )
    if cfg.metric_specs is not None and specs is not None:
        _metric_specs(cfg, cfg.metric_specs, specs, migrate)
    return env


def _metric_specs(cfg: GraphyardConfig, wanted: MetricSpecs, content: str, migrate: OperationMeta | None) -> None:
    written = secret_file(
        name="Render declarative metric collection specs",
        path=cfg.specs_path,
        content=SecretContent(content),
        user="root",
        group=cfg.group,
        mode="0640",
    )
    if cfg.skip_django_manage:
        return
    probe_command = when_present(
        [cfg.db_path],
        runuser(cfg.user, ["python3", "-I", "-c", SPECS_PROBE, str(cfg.db_path)]),
        otherwise="",
    )
    stored = strict_probe(probe_command, name="graphyard metric collection specs")
    current = stored is not None and specs_current(stored, content, prune=wanted.prune)
    args = ["apply_metric_collection_specs", "--file", str(cfg.specs_path), *(["--prune"] if wanted.prune else [])]
    if (kwargs := gate(not current, [written, migrate])) is not None:
        server.shell(
            name="Apply declarative metric collection specs", commands=[_manage(cfg, *args) + " >/dev/null"], **kwargs
        )
    if stored is None:
        verify_probe(probe_command, name="graphyard metric collection specs")


# -- the role: inventory_releases.yml, service.yml, health.yml ------------------------


def _inventory_releases(cfg: GraphyardConfig, secrets: SecretValues) -> None:
    sources = cfg.inventory_release_sources
    timer = "graphyard-inventory-releases.timer"
    if sources is None or cfg.skip_django_manage:
        present = probe(f"test -e /etc/systemd/system/{timer} && echo present").strip() == "present"
        if present:
            systemd.service(name=f"Stop and disable {timer}", service=timer, running=False, enabled=False)
            systemd.service(
                name="Stop graphyard-inventory-releases.service",
                service="graphyard-inventory-releases.service",
                running=False,
            )
        return
    files.put(
        name="Install the explicit release source registry",
        src=StringIO(render_releases(sources)),
        dest=str(cfg.releases_path),
        user="root",
        group=cfg.group,
        mode="0640",
    )
    argv = [str(cfg.venv_bin / "python"), "manage.py", "refresh_inventory_releases"]
    check = runuser(cfg.user, [*argv, "--file", str(cfg.releases_path), "--check"], env=_home_env(cfg))
    mark_read_only(
        server.shell(
            name="Validate the release registry without fetching or changing the database",
            commands=[_in(cfg.django_path, check)],
        )
    )
    units = [
        systemd_unit(f"graphyard-inventory-releases.{kind}", render(f"inventory-releases.{kind}.j2", cfg, secrets))
        for kind in ("service", "timer")
    ]
    systemd.daemon_reload(name="Reload systemd for the release refresh units", _if=any_changed(*units))
    systemd.service(name=f"Enable and start {timer}", service=timer, running=True, enabled=True)


def _health(cfg: GraphyardConfig, check: HealthCheck) -> None:
    wait_port(
        cfg.web_bind_port,
        host=cfg.web_bind_host,
        retries=max(1, check.retries * check.delay_seconds),
        name="Wait for the graphyard web port",
    )
    parse = "import json,sys; sys.exit(0 if json.load(sys.stdin).get('status') in ('ok', 'warning', 'critical') else 1)"
    script = (
        f"for i in $(seq 1 {check.retries}); do "
        f"body=$(curl -sS --max-time {check.timeout_seconds} -H 'X-Forwarded-Proto: https' "
        f"-w '\\n%{{http_code}}' {shlex.quote(cfg.health_url)} 2>/dev/null) && "
        'code=$(printf %s "$body" | tail -n1) && body=$(printf %s "$body" | sed "$ d") && '
        f'[ "$code" = 200 ] && printf %s "$body" | python3 -c {shlex.quote(parse)} && exit 0; '
        f"sleep {check.delay_seconds}; done; "
        "echo 'Graphyard health endpoint returned an unexpected payload' >&2; exit 1"
    )
    mark_read_only(
        server.shell(name="Query the Graphyard health endpoint", commands=[f"bash -c {shlex.quote(script)}"])
    )
    units = " ".join(shlex.quote(f"{name}.service") for name in (cfg.web_service_name, cfg.agent_service_name))
    mark_read_only(
        server.shell(
            name="Verify graphyard services are active",
            commands=[f"systemctl is-active --quiet {units} || {{ systemctl is-active {units} >&2; exit 1; }}"],
        )
    )


def _site_owned(cfg: GraphyardConfig) -> OperationMeta | None:
    """The role's recursive ``file: owner/group`` on the site, only when something is off.

    Unlike the role, the ``foreign_paths`` (Logyard's datasource file and
    dashboards) are left alone: the role takes them back and the Logyard
    deploy then sets them to root again on every run of either.
    """

    site = shlex.quote(str(cfg.site_path))
    pruned = " -o ".join(f"-path {shlex.quote(str(cfg.site_path / path))}" for path in cfg.foreign_paths)
    skip = f"\\( {pruned} \\) -prune -o " if pruned else ""
    wrong = f"\\( ! -user {cfg.user} -o ! -group {cfg.group} \\)"
    if not probe(f"find {site} {skip}{wrong} -print -quit").strip():
        return None
    return server.shell(
        name="Ensure ownership for synced files",
        commands=[f"find {site} {skip}{wrong} -exec chown -h {cfg.user}:{cfg.group} {{}} +"],
    )


def core_steps(cfg: GraphyardConfig, secrets: SecretValues, rsync: RsyncRunner) -> None:
    if cfg.runtime is not None and cfg.runtime.ca_store_root is not None:
        require_container_ca_stores(cfg.runtime.ca_store_root, (cfg.influx.container_name, cfg.grafana.container_name))
    secrets.require(cfg.required_secret_keys)
    check_secrets(cfg, secrets)
    specs = render_specs(cfg, secrets) if cfg.metric_specs is not None else None
    compose = SecretContent(render("docker-compose.yml.j2", cfg, secrets)) if cfg.runtime is not None else None

    # user.yml
    system_user(cfg.user, group=cfg.group, home=cfg.home, shell="/bin/bash", directories=[cfg.site_path])
    files.directory(name=f"Ensure {cfg.env_dir}", path=str(cfg.env_dir), user="root", group=cfg.group, mode="0750")

    # source_rsync.yml
    apt.packages(name="Install rsync", packages=["rsync"])
    code = sync_tree(
        name="Sync Graphyard source",
        src=cfg.source_path,
        dest=cfg.site_path,
        excludes=cfg.source_excludes,
        runner=rsync,
        user=cfg.user,
        group=cfg.group,
    )
    owned = _site_owned(cfg)

    if cfg.runtime is not None and compose is not None:
        docker_steps(cfg.runtime.docker)
        _runtime(cfg, cfg.runtime, compose, secrets)

    venv, deps = _python(cfg, [code, owned])
    changed = [code, venv, deps]
    env = _django(cfg, secrets, changed, specs)
    # The role's agent_rust.yml: after the migrations, so --check-schema sees the schema the agent runs against.
    installed = install_agent(cfg)
    if cfg.influx.retention_apply:
        _retention(cfg)

    units = {
        name: systemd_unit(name, render(template, cfg, secrets))
        for name, template in (
            (cfg.web_service_name, "graphyard-web.service.j2"),
            (cfg.agent_service_name, "graphyard-agent.service.j2"),
        )
    }
    # Every switch and version change rewrites the agent drop-in: reload and restart.
    selected = select_agent(cfg)
    _inventory_releases(cfg, secrets)
    # The role's handlers, flushed before the health checks.
    for name, unit in units.items():
        rolled = [unit, selected] if name == cfg.agent_service_name else [unit]
        service_rollout(name, units=rolled, restart_when=[*present(changed), env])
    # The role's agent_verify.yml: the live process is the selected agent, then old versions go.
    check_agent(cfg)
    prune_agents(cfg, [installed, selected])

    if cfg.healthcheck is not None:
        _health(cfg, cfg.healthcheck)
    # Last: only a deploy that came up healthy records its commit.
    record_source(cfg.site_path, cfg.source_commit, user=cfg.user, group=cfg.group)


@deploy("Deploy graphyard core")
def deploy_graphyard_core(
    cfg: GraphyardConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner
) -> None:
    core_steps(cfg, secrets, rsync)
