"""graphyard vector: the host-metrics producer that pushes to Graphyard's ingest endpoint.

Port of the ``graphyard_vector_deploy`` role (apt and systemd; the role's
Homebrew/launchd branch for the macOS hosts stays on Ansible) and
``playbooks/deploy-graphyard-vector.yml``. Vector comes from its apt channel
(``vector_apt_install``), shares ``config.d``, the global ``data_dir`` fragment
and ``/etc/default/vector`` with the Logyard producer, and the Graphyard
fragment is validated together with the other fragments before it replaces the
live one. The template is shipped unchanged, so the fragment is byte-identical
to the role's (``tests/test_graphyard_parity.py``).

The fragment holds the ingest bearer token: it is written with
``secret_file`` and reaches the validation directory on stdin, never on a
command line.
"""

from __future__ import annotations

import base64
import json
import shlex
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated

from pydantic import Field, field_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.files import FileContents
from pyinfra.operations import files, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base import RoleConfig
from ops_deploy.core.config import ServiceName
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import mark_read_only
from ops_deploy.infra import VectorAptInstallConfig, vector_apt_steps
from ops_deploy.ops import secret_file, secret_stdin
from ops_deploy.services.graphyard._common import Url, Word, absolute, render_role
from ops_deploy.services.logyard.vector import env_line, global_data_dir

CONFIG_PATTERNS = ("*.yaml", "*.yml", "*.toml", "*.json")
FragmentName = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+\.(yaml|yml)$")]
TagValue = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/ -]*$")]


class GraphyardVectorConfig(RoleConfig):
    """The role's variables without the ``graphyard_vector_`` prefix (its Linux defaults).

    The ingest token is a deploy secret (``vector_ingest_token``).
    """

    apt: VectorAptInstallConfig = VectorAptInstallConfig()
    config_dir: PurePosixPath = PurePosixPath("/etc/vector/config.d")
    config_name: FragmentName = "20-graphyard-host-metrics.yaml"
    global_config_name: FragmentName = "00-global.yaml"
    env_file: PurePosixPath = PurePosixPath("/etc/default/vector")
    data_dir: PurePosixPath = PurePosixPath("/var/lib/vector")
    service_name: ServiceName = "vector"

    scrape_interval_secs: int = Field(default=60, ge=1)
    collectors: tuple[Word, ...] = Field(
        default=("cpu", "disk", "filesystem", "load", "memory", "network"), min_length=1
    )
    filesystem_mountpoint_excludes: tuple[Annotated[str, Field(pattern=r"^/[^\s\"\\]*$")], ...] = (
        "/run/docker/netns/*",
        "/var/lib/docker/*",
    )
    metric_prefixes: tuple[Word, ...] = Field(
        default=("filesystem_", "disk_", "memory_", "cpu_", "load", "network_"), min_length=1
    )
    host_id: Word
    service_id: Word = "host_metrics"
    ingest_url: Url
    source_tag: TagValue = "vector-host-metrics"

    http_timeout_secs: int = Field(default=15, ge=1)
    request_concurrency: int = Field(default=1, ge=1)
    retry_initial_backoff_secs: int = Field(default=1, ge=1)
    retry_max_duration_secs: int = Field(default=3600, ge=1)
    batch_timeout_secs: int = Field(default=5, ge=1)
    batch_max_events: int = Field(default=50, ge=1)
    buffer_max_size: int = Field(default=268435488, ge=1)

    @field_validator("config_dir", "env_file", "data_dir")
    @classmethod
    def _absolute(cls, value: PurePosixPath) -> PurePosixPath:
        return absolute(value)

    @property
    def config_path(self) -> PurePosixPath:
        return self.config_dir / self.config_name

    @property
    def global_config_path(self) -> PurePosixPath:
        return self.config_dir / self.global_config_name


def role_vars(cfg: GraphyardVectorConfig, token: str) -> dict[str, object]:
    return {
        "graphyard_vector_scrape_interval_secs": cfg.scrape_interval_secs,
        "graphyard_vector_collectors": list(cfg.collectors),
        "graphyard_vector_filesystem_mountpoint_excludes": list(cfg.filesystem_mountpoint_excludes),
        "graphyard_vector_metric_prefixes": list(cfg.metric_prefixes),
        "graphyard_vector_host_id": cfg.host_id,
        "graphyard_vector_service_id": cfg.service_id,
        "graphyard_vector_source_tag": cfg.source_tag,
        "graphyard_vector_ingest_url": cfg.ingest_url,
        "graphyard_vector_ingest_token": token,
        "graphyard_vector_http_timeout_secs": cfg.http_timeout_secs,
        "graphyard_vector_request_concurrency": cfg.request_concurrency,
        "graphyard_vector_retry_initial_backoff_secs": cfg.retry_initial_backoff_secs,
        "graphyard_vector_retry_max_duration_secs": cfg.retry_max_duration_secs,
        "graphyard_vector_batch_timeout_secs": cfg.batch_timeout_secs,
        "graphyard_vector_batch_max_events": cfg.batch_max_events,
        "graphyard_vector_buffer_max_size": cfg.buffer_max_size,
    }


def ingest_token(secrets: SecretValues) -> str:
    token = secrets.get("vector_ingest_token", "")
    if not token or token == "CHANGEME":
        raise ValueError("secret vector_ingest_token must be set and not a placeholder")
    if any(c in token for c in "\r\n"):
        raise ValueError("secret vector_ingest_token must be a single line")
    return token


def fragment_text(cfg: GraphyardVectorConfig, secrets: SecretValues) -> str:
    return render_role("vector.yaml.j2", role_vars(cfg, ingest_token(secrets)))


def render_fragment(cfg: GraphyardVectorConfig, secrets: SecretValues) -> SecretContent:
    return SecretContent(fragment_text(cfg, secrets))


def render_global(cfg: GraphyardVectorConfig) -> str:
    """The shared global fragment (``data_dir``), as the role writes it."""

    return f"data_dir: {json.dumps(str(cfg.data_dir))}\n"


def validate_command(cfg: GraphyardVectorConfig) -> str:
    """Validate the config directory with this deploy's two fragments swapped in, in a temp directory.

    The candidate Graphyard fragment comes base64-encoded on stdin; the other
    fragments are copied from the live directory, as the role does.
    """

    live = shlex.quote(str(cfg.config_dir))
    names = " -o ".join(f"-name '{pattern}'" for pattern in CONFIG_PATTERNS)
    skip = " ".join(f"! -name {shlex.quote(name)}" for name in (cfg.config_name, cfg.global_config_name))
    global_b64 = base64.b64encode(render_global(cfg).encode()).decode()
    return (
        "set -e; dir=$(mktemp -d /tmp/graphyard-vector-validate-XXXXXX); trap 'rm -rf \"$dir\"' EXIT; "
        f'if [ -d {live} ]; then find {live} -maxdepth 1 -type f \\( {names} \\) {skip} -exec cp {{}} "$dir"/ \\;; fi; '
        f'printf %s {global_b64} | base64 -d > "$dir"/{shlex.quote(cfg.global_config_name)}; '
        f'base64 -d > "$dir"/{shlex.quote(cfg.config_name)}; '
        'vector validate --config-dir "$dir"'
    )


def vector_steps(cfg: GraphyardVectorConfig, secrets: SecretValues) -> None:
    text = fragment_text(cfg, secrets)
    fragment = SecretContent(text)
    vector_apt_steps(cfg.apt)

    existing = global_data_dir(host.get_fact(FileContents, path=str(cfg.global_config_path)) or None, cfg.data_dir)
    if existing != str(cfg.data_dir):
        raise DeployError(
            f"existing shared Vector global config uses data_dir={existing}, "
            f"but data_dir={cfg.data_dir}; align the shared Vector data_dir before deploying"
        )
    files.directory(
        name="Ensure Vector data directory", path=str(cfg.data_dir), user="vector", group="vector", mode="0750"
    )
    files.directory(
        name="Ensure Vector config directory", path=str(cfg.config_dir), user="root", group="vector", mode="0750"
    )
    # Validation before anything Vector reads changes: a fragment it rejects never goes live.
    mark_read_only(
        secret_stdin(
            name="Validate the staged Vector configuration",
            command=validate_command(cfg),
            content=SecretContent(base64.b64encode(text.encode()).decode() + "\n"),
        )
    )
    env = env_line(
        name="Point Vector at its config directory",
        path=str(cfg.env_file),
        line=f"VECTOR_CONFIG_DIR={cfg.config_dir}",
    )
    files.file(name="Remove the legacy monolithic Vector config", path="/etc/vector/vector.yaml", present=False)
    global_config = files.put(
        name="Deploy the shared Vector global config",
        src=StringIO(render_global(cfg)),
        dest=str(cfg.global_config_path),
        user="root",
        group="vector",
        mode="0640",
    )
    config = secret_file(
        name="Deploy the Graphyard Vector config fragment",
        path=cfg.config_path,
        content=fragment,
        user="root",
        group="vector",
        mode="0640",
    )
    # The role's "Restart Graphyard Vector Service" handler, flushed before the
    # service is enabled and started.
    unit = f"{cfg.service_name}.service"
    systemd.service(
        name=f"Restart {unit}",
        service=unit,
        running=None,
        command="restart",
        _if=any_changed(env, global_config, config),
    )
    systemd.service(name=f"Enable {unit}", service=unit, running=None, enabled=True)
    systemd.service(name=f"Start {unit}", service=unit, running=True)


@deploy("Deploy graphyard vector")
def deploy_graphyard_vector(cfg: GraphyardVectorConfig, secrets: SecretValues) -> None:
    vector_steps(cfg, secrets)
