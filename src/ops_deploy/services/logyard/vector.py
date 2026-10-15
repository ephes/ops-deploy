"""logyard vector: the journald producer that ships a host's logs to Logyard.

Port of the ``logyard_vector_deploy`` role (with ``vector_apt_install``) and
``playbooks/deploy-logyard-vector.yml``. Vector is installed from its apt
channel, the shared global fragment and the Logyard fragment are written into
``config.d``, and the whole directory is validated with ``vector validate``
before either live file is replaced. The fragment template is shipped
unchanged and rendered like Ansible's ``template`` module renders it, so the
files are byte-identical to the role's (``tests/test_logyard_parity.py``).

The role reads ``vector --version`` after installing the package to decide
whether to emit the template-confinement opt-out (Vector 0.57 and newer).
pyinfra decides while planning, before anything is installed: on a host that
already runs Vector the answer is the same; on a host without it the
configured default applies (``supports_template_confinement``), and the
validation step stops a wrong guess before it replaces the running config.
"""

from __future__ import annotations

import base64
import json
import re
import shlex
from collections.abc import Generator
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated, Literal

import yaml
from pydantic import Field, field_validator
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.facts.files import FileContents
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base import RoleConfig
from ops_deploy.core.config import ServiceName
from ops_deploy.helpers import mark_read_only
from ops_deploy.infra import VectorAptInstallConfig, vector_apt_steps
from ops_deploy.services.logyard._common import Part, Url, Word, probe, render_role

VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
CONFINEMENT_SINCE = (0, 57, 0)
CONFIG_PATTERNS = ("*.yaml", "*.yml", "*.toml", "*.json")


class Match(Part):
    """One journald ``include_matches`` entry."""

    key: Annotated[str, Field(min_length=1)]
    value: str | tuple[str, ...]


class LogyardVectorConfig(RoleConfig):
    """The role's variables without the ``logyard_vector_`` prefix (defaults from its defaults/main.yml)."""

    apt: VectorAptInstallConfig = VectorAptInstallConfig()
    config_dir: PurePosixPath = PurePosixPath("/etc/vector/config.d")
    config_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+\.(yaml|yml)$")] = "30-logyard-journald.yaml"
    global_config_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+\.(yaml|yml)$")] = "00-global.yaml"
    env_file: PurePosixPath = PurePosixPath("/etc/default/vector")
    data_dir: PurePosixPath = PurePosixPath("/var/lib/vector")
    service_name: ServiceName = "vector"

    ingest_endpoint: Url = "http://127.0.0.1:3101"
    host_id: Word
    environment: Word = "prod"
    source_type: Literal["journald"] = "journald"
    include_units: tuple[str, ...] = ()
    exclude_units: tuple[str, ...] = ()
    include_matches: tuple[Match, ...] = ()
    current_boot_only: bool = False

    http_timeout_secs: int = Field(default=15, ge=1)
    request_concurrency: int = Field(default=1, ge=1)
    retry_initial_backoff_secs: int = Field(default=1, ge=1)
    retry_max_duration_secs: int = Field(default=3600, ge=1)
    batch_timeout_secs: int = Field(default=5, ge=1)
    batch_max_events: int = Field(default=200, ge=1)
    buffer_max_size: int = Field(default=268435488, ge=1)
    healthcheck_enabled: bool = False
    allow_unconfined_label_templates: bool = True
    # Used only when the installed Vector version cannot be read while planning.
    supports_template_confinement: bool = True

    @field_validator("config_dir", "env_file", "data_dir")
    @classmethod
    def _absolute(cls, value: PurePosixPath) -> PurePosixPath:
        if not value.is_absolute() or ".." in value.parts or value == PurePosixPath("/"):
            raise ValueError("paths must be absolute, without '..', and not '/'")
        return value

    @property
    def config_path(self) -> PurePosixPath:
        return self.config_dir / self.config_name

    @property
    def global_config_path(self) -> PurePosixPath:
        return self.config_dir / self.global_config_name


def role_vars(cfg: LogyardVectorConfig, supports_confinement: bool | None = None) -> dict[str, object]:
    return {
        "logyard_vector_ingest_endpoint": cfg.ingest_endpoint,
        "logyard_vector_host_id": cfg.host_id,
        "logyard_vector_environment": cfg.environment,
        "logyard_vector_source_type": cfg.source_type,
        "logyard_vector_include_units": list(cfg.include_units),
        "logyard_vector_exclude_units": list(cfg.exclude_units),
        "logyard_vector_include_matches": [
            {"key": m.key, "value": list(m.value) if isinstance(m.value, tuple) else m.value}
            for m in cfg.include_matches
        ],
        "logyard_vector_current_boot_only": cfg.current_boot_only,
        "logyard_vector_http_timeout_secs": cfg.http_timeout_secs,
        "logyard_vector_request_concurrency": cfg.request_concurrency,
        "logyard_vector_retry_initial_backoff_secs": cfg.retry_initial_backoff_secs,
        "logyard_vector_retry_max_duration_secs": cfg.retry_max_duration_secs,
        "logyard_vector_batch_timeout_secs": cfg.batch_timeout_secs,
        "logyard_vector_batch_max_events": cfg.batch_max_events,
        "logyard_vector_buffer_max_size": cfg.buffer_max_size,
        "logyard_vector_healthcheck_enabled": cfg.healthcheck_enabled,
        "logyard_vector_allow_unconfined_label_templates": cfg.allow_unconfined_label_templates,
        "logyard_vector_supports_template_confinement": (
            cfg.supports_template_confinement if supports_confinement is None else supports_confinement
        ),
    }


def render_fragment(cfg: LogyardVectorConfig, supports_confinement: bool | None = None) -> str:
    return render_role("vector.yaml.j2", role_vars(cfg, supports_confinement))


def render_global(cfg: LogyardVectorConfig) -> str:
    """The shared global fragment (``data_dir``), as the role writes it."""

    return f"data_dir: {json.dumps(str(cfg.data_dir))}\n"


def supports_confinement(version_output: str, default: bool) -> bool:
    """Whether ``vector --version`` output names Vector 0.57 or newer; ``default`` when unreadable."""

    found = VERSION_PATTERN.search(version_output)
    if not found:
        return default
    return tuple(int(part) for part in found.group().split(".")) >= CONFINEMENT_SINCE


def global_data_dir(raw: list[str] | None, default: PurePosixPath) -> str:
    """``data_dir`` of the existing shared global fragment (the role's ``from_yaml`` lookup)."""

    if not raw:
        return str(default)
    loaded = yaml.safe_load("\n".join(raw)) or {}
    if not isinstance(loaded, dict):
        raise DeployError("the shared Vector global config is not a mapping")
    return str(loaded.get("data_dir") or default)


def lineinfile(path: str, regexp: str, line: str, *, current: list[str] | None) -> str:
    """``current`` with ``line`` replacing the last line matching ``regexp``, else appended."""

    lines = list(current or [])
    pattern = re.compile(regexp)
    matches = [index for index, text in enumerate(lines) if pattern.search(text)]
    if matches:
        lines[matches[-1]] = line
    else:
        lines.append(line)
    return "\n".join(lines) + "\n"


@operation()
def _env_line(path: str, line: str) -> Generator[StringCommand, None, None]:
    """The role's ``lineinfile``: ``VECTOR_CONFIG_DIR=`` set in the defaults file, created if missing."""

    content = lineinfile(path, "^VECTOR_CONFIG_DIR=", line, current=host.get_fact(FileContents, path=path))
    yield from files.put._inner(src=StringIO(content), dest=path, user="root", group="root", mode="0644")


def validate_command(cfg: LogyardVectorConfig, fragment: str) -> str:
    """Validate the config directory with this deploy's two fragments swapped in, in a temp directory."""

    def b64(text: str) -> str:
        return base64.b64encode(text.encode()).decode()

    live = shlex.quote(str(cfg.config_dir))
    names = " -o ".join(f"-name '{pattern}'" for pattern in CONFIG_PATTERNS)
    skip = " ".join(f"! -name {shlex.quote(name)}" for name in (cfg.config_name, cfg.global_config_name))
    script = (
        "set -e; dir=$(mktemp -d /tmp/logyard-vector-validate-XXXXXX); trap 'rm -rf \"$dir\"' EXIT; "
        f'if [ -d {live} ]; then find {live} -maxdepth 1 -type f \\( {names} \\) {skip} -exec cp {{}} "$dir"/ \\;; fi; '
        f'printf %s {b64(render_global(cfg))} | base64 -d > "$dir"/{shlex.quote(cfg.global_config_name)}; '
        f'printf %s {b64(fragment)} | base64 -d > "$dir"/{shlex.quote(cfg.config_name)}; '
        'vector validate --skip-healthchecks --config-dir "$dir"'
    )
    return f"bash -c {shlex.quote(script)}"


def vector_steps(cfg: LogyardVectorConfig) -> None:
    vector_apt_steps(cfg.apt)

    fragment = render_fragment(cfg, supports_confinement(probe("vector --version"), cfg.supports_template_confinement))
    existing = global_data_dir(host.get_fact(FileContents, path=str(cfg.global_config_path)) or None, cfg.data_dir)
    if existing != str(cfg.data_dir):
        raise DeployError(
            f"existing shared Vector global config uses data_dir={existing}, "
            f"but data_dir={cfg.data_dir}; align the shared Vector data_dir before deploying"
        )

    # Validation first: nothing live (env file, legacy config) changes if it fails.
    mark_read_only(
        server.shell(name="Validate the staged Vector configuration", commands=[validate_command(cfg, fragment)])
    )
    files.directory(
        name="Ensure Vector data directory", path=str(cfg.data_dir), user="vector", group="vector", mode="0750"
    )
    files.directory(
        name="Ensure Vector config directory", path=str(cfg.config_dir), user="root", group="vector", mode="0750"
    )
    env = _env_line(
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
    config = files.put(
        name="Deploy the Logyard Vector config fragment",
        src=StringIO(fragment),
        dest=str(cfg.config_path),
        user="root",
        group="vector",
        mode="0640",
    )
    # The role's "Restart Logyard Vector Service" handler, flushed before the
    # service is enabled and started. It also fires on the run that installed
    # Vector: the package may start the service with its stock config first.
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


@deploy("Deploy logyard vector")
def deploy_logyard_vector(cfg: LogyardVectorConfig) -> None:
    vector_steps(cfg)
