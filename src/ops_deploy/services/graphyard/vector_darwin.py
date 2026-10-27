"""The existing Graphyard Vector Homebrew/launchd role branch."""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from importlib.resources import files
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Annotated, Any
from xml.sax.saxutils import escape

from pydantic import Field, field_validator
from pyinfra import host
from pyinfra.facts.server import Command
from pyinfra.operations import server

from ops_deploy.base import RoleConfig
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.ops import secret_stdin
from ops_deploy.services.graphyard._common import Word, absolute, render_role

if TYPE_CHECKING:
    from ops_deploy.services.graphyard.vector import GraphyardVectorConfig


class GraphyardVectorDarwinConfig(RoleConfig):
    """Role defaults for Darwin; existing runtime identities must already exist."""

    brew_user: Word
    brew_bin: PurePosixPath | None = None
    brew_package: Word = "vector"
    brew_update: bool = False
    disable_brew_service: bool = True
    brew_service_name: Word = "vector"
    binary_path: PurePosixPath | None = None
    runtime_user: Word = "root"
    runtime_group: Word = "wheel"
    validation_group: Word = "wheel"
    launchd_label: Word = "de.wersdoerfer.graphyard.vector"
    launchd_plist_path: PurePosixPath | None = None
    launchd_keepalive: bool = True
    launchd_path: Annotated[str, Field(pattern=r"^[^\x00-\x1f\x7f]+$")] = (
        "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    )
    log_dir: PurePosixPath = PurePosixPath("/var/log/vector")
    stdout_log_path: PurePosixPath | None = None
    stderr_log_path: PurePosixPath | None = None
    newsyslog_conf_path: PurePosixPath = PurePosixPath("/etc/newsyslog.d/graphyard-vector.conf")
    log_rotation_enabled: bool = True
    log_rotation_owner_group: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+:[A-Za-z0-9_-]+$")] = "root:wheel"
    log_rotation_mode: Annotated[str, Field(pattern=r"^[0-7]{3,4}$")] = "640"
    log_rotation_count: int = Field(default=7, ge=0)
    log_rotation_size_kb: int = Field(default=10240, ge=1)
    log_rotation_when: Annotated[str, Field(pattern=r"^[A-Za-z0-9*/@$:.-]+$")] = "*"
    log_rotation_flags: Annotated[str, Field(pattern=r"^[A-Za-z]+$")] = "ZN"

    @field_validator(
        "brew_bin",
        "binary_path",
        "launchd_plist_path",
        "log_dir",
        "stdout_log_path",
        "stderr_log_path",
        "newsyslog_conf_path",
    )
    @classmethod
    def _absolute(cls, value: PurePosixPath | None) -> PurePosixPath | None:
        if value is not None and any(ord(char) < 32 or ord(char) == 127 for char in str(value)):
            raise ValueError("native paths must not contain control characters")
        return None if value is None else absolute(value)


def native_payload(cfg: GraphyardVectorConfig, fragment: str) -> dict[str, Any]:
    native = cfg.darwin
    assert native is not None
    values = {"graphyard_vector_" + key: value for key, value in native.model_dump(mode="json").items()}
    values.update(
        graphyard_vector_binary_path_resolved=str(native.binary_path)
        if native.binary_path
        else "__GRAPHYARD_VECTOR_BINARY__",
        graphyard_vector_config_dir=str(cfg.config_dir),
        graphyard_vector_data_dir=str(cfg.data_dir),
        graphyard_vector_stdout_log_path=str(native.stdout_log_path or native.log_dir / "graphyard-vector.log"),
        graphyard_vector_stderr_log_path=str(native.stderr_log_path or native.log_dir / "graphyard-vector.err.log"),
    )
    data = native.model_dump(mode="json")
    data.update(
        config_dir=str(cfg.config_dir),
        config_path=str(cfg.config_path),
        global_config_path=str(cfg.global_config_path),
        data_dir=str(cfg.data_dir),
        launchd_plist_path=str(
            native.launchd_plist_path or PurePosixPath("/Library/LaunchDaemons") / (native.launchd_label + ".plist")
        ),
    )
    contents = {
        str(cfg.config_path): fragment,
        str(cfg.global_config_path): "data_dir: " + json.dumps(str(cfg.data_dir)) + "\n",
        str(data["launchd_plist_path"]): render_role(
            "vector.launchd.plist.j2",
            {key: escape(value) if isinstance(value, str) else value for key, value in values.items()},
        ),
    }
    if native.log_rotation_enabled:
        contents[str(native.newsyslog_conf_path)] = render_role("vector.newsyslog.conf.j2", values)
    data["contents"] = contents
    return data


def host_command(data: dict[str, Any], action: str) -> str:
    # Only hashes, paths and public runtime settings appear in argv. The bearer
    # token and full configuration reach apply exclusively through secret_stdin.
    public = {key: value for key, value in data.items() if key != "contents"}
    contents = data["contents"]
    assert isinstance(contents, dict)
    public["hashes"] = {path: hashlib.sha256(text.encode()).hexdigest() for path, text in contents.items()}
    public["plist_template"] = contents[str(data["launchd_plist_path"])]
    script = files("ops_deploy.services.graphyard").joinpath("files/graphyard_vector_host.py").read_bytes()
    launcher = (
        "import base64;exec(compile(base64.b64decode('"
        + base64.b64encode(script).decode()
        + "'),'<graphyard-vector-host>','exec'))"
    )
    encoded = base64.b64encode(json.dumps(public).encode()).decode()
    return shlex.join(["/usr/bin/python3", "-B", "-c", launcher, action, encoded])


def darwin_steps(cfg: GraphyardVectorConfig, fragment: str) -> None:
    data = native_payload(cfg, fragment)
    current = host.get_fact(Command, command=host_command(data, "status"))
    if current != "current":
        secret_stdin(
            name="Converge native Graphyard Vector",
            command=host_command(data, "apply"),
            content=SecretContent(json.dumps(data) + "\n"),
        )
    mark_read_only(
        server.shell(
            name="Verify native Graphyard Vector and live configuration", commands=[host_command(data, "verify")]
        )
    )
