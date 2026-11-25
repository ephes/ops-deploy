"""Voice session proxy deploy.

A loopback proxy on the Home Assistant host between HA's built-in voice
bridge and the OpenClaw gateway: all voice turns of one day share one warm
OpenClaw session, and HA's per-second date/time prompt line is dropped. See
``files/voice_session_proxy.py``. It holds no secrets: HA's Authorization
header passes through.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path, PurePosixPath

from pydantic import Field, field_validator
from pyinfra.api import deploy
from pyinfra.operations import files, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.templates import render

TEMPLATE_PACKAGE = "ops_deploy.services.voice_session_proxy"
ROOT = Path(__file__).parent


class VoiceSessionProxyConfig(BaseServiceConfig):
    service_name: ServiceName = "voice-session-proxy"
    # Name of the systemd DynamicUser; no account is created on the host.
    user: UnixUser = "voice-session-proxy"
    site_path: PurePosixPath = PurePosixPath("/usr/local/lib/voice-session-proxy")
    listen_port: int = Field(default=18790, ge=1024, le=65535)
    upstream_url: str = "http://127.0.0.1:18789"
    session_prefix: str = Field(default="voice-wohnzimmer", pattern=r"^[a-z0-9][a-z0-9-]{0,40}$")
    rollover_hour: int = Field(default=4, ge=0, le=23)
    timezone: str = Field(default="Europe/Berlin", pattern=r"^[A-Za-z_]+(/[A-Za-z_]+)*$")

    @field_validator("upstream_url")
    @classmethod
    def _loopback_http(cls, value: str) -> str:
        if not (value.startswith("http://127.0.0.1:") or value.startswith("http://localhost:")):
            raise ValueError("upstream_url must be a loopback http:// URL")
        return value

    @property
    def script_path(self) -> PurePosixPath:
        return self.site_path / "voice_session_proxy.py"

    @property
    def unit_path(self) -> PurePosixPath:
        return PurePosixPath("/etc/systemd/system") / f"{self.service_name}.service"


@deploy("Deploy voice session proxy")
def deploy_voice_session_proxy(cfg: VoiceSessionProxyConfig) -> None:
    files.directory(
        name="Create script directory",
        path=str(cfg.site_path),
        user="root",
        group="root",
        mode="0755",
    )
    script = files.put(
        name="Install proxy script",
        src=str(ROOT / "files/voice_session_proxy.py"),
        dest=str(cfg.script_path),
        user="root",
        group="root",
        mode="0644",
    )
    unit = files.put(
        name="Install systemd unit",
        src=StringIO(render(TEMPLATE_PACKAGE, "voice-session-proxy.service.j2", cfg=cfg)),
        dest=str(cfg.unit_path),
        user="root",
        group="root",
        mode="0644",
    )
    systemd.daemon_reload(name="Reload systemd", _if=any_changed(unit))
    systemd.service(
        name="Enable and start service",
        service=f"{cfg.service_name}.service",
        running=True,
        enabled=True,
    )
    systemd.service(
        name="Restart service",
        service=f"{cfg.service_name}.service",
        restarted=True,
        _if=any_changed(script, unit),
    )
