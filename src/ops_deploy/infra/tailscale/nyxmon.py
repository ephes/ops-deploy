"""Dedicated original Tailscale SQL semantics, without generic check retirement."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.helpers.probes import StdinLines, probe
from ops_deploy.infra.netplan.config import Hostname

SCRIPT = (Path(__file__).parents[1] / "files/tailscale_nyxmon.py").read_text()


class TailscaleNyxmonTarget(RoleConfig):
    hostname: Hostname
    url: str
    check_interval: int = Field(default=3600, ge=1)
    max_age_seconds: int = Field(default=900, ge=1)
    stale_severity: Literal["warning", "critical"] = "critical"
    notify_consecutive_failures: int = Field(default=0, ge=0)
    require_self_online: bool = False
    require_default_ipv4_route: bool = False
    require_mdraid_healthy: bool = False

    @model_validator(mode="after")
    def _url(self) -> TailscaleNyxmonTarget:
        value = urlsplit(self.url)
        if (
            value.scheme not in {"http", "https"}
            or not value.hostname
            or value.username
            or value.password
            or any(c.isspace() or ord(c) < 32 for c in self.url)
        ):
            raise ValueError("Tailscale check URL must be HTTP(S) without embedded credentials")
        return self


class TailscaleNyxmonConfig(RoleConfig):
    db_path: AbsolutePath = "/home/nyxmon/site/db.sqlite3"
    user: str = Field(default="nyxmon", pattern=r"^[a-z_][a-z0-9_-]*$")
    service_name: str = "Tailscale"
    targets: tuple[TailscaleNyxmonTarget, ...] = ()

    @model_validator(mode="after")
    def _safe(self) -> TailscaleNyxmonConfig:
        if ".." in self.db_path.split("/") or not self.service_name or any(ord(c) < 32 for c in self.service_name):
            raise ValueError("invalid Tailscale DB/service binding")
        if len({target.hostname for target in self.targets}) != len(self.targets):
            raise ValueError("Tailscale SQL target hostnames must be unique")
        return self


def check_row(target: TailscaleNyxmonTarget, credential: SecretStr) -> dict[str, object]:
    checks: list[dict[str, object]] = [dict(path="$.summary.backend_running", op="==", value=True, severity="critical")]
    for field in ("self_online", "default_ipv4_route", "mdraid_healthy"):
        if getattr(target, "require_" + field):
            key = field + "_present" if field == "default_ipv4_route" else field
            checks.append(dict(path="$.summary." + key, op="==", value=True, severity="critical"))
    checks += [
        dict(path="$.summary.key_expiry_critical_ok", op="==", value=True, severity="critical"),
        dict(path="$.summary.key_expiry_warning_ok", op="==", value=True, severity="warning"),
        dict(path="$.meta.age_seconds", op="<", value=target.max_age_seconds, severity=target.stale_severity),
    ]
    data: dict[str, object] = dict(
        url=target.url,
        timeout=10.0,
        retries=1,
        retry_delay=2.0,
        auth=dict(username="nyxmon", password=credential.get_secret_value()),
        checks=checks,
    )
    if target.notify_consecutive_failures:
        data["notification_policy"] = dict(consecutive_failures=target.notify_consecutive_failures)
    return dict(
        name=f"Tailscale key expiry ({target.hostname})",
        check_type="json-metrics",
        url=target.url,
        check_interval=target.check_interval,
        data=data,
    )


@operation()
def reconcile(data: SecretStr, user: str) -> Generator[StringCommand, None, None]:
    command = shlex.join(["runuser", "-u", user, "--", "python3", "-I", "-B", "-c", SCRIPT])
    content = data.get_secret_value()
    answer = probe(command + " check", name="Dedicated Tailscale Nyxmon declared rows", stdin=content)
    if answer in {"current", "absent"}:
        host.noop("Tailscale checks current, or original optional Nyxmon database absent")
    elif answer == "pending":
        yield StringCommand(command + " apply", _stdin=StdinLines(content), _get_pty=False, _shell_executable="sh")
    else:
        raise DeployError("Tailscale Nyxmon DB state is unavailable; no SQL write admitted")


@deploy("Upsert dedicated Tailscale expiry checks")
def deploy_tailscale_nyxmon(cfg: TailscaleNyxmonConfig, credentials: dict[str, SecretStr]) -> None:
    if set(credentials) != {target.hostname for target in cfg.targets}:
        raise DeployError("Tailscale SQL credentials must bind exactly the prepared endpoint targets")
    if any(not value.get_secret_value() for value in credentials.values()):
        raise DeployError("Tailscale SQL credentials must be nonempty")
    content = json.dumps(
        dict(
            db_path=cfg.db_path,
            user=cfg.user,
            service_name=cfg.service_name,
            checks=[check_row(target, credentials[target.hostname]) for target in cfg.targets],
        )
    )
    reconcile(
        name="Preserve disabled/status/processing/schedule while upserting original fields",
        data=SecretStr(content),
        user=cfg.user,
    )
