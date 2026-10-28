"""Read before invoking the deployed helper, preserving software-live row semantics."""

from __future__ import annotations

import hashlib
import json
import shlex
from pathlib import PurePosixPath
from typing import Annotated, Any, ClassVar, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pyinfra.api.deploy import deploy

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.ops import secret_stdin
from ops_deploy.services.metrics_endpoint.common import PlainPath, password
from ops_deploy.services.software_live.common import RESOURCE


class SoftwareLiveTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    host_id: Annotated[str, Field(min_length=1)]
    url: Annotated[str, Field(pattern=r'^http://[^\s"\x27\\]+$')]


class SoftwareLiveNyxmonConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = ()
    service_name: ServiceName = "software-live-nyxmon"
    user: UnixUser = "nyxmon"
    site_path: PlainPath = PurePosixPath("/home/nyxmon/site")
    db_path: PlainPath = PurePosixPath("/home/nyxmon/site/db.sqlite3")
    install_dir: PlainPath = PurePosixPath("/usr/local/lib/software-live")
    auth_user: str = "nyxmon"
    targets: tuple[SoftwareLiveTarget, ...] = ()
    disable_names: tuple[str, ...] = ()

    @model_validator(mode="after")
    def upsert_credentials(self) -> Self:
        if self.targets and not self.disable_names and self.secrets is None:
            raise ValueError("software-live check upsert requires endpoint credentials")
        return self


def checks(cfg: SoftwareLiveNyxmonConfig, secret: str) -> list[dict[str, Any]]:
    specs = [
        ("$.schema_version", 2, "critical"),
        ("$.summary.fresh", True, "critical"),
        ("$.summary.observation_ok", True, "critical"),
        ("$.summary.os_ok", True, "warning"),
        ("$.summary.postgresql_ok", True, "warning"),
        ("$.summary.traefik_ok", True, "warning"),
        ("$.summary.security_updates_ok", True, "warning"),
        ("$.summary.apt_indexes_fresh", True, "warning"),
    ]
    return [
        {
            "service": "Live software health",
            "name": f"Software health ({target.host_id})",
            "url": target.url,
            "interval": 3600,
            "data": {
                "url": target.url,
                "timeout": 10,
                "retries": 1,
                "retry_delay": 2,
                "auth": {"username": cfg.auth_user, "password": secret},
                "checks": [
                    {"path": path, "op": "==", "value": value, "severity": severity}
                    for path, value, severity in [("$.host", target.host_id, "critical"), *specs]
                ],
            },
        }
        for target in cfg.targets
    ]


def current(output: str | None, desired: list[dict[str, Any]]) -> bool:
    expected = {}
    for check in desired:
        key = hashlib.sha256(json.dumps([check["service"], check["name"]]).encode()).hexdigest()
        data = json.dumps(check["data"], sort_keys=True)
        digest = hashlib.sha256(
            json.dumps(["json-metrics", check["url"], check["interval"], data, False]).encode()
        ).hexdigest()
        expected[key] = digest
    found = {}
    for line in (output or "").splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[0] != "check":
            return False
        found[parts[1]] = parts[2]
    return output is not None and found == expected


def command(cfg: SoftwareLiveNyxmonConfig, *args: str) -> str:
    return shlex.join(
        [
            "runuser",
            "-u",
            cfg.user,
            "--",
            "/usr/bin/python3",
            "-I",
            "-c",
            RESOURCE.joinpath("files/nyxmon_probe.py").read_text(),
            *args,
        ]
    )


@deploy("Provision software live Nyxmon checks")
def deploy_software_live_nyxmon(cfg: SoftwareLiveNyxmonConfig, secrets: SecretValues | None) -> None:
    payload: dict[str, Any]
    if cfg.disable_names:
        query = command(cfg, "disable", str(cfg.db_path), *cfg.disable_names)
        found = probe(query, name="Read software-live disabled checks")
        change = found != "enabled 0"
        payload = {"db": str(cfg.db_path), "disable_names": list(cfg.disable_names)}
    else:
        if not cfg.targets:
            return
        if secrets is None:
            raise ValueError("software-live Nyxmon needs credentials")
        desired = checks(cfg, password(secrets))
        names = [item for check in desired for item in (check["service"], check["name"])]
        query = command(cfg, "upsert", str(cfg.db_path), *names)
        found = probe(query, name="Read software-live owned checks")
        change = not current(found, desired)
        payload = {"db": str(cfg.db_path), "checks": desired}
    if change:
        # The existing deployed helper is also used by inventory/estate callers.
        secret_stdin(
            name="Update software-live Nyxmon checks",
            command=shlex.join(
                ["runuser", "-u", cfg.user, "--", "/usr/bin/python3", str(cfg.install_dir / "nyxmon_checks.py")]
            )
            + " >/dev/null",
            content=SecretContent(json.dumps(payload)),
        )
    if found is None:
        mark_read_only(verify_probe(query, name="Verify software-live check access"))
