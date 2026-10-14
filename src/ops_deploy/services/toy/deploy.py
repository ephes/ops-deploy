"""Toy service deploy.

A deliberately small service that exercises the pieces later services use:
typed config, a controller-side rsync behind an injectable runner, rendered
files, and a restart gated on changes. It writes no secrets.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path, PurePosixPath

from pydantic import Field, field_validator
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.templates import render
from ops_deploy.ops import sync_tree

TEMPLATE_PACKAGE = "ops_deploy.services.toy"

# Local environment files never reach the host (on top of sync_tree's own excludes).
SOURCE_EXCLUDES = (".env",)


class ToyConfig(BaseServiceConfig):
    service_name: ServiceName = "toy"
    user: UnixUser = "toy"
    site_path: PurePosixPath = PurePosixPath("/home/toy/site")
    source_path: Path | None = None
    app_port: int = Field(default=10099, ge=1024, le=65535)
    greeting: str = "hello"

    @field_validator("source_path")
    @classmethod
    def _source_is_directory(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_dir():
            raise ValueError("source_path is not a directory")
        return value

    @property
    def unit_path(self) -> PurePosixPath:
        return PurePosixPath("/etc/systemd/system") / f"{self.service_name}.service"

    @property
    def config_path(self) -> PurePosixPath:
        return self.site_path / "toy.conf"


@deploy("Deploy toy service")
def deploy_toy(cfg: ToyConfig, rsync: RsyncRunner = subprocess_rsync_runner) -> None:
    files.directory(
        name="Create site directory",
        path=str(cfg.site_path),
        user=cfg.user,
        group=cfg.user,
        mode="0755",
    )

    changes: list[OperationMeta] = []
    if cfg.source_path is not None:
        changes.append(
            sync_tree(
                name="Sync source",
                src=cfg.source_path,
                dest=cfg.site_path / "app",
                user=cfg.user,
                group=cfg.user,
                excludes=SOURCE_EXCLUDES,
                runner=rsync,
            )
        )

    changes.append(
        files.put(
            name="Write config",
            src=StringIO(render(TEMPLATE_PACKAGE, "toy.conf.j2", cfg=cfg)),
            dest=str(cfg.config_path),
            user=cfg.user,
            group=cfg.user,
            mode="0644",
        )
    )
    unit = files.put(
        name="Install systemd unit",
        src=StringIO(render(TEMPLATE_PACKAGE, "toy.service.j2", cfg=cfg)),
        dest=str(cfg.unit_path),
        mode="0644",
    )
    changes.append(unit)

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
        _if=any_changed(*changes),
    )
