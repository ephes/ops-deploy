"""Toy service deploy.

A deliberately small service that exercises the pieces later services use:
typed config, a controller-side rsync behind an injectable runner, rendered
files, and a restart gated on changes. It writes no secrets.
"""

from __future__ import annotations

from collections.abc import Generator, Sequence
from io import StringIO
from pathlib import Path, PurePosixPath

from pydantic import Field, field_validator
from pyinfra import host
from pyinfra.api import FunctionCommand, deploy, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.rsync import RsyncRunner, run_checked, subprocess_rsync_runner
from ops_deploy.core.templates import render

TEMPLATE_PACKAGE = "ops_deploy.services.toy"

# Never transferred, whatever the source tree contains.
MANDATORY_EXCLUDES = (".git", ".venv", "__pycache__", ".env")


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


def rsync_argv(cfg: ToyConfig, remote: str, *, dry_run: bool) -> list[str]:
    """Build the rsync command line; ``remote`` is ``user@host``."""

    assert cfg.source_path is not None
    argv = ["rsync", "-rlt", "--delete", "--no-owner", "--no-group", f"--chown={cfg.user}:{cfg.user}"]
    if dry_run:
        argv += ["--dry-run", "--itemize-changes", "--out-format=%i %n%L"]
    argv += [f"--exclude={pattern}" for pattern in MANDATORY_EXCLUDES]
    argv += ["-e", "ssh", f"{cfg.source_path}/", f"{remote}:{cfg.site_path / 'app'}/"]
    return argv


def _remote_for_current_host() -> str:
    hostname = host.data.get("ssh_hostname") or host.name
    user = host.data.get("ssh_user") or "root"
    return f"{user}@{hostname}"


def _run_rsync(runner: RsyncRunner, argv: Sequence[str]) -> None:
    run_checked(runner, argv)


@operation()
def push_source(cfg: ToyConfig, runner: RsyncRunner) -> Generator[FunctionCommand, None, None]:
    """Sync ``cfg.source_path`` to ``<site_path>/app`` if rsync reports changes.

    The dry run happens at plan time so the operation reports no change (and
    yields nothing) when the trees already match.
    """

    remote = _remote_for_current_host()
    plan = run_checked(runner, rsync_argv(cfg, remote, dry_run=True))
    if not plan.itemized_lines:
        host.noop(f"{cfg.site_path / 'app'} is up to date")
        return
    yield FunctionCommand(_run_rsync, (runner, rsync_argv(cfg, remote, dry_run=False)), {})


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
        changes.append(push_source(name="Sync source", cfg=cfg, runner=rsync))

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
