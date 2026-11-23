"""Original Home Assistant UV dependency; shared installer defaults stay unchanged."""

from __future__ import annotations

import shlex
from collections.abc import Generator
from typing import Self

from pydantic import Field, model_validator
from pyinfra import host
from pyinfra.api import operation
from pyinfra.facts.files import File, Link
from pyinfra.operations import files, server

from ops_deploy.base._common import Sha256, Version
from ops_deploy.base.uv_install import UvInstallConfig, deploy_uv_install, installed_version, release, trusted_file
from ops_deploy.helpers.checks import mark_read_only

from .planning import executing


class HomeAssistantUvConfig(UvInstallConfig):
    """Resolved include inputs; the original inert ``uv_install_user`` is absent.

    The private mapper must resolve the HA include's version/path/update/force
    variables and the generic role's owner/group/checksum variables separately.
    The include disables deprecated symlinks, so this component creates none.
    """

    version: Version = "0.13.9"
    checksums: dict[str, Sha256] = Field(
        default_factory=lambda: {
            "x86_64-unknown-linux-gnu": "a7fbaff2b9a271d85c1bdb540941090fd1ce011797b4abeb48e4dcd39c2471d5",
            "aarch64-unknown-linux-gnu": "0797542018e541a9288855df555c8077eed06f7a47d206362030480e8ecc9f3d",
            "x86_64-apple-darwin": "617a3211261b0fc739562f0071aa34e9739797c510208ede8e2977c30903d041",
            "aarch64-apple-darwin": "5aeca67f2283f75235de40d0bd9c0a5bbc5fce23b6d48b3bf9fa1b2db08382ca",
        }
    )

    @model_validator(mode="after")
    def linux_dependency(self) -> Self:
        if self.darwin:
            raise ValueError("Home Assistant requires the Linux uv dependency")
        return self


@operation()
def _verify_uv(binary: str) -> Generator[str, None, None]:
    if not executing():
        return  # Read-only check: listed without a change in a dry run.
    yield from server.shell._inner(commands=[f"{binary} --version && {binary} --help >/dev/null"])


def install_uv(cfg: HomeAssistantUvConfig, *, manage: bool) -> bool:
    """Call at the original UV include boundary, after account/layout tasks.

    Return whether a UV installation is registered: later steps that run UV
    cannot be inspected while planning before it has run.
    """
    if not manage:
        return False
    binary_path = cfg.install_dir + "/uv"
    is_link = bool(host.get_fact(Link, path=binary_path))
    exists = is_link or bool(host.get_fact(File, path=binary_path))
    # Never run a foreign-owned, writable or non-executable uv; such a file counts as missing.
    exists = exists and (is_link or trusted_file(binary_path, cfg.owner))
    current = installed_version(binary_path) if exists and not is_link else ""
    # Match the original role before delegating installation. The shared helper
    # additionally repairs a missing uvx/broken uv even with updates disabled;
    # those repairs were not part of this role's include contract.
    # A newer uv is kept, never downgraded (as deploy_uv_install does).
    # A broken uv (no parseable version) still counts as needing the update.
    older = not current or release(current) < release(cfg.version)
    needed = not exists or is_link or cfg.force_reinstall or (cfg.update_existing and older)
    if needed:
        deploy_uv_install(cfg=cfg)
    else:
        files.directory(name=f"Ensure {cfg.install_dir}", path=cfg.install_dir, mode="0755")
    binary = shlex.quote(cfg.install_dir + "/uv")
    mark_read_only(_verify_uv(name="Verify Home Assistant UV version and functionality", binary=binary))
    return needed
