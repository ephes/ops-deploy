"""Remove foreign dpkg architectures (the ``dpkg_arch_remove`` role)."""

from __future__ import annotations

import shlex
from typing import Annotated, Any

from pydantic import Field, field_validator, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Command, Which
from pyinfra.operations import apt, server

from ops_deploy.base._common import RoleConfig, require_linux
from ops_deploy.helpers.probes import probe_command, probe_output

# A dpkg architecture name (``i386``, ``armhf``, ``musl-linux-amd64``). It may
# not start with ``-``, so it can never be read as an option of ``dpkg``.
DpkgArch = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]*$")]

FOREIGN = "dpkg --print-foreign-architectures"
INSTALLED = "dpkg-query -W -f='${Package} ${Architecture}\\n'"


class DpkgArchRemoveConfig(RoleConfig):
    # Like the role: a single name or a list; names are trimmed, empty ones
    # dropped and duplicates removed (first one kept).
    targets: tuple[DpkgArch, ...] = ("i386",)
    # The role can remove the packages of a target architecture first. The
    # port does not: either is refused when the config is built, and a host
    # with such packages makes the deploy fail before any change, as the role
    # does with its defaults.
    purge_packages: bool = False
    autoremove: bool = False
    update_cache: bool = True

    @field_validator("targets", mode="before")
    @classmethod
    def _normalize_targets(cls, value: Any) -> Any:
        items = [value] if isinstance(value, str) else value
        if not isinstance(items, list | tuple):
            return value
        names: list[Any] = []
        for item in items:
            name = item.strip() if isinstance(item, str) else item
            if name != "" and name not in names:
                names.append(name)
        return tuple(names)

    @model_validator(mode="after")
    def _no_package_removal(self) -> DpkgArchRemoveConfig:
        if self.purge_packages or self.autoremove:
            raise ValueError(
                "purge_packages and autoremove are not supported: remove the foreign-architecture packages first"
            )
        return self


def _read(command: str, what: str) -> list[str]:
    """Stripped, non-empty stdout lines of ``command``; the deploy fails when it fails."""

    output = probe_output(str(host.get_fact(Command, command=probe_command(command)) or ""))
    if output is None:
        raise DeployError(f"dpkg_arch_remove: cannot read {what} ({command} failed)")
    return [line.strip() for line in output.splitlines() if line.strip()]


@deploy("dpkg foreign architectures")
def deploy_dpkg_arch_remove(cfg: DpkgArchRemoveConfig) -> None:
    require_linux("dpkg_arch_remove")
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("dpkg_arch_remove needs a Debian-family host")

    foreign = set(_read(FOREIGN, "the foreign architectures"))
    present = [arch for arch in cfg.targets if arch in foreign]
    if not present:
        return

    installed = [line.partition(" ") for line in _read(INSTALLED, "the installed packages")]
    blocked = {
        arch: [f"{package}:{arch}" for package, _, package_arch in installed if package_arch == arch]
        for arch in present
    }
    found = "; ".join(f"'{arch}': {', '.join(names)}" for arch, names in blocked.items() if names)
    if found:
        # Before any change, also for the targets without packages.
        raise DeployError(
            f"dpkg_arch_remove: found packages for architecture {found}. "
            "Remove them before dropping the architecture (purging is not supported)."
        )

    for arch in present:
        server.shell(
            name=f"Remove dpkg architecture {arch}", commands=[f"dpkg --remove-architecture {shlex.quote(arch)}"]
        )
    if cfg.update_cache:
        apt.update(name="Update apt cache after architecture removal")
