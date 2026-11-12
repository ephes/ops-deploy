"""apt installs that leave every other service alone, for the NFS and tlshd deploys.

needrestart runs after each dpkg transaction and, in its default interactive
mode, may restart services whose libraries changed; package scripts may also
toggle units (the NFS over TLS lab test of 2026-11-12 found ``zfs-share`` and
``remote-fs-pre.target`` changed after the NFS packages came and went). So
needrestart is suspended and set to list mode, and units that were enabled
before the install are enabled again afterwards (nothing is started or
stopped).
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence

from pyinfra import host
from pyinfra.api import DeployError
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.deb import DebPackages
from pyinfra.facts.server import Which
from pyinfra.operations import server

from ops_deploy.base._units import ENABLED, unit_states

APT_ENV = ("NEEDRESTART_SUSPEND=1", "NEEDRESTART_MODE=l", "DEBIAN_FRONTEND=noninteractive")
# Units an NFS package change was seen to toggle. ``static`` units (the
# target on both noble hosts) have no enablement and are left alone.
KEEP_ENABLED = ("zfs-share.service", "remote-fs-pre.target")


def install_command(packages: Sequence[str]) -> str:
    return shlex.join(["env", *APT_ENV, "apt-get", "install", "-y", "-q", "--no-install-recommends", *packages])


def install_packages(packages: Sequence[str], *, what: str) -> OperationMeta | None:
    """Install the missing ``packages``; ``None`` when all are installed already.

    The enablement of :data:`KEEP_ENABLED` is read while planning, that is
    before the install, and restored right after it.
    """

    if not host.get_fact(Which, command="apt-get"):
        raise DeployError(f"{what} needs Debian/Ubuntu apt")
    installed = host.get_fact(DebPackages) or {}
    missing = [name for name in packages if name not in installed]
    if not missing:
        return None
    enabled = [unit for unit, state in unit_states(KEEP_ENABLED).items() if state.get("UnitFileState") in ENABLED]
    install = server.shell(
        name=f"Install {' '.join(missing)}", commands=["apt-get update -q", install_command(missing)]
    )
    if enabled:
        server.shell(
            name=f"Keep {' '.join(enabled)} enabled after the install",
            commands=[f"systemctl enable -- {shlex.join(enabled)}"],
        )
    return install
