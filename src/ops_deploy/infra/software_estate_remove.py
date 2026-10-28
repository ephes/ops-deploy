"""Remove only the retired software-estate pilot's original installation path."""

from typing import Literal

from pyinfra.api.deploy import deploy
from pyinfra.operations import files

from ops_deploy.base import RoleConfig


class SoftwareEstateRemoveConfig(RoleConfig):
    install_dir: Literal["/usr/local/lib/software-estate"] = "/usr/local/lib/software-estate"


@deploy("Remove software estate tools")
def remove_software_estate(cfg: SoftwareEstateRemoveConfig) -> None:
    # Ansible file(state=absent) removes a directory, regular file or link, but
    # never follows a leaf symlink. Do not create a backup of a wrong-type leaf.
    files.directory(
        name="Remove software estate collector and bundled scanner",
        path=cfg.install_dir,
        present=False,
        force=True,
        force_backup=False,
    )
