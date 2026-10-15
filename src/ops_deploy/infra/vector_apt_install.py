"""Vector from its suite-independent apt repository (the ``vector_apt_install`` role).

The signing key is downloaded once into a temporary file and converted into
an apt keyring (``gpg --dearmor``), and the repository is one line in
``vector.list``; both are what the role writes, so Ansible and this deploy can
take turns on a host without rewriting anything. The package is installed
unpinned from the ``vector-0`` channel, as the role does.
"""

from __future__ import annotations

import shlex
from io import StringIO
from pathlib import PurePosixPath

from pyinfra import host
from pyinfra.api import deploy
from pyinfra.facts.files import File
from pyinfra.operations import apt, files, server
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import AbsolutePath, RoleConfig, require_linux
from ops_deploy.infra.postgres_install import PackageName, RepoWord, Url

PREREQUISITES = ["apt-transport-https", "ca-certificates", "curl", "gnupg"]


class VectorAptInstallConfig(RoleConfig):
    """The role's variables without the ``vector_apt_install_`` prefix (its defaults)."""

    package_name: PackageName = "vector"
    repo_url: Url = "https://apt.vector.dev/"
    repo_channel: RepoWord = "stable"
    repo_version: RepoWord = "vector-0"
    repo_key_url: Url = "https://keys.datadoghq.com/DATADOG_APT_KEY_CURRENT.public"
    repo_key_tmp: AbsolutePath = "/tmp/vector-datadog-archive-keyring.public"
    repo_keyring_path: AbsolutePath = "/usr/share/keyrings/datadog-archive-keyring.gpg"
    repo_list_file: AbsolutePath = "/etc/apt/sources.list.d/vector.list"


def repository_line(cfg: VectorAptInstallConfig) -> str:
    """The one line ``apt_repository`` keeps in the list file."""

    return f"deb [signed-by={cfg.repo_keyring_path}] {cfg.repo_url} {cfg.repo_channel} {cfg.repo_version}\n"


def vector_apt_steps(cfg: VectorAptInstallConfig) -> None:
    """The role's operations, for deploys that run the Vector install as a step of their own."""

    require_linux("vector_apt_install")
    apt.packages(name="Install apt prerequisites for Vector", packages=PREREQUISITES, update=True, cache_time=3600)
    keyring_dir = str(PurePosixPath(cfg.repo_keyring_path).parent)
    files.directory(name=f"Ensure {keyring_dir}", path=keyring_dir, user="root", group="root", mode="0755")
    # Downloaded once, like the role's get_url without force.
    key = files.download(
        name="Download Vector repository key",
        src=cfg.repo_key_url,
        dest=cfg.repo_key_tmp,
        user="root",
        group="root",
        mode="0644",
    )
    keyring_exists = bool(host.get_fact(File, path=cfg.repo_keyring_path))
    server.shell(
        name="Convert Vector repository key to an apt keyring",
        commands=[f"gpg --dearmor --yes --output {shlex.quote(cfg.repo_keyring_path)} {shlex.quote(cfg.repo_key_tmp)}"],
        _if=lambda: key.did_change() or not keyring_exists,
    )
    files.file(
        name="Ensure apt can read the Vector keyring",
        path=cfg.repo_keyring_path,
        user="root",
        group="root",
        mode="0644",
    )
    repo = files.put(
        name="Add Vector apt repository",
        src=StringIO(repository_line(cfg)),
        dest=cfg.repo_list_file,
        user="root",
        group="root",
        mode="0644",
    )
    apt.update(name="Update apt cache for the Vector repository", _if=any_changed(repo, key))
    apt.packages(name=f"Install {cfg.package_name}", packages=[cfg.package_name])


@deploy("Install Vector from apt")
def deploy_vector_apt_install(cfg: VectorAptInstallConfig) -> None:
    vector_apt_steps(cfg)
