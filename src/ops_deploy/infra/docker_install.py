"""Docker Engine and the Compose plugin from Docker's apt repository (the ``docker_install`` role).

Ubuntu only, like the role. The repository file is the one the role's
``deb822_repository`` task writes, byte for byte, so the two tools can take
turns on a host without rewriting it. Nothing here touches containers,
images, volumes or networks.
"""

from __future__ import annotations

import json
import shlex
from io import StringIO
from pathlib import PurePosixPath

from pydantic import Field, field_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Arch
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import AbsolutePath, RoleConfig, output, require_linux, require_systemd
from ops_deploy.core.config import UnixUser
from ops_deploy.helpers import mark_read_only
from ops_deploy.infra._common import apt_repository, codename
from ops_deploy.infra.postgres_install import PackageName, RepoWord, Url

ARCHITECTURES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


class DockerInstallConfig(RoleConfig):
    """The role's variables without the ``docker_install_`` prefix (its defaults)."""

    repo_url: Url = "https://download.docker.com/linux/ubuntu"
    # None: the host's release codename (the role's ansible_distribution_release).
    repo_suite: RepoWord | None = None
    repo_components: tuple[RepoWord, ...] = ("stable",)
    repo_key_url: Url = "https://download.docker.com/linux/ubuntu/gpg"
    repo_keyring_path: AbsolutePath = "/etc/apt/keyrings/docker.asc"

    # python3-debian is only needed by Ansible's deb822_repository; it stays so
    # that an Ansible run after this one finds its prerequisites in place.
    prerequisite_packages: tuple[PackageName, ...] = ("ca-certificates", "curl", "gnupg", "python3-debian")
    packages: tuple[PackageName, ...] = (
        "docker-ce",
        "docker-ce-cli",
        "containerd.io",
        "docker-buildx-plugin",
        "docker-compose-plugin",
    )
    # Distribution packages that conflict with docker-ce are purged.
    remove_conflicting_packages: bool = True
    conflicting_packages: tuple[PackageName, ...] = (
        "docker.io",
        "docker-compose",
        "docker-compose-v2",
        "docker-doc",
        "podman-docker",
        "containerd",
        "runc",
    )

    service_name: PackageName = "docker"
    enable_service: bool = True
    start_service: bool = True
    manage_service: bool = True
    # Added to the ``docker`` group (they need to log in again).
    users: tuple[UnixUser, ...] = ()

    configure_daemon: bool = False
    daemon_config_path: AbsolutePath = "/etc/docker/daemon.json"
    daemon_config: dict[str, object] = Field(default_factory=dict)

    verify: bool = True
    verify_docker_info: bool = True

    @field_validator("repo_keyring_path", "daemon_config_path")
    @classmethod
    def _file_path(cls, value: str) -> str:
        if value.endswith("/") or not PurePosixPath(value).name:
            raise ValueError("must be a file path")
        return value


def daemon_json(config: dict[str, object]) -> str:
    """``to_nice_json`` plus a newline, as the role writes ``daemon.json``."""

    return json.dumps(config, indent=4, sort_keys=True, separators=(",", ": ")) + "\n"


def _release() -> str:
    release = output('. /etc/os-release && echo "$ID"').strip()
    if release != "ubuntu":
        raise DeployError(f"docker_install currently supports Ubuntu only (got {release or 'unknown'})")
    return release


def docker_steps(cfg: DockerInstallConfig) -> None:
    """The role's operations, for deploys that run Docker's install as a step of their own."""

    require_linux("docker_install")
    _release()
    arch = ARCHITECTURES.get(host.get_fact(Arch) or "", host.get_fact(Arch) or "")
    suite = cfg.repo_suite or codename()

    apt.packages(
        name="Install Docker prerequisites",
        packages=list(cfg.prerequisite_packages),
        update=True,
        cache_time=3600,
    )
    if cfg.remove_conflicting_packages:
        apt.packages(
            name="Remove distribution packages that conflict with Docker",
            packages=list(cfg.conflicting_packages),
            present=False,
            extra_uninstall_args="--purge",
        )
    repo = apt_repository(
        name="docker",
        key_url=cfg.repo_key_url,
        keyring=cfg.repo_keyring_path,
        uris=cfg.repo_url,
        suites=(suite,),
        components=cfg.repo_components,
        architectures=(arch,),
    )
    # Decided while planning, so a converged dry run shows no update.
    if repo.will_change:
        apt.update(name="Update apt cache for the Docker repository")
    apt.packages(name="Install Docker Engine and Compose", packages=list(cfg.packages), update=True, cache_time=3600)

    daemon = None
    if cfg.configure_daemon:
        files.directory(
            name=f"Ensure {PurePosixPath(cfg.daemon_config_path).parent}",
            path=str(PurePosixPath(cfg.daemon_config_path).parent),
            mode="0755",
        )
        daemon = files.put(
            name="Write daemon.json",
            src=StringIO(daemon_json(cfg.daemon_config)),
            dest=cfg.daemon_config_path,
            user="root",
            group="root",
            mode="0644",
        )

    if cfg.manage_service:
        require_systemd("docker_install")
        server.group(name="Ensure group docker", group="docker", system=True)
        for user in cfg.users:
            server.user(name=f"Add {user} to the docker group", user=user, groups=["docker"], append=True)
        unit = f"{cfg.service_name}.service"
        systemd.service(
            name=f"Set {unit} state",
            service=unit,
            running=cfg.start_service,
            enabled=cfg.enable_service,
        )
        if daemon is not None and cfg.start_service:
            # The role's "Restart docker" handler (after the service task there).
            systemd.service(
                name=f"Restart {unit} for daemon.json",
                service=unit,
                running=None,
                restarted=True,
                _if=any_changed(daemon),
            )
    if cfg.verify:
        _verify(cfg)


@deploy("Install Docker")
def deploy_docker_install(cfg: DockerInstallConfig) -> None:
    docker_steps(cfg)


def _verify(cfg: DockerInstallConfig) -> None:
    checks = ["docker --version", "docker compose version"]
    if cfg.start_service and cfg.manage_service:
        checks.append(f"systemctl is-active --quiet {shlex.quote(cfg.service_name)}.service")
        if cfg.verify_docker_info:
            checks.append("docker info >/dev/null")
    mark_read_only(
        server.shell(
            name="Check Docker and Compose",
            commands=[" && ".join(checks)],
        )
    )
