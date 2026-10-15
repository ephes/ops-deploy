"""``deploy_docker_install`` and ``deploy_vector_apt_install`` against the fake connector."""

import json
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.infra import (
    DockerInstallConfig,
    VectorAptInstallConfig,
    deploy_docker_install,
    deploy_vector_apt_install,
)
from ops_deploy.infra._common import deb822_sources
from ops_deploy.infra.docker_install import daemon_json
from ops_deploy.infra.vector_apt_install import repository_line
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

DOCKER = DockerInstallConfig()
SOURCES = "/etc/apt/sources.list.d/docker.sources"
DOCKER_PACKAGES = (*DOCKER.prerequisite_packages, *DOCKER.packages)
DOCKER_CHECK = "Install Docker | Check Docker and Compose"


def docker_sources(cfg: DockerInstallConfig = DOCKER, arch: str = "amd64") -> str:
    return deb822_sources(
        name="docker",
        uris=cfg.repo_url,
        suites=("noble",),
        components=cfg.repo_components,
        signed_by=cfg.repo_keyring_path,
        architectures=(arch,),
    )


def docker_converged(cfg: DockerInstallConfig = DOCKER) -> dict[str, Any]:
    return {
        **fakehost.UBUNTU,
        **fakehost.apt_cache_fresh(),
        **fakehost.deb_installed(*DOCKER_PACKAGES),
        **fakehost.directory("/etc/apt/keyrings"),
        **fakehost.file(cfg.repo_keyring_path, "docker key"),
        **fakehost.directory("/etc/apt/sources.list.d"),
        **fakehost.file(SOURCES, docker_sources(cfg)),
        **fakehost.accounts({}, ("docker",)),
        **fakehost.service("docker.service"),
        **fakehost.directory("/etc/docker"),
    }


def run_docker(responses: dict[str, Any], cfg: DockerInstallConfig = DOCKER) -> FakeRun:
    result = run_deploy_fake(deploy_docker_install, cfg, responses=responses)
    assert result.succeeded, result.error
    return result


def test_docker_on_a_fresh_host_installs_everything() -> None:
    result = run_docker({**fakehost.UBUNTU, "uname -m": ["aarch64"]})

    commands = result.executed_commands
    assert any("install ca-certificates curl gnupg python3-debian" in c for c in commands)
    assert any("download.docker.com/linux/ubuntu/gpg" in c for c in commands)
    assert result.upload(SOURCES).decode() == docker_sources(arch="arm64")
    assert any(
        "install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin" in c
        for c in commands
    )
    assert "systemctl start docker.service" in commands
    assert "systemctl enable docker.service" in commands
    assert "groupadd -r docker" in commands
    # Nothing is removed that is not installed.
    assert not any("purge" in c or "remove" in c for c in commands)


def test_docker_second_run_changes_nothing() -> None:
    result = run_docker(docker_converged())

    assert result.mutating_changed_ops == []
    assert result.changed_ops == [DOCKER_CHECK]
    assert result.uploaded_paths == []


def test_conflicting_distribution_packages_are_purged() -> None:
    responses = docker_converged()
    responses["dpkg -l"] = [*responses["dpkg -l"], "ii  docker.io  1.0  all  docker.io", "ii  runc  1.0  all  runc"]

    result = run_docker(responses)

    assert result.mutating_changed_ops == ["Install Docker | Remove distribution packages that conflict with Docker"]
    assert any("remove" in c and "--purge" in c and "docker.io" in c and "runc" in c for c in result.executed_commands)


def test_conflicting_packages_can_be_kept() -> None:
    responses = docker_converged()
    responses["dpkg -l"] = [*responses["dpkg -l"], "ii  docker.io  1.0  all  docker.io"]

    result = run_docker(responses, DockerInstallConfig(remove_conflicting_packages=False))

    assert result.mutating_changed_ops == []


def test_changed_repository_file_is_rewritten_and_the_cache_updated() -> None:
    responses = docker_converged()
    responses.update(fakehost.file(SOURCES, "Types: deb\n"))

    result = run_docker(responses)

    assert result.mutating_changed_ops == [
        "Install Docker | Configure docker apt repository",
        "Install Docker | Update apt cache for the Docker repository",
    ]
    assert result.upload(SOURCES).decode() == docker_sources()


def test_docker_refuses_a_host_that_is_not_ubuntu() -> None:
    result = run_deploy_fake(deploy_docker_install, DOCKER, responses={**fakehost.UBUNTU, 'echo "$ID"': ["debian"]})

    assert not result.succeeded
    assert "supports Ubuntu only (got debian)" in str(result.error)
    assert result.executed_commands == []


def test_users_join_the_docker_group_and_a_stopped_service_is_started() -> None:
    cfg = DockerInstallConfig(users=("deploy",))
    responses = docker_converged(cfg)
    responses.update(fakehost.accounts({"deploy": "/home/deploy"}, ("docker",), shell="/bin/bash"))
    responses.update(fakehost.service("docker.service", running=False, enabled=False))

    result = run_docker(responses, cfg)

    assert "usermod -a -G docker deploy" in result.executed_commands
    assert "systemctl start docker.service" in result.executed_commands
    assert "systemctl enable docker.service" in result.executed_commands


def test_daemon_json_is_written_as_to_nice_json_and_restarts_docker() -> None:
    cfg = DockerInstallConfig(configure_daemon=True, daemon_config={"log-driver": "journald", "iptables": True})
    responses = docker_converged(cfg)

    result = run_docker(responses, cfg)

    text = result.upload("/etc/docker/daemon.json").decode()
    assert text == '{\n    "iptables": true,\n    "log-driver": "journald"\n}\n'
    assert json.loads(text) == cfg.daemon_config
    assert "Install Docker | Restart docker.service for daemon.json" in result.mutating_changed_ops
    assert "systemctl restart docker.service" in result.executed_commands


def test_daemon_json_matches_the_role_for_empty_and_nested_config() -> None:
    assert daemon_json({}) == "{}\n"
    assert (
        daemon_json({"a": {"b": [1, 2]}})
        == '{\n    "a": {\n        "b": [\n            1,\n            2\n        ]\n    }\n}\n'
    )


def test_unmanaged_service_skips_the_service_and_its_check() -> None:
    cfg = DockerInstallConfig(manage_service=False, verify_docker_info=False)

    result = run_docker(docker_converged(cfg), cfg)

    assert not any("systemctl" in c for c in result.executed_commands)
    assert result.mutating_changed_ops == []


@pytest.mark.parametrize(
    "bad", [{"repo_url": "http://download.docker.com"}, {"packages": ("Docker CE",)}, {"repo_keyring_path": "etc/key"}]
)
def test_docker_config_rejects_bad_inputs(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        DockerInstallConfig(**bad)
    with pytest.raises(ValidationError):
        DockerInstallConfig(unknown=1)  # type: ignore[call-arg]


# -- vector_apt_install ---------------------------------------------------------------

VECTOR = VectorAptInstallConfig()


def vector_converged(cfg: VectorAptInstallConfig = VECTOR) -> dict[str, Any]:
    return {
        **fakehost.UBUNTU,
        **fakehost.apt_cache_fresh(),
        **fakehost.deb_installed("apt-transport-https", "ca-certificates", "curl", "gnupg", "vector"),
        **fakehost.directory("/usr/share/keyrings"),
        **fakehost.file(cfg.repo_key_tmp, "armored key"),
        **fakehost.file(cfg.repo_keyring_path, "binary keyring"),
        **fakehost.directory("/etc/apt/sources.list.d"),
        **fakehost.file(cfg.repo_list_file, repository_line(cfg)),
    }


def run_vector(responses: dict[str, Any], cfg: VectorAptInstallConfig = VECTOR) -> FakeRun:
    result = run_deploy_fake(deploy_vector_apt_install, cfg, responses=responses)
    assert result.succeeded, result.error
    return result


def test_vector_repository_line_is_the_roles() -> None:
    assert repository_line(VECTOR) == (
        "deb [signed-by=/usr/share/keyrings/datadog-archive-keyring.gpg] https://apt.vector.dev/ stable vector-0\n"
    )


def test_vector_on_a_fresh_host_adds_key_repository_and_package() -> None:
    result = run_vector(dict(fakehost.UBUNTU))

    commands = result.executed_commands
    assert any("keys.datadoghq.com/DATADOG_APT_KEY_CURRENT.public" in c for c in commands)
    assert (
        "gpg --dearmor --yes --output /usr/share/keyrings/datadog-archive-keyring.gpg "
        "/tmp/vector-datadog-archive-keyring.public"
    ) in commands
    assert result.upload(VECTOR.repo_list_file).decode() == repository_line(VECTOR)
    assert commands.count("apt-get update") >= 1
    assert any(c.endswith("install vector") for c in commands)


def test_vector_second_run_changes_nothing() -> None:
    result = run_vector(vector_converged())

    assert result.mutating_changed_ops == []
    assert result.uploaded_paths == []
    assert not any("gpg" in c for c in result.executed_commands)


def test_missing_keyring_is_converted_from_the_downloaded_key() -> None:
    responses = vector_converged()
    for key in [k for k in responses if VECTOR.repo_keyring_path in k]:
        del responses[key]

    result = run_vector(responses)

    assert any("gpg --dearmor" in c for c in result.executed_commands)


def test_other_package_name_and_channel() -> None:
    cfg = VectorAptInstallConfig(package_name="vector-nightly", repo_channel="nightly")
    result = run_vector(vector_converged(cfg), cfg)

    assert result.mutating_changed_ops == [
        "Install Vector from apt | Install vector-nightly",
    ]
    assert " nightly vector-0\n" in repository_line(cfg)


def test_vector_config_rejects_bad_inputs() -> None:
    for bad in ({"repo_url": "http://apt.vector.dev"}, {"repo_key_tmp": "tmp/key"}, {"package_name": "Vector Pkg"}):
        with pytest.raises(ValidationError):
            VectorAptInstallConfig(**bad)
