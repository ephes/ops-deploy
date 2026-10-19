"""The destructive synthetic-fixture setup must reject foreign Docker mounts first."""

from __future__ import annotations

import copy
import json
import subprocess
from typing import Any

import pytest

from tests.test_native_venv_inventory_docker import DockerFixture


def inspected_fixture() -> dict[str, Any]:
    return {
        "Name": "/native-p0a-fixture",
        "State": {"Running": True},
        "Image": "sha256:fixture",
        "Mounts": [],
        "Config": {
            "User": "65534:65534",
            "Volumes": None,
            "Labels": {"ops-deploy.fixture": "native-venv-inventory", "ops-deploy.run": "fixture"},
        },
        "HostConfig": {
            "ReadonlyRootfs": True,
            "NetworkMode": "none",
            "Binds": None,
            "Mounts": [],
            "PortBindings": {},
            "Memory": 256 * 1024 * 1024,
            "MemorySwap": 256 * 1024 * 1024,
            "NanoCpus": 1000000000,
            "PidsLimit": 32,
            "CapDrop": ["ALL"],
            "CapAdd": ["CAP_CHOWN"],
            "Tmpfs": {
                "/opt/native-venv-inventory-fixture": "rw,nosuid,nodev,noexec,size=32m,mode=0755,uid=65534,gid=65534"
            },
            "Privileged": False,
            "SecurityOpt": ["no-new-privileges"],
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "UsernsMode": "",
            "CgroupnsMode": "private",
            "Devices": [],
            "DeviceRequests": None,
            "VolumesFrom": None,
        },
    }


def admit(monkeypatch: pytest.MonkeyPatch, info: dict[str, Any]) -> DockerFixture:
    monkeypatch.setenv("NATIVE_VENV_DOCKER_CONTAINER", "a" * 64)
    monkeypatch.setenv("NATIVE_VENV_RUN_ID", "fixture")
    monkeypatch.setenv("NATIVE_VENV_IMAGE_ID", "sha256:fixture")
    monkeypatch.setattr("tests.test_native_venv_inventory_docker.shutil.which", lambda name: "/fixture/docker")

    def inspect(self: DockerFixture, *args: str) -> subprocess.CompletedProcess[str]:
        # Exercise the actual admission caller, with no chance of fixture exec.
        assert args == ("container", "inspect", "a" * 64)
        return subprocess.CompletedProcess(args, 0, json.dumps([info]))

    monkeypatch.setattr(DockerFixture, "command", inspect)
    return DockerFixture()


def test_manifest_fixture_is_admitted(monkeypatch: pytest.MonkeyPatch) -> None:
    assert admit(monkeypatch, inspected_fixture()).identifier == "a" * 64


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("HostConfig", "Mounts", [{"Type": "bind", "Source": "/foreign", "Target": "/opt/fixture"}]),
        (None, "Mounts", [{"Type": "bind", "Source": "/foreign", "Destination": "/opt/fixture"}]),
        ("Config", "Volumes", {"/foreign": {}}),
        ("HostConfig", "Privileged", True),
        ("HostConfig", "SecurityOpt", []),
        ("HostConfig", "Tmpfs", {"/opt/native-venv-inventory-fixture": "rw,size=32m,uid=65534,gid=65534"}),
        ("HostConfig", "PidMode", "host"),
        ("HostConfig", "IpcMode", "host"),
        ("HostConfig", "UTSMode", "host"),
        ("HostConfig", "UsernsMode", "host"),
        ("HostConfig", "CgroupnsMode", "host"),
        ("HostConfig", "Devices", [{"PathOnHost": "/dev/foreign"}]),
        ("HostConfig", "DeviceRequests", [{"Count": -1}]),
        ("HostConfig", "VolumesFrom", ["foreign"]),
    ],
)
def test_foreign_or_weakened_fixture_is_refused_before_exec(
    monkeypatch: pytest.MonkeyPatch, section: str | None, field: str, value: Any
) -> None:
    info = copy.deepcopy(inspected_fixture())
    target = info if section is None else info[section]
    target[field] = value
    with pytest.raises(AssertionError):
        admit(monkeypatch, info)
