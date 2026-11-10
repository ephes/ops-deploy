import hashlib
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import BindSource, EngineBinds, ExternalBindStorageConfig, deploy_external_bind_storage
from ops_deploy.base.external_bind_storage import daemon_json, enabled_units, escape_path, unit_files
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

CFG = ExternalBindStorageConfig(
    mount="/mnt/data",
    root="/mnt/data/host",
    sources=(
        BindSource(path="/opt/backups", automount=True),
        BindSource(path="/var/lib/docker"),
        BindSource(path="/var/lib/containerd"),
    ),
    engines=(
        EngineBinds(unit="docker.service", paths=("/var/lib/docker", "/var/lib/containerd")),
        EngineBinds(unit="containerd.service", paths=("/var/lib/containerd",)),
    ),
    docker_builder_gc_bytes=10_000_000_000,
)
SYSTEMD = {**LINUX, "cat /proc/1/comm": ["systemd"]}


def unit_state_lines(*states: str) -> dict[str, Any]:
    lines: list[str] = []
    for state in states:
        lines += ["LoadState=loaded", "ActiveState=active", f"UnitFileState={state}", "---"]
    return {"for unit in": lines}


def host(*, states: tuple[str, ...] = ("enabled", "enabled", "enabled")) -> dict[str, Any]:
    responses: dict[str, Any] = {**SYSTEMD, **unit_state_lines(*states)}
    for directory in ("/etc/systemd/system", "/etc/docker"):
        responses.update(fakehost.directory(directory))
    for engine in ("docker", "containerd"):
        responses.update(fakehost.directory(f"/etc/systemd/system/{engine}.service.d", mode="drwx------"))
    for path, content in unit_files(CFG).items():
        responses.update(fakehost.file(path, content, mode="-rw-------"))
    responses.update(fakehost.file("/etc/docker/daemon.json", daemon_json(10_000_000_000), mode="-rw-------"))
    return responses


def test_units_are_the_migration_tools_bytes() -> None:
    files = unit_files(CFG)

    assert files["/etc/systemd/system/opt-backups.mount"] == (
        "[Unit]\nDescription=External bulk storage\nRequiresMountsFor=/mnt/data\n"
        "BindsTo=mnt-data.mount\nAfter=mnt-data.mount\n\n[Mount]\nWhat=/mnt/data/host/opt/backups\n"
        "Where=/opt/backups\nType=none\nOptions=bind\n\n[Install]\nWantedBy=local-fs.target\n"
    )
    assert files["/etc/systemd/system/opt-backups.automount"] == (
        "[Unit]\nDescription=Guard external backup storage access\n\n[Automount]\nWhere=/opt/backups\n"
        "TimeoutIdleSec=0\n\n[Install]\nWantedBy=local-fs.target\n"
    )
    assert files["/etc/systemd/system/docker.service.d/90-host-storage.conf"] == (
        "[Unit]\nRequires=var-lib-docker.mount var-lib-containerd.mount\n"
        "After=var-lib-docker.mount var-lib-containerd.mount\n"
        "BindsTo=var-lib-docker.mount var-lib-containerd.mount\n"
    )
    assert "/etc/systemd/system/var-lib-docker.automount" not in files
    assert enabled_units(CFG) == ["opt-backups.automount", "var-lib-docker.mount", "var-lib-containerd.mount"]


def test_daemon_json_is_the_tools_builder_policy() -> None:
    assert daemon_json(5) == (
        '{\n  "builder": {\n    "gc": {\n      "enabled": true,\n      "policy": [\n        {\n'
        '          "all": true,\n          "reservedSpace": "0B",\n          "maxUsedSpace": "5"\n'
        "        }\n      ]\n    }\n  }\n}\n"
    )


@pytest.mark.parametrize(
    ("path", "escaped"),
    [
        ("/var/backups/security-trust-remediation", "var-backups-security\\x2dtrust\\x2dremediation"),
        ("/srv//data/", "srv-data"),
        ("/", "-"),
        ("/.hidden/a.b", "\\x2ehidden-a.b"),
        ("/x y/ä", "x\\x20y-\\xc3\\xa4"),
    ],
)
def test_escape_path_matches_systemd_escape(path: str, escaped: str) -> None:
    assert escape_path(path) == escaped


def test_converged_host_changes_nothing() -> None:
    run = run_deploy_fake(deploy_external_bind_storage, CFG, responses=host())

    assert run.succeeded, run.error
    assert run.changed_ops == []


def test_fresh_host_writes_reloads_and_enables_without_starting() -> None:
    run = run_deploy_fake(deploy_external_bind_storage, CFG, responses={**SYSTEMD, **unit_state_lines("", "", "")})

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert "chmod 700 /etc/systemd/system/docker.service.d" in commands
    assert "chmod 600 /etc/systemd/system/opt-backups.mount" in commands
    assert run.upload("/etc/docker/daemon.json").decode() == daemon_json(10_000_000_000)
    reload = commands.index("systemctl daemon-reload")
    for unit in enabled_units(CFG):
        assert commands.index(f"systemctl enable -- {unit}") > reload
    assert not any(" start " in command or "restart" in command for command in commands)


def test_disabled_unit_is_enabled_alone() -> None:
    run = run_deploy_fake(deploy_external_bind_storage, CFG, responses=host(states=("enabled", "disabled", "enabled")))

    assert run.changed_ops == ["External bind storage | Enable var-lib-docker.mount"]


def test_escaped_unit_name_is_quoted_for_the_shell() -> None:
    cfg = CFG.model_copy(update={"sources": (BindSource(path="/var/backups/a-b"),), "engines": ()})

    run = run_deploy_fake(deploy_external_bind_storage, cfg, responses={**SYSTEMD, **unit_state_lines("disabled")})

    assert "systemctl enable -- 'var-backups-a\\x2db.mount'" in run.executed_commands


@pytest.mark.parametrize(
    "fields",
    [
        {"engines": (EngineBinds(unit="docker.service", paths=("/srv/other",)),)},
        {"root": "/elsewhere"},
        {"root": "/mnt/data/../etc"},
        {"root": "/mnt/data/"},
        {"root": "/mnt/data"},
        {"mount": "/", "root": "/host"},
        {"sources": (BindSource(path="/a/../b"),), "engines": ()},
        {"sources": (BindSource(path="/srv/x"), BindSource(path="/srv/x", automount=True)), "engines": ()},
        {"sources": ()},
        {"docker_builder_gc_bytes": 0},
    ],
)
def test_invalid_configs_are_refused(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ExternalBindStorageConfig(**{**CFG.model_dump(), **fields})


ESCAPED = "/etc/systemd/system/var-backups-a\\x2db.mount"
ESCAPED_CFG = CFG.model_copy(update={"sources": (BindSource(path="/var/backups/a-b"),), "engines": ()})


def escaped_host(digest_of: str, *, mode: str = "-rw-------") -> dict[str, Any]:
    """GNU sha256sum escapes a backslash name, so only the stdin hash is answered."""

    stat = f"user=root group=root mode={mode} atime=0 mtime=0 ctime=0 size=10 '{ESCAPED}'"
    return {
        **SYSTEMD,
        **unit_state_lines("enabled"),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.directory("/etc/docker"),
        **fakehost.file("/etc/docker/daemon.json", daemon_json(10_000_000_000), mode="-rw-------"),
        f"test -e '{ESCAPED}' ||": [stat],
        f"sha256sum < '{ESCAPED}'": [hashlib.sha256(digest_of.encode()).hexdigest() + "  -"],
        f"sha1sum {ESCAPED}": [f"\\0000  {ESCAPED}"],
    }


def test_escaped_name_that_matches_changes_nothing() -> None:
    responses = escaped_host(unit_files(ESCAPED_CFG)[ESCAPED])

    run = run_deploy_fake(deploy_external_bind_storage, ESCAPED_CFG, responses=responses)

    assert run.succeeded, run.error
    assert run.changed_ops == []


@pytest.mark.parametrize(("digest_of", "mode"), [("other\n", "-rw-------"), (None, "-rw-r--r--")])
def test_escaped_name_that_differs_is_written(digest_of: str | None, mode: str) -> None:
    content = unit_files(ESCAPED_CFG)[ESCAPED]

    run = run_deploy_fake(
        deploy_external_bind_storage, ESCAPED_CFG, responses=escaped_host(digest_of or content, mode=mode)
    )

    assert f"External bind storage | Install {ESCAPED}" in run.changed_ops
    assert "External bind storage | Reload systemd for the storage units" in run.changed_ops
