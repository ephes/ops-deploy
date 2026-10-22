"""Paired uv installation, explicit adoption and fail-closed compatibility paths."""

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import UvAliasConfig, UvInstallConfig, deploy_uv_install
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

ROOTS = {
    key: value
    for path in ("/", "/usr", "/usr/local", "/usr/local/bin")
    for key, value in fakehost.directory(path).items()
}
X86 = {
    **LINUX,
    **ROOTS,
    "command -v dpkg-query": ["/usr/bin/dpkg-query"],
    "if dpkg-query -S": ["unowned"],
    "uname -m": ["x86_64"],
}
SHA_X86 = "2b428396f12572d4429cf210ca234dd599a33b3af0958a4d5ed569d63e3f344f"


def installed(version: str = "0.13.4", *, uvx: str | None = "0.13.4") -> dict[str, Any]:
    responses: dict[str, Any] = {}
    for name, ver in (("uv", version), ("uvx", uvx)):
        if ver:
            responses.update(fakehost.file(f"/usr/local/bin/{name}", "binary", mode="-rwxr-xr-x"))
            responses[f"/usr/local/bin/{name} --version"] = [f"{name} {ver} (x86_64-unknown-linux-gnu)"]
    return responses


def install_command(run: FakeRun) -> str:
    assert run.succeeded, run.error
    (command,) = [c for c in run.executed_commands if "release.tar.gz" in c]
    return str(command)


def test_installs_verified_pair_when_missing() -> None:
    command = install_command(run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=X86))
    assert "https://github.com/astral-sh/uv/releases/download/0.13.4/uv-x86_64-unknown-linux-gnu.tar.gz" in command
    assert f"echo {SHA_X86}'  '\"$tmp/release.tar.gz\" | sha256sum -c --quiet -" in command
    assert command.index("sha256sum") < command.index("install -o root -g root -m 0755")
    for name in ("uv", "uvx"):
        assert f"&& mv -f /usr/local/bin/.{name}.ops-deploy-new /usr/local/bin/{name}" in command
        assert f'"$(/usr/local/bin/{name} --version | cut -d' in command


def test_same_pair_changes_nothing() -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={**X86, **installed()})
    assert run.succeeded, run.error
    assert run.changed_ops == []


@pytest.mark.parametrize("uvx", [None, "0.9.0"])
def test_current_uv_but_missing_or_wrong_uvx_reinstalls(uvx: str | None) -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={**X86, **installed(uvx=uvx)})
    assert install_command(run)


def test_other_version_is_replaced_unless_updates_are_off() -> None:
    responses = {**X86, **installed("0.9.0", uvx="0.9.0")}
    assert install_command(run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses))
    kept = run_deploy_fake(deploy_uv_install, UvInstallConfig(update_existing=False), responses=responses)
    assert kept.succeeded, kept.error
    assert kept.changed_ops == []


def test_updates_disabled_refuses_inconsistent_pair() -> None:
    run = run_deploy_fake(
        deploy_uv_install, UvInstallConfig(update_existing=False), responses={**X86, **installed(uvx="0.9.0")}
    )
    assert "mismatched" in str(run.error)
    assert run.executed_commands == []


@pytest.mark.parametrize("force", [False, True])
def test_stale_controller_refuses_downgrade(force: bool) -> None:
    run = run_deploy_fake(
        deploy_uv_install,
        UvInstallConfig(force_reinstall=force),
        responses={**X86, **installed("0.14.0", uvx="0.14.0")},
    )
    assert "refusing downgrade" in str(run.error)
    assert run.executed_commands == []


def test_force_reinstall() -> None:
    assert install_command(
        run_deploy_fake(deploy_uv_install, UvInstallConfig(force_reinstall=True), responses={**X86, **installed()})
    )


@pytest.mark.parametrize("name", ["uv", "uvx"])
def test_metadata_drift_is_repaired_without_download(name: str) -> None:
    responses = {**X86, **installed(), **fakehost.stat(f"/usr/local/bin/{name}", group="staff", mode="-rwx------")}
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses)
    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    assert "chmod 755" in commands
    assert "chown root:root" in commands
    assert "release.tar.gz" not in commands


def test_explicit_previous_owner_is_adopted() -> None:
    responses = {
        **X86,
        **installed(),
        **fakehost.file("/usr/local/bin/uvx", "binary", user="legacy", mode="-rwxr-xr-x"),
    }
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(previous_owners=("legacy",)), responses=responses)
    assert run.succeeded, run.error
    assert any("chown root:root /usr/local/bin/uvx" in command for command in run.executed_commands)


@pytest.mark.parametrize("path", ["/usr/local/bin/uv", "/usr/local/bin/uvx", "/usr/local/bin/.uv.ops-deploy-new"])
@pytest.mark.parametrize("kind", ["link", "directory", "foreign"])
def test_unsafe_canonical_paths_fail_before_execution(path: str, kind: str) -> None:
    unsafe = {
        "link": fakehost.symlink(path, "/opt/homebrew/Cellar/uv/uv"),
        "directory": fakehost.directory(path),
        "foreign": fakehost.file(path, "binary", user="unknown"),
    }[kind]
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={**X86, **installed(), **unsafe})
    assert not run.succeeded
    assert run.executed_commands == []
    assert not any(" --version" in command for command in run.fact_commands)


@pytest.mark.parametrize(
    "unsafe",
    [
        fakehost.symlink("/usr/local", "/opt/elsewhere"),
        fakehost.directory("/usr", user="unknown"),
        fakehost.directory("/usr/local/bin", mode="drwxrwxr-x"),
    ],
)
def test_unsafe_ancestors_fail_before_execution(unsafe: dict[str, Any]) -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={**X86, **unsafe})
    assert "unsafe directory" in str(run.error)
    assert run.executed_commands == []


def test_explicit_alias_pair_and_unchanged_second_plan() -> None:
    cfg = UvInstallConfig(
        aliases=tuple(UvAliasConfig(path=f"/usr/local/{name}", binary=name) for name in ("uv", "uvx"))
    )
    run = run_deploy_fake(deploy_uv_install, cfg, responses={**X86, **installed()})
    assert run.succeeded, run.error
    for name in ("uv", "uvx"):
        assert any(f"ln -s /usr/local/bin/{name} /usr/local/{name}" in command for command in run.executed_commands)
    second = run_deploy_fake(
        deploy_uv_install,
        cfg,
        responses={
            **X86,
            **installed(),
            **fakehost.symlink("/usr/local/uv", "/usr/local/bin/uv"),
            **fakehost.symlink("/usr/local/uvx", "/usr/local/bin/uvx"),
        },
    )
    assert second.succeeded, second.error
    assert second.changed_ops == []


def test_legacy_alias_requires_exact_approval_and_keeps_backup() -> None:
    legacy = fakehost.file("/usr/local/uv", "old uv", user="legacy")
    alias = UvAliasConfig(
        path="/usr/local/uv", binary="uv", replace_owner="legacy", replace_sha256=hashlib.sha256(b"old uv").hexdigest()
    )
    run = run_deploy_fake(
        deploy_uv_install, UvInstallConfig(aliases=(alias,)), responses={**X86, **installed(), **legacy}
    )
    assert run.succeeded, run.error
    assert any("mv /usr/local/uv" in command for command in run.executed_commands)
    assert any("ln -s /usr/local/bin/uv /usr/local/uv" in command for command in run.executed_commands)


@pytest.mark.parametrize("kind", ["unapproved", "hash", "owner", "directory", "symlink"])
def test_unapproved_alias_is_never_replaced(kind: str) -> None:
    alias = UvAliasConfig(path="/usr/local/uv", binary="uv", replace_sha256="0" * 64 if kind != "unapproved" else None)
    existing = {
        "directory": fakehost.directory("/usr/local/uv"),
        "symlink": fakehost.symlink("/usr/local/uv", "/opt/foreign/uv"),
        "owner": fakehost.file("/usr/local/uv", "binary", user="unknown"),
    }.get(kind, fakehost.file("/usr/local/uv", "binary"))
    run = run_deploy_fake(
        deploy_uv_install, UvInstallConfig(aliases=(alias,)), responses={**X86, **installed(), **existing}
    )
    assert not run.succeeded
    assert run.executed_commands == []


def test_unpinned_architecture_fails_before_any_change() -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={**X86, "uname -m": ["riscv64"]})
    assert "no pinned checksum" in str(run.error)
    assert run.executed_commands == []


def test_arm_uses_existing_pinned_archive() -> None:
    assert "uv-aarch64-unknown-linux-gnu.tar.gz" in install_command(
        run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={**X86, "uname -m": ["aarch64"]})
    )


def test_refuses_macos_without_touching_homebrew() -> None:
    run = run_deploy_fake(
        deploy_uv_install,
        UvInstallConfig(),
        responses={"uname -s": ["Darwin"], **fakehost.symlink("/usr/local/bin/uv", "/opt/homebrew/Cellar/uv/uv")},
    )
    assert "Linux hosts only" in str(run.error)
    assert run.executed_commands == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"install_dir": "/"},
        {"install_dir": "relative"},
        {"install_dir": "/usr/../bin"},
        {"install_dir": "/usr//bin"},
        {"version": "latest"},
        {"checksums": {"x": "nothex"}},
        {"aliases": [{"path": "/usr/local/bin/uv", "binary": "uv"}]},
    ],
)
def test_rejects_invalid_config(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        UvInstallConfig(**overrides)


def test_installs_curl_when_missing() -> None:
    run = run_deploy_fake(
        deploy_uv_install,
        UvInstallConfig(),
        responses={**X86, "command -v curl": [], "command -v apt-get": ["/usr/bin/apt-get"]},
    )
    assert run.succeeded, run.error
    assert any("apt-get" in c and "curl" in c for c in run.executed_commands)


@pytest.mark.parametrize("status", ["owned", "unknown", "", "unexpected"])
def test_package_ownership_or_unknown_query_refuses_before_execution(status: str) -> None:
    run = run_deploy_fake(
        deploy_uv_install, UvInstallConfig(), responses={**X86, **installed(), "if dpkg-query -S": [status]}
    )
    assert "package provenance" in str(run.error)
    assert run.executed_commands == []
    assert not any(" --version" in command for command in run.fact_commands)


def test_rpm_unowned_result_is_supported() -> None:
    run = run_deploy_fake(
        deploy_uv_install,
        UvInstallConfig(),
        responses={
            **X86,
            **installed(),
            "command -v dpkg-query": [],
            "command -v rpm": ["/usr/bin/rpm"],
            "result=$(LC_ALL=C rpm -qf": ["unowned"],
        },
    )
    assert run.succeeded, run.error
    assert run.changed_ops == []
    assert any("is not owned by any package" in command for command in run.fact_commands)


def test_missing_package_manager_fails_closed() -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={**X86, "command -v dpkg-query": []})
    assert "dpkg-query or rpm required" in str(run.error)
    assert run.executed_commands == []


def test_writable_binary_is_not_executed_and_is_reinstalled() -> None:
    run = run_deploy_fake(
        deploy_uv_install,
        UvInstallConfig(),
        responses={**X86, **installed(), **fakehost.file("/usr/local/bin/uvx", "unsafe", mode="-rwxrwxrwx")},
    )
    assert install_command(run)
    assert not any("/usr/local/bin/uvx --version" in command for command in run.fact_commands)


def test_occupied_regular_staging_path_fails_closed() -> None:
    run = run_deploy_fake(
        deploy_uv_install,
        UvInstallConfig(),
        responses={**X86, **fakehost.file("/usr/local/bin/.uv.ops-deploy-new", "partial")},
    )
    assert "staging path already exists" in str(run.error)
    assert run.executed_commands == []


def test_install_directory_mode_converges() -> None:
    run = run_deploy_fake(
        deploy_uv_install,
        UvInstallConfig(),
        responses={**X86, **installed(), **fakehost.directory("/usr/local/bin", mode="drwx------")},
    )
    assert run.succeeded, run.error
    assert any("chmod 755 /usr/local/bin" in command for command in run.executed_commands)
    assert not any("release.tar.gz" in command for command in run.executed_commands)


def test_every_available_package_manager_must_approve() -> None:
    run = run_deploy_fake(
        deploy_uv_install,
        UvInstallConfig(),
        responses={**X86, **installed(), "command -v rpm": ["/usr/bin/rpm"], "result=$(LC_ALL=C rpm -qf": ["owned"]},
    )
    assert "package provenance" in str(run.error)
    assert run.executed_commands == []


@pytest.mark.parametrize(
    ("manager", "exit_code", "reply", "expected", "exists"),
    [
        ("dpkg-query", 0, "package: /usr/local/bin/uv", "owned", False),
        ("dpkg-query", 1, "no path found", "unowned", False),
        ("dpkg-query", 2, "database unreadable", "unknown", False),
        ("rpm", 0, "package", "owned", False),
        ("rpm", 1, "file /usr/local/bin/uv is not owned by any package", "unowned", False),
        ("rpm", 1, "error: database unreadable", "unknown", False),
        ("rpm", 2, "", "unknown", False),
        ("rpm", 1, "error: file /usr/local/bin/uv: No such file or directory", "unowned", False),
        ("rpm", 1, "error: file /usr/local/bin/uv: No such file or directory", "unknown", True),
    ],
)
def test_package_probe_shell_classifies_exit_status(
    tmp_path: Path, manager: str, exit_code: int, reply: str, expected: str, exists: bool
) -> None:
    responses = {**X86, **installed()}
    if manager == "rpm":
        responses.update(
            {"command -v dpkg-query": [], "command -v rpm": ["/usr/bin/rpm"], "result=$(LC_ALL=C rpm -qf": ["unowned"]}
        )
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses)
    assert run.succeeded, run.error
    marker = "if dpkg-query -S" if manager == "dpkg-query" else "result=$(LC_ALL=C rpm -qf"
    probe = next(command for command in run.fact_commands if marker in command)
    probe_path = tmp_path / "binary"
    if exists:
        probe_path.touch()
    probe = probe.replace("/usr/local/bin/uv", str(probe_path))
    reply = reply.replace("/usr/local/bin/uv", str(probe_path))
    binary = tmp_path / manager
    binary.write_text('#!/bin/sh\nprintf "%s\\n" "$QUERY_REPLY" >&2\nexit "$QUERY_EXIT"\n')
    binary.chmod(0o755)
    result = subprocess.run(
        ["/bin/sh", "-c", probe],
        env={"PATH": str(tmp_path), "QUERY_EXIT": str(exit_code), "QUERY_REPLY": reply},
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == expected


def test_checksum_failure_stops_before_unpack_or_destination_changes(tmp_path: Path) -> None:
    command = install_command(run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=X86))
    tools = tmp_path / "bin"
    tools.mkdir()
    marker = tmp_path / "mutation"
    # The fake download is inert. A checksum failure must short-circuit the real
    # install command before even unpacking, regardless of destination contents.
    for name, body in (
        ("curl", "exit 0"),
        ("sha256sum", "exit 1"),
        ("tar", 'touch "$MUTATION"; exit 99'),
        ("install", 'touch "$MUTATION"; exit 99'),
        ("mv", 'touch "$MUTATION"; exit 99'),
    ):
        executable = tools / name
        executable.write_text(f"#!/bin/sh\n{body}\n")
        executable.chmod(0o755)
    result = subprocess.run(
        ["/bin/sh", "-c", command],
        env={"PATH": f"{tools}:{os.defpath}", "MUTATION": str(marker), "TMPDIR": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert not marker.exists()


def test_force_reinstall_keeps_its_override_of_updates_disabled() -> None:
    run = run_deploy_fake(
        deploy_uv_install,
        UvInstallConfig(update_existing=False, force_reinstall=True),
        responses={**X86, **installed("0.9.0", uvx="0.9.0")},
    )
    assert install_command(run)


def test_rpm_missing_pair_and_new_aliases_can_be_installed() -> None:
    cfg = UvInstallConfig(aliases=(UvAliasConfig(path="/usr/local/uv", binary="uv"),))
    run = run_deploy_fake(
        deploy_uv_install,
        cfg,
        responses={
            **X86,
            "command -v dpkg-query": [],
            "command -v rpm": ["/usr/bin/rpm"],
            "result=$(LC_ALL=C rpm -qf": ["unowned"],
        },
    )
    assert install_command(run)
    assert any("ln -s /usr/local/bin/uv /usr/local/uv" in command for command in run.executed_commands)


def test_rpm_owned_missing_leaf_is_refused_before_install() -> None:
    run = run_deploy_fake(
        deploy_uv_install,
        UvInstallConfig(),
        responses={
            **X86,
            "command -v dpkg-query": [],
            "command -v rpm": ["/usr/bin/rpm"],
            "result=$(LC_ALL=C rpm -qf": ["owned"],
        },
    )
    assert "package provenance" in str(run.error)
    assert run.executed_commands == []
