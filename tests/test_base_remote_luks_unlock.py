from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import RemoteLuksUnlockConfig, deploy_remote_luks_unlock
from ops_deploy.base.remote_luks_unlock import (
    authorized_keys_file,
    cmdline_tokens,
    dropbear_options,
    grub_with_ip,
    ip_param,
    set_line,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample operator@example"
STATIC = RemoteLuksUnlockConfig(
    interface="eno1",
    ip_mode="static",
    static_ip="192.0.2.10",
    static_gateway="192.0.2.1",
    static_hostname="node",
    authorized_keys=(KEY,),
)
PARAM = "ip=192.0.2.10::192.0.2.1:255.255.255.0:node:eno1:none"
OPTIONS = 'DROPBEAR_OPTIONS="-p 2222 -I 600 -s -j -k"'


def grub(cmdline: str) -> str:
    return f'GRUB_DEFAULT=0\nGRUB_TIMEOUT=0\nGRUB_CMDLINE_LINUX_DEFAULT="{cmdline}"\nGRUB_CMDLINE_LINUX=""\n'


def host(extra: dict[str, Any] | None = None, *, cmdline: str = PARAM) -> dict[str, Any]:
    """A converged host for ``STATIC``; ``extra`` replaces or adds responses."""

    responses: dict[str, Any] = {
        **LINUX,
        **fakehost.deb_installed("dropbear-initramfs"),
        **fakehost.directory("/etc/dropbear/initramfs"),
        "grep -e '^DROPBEAR=.*$'": ["DROPBEAR=y"],
        **fakehost.file("/etc/dropbear/initramfs/authorized_keys", authorized_keys_file((KEY,)), mode="-rw-------"),
        "grep -e '^DROPBEAR_OPTIONS=.*$'": [OPTIONS],
        "grep '^DEVICE='": [""],
        **fakehost.directory("/etc/default"),
        **fakehost.file("/etc/default/grub", grub(cmdline)),
    }
    responses.update(extra or {})
    return responses


def test_converged_host_changes_nothing() -> None:
    run = run_deploy_fake(deploy_remote_luks_unlock, STATIC, responses=host())

    assert run.succeeded, run.error
    assert run.changed_ops == []


def test_fresh_host_installs_configures_and_rebuilds() -> None:
    responses = {**LINUX, **fakehost.file("/etc/default/grub", grub("quiet splash"))}

    run = run_deploy_fake(deploy_remote_luks_unlock, STATIC, responses=responses)

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert "install dropbear-initramfs" in commands[2]
    assert "echo DROPBEAR=y >> /etc/initramfs-tools/initramfs.conf" in commands
    assert f"echo '{OPTIONS}' >> /etc/dropbear/initramfs/dropbear.conf" in commands
    assert run.upload("/etc/dropbear/initramfs/authorized_keys").decode() == (
        "# Authorized SSH keys for remote LUKS unlock\n# Managed by Ansible - DO NOT EDIT MANUALLY\n" + KEY + "\n"
    )
    assert "chmod 600 /etc/dropbear/initramfs/authorized_keys" in commands
    assert run.upload("/etc/default/grub").decode() == grub(f"quiet splash {PARAM}")
    # The backup comes before the write; both handlers run last.
    assert commands.index('cp -p /etc/default/grub /etc/default/grub."$(date +%Y-%m-%d@%H:%M:%S)"~') < commands.index(
        "chmod 644 /etc/default/grub"
    )
    assert commands[-2:] == ["update-initramfs -u -k all", "update-grub"]


def test_only_a_new_key_rebuilds_the_initramfs() -> None:
    cfg = STATIC.model_copy(update={"authorized_keys": (KEY, "ssh-ed25519 AAAAother other@example")})

    run = run_deploy_fake(deploy_remote_luks_unlock, cfg, responses=host())

    assert run.changed_ops == [
        "Remote LUKS unlock | Configure Dropbear authorized_keys",
        "Remote LUKS unlock | Rebuild initramfs",
    ]
    assert "update-grub" not in run.executed_commands


def test_changed_options_are_replaced_in_place() -> None:
    run = run_deploy_fake(
        deploy_remote_luks_unlock, STATIC, responses=host({"grep -e '^DROPBEAR_OPTIONS=.*$'": ['DROPBEAR_OPTIONS=""']})
    )

    assert run.changed_ops == [
        "Remote LUKS unlock | Configure Dropbear options",
        "Remote LUKS unlock | Rebuild initramfs",
    ]
    assert any("sed -i" in command and "DROPBEAR_OPTIONS" in command for command in run.executed_commands)


def test_device_of_this_interface_is_removed_from_initramfs_conf() -> None:
    run = run_deploy_fake(
        deploy_remote_luks_unlock,
        STATIC,
        responses=host(
            {"grep '^DEVICE='": ["eno1"], "grep -e '^DEVICE=.*$'": ["DEVICE=eno1"], "grep -e '^IP=.*$'": ["IP=dhcp"]}
        ),
    )

    assert run.changed_ops == [
        "Remote LUKS unlock | Remove DEVICE= from initramfs.conf",
        "Remote LUKS unlock | Remove IP= from initramfs.conf",
        "Remote LUKS unlock | Rebuild initramfs",
    ]


def test_edit_grub_false_leaves_grub_alone() -> None:
    cfg = STATIC.model_copy(update={"edit_grub": False})

    run = run_deploy_fake(deploy_remote_luks_unlock, cfg, responses=host(cmdline="quiet"))

    assert run.changed_ops == []
    assert not any("/etc/default/grub" in command for command in run.fact_commands)


def test_missing_grub_fails_before_any_change() -> None:
    responses = host()
    for key in [key for key in responses if "/etc/default/grub" in key]:
        del responses[key]
    responses["cat /etc/default/grub"] = ["__pyinfra_missing_/etc/default/grub"]

    run = run_deploy_fake(deploy_remote_luks_unlock, STATIC, responses=responses)

    assert not run.succeeded
    assert "/etc/default/grub is missing" in str(run.error)
    assert run.executed_commands == []


def test_grub_ip_replaces_only_this_interfaces_parameter() -> None:
    lines = grub("quiet ip=10.0.0.5::10.0.0.1:255.0.0.0:old:eno1:none ip=:::::eth9:dhcp").splitlines()

    new = grub_with_ip(lines, STATIC)

    assert new is not None
    assert cmdline_tokens(new) == ["quiet", "ip=:::::eth9:dhcp", PARAM]
    assert grub_with_ip(new, STATIC) is None


def test_grub_without_cmdline_line_gets_one_appended() -> None:
    assert grub_with_ip(["GRUB_DEFAULT=0"], STATIC) == ["GRUB_DEFAULT=0", f'GRUB_CMDLINE_LINUX_DEFAULT="{PARAM}"']


def test_set_line_replaces_the_last_match() -> None:
    assert set_line(["A=1", "B=2", "A=3"], r"^A=", "A=9") == ["A=1", "B=2", "A=9"]


def test_cmdline_tokens_unquotes_like_the_role() -> None:
    assert cmdline_tokens(["GRUB_CMDLINE_LINUX_DEFAULT='a  b'"]) == ["a", "b"]
    assert cmdline_tokens(['GRUB_CMDLINE_LINUX_DEFAULT="unbalanced']) == ['"unbalanced']
    assert cmdline_tokens(["GRUB_DEFAULT=0"]) is None


def test_dhcp_parameter_and_option_switches() -> None:
    cfg = RemoteLuksUnlockConfig(
        interface="eth0",
        authorized_keys=(KEY,),
        port=22,
        no_password_auth=False,
        disable_forwarding=False,
        extra_dropbear_options="-c cryptroot-unlock",
    )

    assert ip_param(cfg) == "ip=:::::eth0:dhcp"
    assert dropbear_options(cfg) == "-p 22 -I 600 -c cryptroot-unlock"


@pytest.mark.parametrize(
    "fields",
    [
        {"authorized_keys": ()},
        {"authorized_keys": ("a\nb",)},
        {"ip_mode": "static", "static_ip": "", "static_gateway": "192.0.2.1", "static_hostname": "n"},
        {"ip_mode": "static", "static_ip": "192.0.2.2", "static_gateway": "192.0.2.1"},
        {"interface": "eth0;rm"},
        {"extra_dropbear_options": '-c "x"'},
    ],
)
def test_invalid_configs_are_refused(fields: dict[str, Any]) -> None:
    values: dict[str, Any] = {"interface": "eth0", "authorized_keys": (KEY,), **fields}

    with pytest.raises(ValidationError):
        RemoteLuksUnlockConfig(**values)
