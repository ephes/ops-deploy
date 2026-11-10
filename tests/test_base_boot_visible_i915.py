from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import BootVisibleI915Config, deploy_boot_visible_i915
from ops_deploy.base.boot_visible_i915 import cmdline, grub_file
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

HEADER = (
    "# /etc/default/grub - managed by boot_visible_i915 role\n"
    "# WARNING: This file is managed by Ansible. Local edits will be overwritten.\n"
    "# To customize, set variables in your playbook or host_vars.\n\n"
)
# What the role's grub.j2 renders with its defaults (Ansible keeps the final newline).
DEFAULT_GRUB = HEADER + (
    "GRUB_DEFAULT=0\n"
    "GRUB_TIMEOUT_STYLE=menu\n"
    "GRUB_TIMEOUT=5\n"
    "GRUB_DISTRIBUTOR=`lsb_release -i -s 2>/dev/null || echo Debian`\n"
    'GRUB_CMDLINE_LINUX_DEFAULT=""\n'
    'GRUB_CMDLINE_LINUX=""\n'
    "\n"
    "GRUB_TERMINAL=console\n"
    "GRUB_GFXPAYLOAD_LINUX=text\n"
    "# Uncomment to disable generation of recovery mode menu entries\n"
    '#GRUB_DISABLE_RECOVERY="true"\n'
)
MODULES = "# List of modules\ni915\n"


def host(extra: dict[str, Any] | None = None, *, grub: str = DEFAULT_GRUB) -> dict[str, Any]:
    responses: dict[str, Any] = {
        **LINUX,
        "grep -lE": [],
        **fakehost.file("/etc/initramfs-tools/modules", MODULES),
        "grep -e '^1915$'": [],
        "grep -e '^i915$'": ["i915"],
        **fakehost.directory("/etc/default"),
        **fakehost.file("/etc/default/grub", grub),
    }
    responses.update(extra or {})
    return responses


def test_default_template_matches_the_role() -> None:
    assert grub_file(BootVisibleI915Config()) == DEFAULT_GRUB


def test_menu_entry_extra_params_and_hidden_menu() -> None:
    cfg = BootVisibleI915Config(
        grub_default_entry="Advanced options for Ubuntu>Ubuntu, with Linux 6.8.0-1-generic",
        grub_extra_params=("ip=:::::eth0:dhcp",),
        show_grub_menu=False,
        grub_terminal="",
        grub_gfxpayload="",
    )

    content = grub_file(cfg)

    assert 'GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 6.8.0-1-generic"\n' in content
    assert "GRUB_TIMEOUT_STYLE=hidden\nGRUB_TIMEOUT=0\n" in content
    assert 'GRUB_CMDLINE_LINUX_DEFAULT="ip=:::::eth0:dhcp"\n' in content
    assert content.endswith('GRUB_CMDLINE_LINUX=""\n\n# Uncomment to disable generation of recovery mode menu entries\n'
                            '#GRUB_DISABLE_RECOVERY="true"\n')  # fmt: skip


def test_cmdline_removes_flags_and_keeps_first_occurrence() -> None:
    cfg = BootVisibleI915Config(
        grub_base_cmdline=("quiet", "splash", "nomodeset", "mitigations=auto"),
        grub_remove_quiet=False,
        grub_extra_params=("quiet", "ip=:::::eth0:dhcp"),
    )

    assert cmdline(cfg) == "quiet mitigations=auto ip=:::::eth0:dhcp"


def test_converged_host_changes_nothing() -> None:
    run = run_deploy_fake(deploy_boot_visible_i915, BootVisibleI915Config(), responses=host())

    assert run.succeeded, run.error
    assert run.changed_ops == []


def test_fresh_host_loads_i915_renders_grub_and_rebuilds() -> None:
    stock = 'GRUB_DEFAULT=0\nGRUB_CMDLINE_LINUX_DEFAULT="quiet splash"\n'
    responses = host(
        {
            "grep -lE": ["/etc/modprobe.d/blacklist-gpu.conf"],
            "grep -E -e": ["blacklist i915"],
            "grep -e '^i915$'": [],
            "grep -e '^1915$'": ["1915"],
        },
        grub=stock,
    )

    run = run_deploy_fake(deploy_boot_visible_i915, BootVisibleI915Config(), responses=responses)

    assert run.succeeded, run.error
    assert run.changed_ops == [
        "Boot visible i915 | Remove i915 blacklist from /etc/modprobe.d/blacklist-gpu.conf",
        "Boot visible i915 | Remove i915 typo 1915",
        "Boot visible i915 | Load i915 in initramfs",
        "Boot visible i915 | Back up /etc/default/grub",
        "Boot visible i915 | Render /etc/default/grub",
        "Boot visible i915 | Update initramfs",
        "Boot visible i915 | Update GRUB",
    ]
    assert "echo i915 >> /etc/initramfs-tools/modules" in run.executed_commands
    assert run.upload("/etc/default/grub").decode() == DEFAULT_GRUB
    assert run.executed_commands[-2:] == ["update-initramfs -u -k all", "update-grub"]


def test_grub_only_change_updates_grub_not_the_initramfs() -> None:
    cfg = BootVisibleI915Config(grub_timeout=10)

    run = run_deploy_fake(deploy_boot_visible_i915, cfg, responses=host())

    assert run.changed_ops == [
        "Boot visible i915 | Back up /etc/default/grub",
        "Boot visible i915 | Render /etc/default/grub",
        "Boot visible i915 | Update GRUB",
    ]


def test_switches_off_skip_their_parts() -> None:
    cfg = BootVisibleI915Config(enable_i915=False, modify_grub_cmdline=False)

    run = run_deploy_fake(deploy_boot_visible_i915, cfg, responses=host())

    assert run.changed_ops == []
    assert not any("grub" in command or "modules" in command for command in run.fact_commands)


@pytest.mark.parametrize(
    "fields",
    [
        {"grub_default_entry": 'x" ; reboot ; "'},
        {"grub_extra_params": ("a b",)},
        {"grub_terminal": "console; reboot"},
        {"grub_timeout": -1},
    ],
)
def test_unsafe_values_are_refused(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        BootVisibleI915Config(**fields)
