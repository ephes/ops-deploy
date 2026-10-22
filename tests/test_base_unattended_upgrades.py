"""``unattended_upgrades``: rendered drop-ins per distribution, first and converged runs, refusals, validation."""

from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import UnattendedUpgradesConfig, deploy_unattended_upgrades
from ops_deploy.base.unattended_upgrades import (
    APT_DROPIN,
    NEEDRESTART_DIR,
    NEEDRESTART_DROPIN,
    STAT_KIND,
    _check_script,
    apt_settings,
    render_apt_dropin,
    render_needrestart_dropin,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.test_base_headless_mode import SYSTEMD

OS_PROBE = 'printf "%s %s'
CHECK = "unattended-upgrades | Check the effective unattended-upgrades policy"
WRITE_APT = f"unattended-upgrades | Write {APT_DROPIN}"
WRITE_NR = f"unattended-upgrades | Write {NEEDRESTART_DROPIN}"
INSTALL = "unattended-upgrades | Install unattended-upgrades"
REFRESH = "unattended-upgrades | Refresh apt cache"
DEFAULT = UnattendedUpgradesConfig()
OS = {"debian 12": "debian", "debian 13": "debian", "ubuntu 24.04": "ubuntu"}


def host(os: str = "debian 13", *, kinds: tuple[str, str] = ("missing", "missing"), **extra: Any) -> dict[str, Any]:
    """A systemd host running ``os``; ``kinds`` are the drop-ins' file types. apt.conf.d always exists."""

    return {**SYSTEMD, OS_PROBE: [os], STAT_KIND: list(kinds), **extra, **fakehost.directory("/etc/apt/apt.conf.d")}


def converged(cfg: UnattendedUpgradesConfig, os: str = "debian 13") -> dict[str, Any]:
    return host(
        os,
        kinds=("regular file", "regular file"),
        **fakehost.deb_installed("unattended-upgrades", "needrestart"),
        **fakehost.file(APT_DROPIN, render_apt_dropin(cfg, OS[os])),
        **fakehost.directory(NEEDRESTART_DIR),
        **fakehost.file(NEEDRESTART_DROPIN, render_needrestart_dropin(cfg)),
    )


def test_debian_drop_in_is_security_only_and_clears_the_packaged_lists() -> None:
    assert render_apt_dropin(DEFAULT, "debian").splitlines() == [
        "// Managed by ops-deploy (base.unattended_upgrades). Do not edit by hand.",
        "// Effective configuration: apt-config dump | grep -E '^(APT::Periodic|Unattended-Upgrade)'",
        'APT::Periodic::Update-Package-Lists "1";',
        'APT::Periodic::Unattended-Upgrade "1";',
        'APT::Periodic::AutocleanInterval "7";',
        "",
        "// Replace the packaged origin lists and blacklist instead of extending them.",
        "#clear Unattended-Upgrade::Allowed-Origins;",
        "#clear Unattended-Upgrade::Origins-Pattern;",
        "#clear Unattended-Upgrade::Package-Blacklist;",
        "Unattended-Upgrade::Origins-Pattern {",
        '        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";',
        "};",
        "Unattended-Upgrade::Package-Blacklist {",
        "};",
        "",
        'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";',
        'Unattended-Upgrade::Remove-Unused-Dependencies "false";',
        'Unattended-Upgrade::Automatic-Reboot "false";',
        'Unattended-Upgrade::Automatic-Reboot-Time "04:30";',
        'Unattended-Upgrade::SyslogEnable "true";',
    ]


def test_debian_point_releases_add_the_main_archive() -> None:
    cfg = UnattendedUpgradesConfig(debian_point_releases=True)

    origins = [line for line in apt_settings(cfg, "debian") if "Origins-Pattern" in line]
    assert [line.removeprefix("Unattended-Upgrade::Origins-Pattern:: ") for line in origins] == [
        '"origin=Debian,codename=${distro_codename}-security,label=Debian-Security";',
        '"origin=Debian,codename=${distro_codename},label=Debian";',
    ]


def test_ubuntu_takes_security_and_esm_but_never_updates() -> None:
    origins = [line for line in apt_settings(DEFAULT, "ubuntu") if "Origins-Pattern" in line]

    assert origins == [
        'Unattended-Upgrade::Origins-Pattern:: "origin=Ubuntu,archive=${distro_codename}";',
        'Unattended-Upgrade::Origins-Pattern:: "origin=Ubuntu,archive=${distro_codename}-security";',
        'Unattended-Upgrade::Origins-Pattern:: "origin=UbuntuESMApps,archive=${distro_codename}-apps-security";',
        'Unattended-Upgrade::Origins-Pattern:: "origin=UbuntuESM,archive=${distro_codename}-infra-security";',
    ]
    assert "-updates" not in render_apt_dropin(DEFAULT, "ubuntu")


def test_reboot_blacklist_and_cleanup_settings_render() -> None:
    cfg = UnattendedUpgradesConfig(
        automatic_reboot=True,
        automatic_reboot_time="03:15",
        package_blacklist=("^linux-image-", "postgresql-.*"),
        remove_unused_kernel_packages=False,
        autoclean_interval_days=0,
    )

    rendered = render_apt_dropin(cfg, "debian").splitlines()
    assert 'Unattended-Upgrade::Automatic-Reboot "true";' in rendered
    assert 'Unattended-Upgrade::Automatic-Reboot-Time "03:15";' in rendered
    assert 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";' in rendered
    assert 'APT::Periodic::AutocleanInterval "0";' in rendered
    start = rendered.index("Unattended-Upgrade::Package-Blacklist {")
    assert rendered[start : start + 4] == [
        "Unattended-Upgrade::Package-Blacklist {",
        '        "^linux-image-";',
        '        "postgresql-.*";',
        "};",
    ]


def test_needrestart_drop_in() -> None:
    assert render_needrestart_dropin(DEFAULT) == (
        "# Managed by ops-deploy (base.unattended_upgrades). Do not edit by hand.\n$nrconf{restart} = 'a';\n"
    )
    cfg = UnattendedUpgradesConfig(needrestart="list", needrestart_skip_services=("postfix@-.service", "nginx.service"))
    assert render_needrestart_dropin(cfg).splitlines()[1:] == [
        "$nrconf{restart} = 'l';",
        "$nrconf{override_rc}{qr(^postfix\\@-\\.service$)} = 0;",
        "$nrconf{override_rc}{qr(^nginx\\.service$)} = 0;",
    ]


@pytest.mark.parametrize("os", OS)
def test_first_run_installs_writes_and_checks(os: str) -> None:
    run = run_deploy_fake(deploy_unattended_upgrades, DEFAULT, responses=host(os))

    assert run.succeeded, run.error
    assert run.upload(APT_DROPIN) == render_apt_dropin(DEFAULT, OS[os]).encode()
    assert run.upload(NEEDRESTART_DROPIN) == render_needrestart_dropin(DEFAULT).encode()
    assert run.mutating_changed_ops == [
        REFRESH,
        INSTALL,
        WRITE_APT,
        f"unattended-upgrades | Ensure {NEEDRESTART_DIR}",
        WRITE_NR,
    ]
    install = next(command for command in run.executed_commands if " install " in command)
    assert install.endswith("install unattended-upgrades needrestart")
    # The policy check comes last and compares the effective configuration.
    assert run.executed_commands[-1] == _check_script(apt_settings(DEFAULT, OS[os]))
    assert run.op(CHECK).read_only


@pytest.mark.parametrize("os", OS)
def test_converged_host_changes_nothing(os: str) -> None:
    run = run_deploy_fake(deploy_unattended_upgrades, DEFAULT, responses=converged(DEFAULT, os))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.uploads == []
    assert run.executed_commands == [_check_script(apt_settings(DEFAULT, OS[os]))]
    # No apt-get update or install while planning or executing.
    assert not any(
        "apt-get" in command for command in run.executed_commands + run.fact_commands if "dump" not in command
    )


def test_policy_drift_rewrites_only_the_apt_drop_in() -> None:
    reboot = UnattendedUpgradesConfig(automatic_reboot=True)

    run = run_deploy_fake(deploy_unattended_upgrades, reboot, responses=converged(DEFAULT))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [WRITE_APT]
    assert b'Automatic-Reboot "true";' in run.upload(APT_DROPIN)


def test_installed_packages_are_not_refreshed_or_reinstalled() -> None:
    responses = host(**fakehost.deb_installed("unattended-upgrades", "needrestart"))

    run = run_deploy_fake(deploy_unattended_upgrades, DEFAULT, responses=responses)

    assert run.succeeded, run.error
    assert REFRESH not in run.changed_ops
    assert INSTALL not in run.changed_ops


def test_unmanaged_needrestart_is_not_installed_and_its_drop_in_is_removed() -> None:
    cfg = UnattendedUpgradesConfig(needrestart="unmanaged")
    responses = host(
        kinds=("regular file", "regular file"),
        **fakehost.deb_installed("unattended-upgrades"),
        **fakehost.file(APT_DROPIN, render_apt_dropin(cfg, "debian")),
        **fakehost.file(NEEDRESTART_DROPIN, render_needrestart_dropin(DEFAULT)),
    )

    run = run_deploy_fake(deploy_unattended_upgrades, cfg, responses=responses)

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [f"unattended-upgrades | Remove {NEEDRESTART_DROPIN}"]
    assert f"rm -f {NEEDRESTART_DROPIN}" in run.executed_commands


@pytest.mark.parametrize("os", ["debian 11", "ubuntu 22.04", "ubuntu 26.04", "fedora 40", ""])
def test_unsupported_releases_are_refused_before_any_change(os: str) -> None:
    run = run_deploy_fake(deploy_unattended_upgrades, DEFAULT, responses=host(os))

    assert not run.succeeded
    assert "supports debian 12, debian 13, ubuntu 24.04" in str(run.error)
    assert run.ops == []


def test_non_systemd_hosts_are_refused() -> None:
    responses = {**host(), "cat /proc/1/comm": ["init"]}

    run = run_deploy_fake(deploy_unattended_upgrades, DEFAULT, responses=responses)

    assert not run.succeeded
    assert "requires a systemd-managed host" in str(run.error)
    assert run.ops == []


def test_point_releases_are_refused_on_ubuntu() -> None:
    cfg = UnattendedUpgradesConfig(debian_point_releases=True)

    run = run_deploy_fake(deploy_unattended_upgrades, cfg, responses=host("ubuntu 24.04"))

    assert not run.succeeded
    assert "debian_point_releases is for Debian hosts only" in str(run.error)
    assert run.ops == []


@pytest.mark.parametrize(
    ("kinds", "path"),
    [(("symbolic link", "missing"), APT_DROPIN), (("regular file", "directory"), NEEDRESTART_DROPIN)],
)
def test_a_drop_in_path_that_is_not_a_regular_file_is_refused(kinds: tuple[str, str], path: str) -> None:
    run = run_deploy_fake(deploy_unattended_upgrades, DEFAULT, responses=host(kinds=kinds))

    assert not run.succeeded
    assert f"{path} is a {kinds[0] if path == APT_DROPIN else kinds[1]}, not a regular file" in str(run.error)
    assert run.ops == []


def test_check_script_compares_sorted_settings_and_the_timers() -> None:
    script = _check_script(apt_settings(DEFAULT, "debian"))

    assert script.startswith("set -e; dump=$(apt-config dump); ")
    assert "Allowed-Origins" in script  # any packaged Allowed-Origins entry left is a mismatch
    assert "APT::Periodic::Enable" in script
    assert "apt-daily.timer apt-daily-upgrade.timer" in script


@pytest.mark.parametrize(
    "fields",
    [
        {"package_blacklist": ('foo";',)},
        {"package_blacklist": ("foo bar",)},
        {"package_blacklist": ("(unclosed",)},
        {"automatic_reboot_time": "4:30"},
        {"automatic_reboot_time": "24:00"},
        {"automatic_reboot_time": "now"},
        {"needrestart": "interactive"},
        {"needrestart_skip_services": ("nginx",)},
        {"needrestart_skip_services": ("bad)name.service",)},
        {"needrestart": "unmanaged", "needrestart_skip_services": ("nginx.service",)},
        {"autoclean_interval_days": -1},
        {"unknown": True},
    ],
)
def test_invalid_config_is_refused(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        UnattendedUpgradesConfig(**fields)
