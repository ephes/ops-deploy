from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import ShellBasicsConfig, deploy_shell_basics
from ops_deploy.base.shell_basics import BLOCK_BEGIN, BLOCK_END, resolv_conf, with_block
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

CONFIG = "/root/.config/fish/config.fish"
BLOCK = f"{BLOCK_BEGIN}\nfish_add_path -g /root/.local/bin\n{BLOCK_END}\n"
CHEZMOI = "/usr/local/bin/chezmoi --version"


def host(
    extra: dict[str, Any] | None = None, *, shell: str = "/usr/bin/fish", fish_config: str | None = BLOCK
) -> dict[str, Any]:
    """A converged host for the default config; ``extra`` replaces or adds responses."""

    responses: dict[str, Any] = {
        **LINUX,
        "uname -m": ["x86_64"],
        "cat /etc/passwd | cut": [f"root:x:0:0:root:/root:{shell}|root|root||!"],
        "awk '/^nameserver/": ["192.168.178.1"],
        CHEZMOI: ["chezmoi version v2.73.1, commit abc, built at 2026-01-01T00:00:00Z"],
        "update-alternatives --query editor": ["Name: editor", "Status: manual", "Value: /usr/bin/vim.basic"],
        **fakehost.apt_cache_fresh(),
        **fakehost.deb_installed(*ShellBasicsConfig().all_packages),
        **fakehost.directory("/usr/local/bin"),
        **fakehost.directory("/root/.local"),
        **fakehost.directory("/root/.config"),
        **fakehost.directory("/root/.local/bin"),
        **fakehost.directory("/root/.config/fish"),
        **fakehost.symlink("/root/.local/bin/bat", "/usr/bin/batcat"),
        **fakehost.symlink("/root/.local/bin/fd", "/usr/bin/fdfind"),
    }
    if fish_config is not None:
        responses.update(fakehost.file(CONFIG, fish_config))
    responses.update(extra or {})
    return responses


def test_converged_host_changes_nothing() -> None:
    run = run_deploy_fake(deploy_shell_basics, ShellBasicsConfig(), responses=host())

    assert run.succeeded, run.error
    assert run.changed_ops == []


def test_fresh_host_installs_everything() -> None:
    responses = {
        **LINUX,
        "uname -m": ["x86_64"],
        "cat /etc/passwd | cut": ["root:x:0:0:root:/root:/bin/bash|root|root||!"],
        "awk '/^nameserver/": ["127.0.0.53"],
    }

    run = run_deploy_fake(deploy_shell_basics, ShellBasicsConfig(), responses=responses)

    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    assert 'mv -f "$tmp" /etc/resolv.conf' in commands
    assert "nameserver 1.1.1.1" in commands
    assert "apt-get update" in commands
    assert "chezmoi_2.73.1_linux_amd64.tar.gz" in commands
    assert "ln -s /usr/bin/batcat /root/.local/bin/bat" in commands
    assert "ln -s /usr/bin/fdfind /root/.local/bin/fd" in commands
    assert run.upload(CONFIG).decode() == BLOCK
    assert "usermod -s /usr/bin/fish root" in commands
    assert "chown root:root /root/.local" in commands
    assert "update-alternatives --set editor /usr/bin/vim.basic" in commands
    # The shell is checked on the host right before switching (fish arrives with the packages).
    assert commands.index("test -x /usr/bin/fish") < commands.index("usermod -s")


def test_real_nameserver_keeps_resolv_conf() -> None:
    run = run_deploy_fake(
        deploy_shell_basics, ShellBasicsConfig(), responses=host({"awk '/^nameserver/": ["10.0.0.1", "127.0.0.1"]})
    )

    assert not any("resolv.conf" in command for command in run.executed_commands)


def test_resolv_conf_fix_can_be_disabled() -> None:
    cfg = ShellBasicsConfig(fix_resolv_conf=False)

    run = run_deploy_fake(deploy_shell_basics, cfg, responses=host({"awk '/^nameserver/": ["127.0.0.53"]}))

    assert run.changed_ops == []
    assert not any("nameserver" in command for command in run.fact_commands)


def test_other_chezmoi_version_is_replaced() -> None:
    run = run_deploy_fake(
        deploy_shell_basics, ShellBasicsConfig(), responses=host({CHEZMOI: ["chezmoi version v2.73.0, x"]})
    )

    assert run.changed_ops == ["Shell basics | Install chezmoi 2.73.1"]


def test_fish_block_is_replaced_in_place_and_other_lines_kept() -> None:
    existing = f"set -g fish_greeting\n{BLOCK_BEGIN}\nfish_add_path -g /old\n{BLOCK_END}\nalias ll 'eza -l'\n"
    cfg = ShellBasicsConfig(fish_extra_config=("set -gx EDITOR vim",))

    run = run_deploy_fake(deploy_shell_basics, cfg, responses=host(fish_config=existing))

    assert run.upload(CONFIG).decode() == (
        f"set -g fish_greeting\n{BLOCK_BEGIN}\nfish_add_path -g /root/.local/bin\nset -gx EDITOR vim\n{BLOCK_END}\n"
        "alias ll 'eza -l'\n"
    )


def test_with_block_appends_when_missing() -> None:
    assert with_block(["set -g x"], [BLOCK_BEGIN, "y", BLOCK_END]) == f"set -g x\n{BLOCK_BEGIN}\ny\n{BLOCK_END}\n"
    assert with_block(None, [BLOCK_BEGIN, BLOCK_END]) == f"{BLOCK_BEGIN}\n{BLOCK_END}\n"


def test_other_shell_is_switched_only_when_asked() -> None:
    switched = run_deploy_fake(deploy_shell_basics, ShellBasicsConfig(), responses=host(shell="/bin/bash"))
    kept = run_deploy_fake(
        deploy_shell_basics, ShellBasicsConfig(switch_shell=False), responses=host(shell="/bin/bash")
    )

    assert switched.changed_ops == ["Shell basics | Switch login shell of root to /usr/bin/fish"]
    assert kept.changed_ops == []


def test_missing_user_fails_before_any_change() -> None:
    run = run_deploy_fake(deploy_shell_basics, ShellBasicsConfig(user="nobody2"), responses=host())

    assert "user nobody2 must exist" in str(run.error)
    assert run.ops == []


def test_without_bat_package_and_binary_no_link() -> None:
    cfg = ShellBasicsConfig(packages=("fish",))

    run = run_deploy_fake(deploy_shell_basics, cfg, responses=host())

    assert not any(op.name.endswith("Link bat to /usr/bin/batcat") for op in run.ops)


def test_resolv_conf_text() -> None:
    assert resolv_conf(("1.1.1.1",)) == "# Managed by shell_basics_deploy (fallback)\nnameserver 1.1.1.1\n"


@pytest.mark.parametrize(
    "overrides",
    [
        {"resolv_fallback_nameservers": ("not-an-ip",)},
        {"packages": ("fish; rm -rf /",)},
        {"fish_extra_config": ("a\nb",)},
        {"chezmoi_version": "latest"},
        {"user_home": "relative"},
    ],
)
def test_rejects_invalid_config(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ShellBasicsConfig(**overrides)


def test_symlinked_parents_are_left_alone() -> None:
    responses = host(
        {
            **fakehost.symlink("/root/.local", "/data/local"),
            **fakehost.symlink("/root/.config", "/data/config"),
        }
    )

    run = run_deploy_fake(deploy_shell_basics, ShellBasicsConfig(), responses=responses)

    assert run.succeeded, run.error
    assert run.changed_ops == []
