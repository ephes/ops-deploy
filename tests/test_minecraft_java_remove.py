"""The minecraft_java_remove port; synthetic services, accounts, crontabs and firewall only."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from ops_deploy.services.minecraft_java import MinecraftJavaRemoveConfig, remove_minecraft_java
from ops_deploy.services.minecraft_java.remove import CRON, CRON_NAME
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

PARITY = Path(__file__).parent / "parity/minecraft_java/remove"
UNIT = "/etc/systemd/system/minecraft-java.service"


def confirmed(**values: Any) -> MinecraftJavaRemoveConfig:
    return MinecraftJavaRemoveConfig(confirm_removal=True, **values)


def role(name: str) -> Any:
    return yaml.safe_load((PARITY / name).read_text())


def test_fixtures_are_the_recorded_role_files() -> None:
    manifest = json.loads((PARITY / "source.json").read_text())
    for name, entry in manifest["files"].items():
        body = (PARITY / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == entry["sha256"]
        if os.environ.get("OPS_LIBRARY_PATH"):
            assert body == (Path(os.environ["OPS_LIBRARY_PATH"]) / entry["source"]).read_bytes()


def test_defaults_are_the_roles() -> None:
    defaults = role("defaults.yml")
    cfg = MinecraftJavaRemoveConfig()
    assert cfg.confirm_removal is defaults["minecraft_java_confirm_removal"] is False
    for field in ("user", "group", "home", "service_name", "port", "rcon_port"):
        assert getattr(cfg, field) == defaults["minecraft_java_" + field]
    assert list(cfg.firewall_allowed_networks) == defaults["minecraft_java_firewall_allowed_networks"]


def test_role_task_order_and_ignored_failures_are_the_ported_ones() -> None:
    tasks = role("tasks.yml")
    modules = [next(key for key in task if key.startswith(("ansible.", "community."))) for task in tasks]
    assert modules == [
        "ansible.builtin.assert",
        "ansible.builtin.debug",
        "ansible.builtin.systemd",  # stop
        "ansible.builtin.systemd",  # disable
        "ansible.builtin.file",  # unit
        "ansible.builtin.systemd",  # daemon_reload
        "ansible.builtin.cron",
        "ansible.builtin.shell",  # pkill
        "ansible.builtin.file",  # home
        "ansible.builtin.user",
        "ansible.builtin.group",
        "community.general.ufw",
        "community.general.ufw",
        "ansible.builtin.debug",
    ]
    ignored = [index for index, task in enumerate(tasks) if task.get("ignore_errors")]
    assert ignored == [2, 3, 6, 7, 10, 11, 12]
    assert tasks[2]["ansible.builtin.systemd"] == {"name": "{{ minecraft_java_service_name }}", "state": "stopped"}
    assert tasks[3]["ansible.builtin.systemd"] == {"name": "{{ minecraft_java_service_name }}", "enabled": False}
    assert tasks[4]["notify"] == "reload systemd"
    assert tasks[6]["ansible.builtin.cron"]["name"] == CRON_NAME
    assert tasks[9]["ansible.builtin.user"]["remove"] is True
    assert tasks[11]["community.general.ufw"]["rule"] == "allow"
    assert tasks[12]["community.general.ufw"] == {
        "rule": "deny",
        "port": "{{ minecraft_java_rcon_port }}",
        "proto": "tcp",
        "delete": True,
    }
    assert role("handlers.yml") == [{"name": "reload systemd", "ansible.builtin.systemd": {"daemon_reload": True}}]


def test_confirmation_precedes_every_target_probe() -> None:
    run = run_deploy_fake(remove_minecraft_java, MinecraftJavaRemoveConfig())
    assert not run.succeeded
    assert "confirm_removal" in str(run.error)
    assert not run.events
    assert not run.ops


@pytest.mark.parametrize(
    "values",
    [{"home": "/"}, {"home": "/home"}, {"home": "/home/../etc"}, {"user": "root"}, {"group": "root"}],
)
def test_unsafe_targets_are_refused(values: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"home must|root cannot"):
        confirmed(**values)


def test_invalid_network_is_refused() -> None:
    with pytest.raises(ValueError, match="network"):
        confirmed(firewall_allowed_networks=("192.168.0.0/16; reboot",))


def service(*, enabled: bool = True, active: str = "active", load: str = "loaded") -> dict[str, Any]:
    return {"import json, subprocess, sys": [json.dumps(dict(success=True, enabled=enabled, active=active, load=load))]}


def host(*, cron: str = "present", processes: bool = True, ufw: bool = True, **unit: Any) -> dict[str, Any]:
    cfg = MinecraftJavaRemoveConfig()
    return {
        **service(**unit),
        f"inspect {cfg.user}": [cron],
        f"ps -u {cfg.user}": ["4242"] if processes else [],
        "command -v ufw": ["/usr/sbin/ufw"] if ufw else [],
        **fakehost.LINUX,
        **fakehost.file(UNIT, "owned unit"),
        **fakehost.directory(cfg.home, user=cfg.user),
        **fakehost.system_account(cfg.user, cfg.home),
    }


def test_full_removal_follows_the_role_order() -> None:
    cfg = confirmed()
    run = run_deploy_fake(remove_minecraft_java, cfg, responses=host())
    assert run.succeeded, run.error
    commands = [command for command in run.executed_commands if "import json, subprocess" not in command]
    assert commands == [
        "systemctl stop minecraft-java",
        "systemctl disable minecraft-java",
        "rm -rf " + UNIT,
        "systemctl daemon-reload",
        shlex.join(["/usr/bin/python3", "-I", "-B", "-c", CRON, "remove", "minecraft", CRON_NAME]),
        "pkill -u minecraft || true",
        "rm -rf /home/minecraft",
        "userdel -r minecraft",
        "groupdel minecraft",
        "ufw delete allow from 192.168.0.0/16 to any port 25565 proto tcp",
        "ufw delete allow from 10.0.0.0/8 to any port 25565 proto tcp",
        "ufw delete allow from 100.64.0.0/10 to any port 25565 proto tcp",
        "ufw delete deny from any to any port 25575 proto tcp",
        "systemctl daemon-reload",
    ]


def test_a_removed_host_changes_only_the_unconditional_reload() -> None:
    cfg = confirmed()
    responses = {**service(enabled=False, active="inactive", load="not-found"), **fakehost.LINUX}
    responses[f"inspect {cfg.user}"] = ["absent"]
    run = run_deploy_fake(remove_minecraft_java, cfg, responses=responses)
    assert run.error is None
    # The systemd tasks fail on an absent unit; the role ignores that.
    assert run.executed_commands == ["systemctl daemon-reload"]


@pytest.mark.parametrize("active", ["active", "activating", "deactivating", "inactive", "failed"])
def test_stop_and_disable_states(active: str) -> None:
    run = run_deploy_fake(
        remove_minecraft_java, confirmed(), responses=host(enabled=False, active=active, cron="absent")
    )
    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    assert "systemctl disable" not in commands
    assert ("systemctl stop" in commands) is (active in {"active", "activating", "deactivating"})


def test_failed_userdel_stops_the_removal_and_other_failures_do_not() -> None:
    responses = {
        "systemctl stop": {"success": False},
        "crontab -u": {"success": False},
        "userdel": {"success": False},
        **host(cron="error"),
    }
    run = run_deploy_fake(remove_minecraft_java, confirmed(), responses=responses)
    assert not run.succeeded
    commands = "\n".join(run.executed_commands)
    assert "systemctl disable minecraft-java" in commands
    assert "rm -rf /home/minecraft" in commands
    assert "userdel -r minecraft" in commands
    assert "groupdel" not in commands
    assert "ufw" not in commands


def test_without_ufw_no_rule_is_touched() -> None:
    run = run_deploy_fake(remove_minecraft_java, confirmed(), responses=host(ufw=False))
    assert run.succeeded, run.error
    assert not any("ufw" in command for command in run.executed_commands)


def fake_crontab(tmp_path: Path, listing: str, code: int) -> Path:
    written = tmp_path / "written"
    script = tmp_path / "crontab"
    script.write_text(
        f"#!{sys.executable}\nimport sys\n"
        "if sys.argv[1:] == ['-l', '-u', 'minecraft']:\n"
        f" sys.stdout.write({listing!r}); sys.exit({code})\n"
        "assert sys.argv[1:] == ['-u', 'minecraft', '-'], sys.argv\n"
        f"open({str(written)!r}, 'w').write(sys.stdin.read())\n"
    )
    script.chmod(0o700)
    return written


def cron(tmp_path: Path, action: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-B", "-c", CRON, action, "minecraft", CRON_NAME],
        env={**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"]},
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.parametrize(
    ("listing", "code", "state", "rewritten"),
    [
        # Every marked job goes, unrelated lines and the Debian header stay out of the rewrite.
        (
            "# DO NOT EDIT THIS FILE - edit the master and reinstall.\n"
            "# (/tmp/crontab.x installed on Mon)\n# (Cron version -- $Id$)\n"
            "MAILTO=owner\n#Ansible: Minecraft world backup\n0 3 * * * backup\n"
            "@daily other\n#Ansible: Minecraft world backup\n5 4 * * * again\n",
            0,
            "present",
            "MAILTO=owner\n@daily other\n",
        ),
        ("#Ansible: Minecraft world backup\n0 3 * * * backup\n", 0, "present", ""),
        # A trailing marker without a job is dropped too.
        ("@daily other\n#Ansible: Minecraft world backup\n", 0, "present", "@daily other\n"),
        ("#Ansible: Minecraft world backup other\n0 3 * * * x\n", 0, "absent", None),
        ("", 1, "absent", None),
        ("", 2, "error", None),
    ],
)
def test_cron_job_removal_matches_the_cron_module(
    tmp_path: Path, listing: str, code: int, state: str, rewritten: str | None
) -> None:
    written = fake_crontab(tmp_path, listing, code)
    inspected = cron(tmp_path, "inspect")
    assert inspected.stdout.strip() == state
    assert inspected.returncode == (1 if state == "error" else 0)
    removed = cron(tmp_path, "remove")
    assert removed.returncode == inspected.returncode
    if rewritten is None:
        assert not written.exists()
    else:
        assert written.read_text() == rewritten
