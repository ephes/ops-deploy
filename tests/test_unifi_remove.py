"""The unifi_remove port; synthetic services, packages, MongoDB clients and accounts only."""

from __future__ import annotations

import importlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services.unifi import UnifiRemoveConfig, remove_unifi
from ops_deploy.services.unifi.remove import HOST
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

PASSWORD = "fixture-mongo-password"  # pragma: allowlist secret
# What both normal ops-control recipes pass (`-e unifi_remove_*=true`).
RECIPE = dict.fromkeys(
    (
        "drop_mongodb_database",
        "drop_mongodb_user",
        "delete_data",
        "delete_logs",
        "delete_backup_dir",
        "delete_home",
        "remove_user",
        "remove_group",
    ),
    True,
)
host_module = importlib.import_module("ops_deploy.services.unifi.files.remove_host")


def secrets(**values: str) -> SecretValues:
    return SecretValues(SecretRef("secrets/unifi.yml"), values)


def test_defaults() -> None:
    assert UnifiRemoveConfig().model_dump(mode="json") == {
        "backup_dir": "/usr/lib/unifi/data/backup",
        "cache_dir": "/home/unifi/cache",
        "confirm": False,
        "data_dir": "/usr/lib/unifi/data",
        "delete_backup_dir": False,
        "delete_cache": True,
        "delete_data": False,
        "delete_home": False,
        "delete_logs": False,
        "drop_mongodb_database": False,
        "drop_mongodb_user": False,
        "firewall_rules": [
            {"comment": "UniFi device communication", "port": 8080, "proto": "tcp"},
            {"comment": "UniFi web admin", "port": 8443, "proto": "tcp"},
            {"comment": "UniFi STUN", "port": 3478, "proto": "udp"},
            {"comment": "UniFi discovery", "port": 10001, "proto": "udp"},
            {"comment": "UniFi speed test", "port": 6789, "proto": "tcp"},
        ],
        "group": "unifi",
        "home_dir": "/home/unifi",
        "install_dir": "/usr/lib/unifi",
        "java_packages": ["openjdk-17-jre-headless"],
        "logs_dir": "/usr/lib/unifi/logs",
        "manage_firewall": True,
        "manage_traefik": True,
        "mongodb_auth_db": "admin",
        "mongodb_database": "unifi",
        "mongodb_host": "127.0.0.1",
        "mongodb_jvm_args_path": "/etc/unifi-secrets/mongodb.jvmargs",
        "mongodb_packages": [
            "mongodb-org",
            "mongodb-org-server",
            "mongodb-org-shell",
            "mongodb-org-mongos",
            "mongodb-org-tools",
        ],
        "mongodb_port": 27017,
        "mongodb_state_dirs": ["/var/lib/mongodb", "/var/log/mongodb"],
        "mongodb_tool_packages": ["mongodb-database-tools", "mongodb-mongosh", "mongodb-org-database-tools-extra"],
        "mongodb_user": "unifi",
        "remove_group": False,
        "remove_packages": True,
        "remove_service_units": True,
        "remove_user": False,
        "service_name": "unifi",
        "services": ["unifi"],
        "stop_mongod": True,
        "stop_services": True,
        "systemd_unit_path": "/etc/systemd/system/unifi.service",
        "traefik_config_path": "/etc/traefik/dynamic/unifi.yml",
        "trigger_backup": False,
        "unifi_packages": ["unifi"],
        "user": "unifi",
    }


@pytest.mark.parametrize(
    ("overrides", "derived"),
    [
        (
            {"user": "owned", "service_name": "owned-ui"},
            {
                "home_dir": "/home/owned",
                "cache_dir": "/home/owned/cache",
                "systemd_unit_path": "/etc/systemd/system/owned-ui.service",
                "mongodb_jvm_args_path": "/etc/owned-ui-secrets/mongodb.jvmargs",
                "services": ["owned-ui"],
            },
        ),
        (
            {"install_dir": "/srv/ui"},
            {"data_dir": "/srv/ui/data", "logs_dir": "/srv/ui/logs", "backup_dir": "/srv/ui/data/backup"},
        ),
    ],
)
def test_dependent_paths_follow_the_given_names(overrides: dict[str, Any], derived: dict[str, Any]) -> None:
    defaults = UnifiRemoveConfig().model_dump(mode="json")
    cfg = UnifiRemoveConfig(**overrides).model_dump(mode="json")
    assert {key: value for key, value in cfg.items() if value != defaults[key]} == {**overrides, **derived}


def test_confirmation_precedes_every_target_probe() -> None:
    run = run_deploy_fake(remove_unifi, UnifiRemoveConfig(**RECIPE), secrets(mongodb_password=PASSWORD))
    assert not run.succeeded
    assert "confirm" in str(run.error)
    assert not run.events
    assert not run.ops


@pytest.mark.parametrize("values", [{"install_dir": "/usr"}, {"home_dir": "/"}, {"cache_dir": "/home/../etc"}])
def test_unsafe_paths_are_refused(values: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="removal paths"):
        UnifiRemoveConfig(**values)


def test_the_unported_pre_removal_backup_is_refused() -> None:
    with pytest.raises(ValueError, match="trigger_backup"):
        UnifiRemoveConfig(trigger_backup=True)


TOOLS = ("mongodb-database-tools", "mongodb-mongosh", "mongodb-org-database-tools-extra")


def responses(
    *, debian: bool = True, ufw: bool = True, installed: bool = True, leftovers: bool = True
) -> dict[str, Any]:
    cfg = UnifiRemoveConfig()
    service = json.dumps(dict(success=True, enabled=True, active="active", load="loaded"))
    result: dict[str, Any] = {
        "import json, subprocess, sys": [service],
        "test -f /etc/debian_version": ["debian"] if debian else [],
        "command -v ufw": ["/usr/sbin/ufw"] if ufw else [],
        "packages unifi": [json.dumps(["unifi"] if installed else [])],
        "packages mongodb-org": [json.dumps(["mongodb-org", "mongodb-org-server"] if installed else [])],
        "packages mongodb-database-tools": [json.dumps(list(TOOLS) if leftovers else [])],
        "packages openjdk-17-jre-headless": [json.dumps(["openjdk-17-jre-headless"] if installed else [])],
        **fakehost.LINUX,
        **fakehost.system_account(cfg.user, cfg.home_dir),
    }
    for path in (
        cfg.systemd_unit_path,
        cfg.mongodb_jvm_args_path,
        cfg.traefik_config_path,
    ):
        result.update(fakehost.file(path, "owned"))
    for path in (
        "/etc/unifi-secrets",
        cfg.cache_dir,
        cfg.logs_dir,
        cfg.backup_dir,
        cfg.data_dir,
        cfg.install_dir,
        cfg.home_dir,
    ):
        result.update(fakehost.directory(path))
    if leftovers:
        for path in cfg.mongodb_state_dirs:
            result.update(fakehost.directory(path, user="mongodb"))
    return result


def purge(*packages: str) -> str:
    return (
        "env DEBIAN_FRONTEND=noninteractive apt-get -q -y -o Dpkg::Options::=--force-confdef "
        "-o Dpkg::Options::=--force-confold --purge remove -- " + " ".join(packages)
    )


def test_the_recipe_flags_follow_the_role_order() -> None:
    run = run_deploy_fake(
        remove_unifi,
        UnifiRemoveConfig(confirm=True, **RECIPE),
        secrets(mongodb_password=PASSWORD),
        responses=responses(),
    )
    assert run.succeeded, run.error
    quoted = shlex.quote(HOST)
    commands = [
        command.replace(quoted, "HOST")
        for command in run.executed_commands
        if "import json, subprocess, sys" not in command
    ]
    mongo = "/usr/bin/python3 -I -B -c HOST mongo"
    assert commands == [
        "systemctl disable unifi",
        "systemctl stop unifi",
        "rm -rf /etc/systemd/system/unifi.service",
        "rm -rf /etc/unifi-secrets/mongodb.jvmargs",
        "rm -rf /etc/unifi-secrets",
        "systemctl daemon-reload",
        route_guard_command(),
        "rm -rf /etc/traefik/dynamic/unifi.yml",
        "ufw delete allow from any to any port 8080 proto tcp",
        "ufw delete allow from any to any port 8443 proto tcp",
        "ufw delete allow from any to any port 3478 proto udp",
        "ufw delete allow from any to any port 10001 proto udp",
        "ufw delete allow from any to any port 6789 proto tcp",
        mongo,
        mongo,
        "systemctl disable mongod",
        "systemctl stop mongod",
        purge("unifi"),
        purge("mongodb-org", "mongodb-org-server"),
        purge(*TOOLS),
        purge("openjdk-17-jre-headless"),
        "rm -rf /var/lib/mongodb",
        "rm -rf /var/log/mongodb",
        "rm -rf /home/unifi/cache",
        "rm -rf /usr/lib/unifi/logs",
        "rm -rf /usr/lib/unifi/data/backup",
        "rm -rf /usr/lib/unifi/data",
        "rm -rf /usr/lib/unifi",
        "rm -rf /home/unifi",
        "userdel -r unifi",
        "groupdel unifi",
    ]
    # The credentials travel on stdin only.
    assert not any(PASSWORD in command for command in run.executed_commands)
    payloads = [json.loads(stdin) for _command, stdin in run.stdin]
    assert [payload["action"] for payload in payloads] == ["drop-database", "drop-user"]
    assert payloads[0] == {
        "action": "drop-database",
        "host": "127.0.0.1",
        "port": 27017,
        "auth_db": "admin",
        "database": "unifi",
        "user": "unifi",
        "password": PASSWORD,
    }


def test_role_defaults_keep_data_accounts_and_database() -> None:
    run = run_deploy_fake(
        remove_unifi, UnifiRemoveConfig(confirm=True), secrets(mongodb_password=PASSWORD), responses=responses()
    )
    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    assert "rm -rf /home/unifi/cache" in commands
    for kept in ("/usr/lib/unifi\n", "/usr/lib/unifi/data", "/usr/lib/unifi/logs", "/home/unifi\n", "/var/lib/mongodb"):
        assert "rm -rf " + kept not in commands + "\n"
    assert "userdel" not in commands
    assert "groupdel" not in commands
    assert not run.stdin


@pytest.mark.parametrize("values", [{}, {"mongodb_password": ""}])
def test_without_a_password_the_drops_are_skipped(values: dict[str, str]) -> None:
    run = run_deploy_fake(
        remove_unifi, UnifiRemoveConfig(confirm=True, **RECIPE), secrets(**values), responses=responses()
    )
    assert run.succeeded, run.error
    assert not any(command.endswith(" mongo") for command in run.executed_commands)
    run = run_deploy_fake(remove_unifi, UnifiRemoveConfig(confirm=True, **RECIPE), responses=responses())
    assert run.succeeded, run.error
    assert not any(command.endswith(" mongo") for command in run.executed_commands)


@pytest.mark.parametrize(("debian", "ufw"), [(False, True), (True, False)])
def test_firewall_rules_need_debian_and_ufw(debian: bool, ufw: bool) -> None:
    run = run_deploy_fake(remove_unifi, UnifiRemoveConfig(confirm=True), responses=responses(debian=debian, ufw=ufw))
    assert run.succeeded, run.error
    assert not any("ufw delete" in command for command in run.executed_commands)
    run = run_deploy_fake(remove_unifi, UnifiRemoveConfig(confirm=True, manage_firewall=False), responses=responses())
    assert not any("ufw delete" in command for command in run.executed_commands)


def test_mongodb_leftovers_go_only_when_present_and_after_the_purge() -> None:
    cfg = UnifiRemoveConfig(confirm=True, **RECIPE)
    run = run_deploy_fake(remove_unifi, cfg, responses=responses(installed=False, leftovers=False))
    assert run.succeeded, run.error
    changes = [command for command in run.executed_commands if not command.startswith(("/usr/bin/python3", "import"))]
    assert not any("apt-get" in command or "/var/" in command for command in changes)
    run = run_deploy_fake(remove_unifi, cfg, responses=responses(installed=False))
    assert run.succeeded, run.error
    commands = [command for command in run.executed_commands if "import json, subprocess, sys" not in command]
    assert commands[commands.index("systemctl stop mongod") + 1 :][:3] == [
        purge(*TOOLS),
        "rm -rf /var/lib/mongodb",
        "rm -rf /var/log/mongodb",
    ]
    # The package removal off: mongod may still own its directories.
    run = run_deploy_fake(remove_unifi, cfg.model_copy(update={"remove_packages": False}), responses=responses())
    assert run.succeeded, run.error
    assert not any(command.startswith("rm -rf /var/") for command in run.executed_commands)


@pytest.mark.parametrize("dirs", [("/var",), ("/var/lib/../../etc",)])
def test_unsafe_mongodb_state_dirs_are_refused(dirs: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="removal paths"):
        UnifiRemoveConfig(mongodb_state_dirs=dirs)


def test_absent_packages_are_not_purged_and_a_bad_probe_stops() -> None:
    run = run_deploy_fake(
        remove_unifi, UnifiRemoveConfig(confirm=True), responses=responses(installed=False, leftovers=False)
    )
    assert run.succeeded, run.error
    assert not any("apt-get" in command for command in run.executed_commands)
    broken = {**responses(), "packages unifi": ['["other"]']}
    run = run_deploy_fake(remove_unifi, UnifiRemoveConfig(confirm=True), responses=broken)
    assert not run.succeeded
    assert not any("apt-get" in command for command in run.executed_commands)


@pytest.mark.parametrize("delete_home", [False, True])
def test_user_removal_follows_delete_home_and_failures_are_fatal(delete_home: bool) -> None:
    cfg = UnifiRemoveConfig(confirm=True, remove_user=True, remove_group=True, delete_home=delete_home)
    run = run_deploy_fake(remove_unifi, cfg, responses=responses())
    assert run.succeeded, run.error
    assert ("userdel -r unifi" if delete_home else "userdel unifi") in run.executed_commands
    run = run_deploy_fake(remove_unifi, cfg, responses={"userdel": {"success": False}, **responses()})
    assert not run.succeeded
    assert "groupdel unifi" not in run.executed_commands


def test_service_failures_are_ignored() -> None:
    run = run_deploy_fake(
        remove_unifi,
        UnifiRemoveConfig(confirm=True),
        responses={"systemctl disable": {"success": False}, **responses()},
    )
    assert run.error is None
    assert "rm -rf /etc/systemd/system/unifi.service" in run.executed_commands
    assert any(command.startswith("env DEBIAN_FRONTEND") for command in run.executed_commands)


def fake_dpkg(tmp_path: Path, stdout: str, stderr: str, code: int) -> None:
    script = tmp_path / "dpkg-query"
    script.write_text(
        f"#!{sys.executable}\nimport sys\n"
        f"sys.stdout.write({stdout!r}); sys.stderr.write({stderr!r}); sys.exit({code})\n"
    )
    script.chmod(0o700)


def test_package_states_select_installed_and_residual_packages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    fake_dpkg(
        tmp_path,
        "mongodb-org\tinstalled\nmongodb-org-server\tconfig-files\nmongodb-org-shell\tnot-installed\n",
        "dpkg-query: no packages found matching mongodb-org-mongos\n"
        "dpkg-query: no packages found matching mongodb-org-tools\n",
        1,
    )
    names = list(UnifiRemoveConfig().mongodb_packages)
    assert host_module.packages(names) == ["mongodb-org", "mongodb-org-server"]
    fake_dpkg(tmp_path, "", "dpkg-query: error\n", 2)
    with pytest.raises(RuntimeError):
        host_module.packages(names)
    fake_dpkg(tmp_path, "other\tinstalled\n", "", 0)
    with pytest.raises(RuntimeError):
        host_module.packages(["unifi"])
    # An empty list never queries dpkg (dpkg-query -W alone lists every package).
    assert host_module.packages([]) == []


def test_an_empty_package_list_is_a_noop() -> None:
    cfg = UnifiRemoveConfig(confirm=True, mongodb_packages=(), mongodb_tool_packages=(), java_packages=())
    run = run_deploy_fake(remove_unifi, cfg, responses=responses())
    assert run.succeeded, run.error
    assert purge("unifi") in run.executed_commands
    assert sum("apt-get" in command for command in run.executed_commands) == 1


@pytest.mark.parametrize("code", [0, 1])
def test_mongo_runs_the_roles_script_off_argv_with_a_private_home(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    seen: dict[str, Any] = {}

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        home = Path(kwargs["env"]["HOME"])
        seen.update(argv=argv, input=kwargs["input"], env=kwargs["env"], home=home)
        seen["config"] = json.loads((home / ".mongodb/mongosh/config").read_text())
        seen["mode"] = (home / ".mongodb/mongosh/config").stat().st_mode & 0o777
        return subprocess.CompletedProcess(argv, code, "", "")

    monkeypatch.setattr(host_module.subprocess, "run", run)
    payload = {
        "action": "drop-user",
        "host": "127.0.0.1",
        "port": 27017,
        "auth_db": "admin",
        "database": "unifi",
        "user": "unifi",
        "password": PASSWORD,
    }
    assert host_module.mongo(payload) is (code == 0)
    assert seen["argv"] == [
        "mongosh",
        "--quiet",
        "--norc",
        "--host",
        "127.0.0.1",
        "--port",
        "27017",
        "--file",
        "/dev/stdin",
    ]
    assert PASSWORD in seen["input"]
    assert seen["config"] == {"disableLogging": True, "enableTelemetry": False, "updateURL": ""}
    assert seen["mode"] == 0o600
    assert set(seen["env"]) == {"HOME", "PATH", "LC_ALL"}
    assert not seen["home"].exists()


def test_a_failed_client_is_reported_without_output_and_exit_zero(tmp_path: Path) -> None:
    # No mongosh on the script's fixed PATH (or a broken payload): ignored, as the role does.
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", HOST, "mongo"],
        input=json.dumps({"action": "drop-user", "password": PASSWORD}),
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0
    assert result.stdout.startswith("failed")
    assert PASSWORD not in result.stdout + result.stderr


@pytest.mark.parametrize(
    ("action", "statement"),
    [
        ("drop-database", 'printjson(db.getSiblingDB("unifi").dropDatabase());'),
        ("drop-user", 'printjson(db.getSiblingDB("admin").dropUser("unifi"));'),
    ],
)
def test_the_mongosh_script(action: str, statement: str) -> None:
    payload = {"action": action, "auth_db": "admin", "database": "unifi", "user": "unifi", "password": PASSWORD}
    assert host_module.script(payload) == (
        'const authDb = db.getSiblingDB("admin");\n'
        f'if (!authDb.auth("unifi", "{PASSWORD}")) {{ quit(1); }}\n'
        'db = db.getSiblingDB("admin");\n'
        f"{statement}\n"
    )
