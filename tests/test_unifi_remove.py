"""The unifi_remove port; synthetic services, packages, MongoDB clients and accounts only."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services.unifi import UnifiRemoveConfig, remove_unifi
from ops_deploy.services.unifi.remove import HOST
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

PARITY = Path(__file__).parent / "parity/unifi/remove"
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


def role(name: str) -> Any:
    return yaml.safe_load((PARITY / name).read_text())


def test_fixtures_are_the_recorded_role_files() -> None:
    manifest = json.loads((PARITY / "source.json").read_text())
    for name, entry in manifest["files"].items():
        body = (PARITY / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == entry["sha256"]
        if os.environ.get("OPS_LIBRARY_PATH"):
            assert body == (Path(os.environ["OPS_LIBRARY_PATH"]) / entry["source"]).read_bytes()


@pytest.mark.parametrize("overrides", [{}, {"user": "owned", "service_name": "owned-ui"}, {"install_dir": "/srv/ui"}])
def test_defaults_and_dependent_paths_are_the_roles(overrides: dict[str, Any]) -> None:
    cfg = UnifiRemoveConfig(**overrides)
    context = {"unifi_" + key: value for key, value in cfg.model_dump().items()}
    context.update(
        unifi_remove_confirm=cfg.confirm,
        unifi_remove_services=list(cfg.services),
        unifi_firewall_rules=[rule.model_dump() for rule in cfg.firewall_rules],
    )
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    fields = {
        "unifi_remove_confirm": "confirm",
        "unifi_remove_trigger_backup": "trigger_backup",
        "unifi_remove_services": "services",
        "unifi_remove_unifi_packages": "unifi_packages",
        "unifi_remove_mongodb_packages": "mongodb_packages",
        "unifi_remove_java_packages": "java_packages",
        "unifi_remove_service_units": "remove_service_units",
        "unifi_remove_packages": "remove_packages",
        "unifi_remove_user": "remove_user",
        "unifi_remove_group": "remove_group",
    }
    for name, value in role("defaults.yml").items():
        if name == "unifi_remove_cleanup_summary":
            continue  # a debug message only
        if name == "unifi_mongodb_password":
            assert value == ""  # a secret: remove_unifi's secrets argument
            continue
        field = fields.get(name) or name.removeprefix("unifi_remove_").removeprefix("unifi_")
        if isinstance(value, str):
            value = env.from_string(value).render(**context)
        elif isinstance(value, list):
            value = [env.from_string(item).render(**context) if isinstance(item, str) else item for item in value]
        actual = getattr(cfg, field)
        if field == "firewall_rules":
            actual = [rule.model_dump() for rule in actual]
        elif isinstance(actual, tuple):
            actual = list(actual)
        assert actual == overrides.get(field, value), name


def test_role_order_and_ignored_failures() -> None:
    names = [task["name"] for task in role("tasks.yml")]
    assert names == [
        "Display UniFi removal banner",
        "Require explicit confirmation",
        "Run UniFi backup before removal",
        "Stop UniFi related services",
        "Remove systemd unit file",
        "Remove MongoDB JVM argument file",
        "Remove default MongoDB credentials directory",
        "Reload systemd",
        "Remove Traefik config",
        "Remove UniFi firewall rules",
        "main | Run mongosh with a private credential script",
        "main | Run mongosh with a private credential script",
        "Stop MongoDB service post-cleanup",
        "Purge UniFi packages",
        "Purge MongoDB packages",
        "Purge Java runtime packages",
        "Remove UniFi directories",
        "Remove UniFi user",
        "Remove UniFi group",
        "UniFi removal summary",
    ]
    tasks = role("tasks.yml")
    assert tasks[3]["ansible.builtin.systemd"] == {"name": "{{ item }}", "state": "stopped", "enabled": False}
    assert tasks[3]["failed_when"] is False
    assert tasks[12]["failed_when"] is False
    for index in (10, 11):
        drop = tasks[index]["block"][2]
        assert drop["failed_when"] is False
        assert "unifi_mongodb_password | length > 0" in drop["when"]
    for index in (13, 14, 15):
        assert tasks[index]["ansible.builtin.apt"]["state"] == "absent"
        assert tasks[index]["ansible.builtin.apt"]["purge"] is True
    assert tasks[17]["ansible.builtin.user"]["remove"] == "{{ unifi_remove_delete_home | bool }}"
    assert "ignore_errors" not in tasks[17]
    assert "ignore_errors" not in tasks[18]
    assert [item["path"] for item in tasks[16]["loop"]] == [
        "{{ unifi_cache_dir }}",
        "{{ unifi_logs_dir }}",
        "{{ unifi_backup_dir }}",
        "{{ unifi_data_dir }}",
        "{{ unifi_install_dir }}",
        "{{ unifi_home_dir }}",
    ]


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


def responses(*, debian: bool = True, ufw: bool = True, installed: bool = True) -> dict[str, Any]:
    cfg = UnifiRemoveConfig()
    service = json.dumps(dict(success=True, enabled=True, active="active", load="loaded"))
    result: dict[str, Any] = {
        "import json, subprocess, sys": [service],
        "test -f /etc/debian_version": ["debian"] if debian else [],
        "command -v ufw": ["/usr/sbin/ufw"] if ufw else [],
        "packages unifi": [json.dumps(["unifi"] if installed else [])],
        "packages mongodb-org": [json.dumps(["mongodb-org", "mongodb-org-server"] if installed else [])],
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
        purge("openjdk-17-jre-headless"),
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
    for kept in ("/usr/lib/unifi\n", "/usr/lib/unifi/data", "/usr/lib/unifi/logs", "/home/unifi\n"):
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


def test_absent_packages_are_not_purged_and_a_bad_probe_stops() -> None:
    run = run_deploy_fake(remove_unifi, UnifiRemoveConfig(confirm=True), responses=responses(installed=False))
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
    cfg = UnifiRemoveConfig(confirm=True, mongodb_packages=(), java_packages=())
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


@pytest.mark.parametrize("action", ["drop-database", "drop-user"])
def test_the_script_is_the_roles_template(action: str) -> None:
    payload = {"action": action, "auth_db": "admin", "database": "unifi", "user": "unifi", "password": PASSWORD}
    template = jinja2.Environment(undefined=jinja2.StrictUndefined)
    template.filters["to_json"] = json.dumps
    task = role("tasks.yml")[10 if action == "drop-database" else 11]["block"][1]
    variables = task["vars"]
    rendered_script = template.from_string(variables["task_mongo_script"]).render(
        unifi_mongodb_database="unifi", unifi_mongodb_auth_db="admin", unifi_mongodb_user="unifi"
    )
    expected = template.from_string((PARITY / "task-mongosh.js.j2").read_text()).render(
        task_mongo_auth_db="admin",
        task_mongo_database="admin",
        task_mongo_script=rendered_script,
        unifi_mongodb_user="unifi",
        unifi_mongodb_password=PASSWORD,
    )
    # The role quotes names with '...'; the port JSON-encodes them.
    assert host_module.script(payload).replace('"', "'") == expected.replace('"', "'").rstrip("\n") + "\n"
