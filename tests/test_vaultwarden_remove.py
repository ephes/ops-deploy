"""The vaultwarden_remove port as the playbook runs it; synthetic packages, sources and units only."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services.vaultwarden import VaultwardenRemoveConfig, remove_vaultwarden
from ops_deploy.services.vaultwarden.remove import REPO_URL, REPOSITORY, ROUTE, UNIT_PATHS, _repository
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

PARITY = Path(__file__).parent / "parity/vaultwarden/remove"
KEYRING = "/etc/apt/keyrings/vaultwarden-deb-repo-keyring.gpg"
DROPIN = "/etc/systemd/system/vaultwarden.service.d"
PURGE = (
    "env DEBIAN_FRONTEND=noninteractive apt-get -q -y -o DPkg::Lock::Timeout=60 "
    "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --purge remove -- "
)


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
    cfg = VaultwardenRemoveConfig()
    assert cfg.confirm is defaults["vaultwarden_confirm_removal"] is False
    for field in ("config", "repository", "traefik"):
        assert getattr(cfg, "remove_" + field) is defaults["vaultwarden_remove_" + field]
    # Data removal is the playbook's opt-in -e remove_data=true; not offered.
    assert defaults["vaultwarden_remove_data"] is False
    assert "remove_data" not in VaultwardenRemoveConfig.model_fields


def test_role_task_order_and_paths_are_the_ported_ones() -> None:
    tasks = role("tasks.yml")
    assert [task["name"] for task in tasks] == [
        "Confirm removal is intentional",
        "Check for Vaultwarden systemd unit",
        "Stop and disable Vaultwarden service",
        "Remove Vaultwarden packages",
        "Remove systemd override directory",
        "Reload systemd",
        "Remove Traefik configuration",
        "Determine apt repo codename (Ubuntu uses bookworm)",
        "Remove apt repository",
        "Remove apt repository GPG key",
        "Remove configuration file",
        "Backup data before removal (if removing data)",
        "Remove Vaultwarden data directory",
        "Remove Vaultwarden log directory",
        "Display removal summary",
    ]
    assert tasks[1]["loop"] == list(UNIT_PATHS)
    assert tasks[2]["ignore_errors"] is True
    assert tasks[3]["ansible.builtin.apt"]["name"] == ["vaultwarden", "vaultwarden-web-vault"]
    assert tasks[3]["ansible.builtin.apt"]["purge"] == "{{ vaultwarden_remove_config }}"
    assert tasks[4]["ansible.builtin.file"]["path"] == DROPIN
    assert tasks[6]["ansible.builtin.file"]["path"] == ROUTE
    assert tasks[8]["ansible.builtin.apt_repository"]["repo"] == (
        f"deb [signed-by={KEYRING}] {REPO_URL} {{{{ _vaultwarden_repo_codename }}}} main"
    )
    assert tasks[9]["ansible.builtin.file"]["path"] == KEYRING
    assert tasks[10]["ansible.builtin.file"]["path"] == "/etc/vaultwarden.env"
    assert all(task["when"] == "vaultwarden_remove_data | bool" for task in tasks[11:14])
    # The handler restarts Traefik (not ported).
    assert role("handlers.yml") == [
        {
            "name": "reload traefik",
            "ansible.builtin.systemd": {"name": "traefik", "state": "restarted"},
            "failed_when": False,
        }
    ]


def test_confirmation_precedes_every_target_probe() -> None:
    run = run_deploy_fake(remove_vaultwarden, VaultwardenRemoveConfig())
    assert not run.succeeded
    assert "not confirmed" in str(run.error)
    assert not run.events
    assert not run.ops


def host(*, present: bool = True, packages: str = "installed", repo: str = "present") -> dict[str, Any]:
    paths: dict[str, Any] = {}
    if present:
        for path in (ROUTE, KEYRING, "/etc/vaultwarden.env"):
            paths.update(fakehost.file(path, "x"))
        paths.update(fakehost.directory(DROPIN))
    probe = {"success": True, "enabled": present, "active": "active" if present else "inactive"}
    probe["load"] = "loaded" if present else "not-found"
    return {
        **fakehost.LINUX,
        "test -L /etc/systemd/system/vaultwarden.service; } && echo": [UNIT_PATHS[2]] if present else [],
        "names = sys.argv[1:]\nresult": [
            json.dumps([] if packages == "not-installed" else ["vaultwarden", "vaultwarden-web-vault"]),
        ],
        "import json, subprocess, sys\ntry": [json.dumps(probe)],
        _repository("inspect"): [repo],
        **paths,
    }


def without_probes(commands: list[str]) -> list[str]:
    return [command for command in commands if "import json, subprocess" not in command]


def test_the_playbooks_removal_follows_the_role_order_and_keeps_the_data() -> None:
    run = run_deploy_fake(remove_vaultwarden, VaultwardenRemoveConfig(confirm=True), responses=host())
    assert run.succeeded, run.error
    assert without_probes(run.executed_commands) == [
        "systemctl disable vaultwarden",
        "systemctl stop vaultwarden",
        PURGE + "vaultwarden vaultwarden-web-vault",
        f"rm -rf {DROPIN}",
        "systemctl daemon-reload",
        route_guard_command(),
        f"rm -rf {ROUTE}",
        _repository("apply"),
        "apt-get -o DPkg::Lock::Timeout=60 update",
        f"rm -rf {KEYRING}",
        "rm -rf /etc/vaultwarden.env",
    ]
    commands = "\n".join(run.executed_commands)
    assert "/var/lib/vaultwarden" not in commands
    assert "/var/log/vaultwarden" not in commands
    assert not any(command.startswith("tar ") for command in run.executed_commands)
    assert "/root/vaultwarden-backup" not in commands
    assert not any("systemctl" in command and "traefik" in command for command in run.executed_commands)


def test_without_a_unit_file_the_service_is_not_touched() -> None:
    responses = host()
    responses["test -L /etc/systemd/system/vaultwarden.service; } && echo"] = []
    run = run_deploy_fake(remove_vaultwarden, VaultwardenRemoveConfig(confirm=True), responses=responses)
    assert run.succeeded, run.error
    assert not any(command.startswith("systemctl disable") for command in run.executed_commands)
    assert not any("import json, subprocess, sys\ntry" in command for command in run.executed_commands)


def test_config_files_left_by_a_removal_are_purged_and_kept_without_remove_config() -> None:
    run = run_deploy_fake(
        remove_vaultwarden, VaultwardenRemoveConfig(confirm=True), responses=host(packages="config-files")
    )
    assert run.succeeded, run.error
    assert PURGE + "vaultwarden vaultwarden-web-vault" in run.executed_commands
    kept = run_deploy_fake(
        remove_vaultwarden,
        VaultwardenRemoveConfig(confirm=True, remove_config=False),
        responses=host(packages="config-files"),
    )
    assert kept.succeeded, kept.error
    # purge: false removes only installed packages; config-files ones stay.
    assert not any("--purge" in command for command in kept.executed_commands)
    assert "rm -rf /etc/vaultwarden.env" not in kept.executed_commands


def test_a_removed_install_changes_only_the_unconditional_reload() -> None:
    run = run_deploy_fake(
        remove_vaultwarden,
        VaultwardenRemoveConfig(confirm=True),
        responses=host(present=False, packages="not-installed", repo="absent"),
    )
    assert run.succeeded, run.error
    assert without_probes(run.executed_commands) == ["systemctl daemon-reload"]


def test_unreadable_package_state_stops_the_removal() -> None:
    responses = host()
    responses["names = sys.argv[1:]\nresult"] = ["", "ops-deploy-probe-failed"]
    run = run_deploy_fake(remove_vaultwarden, VaultwardenRemoveConfig(confirm=True), responses=responses)
    assert not run.succeeded
    assert not any("apt-get" in command for command in run.executed_commands)


def repository(tmp_path: Path, action: str, os_release: str, sources: dict[str, str]) -> str:
    """Runs the host script against a temporary root by rewriting its absolute paths."""

    (tmp_path / "etc/apt/sources.list.d").mkdir(parents=True, exist_ok=True)
    (tmp_path / "etc/os-release").write_text(os_release)
    for name, body in sources.items():
        (tmp_path / "etc/apt" / name).write_text(body)
    script = REPOSITORY.replace("'/etc/", f"'{tmp_path}/etc/")
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script, action, KEYRING, REPO_URL],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    return result.stdout.strip()


UBUNTU = "ID=ubuntu\nVERSION_CODENAME=noble\n"
LINE = f"deb [signed-by={KEYRING}] {REPO_URL} bookworm main\n"


def test_enabled_repository_lines_go_from_every_list_and_empty_files_are_deleted(tmp_path: Path) -> None:
    sources = {
        "sources.list.d/vaultwarden.list": LINE,
        "sources.list": "deb http://archive.ubuntu.com/ubuntu noble main\n"
        + LINE.replace(" main", "  main  # old")
        + "# "
        + LINE,
        "sources.list.d/disabled.list": "# " + LINE,
        "sources.list.d/other.sources": LINE,
    }
    assert repository(tmp_path, "inspect", UBUNTU, sources) == "present"
    assert repository(tmp_path, "apply", UBUNTU, sources) == "removed"
    assert not (tmp_path / "etc/apt/sources.list.d/vaultwarden.list").exists()
    # The enabled copy (extra spaces, a trailing comment) goes, the commented one stays.
    assert (tmp_path / "etc/apt/sources.list").read_text() == (
        "deb http://archive.ubuntu.com/ubuntu noble main\n# " + LINE
    )
    assert (tmp_path / "etc/apt/sources.list.d/disabled.list").read_text() == "# " + LINE
    # Only .list files are sources for the module.
    assert (tmp_path / "etc/apt/sources.list.d/other.sources").read_text() == LINE
    assert repository(tmp_path, "apply", UBUNTU, {}) == "absent"


def test_repository_suite_is_the_release_codename_off_ubuntu(tmp_path: Path) -> None:
    sources = {"sources.list.d/vaultwarden.list": LINE.replace("bookworm", "trixie")}
    assert repository(tmp_path, "inspect", "ID=debian\nVERSION_CODENAME=trixie\n", sources) == "present"
    assert repository(tmp_path, "inspect", UBUNTU, sources) == "absent"
