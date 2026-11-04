"""The ollama_remove port (macOS); synthetic launchd, directory, account and Homebrew state only."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from ops_deploy.services.ollama import OllamaRemoveConfig, remove_ollama
from ops_deploy.testing import run_deploy_fake

PARITY = Path(__file__).parent / "parity/ollama/remove"
PLIST = "/Library/LaunchDaemons/com.ollama.ollama.plist"
BREW = "cd / && /usr/bin/sudo -H -u jochen -- /usr/bin/env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1"
# What just remove-one ollama passes, with the macstudio inventory.
RECIPE = {
    "remove_data": True,
    "remove_logs": True,
    "remove_user": True,
    "remove_brew_package": True,
    "service_user": "vibe",
    "service_group": "vibe",
    "service_home": "/opt/llm",
    "models_dir": "/opt/llm/models",
    "log_dir": "/var/log/ollama",
    "brew_user": "jochen",
}


def role(name: str) -> Any:
    return yaml.safe_load((PARITY / name).read_text())


def confirmed(**values: Any) -> OllamaRemoveConfig:
    return OllamaRemoveConfig(confirm=True, **{**RECIPE, **values})


def present(path: str) -> str:
    return f"{{ test -e {path} || test -L {path}; }} && echo yes"


def directory(path: str) -> dict[str, Any]:
    line = f"user=root group=wheel mode=drwxr-xr-x atime=0 mtime=0 ctime=0 size=10 '{path}'"
    # First match wins: the presence probe before the stat fact it contains.
    return {present(path): ["yes"], f"test -e {path} ||": [line]}


def host(
    *paths: str,
    os_name: str = "Darwin",
    account: bool = True,
    formulae: str = "listed\nffmpeg\nollama",
    brews: tuple[str, ...] = ("/opt/homebrew/bin/brew",),
) -> dict[str, Any]:
    responses: dict[str, Any] = {
        "uname -s": [os_name],
        "id -un": ["root"],
        "/usr/bin/dscl . -read": ["present" if account else "absent"],
        "grp.getgrnam": ["present" if account else "absent"],
        "list --formula -1": formulae.splitlines(),
        "list --cask -1": ["listed"],
    }
    for path in (*paths, *brews):
        responses.update(directory(path))
    return responses


def test_fixtures_are_the_recorded_role_files() -> None:
    manifest = json.loads((PARITY / "source.json").read_text())
    for name, entry in manifest["files"].items():
        body = (PARITY / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == entry["sha256"]
        if os.environ.get("OPS_LIBRARY_PATH"):
            assert body == (Path(os.environ["OPS_LIBRARY_PATH"]) / entry["source"]).read_bytes()


def test_defaults_are_the_roles() -> None:
    defaults = role("defaults.yml")
    cfg = OllamaRemoveConfig()
    assert cfg.launchd_label == defaults["ollama_launchd_label"]
    assert defaults["ollama_launchd_plist_path"] == "/Library/LaunchDaemons/{{ ollama_launchd_label }}.plist"
    assert cfg.launchd_plist_path == PLIST
    assert OllamaRemoveConfig(launchd_label="x.y").launchd_plist_path == "/Library/LaunchDaemons/x.y.plist"
    for field in ("service_user", "service_group", "service_home", "models_dir", "log_dir", "brew_package"):
        assert getattr(cfg, field) == defaults["ollama_" + field]
    assert defaults["ollama_brew_user"] == defaults["ollama_brew_bin"] == ""
    assert cfg.brew_user is None
    assert cfg.brew_bin is None
    for flag in ("data", "logs", "user", "brew_package"):
        assert getattr(cfg, "remove_" + flag) is defaults["ollama_remove_" + flag] is False


def test_role_task_order_is_the_ported_one() -> None:
    tasks = role("tasks.yml")
    names = [task["name"] for task in tasks]
    assert names == [
        "Validate macOS target",
        "Validate required variables",
        "Validate Homebrew user when running as root",
        "Resolve Homebrew path when not provided",
        "Use provided Homebrew binary path",
        "Validate Homebrew binary path",
        "Stop and unload launchd service",
        "Remove launchd plist",
        "Remove Ollama model data directory",
        "Remove Ollama log directory",
        "Remove Ollama service user",
        "Remove Ollama service group",
        "Uninstall Ollama Homebrew package",
        "Display removal summary",
    ]
    bootout = tasks[6]
    assert bootout["ansible.builtin.command"] == "launchctl bootout system {{ ollama_launchd_plist_path }}"
    assert (bootout["failed_when"], bootout["changed_when"]) == (False, False)
    assert tasks[10]["ansible.builtin.user"] == {
        "name": "{{ ollama_service_user }}",
        "state": "absent",
        "remove": False,
    }
    assert tasks[12]["community.general.homebrew"]["state"] == "absent"
    assert [
        path["path"]
        for path in (tasks[3]["block"][0]["ansible.builtin.stat"], tasks[3]["block"][1]["ansible.builtin.stat"])
    ] == [
        "/opt/homebrew/bin/brew",
        "/usr/local/bin/brew",
    ]


def test_confirmation_precedes_every_probe() -> None:
    run = run_deploy_fake(remove_ollama, OllamaRemoveConfig(**RECIPE))
    assert not run.succeeded
    assert "confirm" in str(run.error)
    assert not run.events
    assert not run.ops


@pytest.mark.parametrize(
    "values", [{"models_dir": "/"}, {"log_dir": "/var"}, {"service_home": "/opt/../x"}, {"service_user": "root"}]
)
def test_unsafe_targets_are_refused(values: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"removal paths|root cannot|pattern"):
        confirmed(**values)


def test_the_recipes_full_wipe_follows_the_role_order() -> None:
    run = run_deploy_fake(remove_ollama, confirmed(), responses=host(PLIST, "/opt/llm/models", "/var/log/ollama"))
    assert run.succeeded, run.error
    assert run.executed_commands == [
        f"/bin/launchctl bootout system {PLIST} || true",
        f"rm -rf {PLIST}",
        "rm -rf /opt/llm/models",
        "rm -rf /var/log/ollama",
        "/usr/bin/dscl . -delete /Users/vibe",
        "/usr/sbin/dseditgroup -o delete -L vibe",
        f"{BREW} /opt/homebrew/bin/brew uninstall --force ollama",
    ]


def test_role_defaults_only_unload_and_delete_the_plist() -> None:
    run = run_deploy_fake(remove_ollama, OllamaRemoveConfig(confirm=True), responses=host(PLIST))
    assert run.succeeded, run.error
    assert run.executed_commands == [f"/bin/launchctl bootout system {PLIST} || true", f"rm -rf {PLIST}"]


def test_a_removed_host_changes_nothing() -> None:
    run = run_deploy_fake(remove_ollama, confirmed(), responses=host(account=False, formulae="listed\nollama-tools"))
    assert run.succeeded, run.error
    assert run.executed_commands == []


def test_homebrew_resolution_and_explicit_binary() -> None:
    run = run_deploy_fake(remove_ollama, confirmed(), responses=host(account=False, brews=("/usr/local/bin/brew",)))
    assert run.succeeded, run.error
    assert run.executed_commands == [f"{BREW} /usr/local/bin/brew uninstall --force ollama"]
    run = run_deploy_fake(remove_ollama, confirmed(brew_bin="/opt/tools/brew"), responses=host(account=False, brews=()))
    assert run.succeeded, run.error
    assert run.executed_commands == [f"{BREW} /opt/tools/brew uninstall --force ollama"]


@pytest.mark.parametrize(
    ("values", "responses", "message"),
    [
        ({}, {"os_name": "Linux"}, "only supports macOS"),
        ({"brew_user": None}, {}, "brew_user must be set"),
        ({}, {"brews": ()}, "Homebrew binary not found"),
    ],
)
def test_validation_refuses_before_any_change(values: dict[str, Any], responses: dict[str, Any], message: str) -> None:
    run = run_deploy_fake(remove_ollama, confirmed(**values), responses=host(PLIST, **responses))
    assert not run.succeeded
    assert message in str(run.error)
    assert run.executed_commands == []


def test_without_the_brew_flag_neither_brew_user_nor_homebrew_is_needed() -> None:
    cfg = confirmed(brew_user=None, remove_brew_package=False)
    run = run_deploy_fake(remove_ollama, cfg, responses=host(account=False, brews=()))
    assert run.succeeded, run.error
    assert run.executed_commands == []


def test_an_unreadable_homebrew_state_fails() -> None:
    # A failing sudo or brew is an error, never "not installed".
    run = run_deploy_fake(remove_ollama, confirmed(), responses=host(account=False, formulae="error"))
    assert not run.succeeded
    assert "uninstall" not in "\n".join(run.executed_commands)


def test_a_cask_is_uninstalled_too() -> None:
    responses = {**host(account=False, formulae="listed"), "list --cask -1": ["listed", "ollama"]}
    run = run_deploy_fake(remove_ollama, confirmed(), responses=responses)
    assert run.succeeded, run.error
    assert run.executed_commands == [f"{BREW} /opt/homebrew/bin/brew uninstall --force ollama"]


def test_an_unreadable_group_state_fails() -> None:
    responses = {**host(), "grp.getgrnam": ["error"]}
    run = run_deploy_fake(remove_ollama, confirmed(), responses=responses)
    assert not run.succeeded
    assert "dseditgroup" not in "\n".join(run.executed_commands)
