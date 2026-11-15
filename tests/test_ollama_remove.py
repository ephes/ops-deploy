"""The ollama_remove port (macOS); synthetic launchd, directory, account and Homebrew state only."""

from __future__ import annotations

from typing import Any

import pytest

from ops_deploy.services.ollama import OllamaRemoveConfig, remove_ollama
from ops_deploy.testing import run_deploy_fake

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


def test_defaults_keep_everything_but_the_service() -> None:
    cfg = OllamaRemoveConfig()
    assert cfg.launchd_label == "com.ollama.ollama"
    assert cfg.launchd_plist_path == PLIST
    assert OllamaRemoveConfig(launchd_label="x.y").launchd_plist_path == "/Library/LaunchDaemons/x.y.plist"
    assert (cfg.service_user, cfg.service_group, cfg.brew_package) == ("ollama", "ollama", "ollama")
    assert [str(cfg.service_home), str(cfg.models_dir), str(cfg.log_dir)] == [
        "/usr/local/var/ollama",
        "/usr/local/var/ollama/models",
        "/usr/local/var/ollama/logs",
    ]
    assert cfg.brew_user is None
    assert cfg.brew_bin is None
    for flag in ("data", "logs", "user", "brew_package"):
        assert getattr(cfg, "remove_" + flag) is False


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
