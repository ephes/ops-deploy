"""Role parity and retained-state/no-restart behavior for native macOS Ollama."""

from __future__ import annotations

import importlib.util
import os
import plistlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import jinja2
import pytest

from ops_deploy.core.config import ConfigValidationError
from ops_deploy.services.ollama import OllamaConfig, deploy_ollama
from ops_deploy.services.ollama.deploy import render_plist, template_vars
from ops_deploy.testing import run_deploy_fake

ROOT = Path(__file__).parents[1]
TEMPLATE = ROOT / "tests/parity/ansible/ollama_install__ollama.launchd.plist.j2"


def host_script() -> Any:
    spec = importlib.util.spec_from_file_location(
        "ollama_host_test", ROOT / "src/ops_deploy/services/ollama/files/ollama_host.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("custom", [False, True])
def test_exact_role_plist_parity(custom: bool) -> None:
    cfg = OllamaConfig(
        user="vibe" if custom else "ollama",
        group="vibe" if custom else "ollama",
        site_path=Path("/opt/llm") if custom else Path("/usr/local/var/ollama"),
        models_dir=Path("/opt/llm/models") if custom else Path("/usr/local/var/ollama/models"),
        log_dir=Path("/var/log/ollama") if custom else Path("/usr/local/var/ollama/logs"),
        launchd_command_args=("--fixture", "argument with spaces") if custom else (),
    )
    environment = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)
    expected = environment.from_string(TEMPLATE.read_text()).render(**template_vars(cfg, "/opt/homebrew/bin/ollama"))
    assert render_plist(cfg, "/opt/homebrew/bin/ollama") == expected


def test_vendored_role_template() -> None:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("OPS_LIBRARY_PATH not set; vendored template check only")
    assert (
        TEMPLATE.read_bytes() == (Path(source) / "roles/ollama_install/templates/ollama.launchd.plist.j2").read_bytes()
    )


def test_xml_arguments_and_environment_are_valid_not_interpreted() -> None:
    cfg = OllamaConfig(env={"A&B": '<literal>&"'}, launchd_command_args=("<x>&",))
    parsed = plistlib.loads(render_plist(cfg, "/path with &/ollama").encode())
    assert parsed["EnvironmentVariables"] == cfg.env
    assert parsed["ProgramArguments"] == ["/path with &/ollama", "serve", "<x>&"]


@pytest.mark.parametrize(
    "changes",
    [
        {"models_dir": "/"},
        {"log_dir": "/a/../b"},
        {"brew_user": "bad user"},
        {"launchd_label": "a/b"},
        {"env": {"A\nB": "x"}},
    ],
)
def test_invalid_config_rejected_before_host_access(changes: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        OllamaConfig(**changes)


def test_disabled_deploy_has_no_operations() -> None:
    run = run_deploy_fake(deploy_ollama, OllamaConfig(enabled=False))
    assert run.succeeded
    assert run.ops == []
    assert run.fact_commands == []


def test_converged_deploy_has_zero_mutations_uploads_or_staging() -> None:
    run = run_deploy_fake(deploy_ollama, OllamaConfig(brew_user="owner"), responses={" status ": ["current"]})
    assert run.succeeded
    assert run.mutating_changed_ops == []
    assert run.uploads == []
    assert len(run.executed_commands) == 1
    assert " verify " in run.executed_commands[0]


def test_failed_apply_stops_before_readiness() -> None:
    run = run_deploy_fake(
        deploy_ollama,
        OllamaConfig(brew_user="owner"),
        responses={" status ": ["changed"], " apply ": {"success": False, "stderr": "owned fault"}},
    )
    assert not run.succeeded
    assert not any(" verify " in command for command in run.executed_commands)


def test_directory_repair_never_changes_retained_children(tmp_path: Path) -> None:
    module = host_script()
    model = tmp_path / "models"
    model.mkdir(mode=0o755)
    child = model / "retained.bin"
    child.write_bytes(b"owned fixture bytes")
    child.chmod(0o640)
    before = child.stat()
    cfg = OllamaConfig(site_path=tmp_path, models_dir=model, log_dir=tmp_path / "logs", manage_user=False).model_dump(
        mode="json"
    )
    records = {"Users": {"UniqueID": str(os.getuid())}, "Groups": {"PrimaryGroupID": str(os.getgid())}}
    with patch.object(module, "record", side_effect=lambda kind, name: records[kind]):
        assert not module.directories(cfg)
        module.directories(cfg, apply=True)
        assert module.directories(cfg)
    assert child.read_bytes() == b"owned fixture bytes"
    after = child.stat()
    assert (after.st_ino, after.st_mtime_ns, after.st_mode, after.st_uid, after.st_gid) == (
        before.st_ino,
        before.st_mtime_ns,
        before.st_mode,
        before.st_uid,
        before.st_gid,
    )


@pytest.fixture
def converged_host() -> Any:
    module = host_script()
    with (
        patch.object(module, "installed", return_value=True),
        patch.object(module, "brew_job", return_value=False),
        patch.object(module, "ensure_identity"),
        patch.object(module, "directories", return_value=False),
        patch.object(module, "plist_current", return_value=True),
        patch.object(module, "launchd", return_value=(True, True)),
        patch.object(module, "foreign_processes", return_value=[]),
        patch.object(module.os, "access", return_value=True),
        patch.object(module, "brew") as brew,
        patch.object(module, "run") as run,
    ):
        yield module, brew, run


def test_metadata_only_repair_preserves_running_version_and_pid(converged_host: Any) -> None:
    module, brew, run = converged_host
    cfg = OllamaConfig(brew_user="owner").model_dump(mode="json")
    cfg["resolved_binary"] = "/installed/newer/ollama"
    module.apply(cfg)
    brew.assert_not_called()
    run.assert_not_called()
    module.directories.assert_called_once_with(cfg, apply=True)


def test_stopped_job_recovery_does_not_reinstall_or_replace_plist(converged_host: Any) -> None:
    module, brew, run = converged_host
    cfg = OllamaConfig(brew_user="owner").model_dump(mode="json")
    cfg["resolved_binary"] = "/installed/ollama"
    module.launchd.return_value = (True, False)
    module.apply(cfg)
    brew.assert_not_called()
    run.assert_called_once_with(["/bin/launchctl", "kickstart", "-k", "system/com.ollama.ollama"])


def test_changed_plist_reloads_only_its_system_label(converged_host: Any) -> None:
    module, brew, run = converged_host
    cfg = OllamaConfig(brew_user="owner", launchd_label="com.example.owned-ollama").model_dump(mode="json")
    cfg["resolved_binary"] = "/installed/ollama"
    module.plist_current.return_value = False
    with patch.object(module, "publish_plist") as publish, patch.object(module, "unload") as unload:
        module.apply(cfg)
    unload.assert_called_once_with(cfg)
    publish.assert_called_once_with(cfg)
    assert [call.args[0][1] for call in run.call_args_list] == ["bootstrap", "enable", "kickstart"]
    brew.assert_not_called()


def test_unload_waits_for_in_progress_job_before_returning() -> None:
    module = host_script()
    cfg = OllamaConfig(brew_user="owner").model_dump(mode="json")
    with (
        patch.object(module, "run", return_value=SimpleNamespace(returncode=36)) as run,
        patch.object(module, "launchd", side_effect=[(True, False), (True, False), (False, False)]) as state,
        patch.object(module.time, "sleep") as sleep,
    ):
        module.unload(cfg)
    run.assert_called_once_with(["/bin/launchctl", "bootout", "system/com.ollama.ollama"], check=False)
    assert state.call_count == 3
    assert sleep.call_count == 2


def test_failed_unload_preserves_old_plist_and_never_bootstraps(converged_host: Any) -> None:
    module, _brew, run = converged_host
    cfg = OllamaConfig(brew_user="owner").model_dump(mode="json")
    cfg["resolved_binary"] = "/installed/ollama"
    module.plist_current.return_value = False
    with (
        patch.object(module, "unload", side_effect=RuntimeError("owned unload fault")),
        patch.object(module, "publish_plist") as publish,
        pytest.raises(RuntimeError, match="owned unload fault"),
    ):
        module.apply(cfg)
    publish.assert_not_called()
    run.assert_not_called()


def test_incomplete_managed_user_gets_missing_uid_and_keeps_existing_ids() -> None:
    module = host_script()
    cfg = OllamaConfig(user="fixture", group="fixture", brew_user="owner").model_dump(mode="json")
    user = {"NFSHomeDirectory": cfg["site_path"], "PrimaryGroupID": "550", "IsHidden": "1"}
    group = {"PrimaryGroupID": "550"}
    with (
        patch.object(module, "record", side_effect=lambda kind, name: user if kind == "Users" else group),
        patch.object(module, "next_id", return_value=443),
        patch.object(module, "hidden_users", return_value=[]),
        patch.object(module, "run") as run,
    ):
        assert not module.identity_current(cfg)
        assert not module.directories(cfg)
        module.ensure_identity(cfg)
    calls = [call.args[0] for call in run.call_args_list]
    assert calls == [
        [
            "/usr/bin/defaults",
            "write",
            "/Library/Preferences/com.apple.loginwindow.plist",
            "HiddenUsersList",
            "-array-add",
            "fixture",
        ],
        ["/usr/bin/dscl", ".", "-create", "/Users/fixture", "UniqueID", "443"],
    ]


def test_missing_package_installs_without_upgrade(converged_host: Any) -> None:
    module, brew, _run = converged_host
    cfg = OllamaConfig(brew_user="owner").model_dump(mode="json")
    cfg["resolved_binary"] = "/installed/ollama"
    module.installed.return_value = False
    module.apply(cfg)
    brew.assert_called_once_with(cfg, "install", "ollama")


def test_darwin_and_brew_owner_fail_before_commands() -> None:
    module = host_script()
    with patch.object(module.platform, "system", return_value="Linux"), patch.object(module, "run") as run:
        with pytest.raises(RuntimeError, match="Darwin"):
            module.prepare(OllamaConfig().model_dump(mode="json"))
        run.assert_not_called()


def test_existing_hidden_account_preserves_legacy_loginwindow_preferences() -> None:
    module = host_script()
    cfg = OllamaConfig(user="vibe", group="vibe", site_path=Path("/opt/llm")).model_dump(mode="json")
    records = {
        "Users": {"UniqueID": "442", "PrimaryGroupID": "501", "NFSHomeDirectory": "/opt/llm", "IsHidden": "1"},
        "Groups": {"PrimaryGroupID": "501"},
    }
    with (
        patch.object(module, "record", side_effect=lambda kind, name: records[kind]),
        patch.object(module, "hidden_users", side_effect=AssertionError("existing preference must be untouched")),
        patch.object(module, "run") as run,
    ):
        assert module.identity_current(cfg)
        module.ensure_identity(cfg)
        run.assert_not_called()


def test_brew_owner_switch_uses_existing_owner_home_not_root_ssh_cwd() -> None:
    module = host_script()
    cfg = OllamaConfig(brew_user="owner", brew_bin=Path("/custom/bin/brew")).model_dump(mode="json")
    with (
        patch.object(module.pwd, "getpwnam", return_value=SimpleNamespace(pw_dir="/Users/owner")),
        patch.object(module, "run") as run,
    ):
        module.brew(cfg, "list", "--versions", "ollama")
    assert run.call_args.kwargs == {"check": True, "cwd": "/Users/owner"}
    args = run.call_args.args[0]
    assert args[:6] == ["/usr/bin/sudo", "-H", "-u", "owner", "--", "/usr/bin/env"]
    assert args[-4:] == ["/custom/bin/brew", "list", "--versions", "ollama"]


def test_reused_foreign_pid_is_not_killed(converged_host: Any) -> None:
    module, _brew, run = converged_host
    cfg = OllamaConfig(brew_user="owner").model_dump(mode="json")
    cfg["resolved_binary"] = "/installed/ollama"
    module.foreign_processes.return_value = [(123, "owner old-start /path/ollama serve")]
    run.return_value = SimpleNamespace(returncode=0, stdout="owner new-start unrelated-process")
    with patch.object(module.os, "kill") as kill:
        module.apply(cfg)
    kill.assert_not_called()


def test_no_activity_heuristics_or_model_store_enumeration() -> None:
    module = host_script()
    source = Path(module.__file__).read_text()
    for forbidden in ("/api/ps", "/api/pull", "/api/generate", "rglob", "walk(", "chown -R", "brew upgrade"):
        assert forbidden not in source
