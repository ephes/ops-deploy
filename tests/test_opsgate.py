"""OpsGate role inputs, rendered resources and preservation boundaries."""

from __future__ import annotations

import json
import os
import plistlib
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.opsgate import OpsGateConfig, deploy_opsgate
from ops_deploy.services.opsgate.config import DEFAULTS
from ops_deploy.services.opsgate.deploy import opsgate_host_command as command
from ops_deploy.services.opsgate.render import SECRET_DEFAULTS, payload
from ops_deploy.testing import RecordingRsyncRunner, run_deploy_fake
from tests import fakehost


def configuration(tmp_path: Path, **overrides: Any) -> OpsGateConfig:
    return OpsGateConfig(opsgate_source_path=str(tmp_path), **overrides)


def credentials() -> dict[str, Any]:
    return {
        "opsgate_session_secret": "synthetic-session-value-for-owned-fixture",
        "opsgate_ui_password_bcrypt": "$2b$12$synthetic-owned-fixture",
        "opsgate_submit_token_nyxmon": "synthetic-nyxmon-value-for-owned-fixture",
        "opsgate_submit_token_operator": "synthetic-operator-value-for-owned-fixture",
        "opsgate_runner_token": "synthetic-runner-value-for-owned-fixture",
    }


def test_original_default_references_are_typed_and_resolved(tmp_path: Path) -> None:
    cfg = configuration(tmp_path)
    assert cfg.opsgate_runner_launchd_manage_state is False
    assert cfg.opsgate_runner_environment["HOME"] == "/Users/ops"
    assert (
        cfg.opsgate_api_program_arguments[-1]
        == "cd /Users/control_service_user/opsgate && .venv/bin/python -m opsgate serve"
    )
    assert cfg.opsgate_ops_workspace_repositories[0].version == "main"
    assert not set(DEFAULTS) & set(SECRET_DEFAULTS)
    assert "CHANGEME" not in cfg.model_dump_json()


def test_explicit_account_paths_propagate_to_derived_resources(tmp_path: Path) -> None:
    cfg = configuration(
        tmp_path, ops_user="fixture_ops", ops_home_dir="/Users/fixture_ops", opsgate_launchd_manage_state=True
    )
    assert cfg.ops_group == "fixture_ops"
    assert cfg.opsgate_runner_app_dir == "/Users/fixture_ops/opsgate"
    assert cfg.opsgate_runner_environment["HOME"] == "/Users/fixture_ops"
    assert cfg.opsgate_runner_launchd_manage_state is True


@pytest.mark.parametrize(
    "overrides",
    [
        {"ops_user": "control_service_user"},
        {"opsgate_service_name": "other"},
        {"opsgate_api_bind_port": 0},
        {"opsgate_api_impl": "rust"},
        {"opsgate_rust_version": "latest"},
        {"opsgate_rust_keep_versions": 0},
        {"opsgate_config_dir": "/etc/../outside"},
        {"ops_user": "has space"},
        {"opsgate_launchd_python_plist_dir": "/Library/LaunchDaemons"},
    ],
)
def test_invalid_inputs_fail_on_controller(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        configuration(tmp_path, **overrides)


def test_python_and_rust_selection_keep_separate_rollback_plists(tmp_path: Path) -> None:
    cfg = configuration(tmp_path, opsgate_api_impl="rust", opsgate_rust_version="0.3.0", opsgate_rust_sha256="a" * 64)
    data = payload(cfg, credentials())
    active = plistlib.loads(data["contents"][cfg.opsgate_api_launchd_plist_path]["content"].encode())
    rollback_path = cfg.opsgate_launchd_python_plist_dir + "/" + cfg.opsgate_api_launchd_label + ".plist"
    rollback = plistlib.loads(data["contents"][rollback_path]["content"].encode())
    assert "exec /usr/local/libexec/opsgate-rs/0.3.0/opsgate serve" in active["ProgramArguments"][-1]
    assert rollback["ProgramArguments"][-1].endswith(".venv/bin/python -m opsgate serve")
    assert active["UserName"] == "control_service_user"
    assert active["GroupName"] == "control_service_user"
    assert "/rust/" in cfg.opsgate_rsync_excludes


def test_deploy_keys_replace_only_unused_account_key(tmp_path: Path) -> None:
    cfg = configuration(tmp_path, opsgate_ops_manage_workspace_repos=True)
    values = credentials()
    values["opsgate_ops_github_deploy_keys"] = {
        name: {"private_key": "synthetic-private-for-owned-fixture", "public_key": "ssh-ed25519 synthetic-public"}
        for name in ["ops-control", "ops-library"]
    }
    data = payload(cfg, values)
    assert set(data["remove"]) == {
        cfg.opsgate_ops_github_ssh_private_key_path,
        cfg.opsgate_ops_github_ssh_public_key_path,
    }
    text = data["contents"][cfg.opsgate_ops_ssh_config_path]["content"]
    assert "Host github-ops-control\n" in text
    assert "Host github.com\n" not in text
    assert "opsgate_ops_github_deploy_keys" not in data
    assert data["deploy_key_names"] == ["ops-control", "ops-library"]


def test_invalid_credentials_never_disclose_values(tmp_path: Path) -> None:
    values = credentials()
    synthetic = "short-sensitive-fixture"
    values["opsgate_ui_password_bcrypt"] = synthetic
    with pytest.raises(ValueError, match="bcrypt credential is incomplete") as error:
        payload(configuration(tmp_path), values)
    assert synthetic not in str(error.value)


def role_oracle(relative: str) -> Path:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("OPS_LIBRARY_PATH unset; paired role oracle parity is run explicitly")
    return Path(source) / "roles/opsgate_deploy" / relative


def test_templates_are_exact_authoritative_role_resources() -> None:
    role = role_oracle("templates")
    assert role.is_dir()
    packaged = files("ops_deploy.services.opsgate").joinpath("templates")
    for path in role.iterdir():
        assert packaged.joinpath(path.name).read_bytes() == path.read_bytes()


def test_default_resource_manifest_matches_role_variables() -> None:
    role = role_oracle("defaults/main.yml")
    import yaml

    expected = yaml.safe_load(role.read_text())
    assert json.loads(files("ops_deploy.services.opsgate").joinpath("defaults.json").read_text()) == {
        key: value for key, value in expected.items() if key not in SECRET_DEFAULTS
    }


def test_current_native_deploy_does_not_sync_stage_or_send_secrets(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname="opsgate"\nversion="0.2.0"\n')
    cfg = configuration(tmp_path)
    data = payload(cfg, credentials())
    data["project_version"] = "0.2.0"
    responses = {
        command(data, action): ["current"]
        for action in ["prepare-status", "runtime-status-api", "runtime-status-runner", "config-status"]
    }
    responses.update(fakehost.directory(cfg.opsgate_app_dir))
    responses.update(fakehost.directory(cfg.opsgate_runner_app_dir))
    rsync = RecordingRsyncRunner()
    result = run_deploy_fake(deploy_opsgate, cfg, credentials(), responses=responses, rsync=rsync)
    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []
    assert result.stdin == []
    assert len(rsync.calls) == 2
    assert all("--dry-run" in argv for argv in rsync.calls)
    # The editable rollback install's build metadata is retained, not deleted.
    assert all("--exclude=*.egg-info" in argv and "--delete" in argv for argv in rsync.calls)
    for value in credentials().values():
        assert value not in "\n".join(result.executed_commands)


def test_fresh_native_deploy_preserves_preparation_source_runtime_order(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname="opsgate"\nversion="0.2.0"\n')
    rsync = RecordingRsyncRunner()
    result = run_deploy_fake(deploy_opsgate, configuration(tmp_path), credentials(), rsync=rsync)
    assert result.succeeded, result.error
    operations = "\n".join(result.mutating_changed_ops)
    assert operations.index("Prepare native") < operations.index("Sync OpsGate api application")
    assert operations.index("Remember pending api") < operations.index("Sync OpsGate api application")
    assert operations.index("Sync OpsGate api application") < operations.index("api Python rollback")
    assert operations.index("runner Python rollback") < operations.index("Converge native OpsGate")
    assert all("--dry-run" not in argv for argv in rsync.calls)
    assert len(result.stdin) == 1
    for value in credentials().values():
        assert value not in "\n".join(result.executed_commands)
