"""Original disabled attention declaration, actual caller and managed import."""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import shlex
from importlib.resources import files
from pathlib import Path
from typing import Any

import pyinfra.api.facts as sdk_facts
import pytest
import yaml
from pydantic import ValidationError
from pyinfra.api.util import get_file_sha1
from pyinfra.facts.files import Directory, File, Sha1File

from ops_deploy.services.daybook_voice_memo_attention import DaybookVoiceMemoAttentionConfig
from ops_deploy.services.daybook_voice_memo_attention import deploy as api
from ops_deploy.services.daybook_voice_memo_attention.config import DEFAULTS, PACKAGE
from ops_deploy.services.daybook_voice_memo_attention.render import render_plist
from ops_deploy.testing import run_deploy_fake


def config(wheel: Path, **overrides: Any) -> DaybookVoiceMemoAttentionConfig:
    return DaybookVoiceMemoAttentionConfig(
        **{
            "daybook_voice_memo_attention_service_user": "fixture",
            "daybook_voice_memo_attention_wheel_src": str(wheel),
            "daybook_voice_memo_attention_config": {
                "version": 1,
                "enabled": False,
                "profile": "synthetic",
                "state_path": "/Users/fixture/.local/state/daybook/voice-memo-attention/state.sqlite3",
                "source": {"kind": "synthetic"},
            },
            **overrides,
        }
    )


@pytest.fixture
def wheel(tmp_path: Path) -> Path:
    path = tmp_path / "daybook-0.0.0-py3-none-any.whl"
    path.write_bytes(b"OWNED inert wheel representation for controller planning only")
    return path


def test_original_disabled_plist_has_no_timer_or_activation(wheel: Path) -> None:
    cfg = config(wheel)
    parsed = plistlib.loads(render_plist(cfg).encode())
    assert parsed["Disabled"] is True
    assert parsed["RunAtLoad"] is True
    assert parsed["KeepAlive"] == {"SuccessfulExit": False}
    assert parsed["ThrottleInterval"] == 900
    assert parsed["Umask"] == 63
    assert parsed["ProgramArguments"] == [
        cfg.daybook_voice_memo_attention_venv + "/bin/python",
        "-I",
        "-m",
        "daybook.attention",
        "--config",
        cfg.daybook_voice_memo_attention_config_path,
        "serve",
    ]
    assert "StartInterval" not in parsed
    assert "StartCalendarInterval" not in parsed


@pytest.mark.parametrize(
    "override",
    [
        {"daybook_voice_memo_attention_enabled": True},
        {"daybook_voice_memo_attention_enabled": "false"},
        {"daybook_voice_memo_attention_service_user": "root"},
        {"daybook_voice_memo_attention_service_user": "CHANGEME"},
        {"daybook_voice_memo_attention_service_home": "/other"},
        {"daybook_voice_memo_attention_install_root": "/other"},
        {"daybook_voice_memo_attention_venv": "/other"},
        {"daybook_voice_memo_attention_uv_bin": "/other"},
        {"daybook_voice_memo_attention_python_install_dir": "/other"},
        {"daybook_voice_memo_attention_runtime_dir": "/other"},
        {"daybook_voice_memo_attention_config_path": "/other"},
        {"daybook_voice_memo_attention_launchd_label": "other"},
        {"daybook_voice_memo_attention_plist_path": "/other"},
        {"daybook_voice_memo_attention_wheel_src": "relative.whl"},
        {"daybook_voice_memo_attention_python_version": "3.14"},
        {"daybook_voice_memo_attention_config": {"enabled": True}},
    ],
)
def test_original_invalid_or_active_intent_refuses(wheel: Path, override: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        config(wheel, **override)


def test_actual_current_caller_keeps_application_import_managed(wheel: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        api, "observe", lambda _: dict.fromkeys(("quiescent", "directories", "wheel", "environment", "resources"), True)
    )
    result = run_deploy_fake(
        api.install_daybook_voice_memo_attention, config(wheel), responses={"uname -s": ["Darwin"]}
    )
    assert result.succeeded, result.error
    commands = [event.value for event in result.events if event.phase == "execute" and event.kind == "shell"]
    assert [shlex.split(command)[-1] for command in commands] == ["verify-import"]
    assert len(result.mutating_changed_ops) == 1
    assert result.uploaded_paths == []
    assert result.fish_unsafe_commands == []


def test_actual_caller_disabled_install_order_and_wheel_transfer(wheel: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        api,
        "observe",
        lambda _: dict.fromkeys(("quiescent", "directories", "wheel", "environment", "resources"), False),
    )
    cfg = config(wheel)
    result = run_deploy_fake(api.install_daybook_voice_memo_attention, cfg, responses={"uname -s": ["Darwin"]})
    assert result.succeeded, result.error
    commands = [event.value for event in result.events if event.phase == "execute" and event.kind == "shell"]
    actions = [shlex.split(command)[-1] for command in commands if "<attention-component>" in command]
    assert actions == ["quiesce", "directories", "environment", "verify-import", "resources"]
    assert result.uploaded_paths == [cfg.daybook_voice_memo_attention_install_root + "/" + wheel.name]
    assert not any(action in actions for action in ("serve", "discover", "baseline", "activate"))


def test_fresh_component_digest_wins_over_sdk_cached_source_filename(
    wheel: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel.write_bytes(b"OWNED prior failed wheel")
    prior = get_file_sha1(str(wheel))
    wheel.write_bytes(b"OWNED recovered wheel")
    assert hashlib.sha1(wheel.read_bytes()).hexdigest() != prior
    cfg = config(wheel)
    destination = cfg.daybook_voice_memo_attention_install_root + "/" + wheel.name
    original_fact = sdk_facts._get_fact

    def fact(
        state: Any,
        host: Any,
        cls: Any,
        args: Any = None,
        kwargs: Any = None,
        ensure_hosts: Any = None,
        apply_failed_hosts: bool = True,
    ) -> Any:
        if cls is File:
            path = (kwargs or {}).get("path")
            return {"user": "root", "group": "wheel", "mode": 644} if path == destination else None
        if cls is Directory:
            return {"user": "root", "group": "wheel", "mode": 755}
        if cls is Sha1File:
            return prior
        return original_fact(state, host, cls, args, kwargs, ensure_hosts, apply_failed_hosts)

    monkeypatch.setattr(sdk_facts, "_get_fact", fact)
    monkeypatch.setattr(
        api,
        "observe",
        lambda _: {"quiescent": True, "directories": True, "wheel": False, "environment": True, "resources": True},
    )
    result = run_deploy_fake(api.install_daybook_voice_memo_attention, cfg, responses={"uname -s": ["Darwin"]})
    assert result.succeeded, result.error
    assert result.uploaded_paths == [destination]
    assert result.uploads[0][1] == b"OWNED recovered wheel"


def test_status_command_binds_original_disabled_payload(wheel: Path) -> None:
    command = shlex.split(api.component_command("status"))
    assert command[:4] == ["/usr/bin/python3", "-I", "-B", "-c"]
    assert command[-1] == "status"
    data = api.payload(config(wheel))
    assert data["config"]["enabled"] is False
    with pytest.raises(ValueError, match="Unsupported"):
        api.component_command("activate")
    assert "daybook_voice_memo_attention_config=" not in repr(config(wheel))
    assert json.loads(json.dumps(data))["wheel_name"] == wheel.name


def test_paired_role_defaults_and_template_bytes_match() -> None:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("Paired original role oracle is run explicitly for qualification")
    role = Path(source) / "roles/daybook_voice_memo_attention_deploy"
    original = yaml.safe_load((role / "defaults/main.yml").read_text())
    original.pop("ops_library_documentation_category")
    assert original == DEFAULTS
    assert (role / "templates/attention.launchd.plist.j2").read_bytes() == files(PACKAGE).joinpath(
        "templates/attention.launchd.plist.j2"
    ).read_bytes()
