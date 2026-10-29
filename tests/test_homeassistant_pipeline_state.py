"""Owned named-storage selection, with captured original expression controls."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
import yaml
from jinja2.nativetypes import NativeEnvironment

SPEC = importlib.util.spec_from_file_location(
    "ha_owned_pipeline_state", str(files("ops_deploy.services.homeassistant").joinpath("files/pipeline_state.py"))
)
assert SPEC is not None
assert SPEC.loader is not None
state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(state)
ORIGINAL = Path(__file__).parent / "parity/homeassistant/pipelines/original.yml"


def store(root: Path, name: str, data: Any) -> Path:
    path = root / ".storage" / name
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"data": data}))
    return path


def options(root: Path) -> dict[str, Any]:
    store(
        root,
        "core.config_entries",
        {
            "entries": [
                {"domain": "other", "entry_id": "no", "data": {"host": "owned", "port": 10300}},
                {"domain": "wyoming", "entry_id": "wrong-port", "data": {"host": "owned", "port": "10300"}},
                {"domain": "wyoming", "entry_id": "first", "data": {"host": "owned", "port": 10300}},
                {"domain": "wyoming", "entry_id": "later", "data": {"host": "owned", "port": 10300}},
            ]
        },
    )
    store(
        root,
        "core.entity_registry",
        {
            "entities": [
                {"platform": "other", "config_entry_id": "first", "entity_id": "stt.unrelated"},
                {"platform": "wyoming", "config_entry_id": "first", "entity_id": "stt.first"},
                {"platform": "wyoming", "config_entry_id": "first", "entity_id": "stt.later"},
                {"platform": "wyoming", "config_entry_id": "first", "entity_id": "tts.first"},
            ]
        },
    )
    return {
        "config_path": str(root),
        "wyoming_host": "owned",
        "wyoming_port": "10300",
        "pipelines": [{"name": "Room", "language": "de"}],
    }


def test_automatic_first_exact_entry_entity_and_no_storage_writes(tmp_path: Path) -> None:
    config = options(tmp_path)
    paths = list((tmp_path / ".storage").iterdir())
    before = [(p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in paths]
    result = state.prepare_list(config)
    assert result[0]["stt_engine"] == "stt.first"
    assert result[0]["tts_engine"] == "tts.first"
    assert result[0]["stt_language"] == result[0]["tts_language"] == "de"
    assert [(p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in paths] == before
    assert "entry_id" not in json.dumps(result)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),
        (False, False),
        (1, True),
        (0, False),
        ("true", True),
        ("YES", True),
        ("on", True),
        ("1", True),
        ("false", False),
        ("off", False),
        ("0", False),
        (None, False),
        ("invalid", False),
    ],
)
def test_original_boolean_field_coercion(tmp_path: Path, value: Any, expected: bool) -> None:
    config = options(tmp_path)
    config["pipelines"][0].update(preferred=value, prefer_local_intents=value)
    result = state.prepare_list(config)[0]
    assert result["preferred"] is expected
    assert result["prefer_local_intents"] is expected


@pytest.mark.parametrize(
    "item",
    [
        {"name": "Room", "language": "de"},
        {"name": "Room", "language": "de", "conversation_engine": "auto:custom_conversation"},
        {"name": "Room", "language": "de", "conversation_engine": "auto:llama_cpp", "tts_voice": "voice"},
        {
            "name": "Room",
            "language": "de",
            "stt_engine_id": "",
            "stt_language": None,
            "wake_word_entity": None,
            "wake_word_id": "",
            "preferred": True,
            "prefer_local_intents": False,
        },
    ],
)
def test_actual_original_definition_expression(tmp_path: Path, item: dict[str, Any]) -> None:
    tasks = yaml.safe_load(ORIGINAL.read_text())
    expression = next(
        task["vars"]["_ha_assist_pipeline_definition"]
        for task in tasks
        if task["name"] == "Build desired Assist pipeline definitions"
    )
    env = NativeEnvironment()
    env.filters["bool"] = bool  # these expression controls use only actual boolean inputs
    env.filters["combine"] = lambda a, b, **_: {**a, **b}
    original = env.from_string(expression).render(
        item=item,
        _ha_custom_conversation_entity_id="conversation.custom",
        _ha_llama_cpp_entity_id="conversation.llama",
        _ha_assist_default_stt_engine_id="stt.first",
        _ha_assist_default_tts_engine_id="tts.first",
    )
    config = options(tmp_path)
    # A second undefined STT declaration enables default discovery even when the
    # first item explicitly supplies an empty engine (original list-level rule).
    config.update(
        pipelines=[item, {"name": "Second", "language": "en"}],
        custom_conversation_entity_id="conversation.custom",
        llama_cpp_entity_id="conversation.llama",
    )
    assert state.prepare_list(config)[0] == original


def test_explicit_empty_does_not_invent_automatic_discovery(tmp_path: Path) -> None:
    config = options(tmp_path)
    config["pipelines"][0].update(stt_engine_id="", tts_engine_id="")
    with pytest.raises(ValueError, match="unresolved desired"):
        state.prepare_list(config)


def test_explicit_selection_does_not_parse_unneeded_registry(tmp_path: Path) -> None:
    config = options(tmp_path)
    config["pipelines"][0].update(stt_engine_id="stt.explicit", tts_engine_id="tts.explicit")
    for p in (tmp_path / ".storage").iterdir():
        p.write_text("not JSON")
    assert state.prepare_list(config)[0]["stt_engine"] == "stt.explicit"


def test_inherited_entry_avoids_config_entries_and_canary_requirement(tmp_path: Path) -> None:
    config = options(tmp_path)
    (tmp_path / ".storage/core.config_entries").write_text("not JSON")
    config.update(wyoming_entry_id="first", llama_cpp_enabled=True)
    config["pipelines"][0]["conversation_engine"] = "auto:llama_cpp"
    with pytest.raises(ValueError, match="canary"):
        state.prepare_list(config)
    config["check_mode"] = True
    assert state.prepare_list(config)[0]["conversation_engine"] == "conversation.home_assistant"
    config.update(check_mode=False, llama_cpp_entity_id="conversation.live")
    assert state.prepare_list(config)[0]["conversation_engine"] == "conversation.live"


def voice_options(root: Path) -> dict[str, Any]:
    config = options(root)
    config.update(manage_stt=True, manage_tts=True)
    store(
        root,
        "assist_pipeline.pipelines",
        {
            "preferred_item": "selected",
            "items": [
                {
                    "id": "selected",
                    "language": "de",
                    "stt_engine": "stt.first",
                    "tts_engine": "tts.first",
                    "stt_language": "de",
                    "tts_language": "en",
                    "tts_voice": "existing",
                    "private": "never-export",
                },
                {"id": "other", "language": "fr", "private": "other-private"},
            ],
        },
    )
    return config


def test_voice_current_fallback_and_explicit_target(tmp_path: Path) -> None:
    config = voice_options(tmp_path)
    result = state.prepare_voice(config)
    assert result["pipeline_id"] == "selected"
    assert not result["needed"]
    assert result["voice"]["tts_language"] == "en"
    assert result["voice"]["tts_voice"] == "existing"
    assert "private" not in json.dumps(result)
    config.update(pipeline_id="other", manage_tts="false")
    result = state.prepare_voice(config)
    assert result["needed"]
    assert not result["manage_tts"]
    assert result["voice"]["stt_language"] == "fr"


@pytest.mark.parametrize("missing", ["core.entity_registry", "assist_pipeline.pipelines"])
def test_voice_required_storage_even_with_explicit_engine(tmp_path: Path, missing: str) -> None:
    config = voice_options(tmp_path)
    config.update(stt_engine_id="stt.explicit", tts_engine_id="tts.explicit", pipeline_id="selected")
    (tmp_path / ".storage" / missing).unlink()
    with pytest.raises(ValueError, match="unresolved"):
        state.prepare_voice(config)


def test_voice_original_target_expression_and_no_modification(tmp_path: Path) -> None:
    config = voice_options(tmp_path)
    data = json.loads((tmp_path / ".storage/assist_pipeline.pipelines").read_bytes())["data"]
    tasks = yaml.safe_load(ORIGINAL.with_name("voice.yml").read_text())
    facts = next(t["ansible.builtin.set_fact"] for t in tasks if t["name"] == "Resolve Assist pipeline target")
    env = NativeEnvironment()
    before = copy.deepcopy(data)
    selected = env.from_string(facts["_ha_assist_pipeline_target_id"]).render(
        homeassistant_assist_pipeline_id="", _ha_assist_pipeline_store=data
    )
    assert state.prepare_voice(config)["pipeline_id"] == selected
    assert data == before


def test_main_returns_fixed_error_without_private_body(tmp_path: Path) -> None:
    assert SPEC is not None
    config = options(tmp_path)
    (tmp_path / ".storage/core.entity_registry").write_text("private-malformed-body")
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(SPEC.origin)],
        input=json.dumps({"mode": "list", "options": config}),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert not result.stderr
    assert json.loads(result.stdout) == {"success": False, "error": "JSONDecodeError"}
    assert "private-malformed-body" not in result.stdout


def test_actual_controller_protects_selected_values_and_execution_context(tmp_path: Path) -> None:
    from types import SimpleNamespace
    from typing import cast

    from pydantic import SecretStr
    from pyinfra.api.host import Host

    from ops_deploy.services.homeassistant.pipeline_state import read_pipeline_preparation
    from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

    config = options(tmp_path)
    selected = state.prepare_list(config)
    calls = []

    def answer(command: Any, **kwargs: Any) -> Any:
        calls.append((command, kwargs))
        assert not kwargs["print_input"]
        assert not kwargs["print_output"]
        assert kwargs["_timeout"] == 5
        assert not kwargs["_get_pty"]
        assert "Room" not in str(command)
        assert str(tmp_path) not in str(command)
        return True, SimpleNamespace(stdout=json.dumps({"success": True, "result": selected}))

    result = read_pipeline_preparation(
        cast(Host, SimpleNamespace(run_shell_command=answer)),
        HomeAssistantRuntimeConfig(),
        "list",
        SecretStr(json.dumps(config)),
        timeout=5,
    )
    assert json.loads(result.get_secret_value()) == selected
    assert "Room" not in str(result)
    assert "Room" not in repr(result)
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("raw", "success"),
    [
        ("private-malformed", True),
        ('{"success":false,"error":"private-error"}', False),
        ('{"success":true,"result":42}', True),
        ('{"success":true,"result":[],"private":"body"}', True),
    ],
)
def test_controller_error_does_not_export_selected_or_error_bodies(raw: str, success: bool) -> None:
    from types import SimpleNamespace
    from typing import cast

    from pydantic import SecretStr
    from pyinfra.api import OperationError
    from pyinfra.api.host import Host

    from ops_deploy.services.homeassistant.pipeline_state import read_pipeline_preparation
    from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

    host = cast(Host, SimpleNamespace(run_shell_command=lambda *a, **k: (success, SimpleNamespace(stdout=raw))))
    with pytest.raises(OperationError, match=r"^Home Assistant pipeline preparation failed$"):
        read_pipeline_preparation(host, HomeAssistantRuntimeConfig(), "list", SecretStr("{}"), timeout=5)


@pytest.mark.parametrize("invalid_data", [None, [], "host port", 17, {}])
def test_original_undefined_host_port_filters_non_mapping_data(tmp_path: Path, invalid_data: Any) -> None:
    import base64

    from jinja2 import ChainableUndefined

    config = options(tmp_path)
    path = tmp_path / ".storage/core.config_entries"
    document = json.loads(path.read_bytes())
    document["data"]["entries"].insert(0, {"domain": "wyoming", "data": invalid_data})
    path.write_text(json.dumps(document))
    task = next(
        item
        for item in yaml.safe_load(ORIGINAL.read_text())
        if item["name"] == "Resolve Wyoming config entry for Assist pipeline auto-detection"
    )
    env = NativeEnvironment(undefined=ChainableUndefined)
    env.filters["b64decode"] = lambda value: base64.b64decode(value).decode()
    env.filters["from_json"] = json.loads
    actual_original = env.from_string(task["ansible.builtin.set_fact"]["_ha_assist_pipeline_entry_id"]).render(
        _ha_assist_pipeline_config_entries_raw={"content": base64.b64encode(path.read_bytes()).decode()},
        homeassistant_wyoming_host="owned",
        homeassistant_wyoming_port="10300",
    )
    assert actual_original == "first"
    assert state.entry_id(config, path.read_bytes()) == actual_original
    assert state.prepare_list(config)[0]["stt_engine"] == "stt.first"
