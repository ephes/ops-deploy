"""Owned legacy metadata selection/removal; no actual application or API calls."""

from __future__ import annotations

import importlib.util
import json
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

SPEC = importlib.util.spec_from_file_location(
    "owned_ha_legacy", str(files("ops_deploy.services.homeassistant").joinpath("files/legacy_conversation.py"))
)
assert SPEC is not None
assert SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


def roots(tmp_path: Path) -> tuple[Path, Path]:
    config, venv = tmp_path / "config", tmp_path / "venv"
    config.mkdir()
    venv.mkdir()
    return config, venv


@pytest.mark.parametrize("kind", ["absent", "directory", "file", "link", "dangling"])
def test_component_original_lstat_presence(tmp_path: Path, kind: str) -> None:
    config, venv = roots(tmp_path)
    component = config / "custom_components/custom_conversation"
    component.parent.mkdir()
    if kind == "directory":
        component.mkdir()
    elif kind == "file":
        component.write_text("synthetic code")
    elif kind in {"link", "dangling"}:
        target = tmp_path / "target"
        if kind == "link":
            target.mkdir()
        component.symlink_to(target)
    result = helper.inspect(str(config), str(venv))
    assert result == {
        "component_present": kind != "absent",
        "litellm_present": False,
        "rebuild": kind != "absent",
        "retire": False,
        "skipped_metadata": 0,
    }


@pytest.mark.parametrize(
    "kind", ["directory", "file", "link", "hidden-parent", "hidden-name", "different-case", "lib-file", "lib-link"]
)
def test_original_find_directory_pattern_no_descendant_link_follow(tmp_path: Path, kind: str) -> None:
    config, venv = roots(tmp_path)
    library = venv / "lib"
    if kind == "lib-file":
        library.write_text("not a directory")
    else:
        library.mkdir()
        target = library / "python3.14/site-packages/litellm-1.dist-info"
        target.parent.mkdir(parents=True)
        if kind in {"directory", "lib-link"}:
            target.mkdir()
        elif kind == "file":
            target.write_text("not a directory")
        elif kind == "link":
            elsewhere = tmp_path / "outside"
            (elsewhere / "litellm-2.dist-info").mkdir(parents=True)
            (library / "linked-packages").symlink_to(elsewhere)
            target.symlink_to(elsewhere / "litellm-2.dist-info")
        elif kind == "hidden-parent":
            (library / ".hidden/litellm-1.dist-info").mkdir(parents=True)
        elif kind == "hidden-name":
            (target.parent / ".litellm-1.dist-info").mkdir()
        elif kind == "different-case":
            (target.parent / "LiteLLM-1.dist-info").mkdir()
        if kind == "lib-link":
            moved = venv / "library-target"
            library.rename(moved)
            library.symlink_to(moved)
    result = helper.inspect(str(config), str(venv))
    assert result["litellm_present"] is (kind in {"directory", "hidden-parent", "lib-link"})
    assert result["rebuild"] is result["litellm_present"]
    assert result["skipped_metadata"] == (1 if kind == "lib-file" else 0)


@pytest.mark.parametrize(
    ("entries", "retire"),
    [
        ([], False),
        ([{"domain": "unrelated", "private": "never export"}], False),
        ([{"domain": "custom_conversation", "entry_id": "owned", "data": {"private": "never export"}}], True),
    ],
)
def test_only_declared_domain_boolean_no_registry_values_exported(
    tmp_path: Path, entries: list[dict[str, Any]], retire: bool
) -> None:
    config, venv = roots(tmp_path)
    storage = config / ".storage/core.config_entries"
    storage.parent.mkdir()
    storage.write_text(json.dumps({"data": {"entries": entries}}))
    before = storage.read_bytes()
    result = helper.inspect(str(config), str(venv))
    assert result["retire"] is retire
    assert storage.read_bytes() == before
    assert "owned" not in json.dumps(result)
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize("body", ["private-invalid-json", "[]", "{}", '{"data":{"entries":null}}'])
def test_malformed_named_registry_fails_not_empty(tmp_path: Path, body: str) -> None:
    config, venv = roots(tmp_path)
    storage = config / ".storage/core.config_entries"
    storage.parent.mkdir()
    storage.write_text(body)
    with pytest.raises((ValueError, TypeError, KeyError)):
        helper.inspect(str(config), str(venv))
    assert storage.read_text() == body


@pytest.mark.parametrize("kind", ["absent", "directory", "file", "link", "dangling"])
def test_actual_sdk_remove_known_component_and_repeat_preserves_link_target(tmp_path: Path, kind: str) -> None:
    from pyinfra import host
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    from ops_deploy.services.homeassistant.legacy_conversation import (
        LegacyConversationState,
        inspect_legacy_conversation,
        remove_legacy_component,
    )
    from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
    from ops_deploy.testing.harness import collect_ops

    config, venv = roots(tmp_path)
    component = config / "custom_components/custom_conversation"
    component.parent.mkdir()
    target = tmp_path / "preserved-target"
    target.mkdir()
    marker = target / "marker"
    marker.write_text("owned unrelated synthetic data")
    if kind == "directory":
        component.mkdir()
        (component / "synthetic.py").write_text("original legacy source")
    elif kind == "file":
        component.write_text("original synthetic component")
    elif kind in {"link", "dangling"}:
        component.symlink_to(target if kind == "link" else tmp_path / "missing")
    cfg = HomeAssistantRuntimeConfig(config_path=str(config), virtualenv_path=str(venv))
    before = marker.read_bytes(), marker.stat().st_mtime_ns, marker.stat().st_ctime_ns, marker.stat().st_ino
    for repeat in (False, True):
        state = State(Inventory(([("@local", {})], {})), Config())
        observed: list[LegacyConversationState] = []

        def deploy(observed: list[LegacyConversationState] = observed) -> None:
            observed.append(inspect_legacy_conversation(host, cfg))
            remove_legacy_component(cfg)

        try:
            connect_all(state)
            add_deploy(state, deploy)
            assert component.is_symlink() or component.exists() or repeat or kind == "absent"
            run_ops(state)
            operations = collect_ops(state, "@local")
            assert all(op.succeeded for op in operations)
            assert sum(op.changed for op in operations) == (1 if not repeat and kind != "absent" else 0)
            assert observed[0].rebuild is (not repeat and kind != "absent")
            assert not component.exists()
            assert not component.is_symlink()
            assert (
                marker.read_bytes(),
                marker.stat().st_mtime_ns,
                marker.stat().st_ctime_ns,
                marker.stat().st_ino,
            ) == before
        finally:
            disconnect_all(state)
