"""Stage planning order on synthetic declarations; no host/app operation runs."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from ops_deploy.core.git_source import SourceTree
from ops_deploy.core.secrets import SecretContent
from tests import test_daybook_sessions_source as source_cases
from tests.test_daybook_sessions_resources import config, secrets, studio

MODULE = importlib.import_module("ops_deploy.services.daybook_sessions.deploy")
checkout = source_cases.checkout


@pytest.mark.parametrize("current", [False, True])
@pytest.mark.parametrize("probe", [False, True])
def test_full_role_preserves_original_stage_order_and_managed_repeat_probe(
    checkout: tuple[dict[str, Any], Path, SourceTree], current: bool, probe: bool
) -> None:
    _source_data, bundle, source = checkout
    cfg = (
        studio(daybook_weeknotes_reconcile_enabled=False, daybook_sessions_repo_ref=source.commit)
        if probe
        else config(daybook_sessions_repo_ref=source.commit)
    )
    calls: list[tuple[str, Any]] = []
    readonly: list[dict[str, Any]] = []

    def operation(**kwargs: Any) -> dict[str, Any]:
        content = kwargs["content"]
        assert isinstance(content, SecretContent)
        assert "fixture-secret" not in repr(content)
        payload = json.loads(content.reveal())
        calls.append((kwargs["command"], payload))
        return kwargs

    def source_install(**kwargs: Any) -> None:
        assert kwargs["source"] is source
        assert kwargs["bundle"] is bundle
        calls.append(("source", None))

    with (
        patch.object(MODULE, "host", Mock(get_fact=Mock(return_value="Darwin"))),
        patch.object(MODULE, "inspect_component", return_value=current),
        patch.object(MODULE, "inspect_sessions_source", return_value={"current": current}),
        patch.object(MODULE, "inspect_sessions_resources", return_value={"current": current}),
        patch.object(MODULE, "install_sessions_source", side_effect=source_install),
        patch.object(MODULE, "resource_command", side_effect=lambda action: action),
        patch.object(MODULE, "secret_stdin", side_effect=operation),
        patch.object(MODULE, "mark_read_only", side_effect=lambda op: readonly.append(op)),
    ):
        MODULE.deploy_daybook_sessions.__wrapped__(cfg, secrets(), source, bundle)
    actions = [name for name, _payload in calls]
    expected = [] if current else ["reconcile-quiesce", "prerequisites-apply", "directories-apply"]
    expected += ["source"] + (["classifier-probe"] if probe else [])
    expected += ([] if current else ["apply"]) + ["verify", "prerequisites-verify"]
    assert actions == expected
    assert len(readonly) == 2
    for action, data in calls:
        if action == "apply":
            assert data["source_changed"] is True
        if action == "verify":
            assert data["source_changed"] is False
    if probe:
        assert all(op["command"] != "classifier-probe" for op in readonly)


def test_disabled_role_does_not_resolve_host_source_or_secrets() -> None:
    cfg = config(daybook_sessions_enabled=False)
    with patch.object(MODULE, "host", Mock(get_fact=Mock(side_effect=AssertionError("no facts")))):
        MODULE.deploy_daybook_sessions.__wrapped__(cfg, {}, None, None)


def test_non_darwin_role_refuses_before_any_private_render_or_operation() -> None:
    cfg = config()
    with (
        patch.object(MODULE, "host", Mock(get_fact=Mock(return_value="Linux"))),
        patch.object(MODULE, "resource_payload", side_effect=AssertionError("no private render")),
        pytest.raises(Exception, match="Darwin targets only"),
    ):
        MODULE.deploy_daybook_sessions.__wrapped__(cfg, {}, None, None)
