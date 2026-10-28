"""Protected profile, action selection, and content-free monitor boundary."""

from __future__ import annotations

import importlib
import io
import json
import os
import plistlib
import urllib.error
from dataclasses import asdict
from importlib.resources import files
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest
from pydantic import ValidationError

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.daybook_operations_runtime import DaybookRuntimeConfig, RuntimeKind, RuntimeWorkers
from ops_deploy.services.daybook_operations_runtime.decision import InstalledRuntime, normal_action
from ops_deploy.services.daybook_operations_runtime.render import render_credential, render_resource, role_values
from ops_deploy.services.daybook_operations_runtime.status import (
    MAX_STATUS_BYTES,
    STATUS_TIMEOUT,
    StatusError,
    _NoRedirect,
    fetch_status,
    parse_status,
)


def access(value: str) -> SecretValues:
    return SecretValues(SecretRef("fixture.yml"), {"monitor_token": value})


def config(**values: Any) -> DaybookRuntimeConfig:
    return DaybookRuntimeConfig(**{"user": "fixture", "revision": "a" * 40, **values})


@pytest.mark.parametrize("owner", ["root", "user"])
@pytest.mark.parametrize("mode", ["serve", "host"])
def test_original_schema_and_launch_agent_contract(owner: str, mode: str) -> None:
    cfg = config(owner=owner, mode=mode)
    policy = json.loads(render_resource(cfg, "policy.json.j2"))
    assert policy == {
        "schema": 5,
        "enabled": False,
        "api_url": cfg.api_url,
        "credential_path": str(cfg.credential),
        "journal": str(cfg.journal),
        "workers": {"count": 2, "long": 1},
        "kinds": [
            {
                "adapter": "voice_memos.ingest.v1",
                "deadline": 330,
                "lease": 600,
                "run": {"importer_policy": str(cfg.importer_policy)},
            }
        ],
    }
    plist = plistlib.loads(render_resource(cfg, "runtime.plist.j2").encode())
    assert plist["KeepAlive"]
    assert plist["RunAtLoad"]
    assert ("host-keep" if mode == "host" else "serve") in plist["ProgramArguments"]
    assert plist["ProgramArguments"][0] == str(cfg.python)
    assert plist["ProgramArguments"][plist["ProgramArguments"].index("--policy-owner") + 1] == owner
    assert ("ThrottleInterval" in plist) == (mode == "host")
    assert not any(key.startswith("StartInterval") for key in plist)
    assert str(cfg.install_root).startswith("/Library/" if owner == "root" else "/Users/fixture/")


@pytest.mark.parametrize(
    "values",
    [
        {"workers": {"count": True, "long": 1}},
        {"workers": {"count": 3, "long": 3}},
        {"kinds": []},
        {"kinds": [{"adapter": "unknown", "deadline": 330, "lease": 600}]},
        {"kinds": [{"adapter": "sessions.ship.v1", "deadline": "330", "lease": 600}]},
        {"kinds": [{"adapter": "sessions.ship.v1", "deadline": 330, "lease": 389}]},
        {"action": "stop"},
        {"action": "replace", "confirmed": True, "start": True},
        {"action": "verify", "confirmed": True, "start": True},
        {"start": True},
        {"journal": "/tmp/../body"},
        {"api_url": "https://user:secret@example.test"},
        {"api_url": "https://example.test/v1/status"},
        {"api_url": "http://example.test"},
        {"api_url": "https://example.test?"},
        {"api_url": "https://example.test#"},
        {"status_sources": ["regular", "regular"]},
        {"user": "CHANGEME"},
    ],
)
def test_original_validation_and_transition_guards(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        config(**values)


def test_kind_run_is_preserved_and_only_absent_importer_run_is_defaulted() -> None:
    cfg = config(
        kinds=(
            RuntimeKind(adapter="voice_memos.ingest.v1", deadline=330, lease=600, run={}),
            RuntimeKind(adapter="sessions.ship.v1", deadline=330, lease=600),
        )
    )
    kinds = json.loads(render_resource(cfg, "policy.json.j2"))["kinds"]
    assert kinds[0]["run"] == {}
    assert "run" not in kinds[1]
    assert RuntimeWorkers(count=3, long=2).model_dump() == {"count": 3, "long": 2}


def test_cutover_is_the_only_profile_enabled_renderer() -> None:
    for action in ("install", "replace", "cutover", "rollback", "closeout", "stop", "verify"):
        cfg = config(action=action, confirmed=True)
        assert json.loads(render_resource(cfg, "policy.json.j2"))["enabled"] == (action == "cutover")


def test_paired_role_templates_are_exact() -> None:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("Paired role oracle requires explicit OPS_LIBRARY_PATH; qualification runs it explicitly")
    root = Path(source) / "roles/daybook_operations_runtime_deploy"
    assert root.is_dir(), "set OPS_LIBRARY_PATH to the paired original role checkout"
    package = files("ops_deploy.services.daybook_operations_runtime").joinpath("templates")
    originals = sorted((root / "templates").glob("*.j2"))
    assert {p.name for p in originals} == {p.name for p in package.iterdir()}
    for path in originals:
        assert package.joinpath(path.name).read_bytes() == path.read_bytes()
    # Independently render the actual original resource with its native filters.
    import jinja2

    FilterModule = importlib.import_module("ansible.plugins.filter.core").FilterModule

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(root / "templates"),
        trim_blocks=True,
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
    )
    env.filters.update(FilterModule().filters())
    for cfg in (config(), config(owner="user", mode="host", action="cutover", confirmed=True)):
        for name in ("policy.json.j2", "runtime.plist.j2"):
            assert render_resource(cfg, name) == env.get_template(name).render(role_values(cfg))


def test_credential_never_enters_config_or_repr() -> None:
    token = "fixture-monitor-not-real-" + "x" * 32
    result = render_credential(token)
    assert token not in repr(result)
    assert json.loads(result.reveal()) == {"token": token}
    with pytest.raises(ValueError, match="invalid"):
        render_credential("CHANGEME")


def test_enabled_default_checks_current_main_and_resources_without_old_pin() -> None:
    cfg = config()
    assert normal_action(cfg, None) == "install_disabled"
    assert normal_action(cfg, InstalledRuntime(False, False, False)) == "install_disabled"
    assert normal_action(cfg, InstalledRuntime(True, True, True)) == "pure_verify"
    for source, resources in ((False, True), (True, False), (False, False)):
        assert normal_action(cfg, InstalledRuntime(True, source, resources)) == "guarded_update"
    assert cfg.revision == "a" * 40
    with pytest.raises(ValueError, match="default"):
        normal_action(config(action="stop", confirmed=True), InstalledRuntime(True, True, True))


def payload(**changes: Any) -> bytes:
    row = {
        "binding": "regular",
        "enabled": True,
        "active_state": None,
        "expiry_pending": False,
        "unapplied_receipts": 0,
        "needs_operator": False,
        "attention": [{"operation_id": "DROP-ME"}],
        "blocker": "DROP-ME",
        "other": "DROP-ME",
    }
    row.update(changes)
    return json.dumps({"schema": 1, "principal": "DROP-ME", "bindings": [row]}).encode()


def test_status_discards_every_unapproved_field_without_parsing_arbitrary_content() -> None:
    status = parse_status(payload(), ["regular"])
    assert asdict(status[0]) == {
        "binding": "regular",
        "enabled": True,
        "active_state": None,
        "expiry_pending": False,
        "unapplied_receipts": 0,
        "needs_operator": False,
    }
    assert "DROP-ME" not in repr(status)


@pytest.mark.parametrize(
    "body",
    [
        b'{"schema":1,"schema":1,"bindings":[]}',
        b'{"schema":true,"bindings":[]}',
        b"not json",
        b"\xff",
        b'{"schema":1,"bindings":[]}',
        payload(enabled="true"),
        payload(active_state="PRIVATE-ERROR-BODY"),
        payload(unapplied_receipts=True),
        payload(unapplied_receipts=-1),
        payload(expiry_pending=None),
    ],
)
def test_status_malformed_missing_and_unsafe_values_fail_closed(body: bytes) -> None:
    with pytest.raises(StatusError) as failure:
        parse_status(body, ["regular"])
    assert "PRIVATE" not in str(failure.value)


def test_status_duplicate_sources_and_size_fail_closed() -> None:
    value = json.loads(payload())
    value["bindings"] *= 2
    with pytest.raises(StatusError, match="duplicate"):
        parse_status(json.dumps(value).encode(), ["regular"])
    with pytest.raises(StatusError, match="invalid_sources"):
        parse_status(payload(), ["regular", "regular"])
    with pytest.raises(StatusError, match="too_large"):
        parse_status(b" " * (MAX_STATUS_BYTES + 1), ["regular"])


def test_monitor_is_single_exact_get_tls_bounded_and_no_redirect_or_fallback() -> None:
    token = access("fixture-monitor-not-real-" + "x" * 32)
    response = Mock(status=200)
    response.read.return_value = payload()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    opener = Mock()
    opener.open.return_value = response
    with patch("urllib.request.build_opener", return_value=opener) as build:
        result = fetch_status("https://example.test", token, ["regular"])
    assert result[0].binding == "regular"
    request = opener.open.call_args.args[0]
    assert request.full_url == "https://example.test/v1/status"
    assert request.method == "GET"
    assert request.headers["Authorization"] == "Bearer " + token["monitor_token"]
    assert opener.open.call_count == 1
    assert opener.open.call_args.kwargs == {"timeout": STATUS_TIMEOUT}
    response.read.assert_called_once_with(MAX_STATUS_BYTES + 1)
    assert isinstance(build.call_args.args[0], _NoRedirect)
    assert build.call_args.args[1]._context.check_hostname
    _NoRedirect().redirect_request(request, None, 302, "private", {}, "https://elsewhere.test")


@pytest.mark.parametrize("code", [301, 302, 401, 403, 500])
def test_http_failures_close_without_reading_error_body_or_retry(code: int) -> None:
    body = io.BytesIO(b"PRIVATE-ERROR-BODY")
    error = urllib.error.HTTPError("https://example.test", code, "PRIVATE-ERROR-BODY", {}, body)  # type: ignore[arg-type]
    opener = Mock()
    opener.open.side_effect = error
    with patch("urllib.request.build_opener", return_value=opener), pytest.raises(StatusError) as failure:
        fetch_status("https://example.test", access("x" * 32), ["regular"])
    assert str(failure.value) == "monitor_http_failed"
    assert body.closed
    assert opener.open.call_count == 1


@pytest.mark.parametrize(
    "origin",
    [
        "https://example.test?",
        "https://example.test#",
        "https://example.test/",
        "https://example.test?body",
        "https://example.test#body",
        "https://example.test/v1",
        "https://user:private@example.test",
        "http://example.test",
        "https://[invalid",
    ],
)
def test_noncanonical_origins_never_send_authorization(origin: str) -> None:
    with patch("urllib.request.build_opener") as build, pytest.raises(StatusError, match="invalid_origin"):
        fetch_status(origin, access("x" * 32), ["regular"])
    build.assert_not_called()


@pytest.mark.parametrize(
    "values",
    [
        {},
        {"monitor_token": ""},
        {"monitor_token": "x" * 32 + "\nprivate"},
        {"monitor_token": None},
        {"monitor_token": 123},
    ],
)
def test_missing_or_invalid_monitor_access_is_sanitized_before_transport(values: dict[str, Any]) -> None:
    with patch("urllib.request.build_opener") as build, pytest.raises(StatusError, match="monitor_invalid_access"):
        fetch_status("https://example.test", SecretValues(SecretRef("fixture.yml"), values), ["regular"])
    build.assert_not_called()
