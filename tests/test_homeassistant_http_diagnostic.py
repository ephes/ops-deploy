"""Read-only bounded entry ordering and no configuration-body evidence."""

from __future__ import annotations

import json
from copy import deepcopy
from types import SimpleNamespace
from typing import Any, cast

import pytest

from tests.integration.homeassistant import diagnose_http as driver
from tests.integration.homeassistant import harness


def response() -> dict[str, Any]:
    return {
        "active_config_type": "pending",
        "revert_at": "2026-10-31T04:10:00+00:00",
        "stable": {"server_port": 8123, "ssl_key": "owned-body-must-not-escape"},
        "pending": {
            "server_port": 10020,
            "error": None,
            "error_message": "owned-body-must-not-escape",
            "trusted_proxies": ["owned-body-must-not-escape"],
        },
        "default": {"server_port": 8123, "arbitrary": "owned-body-must-not-escape"},
    }


def test_fixed_projection_retains_no_settings_timestamps_or_body() -> None:
    original = response()
    before = deepcopy(original)
    actual = driver.project(original)
    assert original == before
    assert actual == {
        "active_slot": "pending",
        "pending_present": True,
        "pending_error": None,
        "revert_scheduled": True,
        "slots": {
            "stable": {"port_is_fixture10020": False, "port_is_builtin8123": True},
            "pending": {"port_is_fixture10020": True, "port_is_builtin8123": False},
            "default": {"port_is_fixture10020": False, "port_is_builtin8123": True},
        },
    }
    encoded = json.dumps(actual)
    assert "owned-body" not in encoded
    assert "2026-10-31" not in encoded
    original.update(pending=None, revert_at=None, active_config_type="stable")
    assert driver.project(original)["pending_present"] is False
    for error in ("not_promoted", "apply_failed"):
        raw = response()
        raw["pending"]["error"] = error
        assert driver.project(raw)["pending_error"] == error


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("active_config_type", "owned-body"),
        ("active_config_type", []),
        ("revert_at", "owned-body"),
        ("revert_at", "2026-10-31T04:10:00"),
        ("revert_at", 123),
        ("stable", None),
        ("stable", {"server_port": True}),
        ("stable", {"server_port": 0}),
        ("default", {"server_port": 65536}),
        ("pending", {"server_port": "owned-body"}),
        ("pending", {"server_port": 10020, "error": "owned-body"}),
        ("pending", {"server_port": 10020, "error": []}),
    ],
)
def test_malformed_projection_refuses_with_fixed_error(key: str, value: Any) -> None:
    raw = response()
    raw[key] = value
    with pytest.raises(ValueError, match="invalid owned HTTP") as caught:
        driver.project(raw)
    assert "owned-body" not in str(caught.value)


@pytest.mark.parametrize("value", [None, [], {}, {**response(), "unexpected": "owned-body"}])
def test_unexpected_response_shape_refuses(value: Any) -> None:
    with pytest.raises(ValueError, match="invalid owned HTTP status"):
        driver.project(value)


def setup(monkeypatch: pytest.MonkeyPatch) -> tuple[list[Any], dict[str, Any]]:
    events: list[Any] = []
    written: dict[str, Any] = {}
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", "current")
    monkeypatch.setattr(driver, "VALUES", [])
    monkeypatch.setattr(driver, "admit", lambda: events.append("admit"))
    monkeypatch.setattr(driver, "seed", lambda version: events.append(("seed", version)))
    monkeypatch.setattr(driver, "original_vars", lambda version: {"original_version": version})
    monkeypatch.setattr(driver, "original", lambda label, values: events.append((label, values)))
    for name in ("verify_native_dependencies", "wait_ready", "wait_http", "diagnostics"):
        monkeypatch.setattr(driver, name, lambda name=name: events.append(name))

    def api(action: str, *, token: str = "", command_value: dict[str, Any] | None = None) -> dict[str, Any]:
        events.append((action, {"token": token, "command_value": command_value}))
        if action == "seed":
            return {"token": "owned-token-never-evidence"}
        if action == "health":
            return {"status": 200}
        assert action == "ws"
        assert command_value == {"type": "http/config"}
        return {"result": response()}

    monkeypatch.setattr(driver, "api", api)
    monkeypatch.setattr(driver, "write", lambda name, value: written.update({name: value}))
    return events, written


def test_one_original00_onboard_readonly_query_and_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    events, written = setup(monkeypatch)
    driver.run()
    assert events == [
        "admit",
        ("seed", "2026.10.2"),
        ("00-original-existing-host-bootstrap", {"original_version": "2026.10.2"}),
        "verify_native_dependencies",
        "wait_ready",
        "wait_http",
        ("seed", {"token": "", "command_value": None}),
        ("health", {"token": "owned-token-never-evidence", "command_value": None}),
        ("ws", {"token": "owned-token-never-evidence", "command_value": {"type": "http/config"}}),
    ]
    assert cast(Any, driver).VALUES == ["owned-token-never-evidence"]
    summary = written["HTTP-DIAGNOSTIC.json"]
    assert summary["http_status_projection_written"] is True
    assert summary["selected_original_phases"] == summary["typed_phases"] == 0
    assert summary["peers_started"] is False
    assert set(written) == {"api-onboarding.json", "http-status-projection.json", "HTTP-DIAGNOSTIC.json"}
    assert "owned-token" not in json.dumps(written)
    assert "owned-body" not in json.dumps(written)


def test_upgrade_refuses_before_any_admission_or_write(monkeypatch: pytest.MonkeyPatch) -> None:
    events, written = setup(monkeypatch)
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", "upgrade")
    with pytest.raises(ValueError, match="requires the current"):
        driver.run()
    assert events == []
    assert written == {}


def test_primary_failure_survives_failed_summary_and_no_query_follows(monkeypatch: pytest.MonkeyPatch) -> None:
    events, _ = setup(monkeypatch)
    primary = RuntimeError("original primary")

    def fail() -> None:
        raise primary

    def write(name: str, value: Any) -> None:
        raise OSError("synthetic evidence failure")

    monkeypatch.setattr(driver, "verify_native_dependencies", fail)
    monkeypatch.setattr(driver, "write", write)
    with pytest.raises(RuntimeError) as caught:
        driver.run()
    assert caught.value is primary
    assert events[-1] == "diagnostics"
    assert not any(isinstance(event, tuple) and event[0] == "ws" for event in events)


def test_malformed_query_retains_partial_summary_without_body(monkeypatch: pytest.MonkeyPatch) -> None:
    _events, written = setup(monkeypatch)
    normal = cast(Any, driver).api

    def api(action: str, **kwargs: Any) -> dict[str, Any]:
        if action == "ws":
            return {"result": {"owned-body": "owned-body"}}
        return cast(dict[str, Any], normal(action, **kwargs))

    monkeypatch.setattr(driver, "api", api)
    with pytest.raises(ValueError, match="invalid owned HTTP status"):
        driver.run()
    assert "http-status-projection.json" not in written
    assert written["HTTP-DIAGNOSTIC.json"]["http_status_projection_written"] is False
    assert "owned-body" not in json.dumps(written)


def test_real_harness_api_serializes_exact_readonly_command(monkeypatch: pytest.MonkeyPatch) -> None:
    _events, written = setup(monkeypatch)
    sent = []

    def transport(*argv: str, stdin: str, timeout: float) -> SimpleNamespace:
        payload = json.loads(stdin)
        sent.append((argv, payload, timeout))
        value: dict[str, Any]
        if payload["action"] == "seed":
            value = {"token": "owned-token-never-evidence"}
        elif payload["action"] == "health":
            value = {"status": 200}
        else:
            assert payload["action"] == "ws"
            assert payload["command"] == {"type": "http/config"}
            value = {"result": response()}
        return SimpleNamespace(stdout=json.dumps(value))

    monkeypatch.setattr(harness, "command", transport)
    monkeypatch.setattr(driver, "api", harness.api)
    driver.run()
    assert len(sent) == 3
    assert all(argv[1:3] == ("-I", "-B") and timeout == 130 for argv, _, timeout in sent)
    assert sent[-1][1]["command"] == {"type": "http/config"}
    assert written["HTTP-DIAGNOSTIC.json"]["http_status_projection_written"] is True
    assert "owned-token" not in json.dumps(written)
