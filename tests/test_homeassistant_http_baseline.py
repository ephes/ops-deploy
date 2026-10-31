"""Owned confirmation refuses drift and retains attempted-write accounting."""

from __future__ import annotations

import asyncio
import importlib
import importlib.metadata
import json
import runpy
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from typing import Any

import pytest

from tests.integration.homeassistant import api as fixture_api
from tests.integration.homeassistant import http_baseline as baseline
from tests.integration.homeassistant import matrix

META = {"created_at": "2026-10-31T00:00:00+00:00", "error": None, "error_message": None}
DEFAULT = {"server_port": 8123, "ip_ban_enabled": True}
EXPECTED = {"server_port": 10020, "server_host": ["0.0.0.0"], "ip_ban_enabled": True}


def states() -> tuple[dict[str, Any], dict[str, Any]]:
    before = {
        "active_config_type": "pending",
        "revert_at": "2026-10-31T00:05:00+00:00",
        "pending": {**EXPECTED, **META},
        "stable": {**DEFAULT, **META},
        "default": {**DEFAULT, **META},
    }
    after = {
        **before,
        "active_config_type": "stable",
        "pending": None,
        "revert_at": None,
        "stable": {**EXPECTED, **META},
    }
    return before, after


def invoke(
    monkeypatch: pytest.MonkeyPatch, before: Any, after: Any, *, failure: str = ""
) -> tuple[dict[str, Any], list[str]]:
    original = SimpleNamespace(
        _META_KEYS=tuple(META), _strip_meta=lambda slot: {k: v for k, v in slot.items() if k not in META}
    )
    monkeypatch.setattr(baseline, "original_expected", lambda ipv4: (original, EXPECTED, DEFAULT))
    calls = []

    async def websocket(command: dict[str, str]) -> Any:
        assert set(command) == {"type"}
        calls.append(command["type"])
        if failure == "promote" and command["type"] == "http/config/promote":
            raise RuntimeError("owned-private-message-never-returned")
        if failure == "after" and len(calls) == 3:
            raise TimeoutError("owned-private-message-never-returned")
        return deepcopy(before if len(calls) == 1 else after) if command["type"] == "http/config" else None

    return asyncio.run(baseline.complete(websocket, "192.0.2.1")), calls


def test_exact_synthetic_trial_one_explicit_confirmation_and_stable_check(monkeypatch: pytest.MonkeyPatch) -> None:
    before, after = states()
    result, calls = invoke(monkeypatch, before, after)
    assert calls == ["http/config", "http/config/promote", "http/config"]
    assert result["confirmed"] is True
    assert result["confirmation_attempted"] is True
    assert result["confirmation_response_success"] is True
    assert result["before"]["revert_scheduled"] is True
    assert result["after"]["revert_scheduled"] is False
    assert "created_at" not in json.dumps(result)
    assert "server_host" not in json.dumps(result)


@pytest.mark.parametrize(
    "fault", ["missing", "error", "port", "proxy", "unknown", "wrong_type", "not_pending", "no_timer", "bad_stable"]
)
def test_missing_error_or_drift_never_promotes(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    before, after = states()
    if fault == "missing":
        before["pending"] = None
    elif fault == "error":
        before["pending"]["error"] = "not_promoted"
    elif fault == "port":
        before["pending"]["server_port"] = 12345
    elif fault == "proxy":
        before["pending"]["server_host"] = ["owned-unexpected-host"]
    elif fault == "unknown":
        before["pending"]["extra"] = "owned-private-message-never-returned"
    elif fault == "wrong_type":
        before["pending"]["ip_ban_enabled"] = 1
    elif fault == "not_pending":
        before["active_config_type"] = "stable"
    elif fault == "no_timer":
        before["revert_at"] = None
    else:
        before["stable"]["server_port"] = 10020
    result, calls = invoke(monkeypatch, before, after)
    assert calls == ["http/config"]
    assert result["confirmed"] is False
    assert result["confirmation_attempted"] is False
    assert "owned-private" not in json.dumps(result)


@pytest.mark.parametrize("failure", ["promote", "after", "mismatch"])
def test_after_attempt_failure_is_not_zero_write_claim(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    before, after = states()
    if failure == "mismatch":
        after["revert_at"] = before["revert_at"]
    result, calls = invoke(monkeypatch, before, after, failure=failure)
    assert result["confirmed"] is False
    assert result["confirmation_attempted"] is True
    assert result["confirmation_response_success"] is (failure != "promote")
    assert calls.count("http/config/promote") == 1
    assert "owned-private" not in json.dumps(result)


def test_source_admission_failure_precedes_every_api_call(monkeypatch: pytest.MonkeyPatch) -> None:
    async def refuse(command: Any) -> Any:
        pytest.fail("source refusal must not call an API")

    def expected(ipv4: str) -> Any:
        raise ValueError("owned-source-rejection")

    monkeypatch.setattr(baseline, "original_expected", expected)
    result = asyncio.run(baseline.complete(refuse, "192.0.2.1"))
    assert result["confirmation_attempted"] is False
    assert result["error_type"] == "ValueError"
    assert "owned-source" not in json.dumps(result)


@pytest.mark.parametrize("case", ["current", "upgrade"])
@pytest.mark.parametrize(("confirmed", "health_status"), [(True, 200), (False, 200), (False, 403)])
def test_actual_matrix_confirms_after_health_before_peers_and_selected_phases(
    monkeypatch: pytest.MonkeyPatch, case: str, confirmed: bool, health_status: int
) -> None:
    events: list[Any] = []
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", case)
    monkeypatch.setattr(matrix, "VALUES", [])
    monkeypatch.setattr(matrix, "seed", lambda version: events.append(("seed", version)))
    monkeypatch.setattr(matrix, "original_vars", lambda version: version)
    monkeypatch.setattr(matrix, "original", lambda label, values: events.append((label, values)))
    for name in ("verify_native_dependencies", "wait_ready", "wait_http"):
        monkeypatch.setattr(matrix, name, lambda name=name: events.append(name))
    monkeypatch.setattr(matrix, "default_ipv4", lambda: "192.0.2.1")
    monkeypatch.setattr(matrix, "write", lambda name, data: events.append(("write", name)))

    def api(action: str, *, token: str = "", command_value: dict[str, Any] | None = None) -> dict[str, Any]:
        events.append(action)
        if action == "seed":
            return {"token": "owned-synthetic-token"}
        if action == "health":
            return {"status": health_status}
        assert action == "confirm-http-baseline"
        assert command_value == {"ipv4": "192.0.2.1"}
        return {"confirmed": confirmed}

    class SelectedBoundary(Exception):
        pass

    @contextmanager
    def peers() -> Any:
        events.append("peers")
        raise SelectedBoundary
        yield  # pragma: no cover -- contextmanager shape, never reached

    monkeypatch.setattr(matrix, "api", api)
    monkeypatch.setattr(matrix, "peers", peers)
    if health_status != 200:
        with pytest.raises(AssertionError, match="must be reachable"):
            matrix.run()
        assert "confirm-http-baseline" not in events
        assert "peers" not in events
        return
    if confirmed:
        with pytest.raises(SelectedBoundary):
            matrix.run()
        assert events[-1] == "peers"
    else:
        with pytest.raises(AssertionError, match="baseline confirmation failed"):
            matrix.run()
        assert "peers" not in events
    version = "2026.10.2" if case == "current" else "2026.10.1"
    assert events[0] == ("seed", version)
    assert events[1] == ("00-original-existing-host-bootstrap", version)
    assert events.index("health") < events.index("confirm-http-baseline")
    assert events.index("confirm-http-baseline") < events.index(("write", "http-baseline-completion.json"))


@pytest.mark.parametrize("url", ["http://127.0.0.1:8123", "http://192.0.2.1:10020"])
def test_actual_api_refuses_wrong_endpoint_before_loading_or_network(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("endpoint refusal must precede helper loading and network")

    monkeypatch.setattr(runpy, "run_path", forbidden)
    monkeypatch.setattr(fixture_api, "websocket", forbidden)
    with pytest.raises(ValueError, match=r"owned fixture port|literal loopback"):
        asyncio.run(fixture_api.execute({"action": "confirm-http-baseline", "url": url}))


@pytest.mark.parametrize("version", ["2026.9.4", "2026.11.0"])
def test_unqualified_actual_original_version_refuses_before_module_import(
    monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    monkeypatch.setattr(importlib.metadata, "version", lambda name: version)

    def forbidden(name: str) -> Any:
        pytest.fail("version refusal must precede original module import")

    monkeypatch.setattr(importlib, "import_module", forbidden)
    with pytest.raises(ValueError, match="unqualified original HTTP version"):
        baseline.original_expected("192.0.2.1")
