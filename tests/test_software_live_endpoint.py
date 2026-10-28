"""Original uri status, anonymous realm and rolling observation comparison rules."""

from __future__ import annotations

import importlib.util
from typing import Any

import pytest

from ops_deploy.services.software_live.common import RESOURCE


@pytest.fixture
def endpoint() -> Any:
    spec = importlib.util.spec_from_file_location(
        "fixture_software_endpoint", str(RESOURCE.joinpath("files/endpoint_check.py"))
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def responses(status: int = 200) -> list[tuple[int, dict[str, str], dict[str, Any]]]:
    body = {"host": "fixture", "summary": {"fresh": True}, "meta": {"age_seconds": 4, "max_age_seconds": 1800}}
    return [
        (401, {"WWW-Authenticate": 'Basic realm="software-live"'}, {"error": "unauthorized"}),
        (200, {}, body),
        (status, {}, {**body, "meta": {"age_seconds": 5, "max_age_seconds": 1800}}),
        (200, {}, {**body, "host": "new-observation"}),
    ]


def test_shadow_accepts_matching_before_body_with_only_age_difference(
    endpoint: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    iterator = iter(responses())
    monkeypatch.setattr(endpoint, "fetch", lambda *_args: next(iterator))
    endpoint.shadow("production", "shadow", "fixture:password")


@pytest.mark.parametrize("status", [401, 500, 503])
def test_shadow_rejects_error_status_even_with_matching_json(
    endpoint: Any, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    iterator = iter(responses(status))
    monkeypatch.setattr(endpoint, "fetch", lambda *_args: next(iterator))
    with pytest.raises(SystemExit, match="does not answer"):
        endpoint.shadow("production", "shadow", "fixture:password")


def test_shadow_rejects_extra_meta_field(endpoint: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    values = responses()
    values[2][2]["meta"]["unexpected"] = True
    iterator = iter(values)
    monkeypatch.setattr(endpoint, "fetch", lambda *_args: next(iterator))
    with pytest.raises(SystemExit, match="does not answer"):
        endpoint.shadow("production", "shadow", "fixture:password")
