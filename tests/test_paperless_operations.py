"""Planning/execute admission with no host connection; native CLI proof remains."""

from __future__ import annotations

import inspect
import json
from types import SimpleNamespace
from typing import Any

import pytest
from pyinfra.api import DeployError

from ops_deploy.services.paperless import operations
from ops_deploy.services.paperless.config import PaperlessConfig


def test_planned_release_change_is_not_hidden_by_current_index(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(operations, "state", SimpleNamespace(is_executing=False))

    def forbidden(*args: Any) -> bool:
        raise AssertionError("no executed result/old index may resolve a pending release")

    meta = SimpleNamespace(will_change=True, did_change=forbidden)
    monkeypatch.setattr(operations, "index_needs_rebuild", forbidden)
    cfg = PaperlessConfig(traefik_domain="home.example.test")
    commands = list(inspect.unwrap(operations.rebuild_index)(cfg, changes=(("release", meta),)))
    assert len(commands) == 1


def test_execute_rechecks_after_prerequisites_and_preserves_trigger(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(operations, "state", SimpleNamespace(is_executing=True))
    seen: list[tuple[str, ...]] = []

    def decision(cfg: PaperlessConfig, triggers: tuple[str, ...]) -> bool:
        seen.append(triggers)
        return bool(triggers)

    monkeypatch.setattr(operations, "index_needs_rebuild", decision)
    cfg = PaperlessConfig(traefik_domain="home.example.test")
    changed = SimpleNamespace(did_change=lambda: True)
    unchanged = SimpleNamespace(did_change=lambda: False)
    operation = inspect.unwrap(operations.rebuild_index)
    assert len(list(operation(cfg, changes=(("packages", changed), ("migrations", unchanged)), deferred=True))) == 1
    assert list(operation(cfg, changes=(("packages", unchanged),), deferred=True)) == []
    assert seen == [("packages",), ()]


@pytest.mark.parametrize("answer", [None, "", "1\n2", "-1"])
def test_unknown_sql_result_refuses_before_index_or_reindex(
    answer: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def probe(command: str, **kwargs: Any) -> str | None:
        calls.append(command)
        return answer

    monkeypatch.setattr(operations, "probe", probe)
    with pytest.raises(DeployError, match="count"):
        operations.index_needs_rebuild(PaperlessConfig(traefik_domain="home.example.test"), ())
    assert len(calls) == 1


@pytest.mark.parametrize(
    "response",
    [
        None,
        {},
        {"reindex": False, "reasons": [], "document_count": 1, "indexed_count": 0},
        {"reindex": False, "reasons": ["force"], "document_count": 1, "indexed_count": 1},
    ],
)
def test_unknown_or_inconsistent_index_response_refuses(response: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    results = iter(["1", json.dumps(response)])
    monkeypatch.setattr(operations, "probe", lambda *args, **kwargs: next(results))
    with pytest.raises(DeployError, match="metadata inspection"):
        operations.index_needs_rebuild(PaperlessConfig(traefik_domain="home.example.test"), ())
