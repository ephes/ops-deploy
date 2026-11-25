from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

HOST = Path(__file__).parents[1] / "src/ops_deploy/services/voxhelm/files/voxhelm_host.py"


def load_host() -> Any:
    spec = importlib.util.spec_from_file_location("voxhelm_host_under_test", HOST)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_wait_unloaded_polls_until_bootout_finished(monkeypatch: pytest.MonkeyPatch) -> None:
    host = load_host()
    states = iter([(True, False), (True, False), (False, False)])
    sleeps: list[float] = []
    monkeypatch.setattr(host, "job", lambda c, unit: next(states))
    monkeypatch.setattr(host.time, "sleep", sleeps.append)
    host.wait_unloaded({}, {"label": "x"})
    assert sleeps == [0.5, 0.5]


def test_wait_unloaded_fails_when_job_stays_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    host = load_host()
    monkeypatch.setattr(host, "job", lambda c, unit: (True, True))
    monkeypatch.setattr(host.time, "sleep", lambda seconds: None)
    with pytest.raises(RuntimeError, match="did not unload"):
        host.wait_unloaded({}, {"label": "x"}, timeout=0.0)
