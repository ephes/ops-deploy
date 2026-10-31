"""Owned diagnostic scope, projection, failure and actual protocol controls."""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any

import pytest

from tests.integration.homeassistant import diagnose_wyoming, wyoming_diagnostics, wyoming_protocol_probe
from tests.integration.homeassistant.wyoming_server import WyomingServer


def test_registry_projection_drops_bodies_and_preserves_matching_metadata(tmp_path: Path) -> None:
    private = "synthetic-body-not-for-evidence"
    source = [
        {
            "domain": "wyoming",
            "entry_id": "owned",
            "state": "loaded",
            "data": {"host": "127.0.0.1", "port": 10300, "token": private},
            "options": {"body": private},
        },
        {"domain": "llama_cpp", "entry_id": "unselected", "data": {"body": private}},
    ]
    result = wyoming_diagnostics.entries(source)
    assert result == [
        {
            "entry_id": "owned",
            "domain": "wyoming",
            "state": "loaded",
            "disabled_by": None,
            "matches_fixture_endpoint": True,
        }
    ]
    assert private not in json.dumps(result)
    path = tmp_path / "registry"
    path.write_text(json.dumps({"data": {"entries": source}}))
    assert wyoming_diagnostics.disk(path, "entries", wyoming_diagnostics.entries)["selected"] == result
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError, match=r"[Ll]evels|symbolic link"):
        wyoming_diagnostics.disk(link, "entries", wyoming_diagnostics.entries)
    path.write_bytes(b"x" * (wyoming_diagnostics.REGISTRY_LIMIT + 1))
    with pytest.raises(ValueError, match="exceeds bounds"):
        wyoming_diagnostics.disk(path, "entries", wyoming_diagnostics.entries)
    with pytest.raises(ValueError, match="invalid owned"):
        wyoming_diagnostics.entities([{}] * 4097)
    assert wyoming_diagnostics.entities(
        [{"platform": "wyoming", "entity_id": "stt.owned", "config_entry_id": "owned", "options": private}]
    ) == [{"entity_id": "stt.owned", "platform": "wyoming", "config_entry_id": "owned", "disabled_by": None}]


def test_collectors_continue_after_failures_and_use_fixed_read_only_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[tuple[list[str], float]] = []
    written = {}

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise ValueError("synthetic private exception body")

    def command(argv: list[str], *, timeout: float) -> dict[str, Any]:
        commands.append((argv, timeout))
        return {"exit": 0, "output": "owned", "timed_out": False, "truncated": False}

    monkeypatch.setattr(wyoming_diagnostics, "api", fail)
    monkeypatch.setattr(wyoming_diagnostics, "disk", fail)
    monkeypatch.setattr(wyoming_diagnostics, "bounded_command", command)
    monkeypatch.setattr(wyoming_diagnostics, "write", lambda name, result: written.update({name: result}))
    result = wyoming_diagnostics.capture("after-original-selected", "synthetic-token")
    assert len(result) == 7
    assert len(commands) == 3
    assert [timeout for _, timeout in commands] == [20, 5, 10]
    assert all("synthetic-token" not in str(argv) for argv, _ in commands)
    assert commands[1][0][:3] == ["systemctl", "show", "homeassistant.service"]
    assert commands[2][0][0] == "journalctl"
    assert "synthetic private" not in json.dumps(written)
    assert result["live_entries"] == {"collection_failed": True, "error_type": "ValueError"}
    with pytest.raises(ValueError, match="unexpected owned"):
        wyoming_diagnostics.capture("other", "synthetic-token")


@pytest.mark.parametrize("evidence_failure", [None, "after", "summary", "both"])
def test_original_failure_is_retained_after_diagnostics_and_peer_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    evidence_failure: str | None,
) -> None:
    from contextlib import contextmanager

    events: list[str] = []
    summaries = {}
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", "current")
    monkeypatch.setattr(diagnose_wyoming, "admit", lambda: events.append("admit"))
    monkeypatch.setattr(diagnose_wyoming, "seed", lambda version: events.append("seed:" + version))
    for name in ("verify_native_dependencies", "wait_ready", "wait_http"):
        monkeypatch.setattr(diagnose_wyoming, name, lambda name=name: events.append(name))
    monkeypatch.setattr(
        diagnose_wyoming, "api", lambda action, **kwargs: {"token": "owned"} if action == "seed" else {"status": 200}
    )
    monkeypatch.setattr(diagnose_wyoming, "VALUES", [])
    monkeypatch.setattr(diagnose_wyoming, "config", lambda **kwargs: object())
    monkeypatch.setattr(diagnose_wyoming, "original_vars", lambda *args, **kwargs: {})

    def capture(label: str, token: str) -> None:
        events.append(label)
        if label == "after-original-selected" and evidence_failure in {"after", "both"}:
            raise OSError("synthetic private secondary failure")

    def write(name: str, value: Any) -> None:
        if name == "summary.json" and evidence_failure in {"summary", "both"}:
            raise OSError("synthetic private secondary failure")
        summaries[name] = value

    monkeypatch.setattr(diagnose_wyoming, "capture", capture)
    monkeypatch.setattr(diagnose_wyoming, "write", write)

    @contextmanager
    def peers() -> Any:
        events.append("peers-start")
        try:
            yield
        finally:
            events.append("peers-cleanup")

    monkeypatch.setattr(diagnose_wyoming, "peers", peers)

    def original(label: str, variables: Any) -> None:
        events.append(label)
        if label == "01-original-selected":
            raise AssertionError("original selection failed")

    monkeypatch.setattr(diagnose_wyoming, "original", original)
    with pytest.raises(AssertionError, match="original selection failed"):
        diagnose_wyoming.run()
    assert events == [
        "admit",
        "seed:2026.10.2",
        "00-original-existing-host-bootstrap",
        "verify_native_dependencies",
        "wait_ready",
        "wait_http",
        "peers-start",
        "before-original-selected",
        "01-original-selected",
        "after-original-selected",
        "peers-cleanup",
    ]
    assert summaries["api-onboarding.json"]["health"] == {"status": 200}
    if evidence_failure not in {"summary", "both"}:
        assert summaries["summary.json"]["selected_original_succeeded"] is False
        assert summaries["summary.json"]["after_diagnostics_written"] is (evidence_failure != "after")
        assert summaries["summary.json"]["typed_phases_executed"] == 0
    stderr = capsys.readouterr().err
    assert "synthetic private" not in stderr
    assert bool(stderr) is (evidence_failure is not None)


def test_actual_installed_wyoming_client_observes_owned_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    client = pytest.importorskip("wyoming.client", reason="explicit installed Wyoming1.10.2 oracle dependency")
    original = client.AsyncTcpClient
    with WyomingServer(0) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def connect(host: str, port: int) -> Any:
            assert host == "127.0.0.1"
            assert port == 10300
            return original(host, server.server_address[1])

        monkeypatch.setattr(client, "AsyncTcpClient", connect)
        try:
            result = asyncio.run(wyoming_protocol_probe.probe())
        finally:
            server.shutdown()
            thread.join(timeout=5)
        assert not thread.is_alive()
        assert result["version"] == "1.10.2"
        assert result["asr"][0]["installed"] is True
        assert result["asr"][0]["models"][0]["languages"] == ["en"]
        assert result["tts"][0]["installed"] is True
        assert result["tts"][0]["voices"][0]["languages"] == ["en"]
        assert server.describe_count == 1
        assert server.unexpected_count == 0


def test_native_dependency_failure_keeps_original_matter_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    written: dict[str, Any] = {}
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", "current")
    monkeypatch.setattr(diagnose_wyoming, "admit", lambda: events.append("admit"))
    monkeypatch.setattr(diagnose_wyoming, "seed", lambda version: events.append("seed"))
    monkeypatch.setattr(diagnose_wyoming, "original", lambda label, values: events.append(label))
    monkeypatch.setattr(diagnose_wyoming, "original_vars", lambda version: {})

    def native() -> None:
        raise ValueError("native dependency failed")

    monkeypatch.setattr(diagnose_wyoming, "verify_native_dependencies", native)
    monkeypatch.setattr(diagnose_wyoming, "diagnostics", lambda: events.append("matter-diagnostics"))
    monkeypatch.setattr(diagnose_wyoming, "api", lambda *args, **kwargs: pytest.fail("onboarding after native failure"))
    monkeypatch.setattr(diagnose_wyoming, "write", lambda name, value: written.update({name: value}))
    with pytest.raises(ValueError, match="native dependency failed"):
        diagnose_wyoming.run()
    assert events == ["admit", "seed", "00-original-existing-host-bootstrap", "matter-diagnostics"]
    assert written["summary.json"]["selected_original_started"] is False
