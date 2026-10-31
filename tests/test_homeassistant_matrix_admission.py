"""Exercise actual matrix admission before any original or typed guest setup."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.integration.homeassistant import harness, matrix


@pytest.mark.parametrize("case", ["current", "upgrade"])
@pytest.mark.parametrize("revision", [harness.ORIGINAL_LIBRARY_SHA, "9d88de8f9d04498bbb6d71174792534e87db4a88"])
def test_actual_admission_requires_corrected_source_before_matrix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, case: str, revision: str
) -> None:
    owned = "homeassistant-123-1"
    for name, body in {
        "proc/1/comm": "systemd\n",
        "etc/ops-homeassistant-owned-id": owned,
        "etc/machine-id": "synthetic-machine",
        "var/tmp/homeassistant-owned-guest.json": json.dumps({"run": owned}),
    }.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "installed-artifact.json").write_text(
        json.dumps({"implementation_sha": "owned-source", "machine_id": "synthetic-machine"})
    )
    monkeypatch.setattr(harness, "Path", lambda name: tmp_path / name.lstrip("/"))
    monkeypatch.setattr(harness, "ROOT", tmp_path / "fixture")
    monkeypatch.setattr(harness, "EVIDENCE", evidence)
    monkeypatch.setattr("tests.integration.homeassistant.harness.os.getuid", lambda: 0)
    monkeypatch.setattr("tests.integration.homeassistant.harness.os.uname", lambda: SimpleNamespace(machine="x86_64"))
    for name, value in {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "HOMEASSISTANT_OWNED_ID": owned,
        "IMPLEMENTATION_SHA": "owned-source",
        "HOMEASSISTANT_FIXTURE_CASE": case,
    }.items():
        monkeypatch.setenv(name, value)
    commands: list[tuple[str, ...]] = []
    calls: list[str] = []

    def original_head(*args: str) -> SimpleNamespace:
        commands.append(args)
        return SimpleNamespace(stdout=revision + "\n")

    monkeypatch.setattr(harness, "command", original_head)
    monkeypatch.setattr(matrix, "run", lambda: calls.append("matrix"))
    monkeypatch.setattr(harness, "write", lambda *args: calls.append("summary"))
    if revision == harness.ORIGINAL_LIBRARY_SHA:
        harness.main()
        assert calls == ["matrix", "summary"]
    else:
        with pytest.raises(AssertionError):
            harness.main()
        assert calls == []
    assert commands == [
        ("git", "-C", str(tmp_path / "fixture/collections/ansible_collections/local/ops_library"), "rev-parse", "HEAD")
    ]
