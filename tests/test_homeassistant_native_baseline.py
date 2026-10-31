"""Existing-host dependency seed boundaries; no inventory/native execution."""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.integration.homeassistant import matrix, prerequisites, seed_requirements


@pytest.mark.parametrize(("case", "version"), [("current", "2026.10.2"), ("upgrade", "2026.10.1")])
def test_selected_dependencies_precede_unchanged_original_bootstrap(
    monkeypatch: pytest.MonkeyPatch, case: str, version: str
) -> None:
    calls = []
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", case)
    monkeypatch.setattr(matrix, "default_ipv4", lambda: "192.0.2.8")
    monkeypatch.setattr(matrix, "seed", lambda selected: calls.append(("seed", selected)))

    def original(label: str, variables: dict[str, Any]) -> None:
        calls.append((label, variables["homeassistant_package_spec"]))
        raise RuntimeError("owned stop before any role invocation")

    monkeypatch.setattr(matrix, "original", original)
    with pytest.raises(RuntimeError, match="owned stop"):
        matrix.run()
    assert calls == [("seed", version), ("00-original-existing-host-bootstrap", "homeassistant==" + version)]


def test_dependency_seed_failure_prevents_original_and_any_matrix_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", "current")

    def fail(_: str) -> None:
        raise RuntimeError("owned dependency failure")

    monkeypatch.setattr(matrix, "seed", fail)
    monkeypatch.setattr(matrix, "original", lambda *args, **kwargs: pytest.fail("original must not run"))
    with pytest.raises(RuntimeError, match="owned dependency failure"):
        matrix.run()


@pytest.mark.parametrize("failure", [None, "venv", "package", "requirements"])
def test_seed_commands_use_owned_account_selected_package_and_retain_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str | None
) -> None:
    library = tmp_path / "owned-library"
    monkeypatch.setenv("OPS_LIBRARY_PATH", str(library))
    calls: list[tuple[str, ...]] = []
    receipts: dict[str, Any] = {}
    labels = ["venv", "package", "requirements"]

    def command(*argv: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        label = labels[len(calls)]
        calls.append(argv)
        assert kwargs["check"] is False
        assert 0 < kwargs["timeout"] <= 900
        return subprocess.CompletedProcess(
            argv,
            7 if label == failure else 0,
            json.dumps(
                {
                    "matter_config_flow_import": True,
                    "original_environment": {
                        "python_exists": True,
                        "python_stdout": "Python 3.14.8",
                        "pip_status": 0,
                        "legacy_matter_status": 1,
                        "application_exists": True,
                        "installed_version": "2026.10.1",
                    },
                }
            ),
            "owned diagnostic",
        )

    monkeypatch.setattr(prerequisites, "command", command)
    monkeypatch.setattr(prerequisites, "write", lambda name, value: receipts.update({name: value}))
    config = tmp_path / "site/config"
    if failure:
        with pytest.raises(RuntimeError, match=f"owned existing-host {failure} seed failed"):
            prerequisites.seed_application(config, "2026.10.1")
        assert len(calls) == labels.index(failure) + 1
        assert receipts["existing-host-" + failure + ".json"]["returncode"] == 7
    else:
        assert prerequisites.seed_application(config, "2026.10.1")["matter_config_flow_import"] is True
        assert len(calls) == 3
    for argv in calls:
        assert argv[:8] == (
            "runuser",
            "-u",
            "homeassistant",
            "--",
            "/usr/bin/env",
            "-u",
            "OPS_DEPLOY_PATH",
            "HOME=/home/homeassistant",
        )
        assert argv[8] == "OPS_LIBRARY_PATH=" + str(library)
    if len(calls) > 1:
        assert calls[1][-1] == "homeassistant==2026.10.1"
    assert "--seed" in calls[0]
    assert "3.14.8" in calls[0]


@pytest.mark.parametrize("failure", ["hash", "requirements", "import", None])
def test_original_loader_failure_never_claims_import_success_and_stops_owned_context(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str | None
) -> None:
    calls = []
    source = tmp_path / "requirements.py"
    source.write_bytes(b"owned original source")
    monkeypatch.setattr(seed_requirements, "original_environment", lambda selected: {})
    monkeypatch.setattr(
        seed_requirements,
        "SOURCE_HASHES",
        {
            "requirements.py": "mismatch" if failure == "hash" else hashlib.sha256(source.read_bytes()).hexdigest(),
        },
    )
    monkeypatch.setattr(seed_requirements, "platform", SimpleNamespace(python_version=lambda: "3.14.8"))

    async def stop(**kwargs: Any) -> None:
        calls.append("stop")

    async def requirements(hass: Any, domain: str) -> Any:
        assert domain == "matter"
        calls.append("requirements")
        if failure == "requirements":
            raise RuntimeError("owned requirement failure")
        return SimpleNamespace(domain="matter")

    def load(name: str) -> Any:
        if name == "homeassistant":
            return SimpleNamespace(__file__=str(tmp_path / "__init__.py"))
        if name == "homeassistant.core":
            return SimpleNamespace(HomeAssistant=lambda path: SimpleNamespace(async_stop=stop))
        if name == "homeassistant.loader":
            return SimpleNamespace(async_setup=lambda hass: calls.append("setup"))
        if name == "homeassistant.requirements":
            return SimpleNamespace(
                async_get_integration_with_requirements=requirements,
                _async_get_manager=lambda hass: SimpleNamespace(integrations_with_reqs={}),
            )
        assert name == "homeassistant.components.matter.config_flow"
        calls.append("import")
        if failure == "import":
            raise ImportError("owned missing dependency")
        return None

    monkeypatch.setattr(
        seed_requirements,
        "importlib",
        SimpleNamespace(
            import_module=load,
            metadata=SimpleNamespace(version=lambda name: "2026.10.2"),
        ),
    )
    if failure:
        with pytest.raises((RuntimeError, ImportError)):
            asyncio.run(seed_requirements.initialize(tmp_path, "2026.10.2"))
    else:
        result = asyncio.run(seed_requirements.initialize(tmp_path, "2026.10.2"))
        assert result["matter_config_flow_import"] is True
        assert result["application_started"] is False
    assert (
        calls
        == {
            "hash": [],
            "requirements": ["setup", "requirements", "stop"],
            "import": ["setup", "requirements", "import", "stop"],
            None: ["setup", "requirements", "import", "stop"],
        }[failure]
    )


@pytest.mark.parametrize(("pip_status", "legacy_status"), [(1, 1), (0, 0)])
def test_seed_refuses_an_environment_the_original_role_would_replace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, pip_status: int, legacy_status: int
) -> None:
    monkeypatch.setenv("OPS_LIBRARY_PATH", str(tmp_path / "owned-library"))
    response = {
        "matter_config_flow_import": True,
        "original_environment": {
            "python_exists": True,
            "python_stdout": "Python 3.14.8",
            "pip_status": pip_status,
            "legacy_matter_status": legacy_status,
            "application_exists": True,
            "installed_version": "2026.10.1",
        },
    }
    receipts = []
    monkeypatch.setattr(
        prerequisites, "command", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, json.dumps(response), "")
    )
    monkeypatch.setattr(prerequisites, "write", lambda name, value: receipts.append(value))
    with pytest.raises(RuntimeError, match="would be replaced"):
        prerequisites.seed_application(tmp_path / "site/config", "2026.10.1")
    assert len(receipts) == 3
    assert json.loads(receipts[-1]["stdout"])["original_environment"]["legacy_matter_status"] == legacy_status
