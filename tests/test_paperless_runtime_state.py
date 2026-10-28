"""Distribution-only runtime inspection: no Paperless/backend initializer."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

MODULE_SPEC = importlib.util.spec_from_file_location(
    "paperless_runtime_state", Path(__file__).parents[1] / "src/ops_deploy/services/paperless/files/runtime_state.py"
)
assert MODULE_SPEC is not None
assert MODULE_SPEC.loader is not None
MODULE = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(MODULE)


class Package:
    version = "3.2.1"

    def __init__(self: Any, body: Any) -> None:
        self.body = body

    def read_text(self: Any, name: str) -> str:
        assert name == "direct_url.json"
        return json.dumps(self.body)


def installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    (tmp_path / "src/paperless").mkdir(parents=True)
    # Importing this source is forbidden by the test fixture itself.
    (tmp_path / "src/paperless/__init__.py").write_text("raise RuntimeError('application import forbidden')\n")
    (tmp_path / "src/manage.py").write_text("raise RuntimeError('application execution forbidden')\n")
    direct = {"url": tmp_path.as_uri(), "dir_info": {"editable": True}}
    monkeypatch.setattr(MODULE.importlib.metadata, "distribution", lambda name: Package(direct))
    versions = {"fido2": "1.1.3", "psycopg": "3.3.4", "psycopg-c": "3.3.4", "psycopg-pool": "3.3.1"}
    monkeypatch.setattr(MODULE.importlib.metadata, "version", lambda name: versions.get(name, "synthetic"))
    monkeypatch.setattr(MODULE.sys, "version_info", (3, 14, 8))
    return direct


def test_healthy_metadata_avoids_application_import(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    installed(tmp_path, monkeypatch)
    assert MODULE.inspect_runtime(str(tmp_path)) == {"python": True, "application": True, "supporting": True}


@pytest.mark.parametrize("broken", ["wrong-source", "noneditable", "missing-source", "wrong-python", "missing-support"])
def test_known_runtime_recovery_signals(broken: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    direct = installed(tmp_path, monkeypatch)
    if broken == "wrong-source":
        direct["url"] = "file:///unrelated"
    elif broken == "noneditable":
        direct["dir_info"]["editable"] = False
    elif broken == "missing-source":
        (tmp_path / "src/manage.py").unlink()
    elif broken == "wrong-python":
        monkeypatch.setattr(MODULE.sys, "version_info", (3, 12, 0))
    else:

        def missing(name: str) -> str:
            raise MODULE.importlib.metadata.PackageNotFoundError(name)

        monkeypatch.setattr(MODULE.importlib.metadata, "version", missing)
    result = MODULE.inspect_runtime(str(tmp_path))
    field = "python" if broken == "wrong-python" else "supporting" if broken == "missing-support" else "application"
    assert result[field] is False


@pytest.mark.parametrize("missing", ["psycopg", "psycopg-c", "psycopg-pool"])
def test_postgres_extra_is_required_without_import_or_connection(
    missing: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed(tmp_path, monkeypatch)
    original = MODULE.importlib.metadata.version

    def version(name: str) -> str:
        if name == missing:
            raise MODULE.importlib.metadata.PackageNotFoundError(name)
        return str(original(name))

    monkeypatch.setattr(MODULE.importlib.metadata, "version", version)
    assert MODULE.inspect_runtime(str(tmp_path))["application"] is False
