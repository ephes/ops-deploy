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
    version = "3.5.1"

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
    versions = {
        "fido2": "1.1.3",
        "gunicorn": "23.0.0",
        "psycopg": "3.3.4",
        "psycopg-c": "3.3.4",
        "psycopg-pool": "3.3.3",
    }
    monkeypatch.setattr(MODULE.importlib.metadata, "version", lambda name: versions.get(name, "synthetic"))
    monkeypatch.setattr(MODULE.sys, "version_info", (3, 14, 8))
    return direct


def test_healthy_metadata_avoids_application_import(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    installed(tmp_path, monkeypatch)
    assert MODULE.inspect_runtime(str(tmp_path)) == {
        "python": True,
        "application": True,
        "supporting": True,
        "gunicorn_repair": False,
    }


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


@pytest.mark.parametrize(
    ("version", "supporting"),
    [
        ("22.0.0", False),
        ("21.2", False),
        ("22.0.0rc1", False),
        ("23.0.0", True),
        ("26.2.0", True),
        ("23.0.1.post1+local.1", True),
        ("x1", False),
        ("23.invalid", False),
        ("23+f\u0131x", False),
        ("1!22.0.0", False),
        ("", False),
        (None, False),
    ],
)
def test_gunicorn_older_than_23_is_reinstalled(
    version: str | None, supporting: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The unit passes --forwarder-headers=, which gunicorn 22 refuses as an unknown argument.
    # None: a distribution without Version metadata (importlib.metadata on Python 3.14).
    installed(tmp_path, monkeypatch)
    original = MODULE.importlib.metadata.version
    monkeypatch.setattr(
        MODULE.importlib.metadata, "version", lambda name: version if name == "gunicorn" else str(original(name))
    )
    result = MODULE.inspect_runtime(str(tmp_path))
    assert result["supporting"] is supporting
    assert result["application"] is True
    assert result["gunicorn_repair"] is (version in (None, "x1", "23.invalid", "", "23+f\u0131x"))
