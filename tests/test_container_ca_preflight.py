"""Exercise the actual precondition shell against owned disposable files."""

import subprocess
from pathlib import Path, PurePosixPath

import pytest
from pyinfra.operations import server

from ops_deploy.helpers import container_ca


@pytest.mark.parametrize("invalid", [None, "bundle.pem", "manifest.json", "empty"])
def test_prepared_store_shape_is_checked_before_deploy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid: str | None,
) -> None:
    store = tmp_path / "service"
    store.mkdir()
    (store / "bundle.pem").write_text("fixture certificate data")
    (store / "manifest.json").write_text("{}")
    (store / "empty").mkdir()
    if invalid == "empty":
        (store / "empty").rmdir()
        (store / "empty").write_text("not a directory")
    elif invalid is not None:
        (store / invalid).write_text("")
    commands: list[str] = []

    def capture(*, name: str, commands: list[str]) -> None:
        observed.extend(commands)

    observed = commands
    monkeypatch.setattr(server, "shell", capture)
    monkeypatch.setattr(container_ca, "mark_read_only", lambda _operation: None)
    container_ca.require_container_ca_stores(PurePosixPath(str(tmp_path)), ("service",))
    assert len(commands) == 1
    result = subprocess.run(["/bin/sh", "-c", commands[0]], capture_output=True, text=True)
    assert (result.returncode == 0) == (invalid is None)
    if invalid is not None:
        assert "prepare" in result.stderr.lower()
