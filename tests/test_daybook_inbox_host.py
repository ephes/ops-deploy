"""Actual host entrypoint composition with owned FS and substituted OS probes.

These are local caller tests, not a root/GUI native qualification claim.
"""

from __future__ import annotations

import io
import json
import sys
import types
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.daybook_voice_memo_inbox.config import PACKAGE
from tests.test_daybook_inbox_controls import Probes
from tests.test_daybook_inbox_resources import declared as declared
from tests.test_daybook_inbox_resources import helper as helper


@pytest.fixture
def entrypoint(monkeypatch: pytest.MonkeyPatch, helper: Any) -> Any:
    for name, package, filename in (
        ("ops_daybook_observer", "ops_deploy.services.daybook_operations_runtime", "runtime_state.py"),
        ("ops_inbox_source", PACKAGE, "inbox_source.py"),
        ("ops_inbox_python", PACKAGE, "inbox_python.py"),
        ("ops_inbox_transfer", PACKAGE, "inbox_transfer.py"),
    ):
        module = types.ModuleType(name)
        monkeypatch.setitem(sys.modules, name, module)
        body = files(package).joinpath("files/" + filename).read_bytes()
        exec(compile(body, "<owned-dependency>", "exec"), module.__dict__)
    monkeypatch.setitem(sys.modules, "ops_inbox_resources", helper)
    result = types.ModuleType("owned_inbox_entrypoint")
    exec(
        compile(files(PACKAGE).joinpath("files/inbox_host.py").read_bytes(), "<actual-host-entrypoint>", "exec"),
        result.__dict__,
    )
    monkeypatch.setattr(result, "prerequisites", lambda *_: None)
    monkeypatch.setattr(result, "source_current", lambda *_: True)
    monkeypatch.setattr(
        result, "NativeProbes", lambda _: types.SimpleNamespace(account=types.SimpleNamespace(pw_uid=501))
    )
    monkeypatch.setattr(result, "NativeControls", Probes)
    return result


def call(
    entrypoint: Any, data: dict[str, Any], action: str, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> tuple[int, Any]:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(data).encode())))
    monkeypatch.setattr(sys, "argv", ["owned", action])
    rc = 0
    try:
        entrypoint.main()
    except SystemExit as error:
        rc = int(error.code or 0)
    result = capsys.readouterr()
    return rc, json.loads(result.out) if rc == 0 else result.err.strip()


def test_stopped_enabled_handoff_verifies_the_original_set_that_installer_wrote(
    entrypoint: Any,
    declared: dict[str, Any],
    helper: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    helper.prepare_directories(declared, Probes())
    # Final keeper expectation differs from the original disabled-first set.
    # Actual profile preservation is a separate assertion in the native fixture.
    rc, report = call(entrypoint, declared, "status", monkeypatch, capsys)
    assert rc == 0
    assert report["resources_current"] is False
    rc, _ = call(entrypoint, declared, "resources", monkeypatch, capsys)
    assert rc == 0
    rc, report = call(entrypoint, declared, "verify-installed", monkeypatch, capsys)
    assert rc == 0
    assert report["resources_current"] is True
    assert report["quiescent"] is True
    rc, failure = call(entrypoint, declared, "verify", monkeypatch, capsys)
    assert rc == 1
    assert failure == "inbox_not_current_after_converge"
    target = Path(declared["resources"][1]["path"])
    assert target.read_text() == declared["resources"][1]["content"]


def test_current_final_projection_verify_remains_distinct_and_does_not_write(
    entrypoint: Any,
    declared: dict[str, Any],
    helper: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    helper.prepare_directories(declared, Probes())
    helper.apply_resources(declared, Probes())
    for row in declared["final_resources"]:
        sys.modules["ops_inbox_filesystem"].put_resource(row)
    target = Path(declared["resources"][1]["path"])
    before = target.stat()
    rc, report = call(entrypoint, declared, "verify", monkeypatch, capsys)
    assert rc == 0
    assert report["resources_current"] is True
    assert report["install_resources_current"] is False
    assert (target.stat().st_ino, target.stat().st_mtime_ns, target.stat().st_ctime_ns) == (
        before.st_ino,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
