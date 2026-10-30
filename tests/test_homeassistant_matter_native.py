"""Fixture-only original native-library provenance and fail-closed boundaries."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.integration.homeassistant import fixture, matter_native, matter_ready


@pytest.mark.parametrize("failure", [None, "version", "hash", "resolver", "dlopen"])
def test_original_loader_requires_qualified_source_and_native_loading(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str | None
) -> None:
    native = tmp_path / "chip/_ChipDeviceCtrl.so"
    native.parent.mkdir()
    native.write_bytes(b"owned synthetic library")
    expected = hashlib.sha256(native.read_bytes()).hexdigest()
    monkeypatch.setattr(matter_native, "HASHES", {"chip/_ChipDeviceCtrl.so": "bad" if failure == "hash" else expected})
    monkeypatch.setattr(
        "tests.integration.homeassistant.matter_native.importlib.metadata.version",
        lambda name: "wrong" if failure == "version" else matter_native.VERSIONS[name],
    )
    monkeypatch.setattr(
        "tests.integration.homeassistant.matter_native.importlib.metadata.distribution",
        lambda name: SimpleNamespace(locate_file=lambda p: tmp_path / p),
    )
    calls = []

    def load(name: str) -> Any:
        calls.append("original-resolver")
        assert name == "chip.native"
        return SimpleNamespace(
            Library=SimpleNamespace(CONTROLLER="controller"),
            FindNativeLibraryPath=lambda selected: str(tmp_path / "other.so" if failure == "resolver" else native),
        )

    def dlopen(path: str) -> None:
        calls.append("dlopen")
        assert Path(path) == native
        if failure == "dlopen":
            raise OSError("owned missing native dependency")

    monkeypatch.setattr("tests.integration.homeassistant.matter_native.ctypes.CDLL", dlopen)
    monkeypatch.setattr("tests.integration.homeassistant.matter_native.importlib.import_module", load)
    if failure:
        with pytest.raises((RuntimeError, OSError)):
            matter_native.inspect_native()
    else:
        assert matter_native.inspect_native()["dlopen"] is True
    assert calls == (
        []
        if failure in ("version", "hash")
        else ["original-resolver"]
        if failure == "resolver"
        else ["original-resolver", "dlopen"]
    )


@pytest.mark.parametrize(
    "failure", [None, "exit", "truncated", "timed_out", "missing-proof", "noise", "duplicate", "non-dict", "malformed"]
)
def test_bounded_commands_retain_failure_and_require_real_loader_proof(
    monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    calls = []
    receipts = {}

    def command(argv: list[str], *, timeout: float) -> dict[str, Any]:
        assert timeout == 15
        calls.append(argv)
        result = {
            "exit": 0,
            "truncated": False,
            "timed_out": False,
            "output": matter_native.MARKER + json.dumps({"dlopen": failure != "missing-proof"}),
        }
        if failure in ("exit", "truncated", "timed_out"):
            result[failure] = 1 if failure == "exit" else True
        if failure == "noise":
            result["output"] = "incidental original warning\n" + str(result["output"]) + "\nincidental native warning\n"
        elif failure == "duplicate":
            result["output"] = str(result["output"]) + "\n" + str(result["output"])
        elif failure in ("non-dict", "malformed"):
            result["output"] = matter_native.MARKER + ("[]" if failure == "non-dict" else "{")
        return result

    monkeypatch.setattr(matter_ready, "bounded_command", command)
    monkeypatch.setattr(fixture, "write", lambda name, value: receipts.update({name: value}))
    if failure and failure != "noise":
        with pytest.raises(RuntimeError):
            matter_native.verify_native_dependencies()
    else:
        matter_native.verify_native_dependencies()
    assert len(calls) == 3
    assert calls[2][:4] == ["runuser", "-u", "homeassistant", "--"]
    assert calls[2][4:7] == [str(matter_native.VENV / "bin/python"), "-I", "-B"]
    assert set(receipts["matter-native-dependencies.json"]) == {"distro", "dynamic", "loader"}
