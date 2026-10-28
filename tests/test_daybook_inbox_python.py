"""Original root uv selection and refusal contracts, no root/app/host execution."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import types
from importlib.resources import files
from typing import Any
from unittest.mock import Mock

import pytest

from ops_deploy.services.daybook_voice_memo_inbox.config import PACKAGE


@pytest.fixture
def helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    for name, package, resource in (
        ("ops_inbox_controls", PACKAGE, "files/inbox_controls.py"),
        ("ops_daybook_observer", "ops_deploy.services.daybook_operations_runtime", "files/runtime_state.py"),
    ):
        module = types.ModuleType(name)
        monkeypatch.setitem(sys.modules, name, module)
        source = files(package).joinpath(resource)
        exec(compile(source.read_bytes(), str(source), "exec"), module.__dict__)
    spec = importlib.util.spec_from_file_location(
        "owned_inbox_python", str(files(PACKAGE).joinpath("files/inbox_python.py"))
    )
    assert spec
    assert spec.loader
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def data() -> dict[str, str]:
    return {
        "checkout": "/Library/Application Support/Daybook/voice-memo-inbox/daybook",
        "python_install_dir": "/Library/Application Support/Daybook/python",
        "python_version": "3.14.7",
        "uv_bin": "/opt/homebrew/bin/uv",
    }


def test_original_root_home_tree_and_download_selector_are_bound(helper: Any) -> None:
    assert helper.root_environment(data()) == {
        "HOME": "/var/root",
        "UV_NO_PROGRESS": "1",
        "UV_PYTHON_INSTALL_DIR": data()["python_install_dir"],
        "UV_PYTHON_PREFERENCE": "only-managed",
        "UV_PROJECT_ENVIRONMENT": data()["checkout"] + "/.venv",
        "UV_PYTHON_DOWNLOADS": "never",
    }
    assert "UV_PYTHON_DOWNLOADS" not in helper.root_environment(data(), downloads=True)
    with pytest.raises(helper.InboxPythonError, match="tree_mismatch"):
        helper.root_environment({**data(), "python_install_dir": "/Users/owned/.local/share/uv/python"})


def test_managed_install_preserves_inherited_policy_and_frozen_sync_disables_downloads(
    helper: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("UV_PYTHON_DOWNLOADS", "never")
    called = Mock(return_value=subprocess.CompletedProcess([], 0, stdout=b"owned metadata", stderr=b""))
    monkeypatch.setattr(helper.subprocess, "run", called)
    helper.managed(data(), [data()["uv_bin"], "python", "install", "--no-bin", "3.14.7"], downloads=True)
    assert called.call_args.kwargs["env"]["UV_PYTHON_DOWNLOADS"] == "never"
    monkeypatch.delenv("UV_PYTHON_DOWNLOADS")
    helper.managed(data(), [data()["uv_bin"], "python", "install", "--no-bin", "3.14.7"], downloads=True)
    assert "UV_PYTHON_DOWNLOADS" not in called.call_args.kwargs["env"]
    assert called.call_args.kwargs["env"]["HOME"] == "/var/root"
    assert "timeout" not in called.call_args.kwargs
    helper.managed(data(), [data()["uv_bin"], "sync", "--frozen", "--no-dev", "--python", "3.14.7"])
    assert called.call_args.kwargs["env"]["UV_PYTHON_DOWNLOADS"] == "never"
    assert called.call_args.kwargs["env"]["UV_PYTHON_INSTALL_DIR"] == data()["python_install_dir"]


def test_managed_failure_discards_child_diagnostic_bodies(helper: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    called = Mock(
        return_value=subprocess.CompletedProcess([], 1, stdout=b"PRIVATE-OWNED-STDOUT", stderr=b"PRIVATE-OWNED-STDERR")
    )
    monkeypatch.setattr(helper.subprocess, "run", called)
    with pytest.raises(helper.InboxPythonError, match=r"^inbox_python_managed_command_failed$"):
        helper.managed(data(), ["/owned/failing-command"])


def test_non_root_install_refuses_before_quiescence_or_any_command(
    helper: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper.os, "geteuid", lambda: 501)
    called = Mock(side_effect=AssertionError("must not probe or run"))
    monkeypatch.setattr(helper, "require_inbox_quiescent", called)
    monkeypatch.setattr(helper.subprocess, "run", called)
    with pytest.raises(helper.InboxPythonError, match="original_root_install"):
        helper.converge_python(data(), object(), object())
    called.assert_not_called()


def test_exact_original_uv_interpreter_path_is_accepted_and_other_minor_is_refused(
    helper: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pathlib import Path

    monkeypatch.setattr(helper, "require_root_inputs", lambda _: None)
    exact = data()["python_install_dir"] + "/cpython-3.14.7-macos-aarch64-none/bin/python3.14"
    monkeypatch.setattr(helper, "managed", lambda *_args, **_kwargs: (exact + "\n").encode())
    probes = Mock()
    probes.protected_binary_hash.return_value = b"a" * 32
    assert helper.interpreter_source(data(), probes) == (Path(exact), b"a" * 32)
    probes.protected_binary_hash.assert_called_once_with(exact, copied=False)
    probes.reset_mock()
    monkeypatch.setattr(helper, "managed", lambda *_args, **_kwargs: exact.replace("python3.14", "python3x14").encode())
    with pytest.raises(helper.InboxPythonError, match="source_path_invalid"):
        helper.interpreter_source(data(), probes)
    probes.protected_binary_hash.assert_not_called()
