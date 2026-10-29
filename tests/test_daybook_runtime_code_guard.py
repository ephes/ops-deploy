"""Original source/env guard distinguishes active current code from replacement."""

from __future__ import annotations

import importlib.resources
import os
import subprocess
import sys
import types
from typing import Any
from unittest.mock import Mock

import pytest


@pytest.fixture
def helper(monkeypatch: Any) -> Any:
    dependency = types.ModuleType("ops_runtime_code_source")
    dependency.__dict__.update(
        SourceError=RuntimeError,
        SourceProbes=type("OwnedSourceProbes", (), {"runtime_current": Mock(return_value=True)}),
        inspect=Mock(),
        checkout_shape=Mock(return_value=False),
        cleanup_transfer=Mock(),
        publish_transfer=Mock(),
    )
    monkeypatch.setitem(sys.modules, dependency.__name__, dependency)
    module = types.ModuleType("owned_runtime_code_guard")
    body = (
        importlib.resources.files("ops_deploy.services.daybook_operations_runtime")
        .joinpath("files/runtime_code_guard.py")
        .read_bytes()
    )
    exec(compile(body, "<actual-runtime-code-guard>", "exec"), module.__dict__)
    return module


def probes(results: list[int]) -> Any:
    return types.SimpleNamespace(
        account=types.SimpleNamespace(pw_uid=os.geteuid()),
        run=Mock(side_effect=[subprocess.CompletedProcess([], code) for code in results]),
    )


def declaration() -> dict[str, str]:
    return {
        "owner": "user",
        "user": "owned-fixture",
        "label": "owned.runtime-keeper",
        "checkout": "/__owned_nonexistent_runtime_checkout",
        "revision": "a" * 40,
    }


def test_current_source_and_environment_do_not_probe_or_stop_active_keeper(helper: Any) -> None:
    state = {"current": True}
    helper.inspect.return_value = state
    driver = probes([])
    assert helper.inspect_code(declaration(), driver) == {**state, "replacing": False}
    driver.run.assert_not_called()


def test_drift_requires_original_unloaded_and_no_serving_process(helper: Any) -> None:
    state = {"current": False}
    helper.inspect.return_value = state
    driver = probes([113, 1])
    assert helper.inspect_code(declaration(), driver, planning=True) == {**state, "replacing": False}
    assert driver.run.call_args_list[0].args[0] == [
        "/bin/launchctl",
        "print",
        f"gui/{os.geteuid()}/owned.runtime-keeper",
    ]
    assert driver.run.call_args_list[1].args[0] == ["/usr/bin/pgrep", "-u", "owned-fixture", "-f", "[o]perations serve"]
    assert helper.inspect.call_args.kwargs == {"planning": True}


@pytest.mark.parametrize("codes", [[0, 1], [113, 0], [0, 0]])
def test_loaded_keeper_or_orphan_serving_process_refuses_replacement(helper: Any, codes: list[int]) -> None:
    helper.inspect.return_value = {"current": False}
    with pytest.raises(helper.RuntimeCodeError, match="in_use"):
        helper.inspect_code(declaration(), probes(codes))


@pytest.mark.parametrize(("codes", "calls"), [([77], 1), ([113, 77], 2)])
def test_tool_or_permission_failure_is_unavailable_not_quiescence(helper: Any, codes: list[int], calls: int) -> None:
    helper.inspect.return_value = {"current": False}
    driver = probes(codes)
    with pytest.raises(helper.RuntimeCodeError, match="unavailable"):
        helper.inspect_code(declaration(), driver)
    assert driver.run.call_count == calls


def test_wrong_connecting_identity_refuses_before_source_or_process_probes(helper: Any) -> None:
    driver = probes([])
    driver.account.pw_uid += 1
    with pytest.raises(helper.RuntimeCodeError, match="identity_mismatch"):
        helper.inspect_code(declaration(), driver)
    helper.inspect.assert_not_called()
    driver.run.assert_not_called()


def test_missing_pinned_python_is_explicit_managed_no_bin_work_after_quiescence(helper: Any) -> None:
    helper.inspect.return_value = {"current": False}
    driver = probes([113, 1, 1, 0])
    driver.managed = Mock()
    data = {**declaration(), "uv_bin": "/owned/uv", "python_version": "3.14.7"}
    helper.managed_python(data, driver)
    driver.managed.assert_called_once_with(["/owned/uv", "python", "install", "--no-bin", "3.14.7"])
    for call in driver.run.call_args_list[2:]:
        assert call.args[0] == ["/owned/uv", "python", "find", "--no-project", "3.14.7"]
        assert call.kwargs == {
            "user": True,
            "extra": {"UV_PYTHON_PREFERENCE": "only-managed", "UV_PYTHON_DOWNLOADS": "never"},
        }


def test_existing_python_is_not_reinstalled_and_failed_postcheck_stays_failed(helper: Any) -> None:
    helper.inspect.return_value = {"current": False}
    data = {**declaration(), "uv_bin": "/owned/uv", "python_version": "3.14.7"}
    driver = probes([113, 1, 0, 0])
    driver.managed = Mock()
    helper.managed_python(data, driver)
    driver.managed.assert_not_called()
    driver = probes([113, 1, 1, 1])
    driver.managed = Mock()
    with pytest.raises(helper.RuntimeCodeError, match="interpreter_unavailable"):
        helper.managed_python(data, driver)
    driver.managed.assert_called_once()


def test_actual_managed_context_matches_no_become_uv_contract_without_login_or_timeout(
    helper: Any, monkeypatch: Any
) -> None:
    driver = helper.RuntimeCodeProbes.__new__(helper.RuntimeCodeProbes)
    driver.account = types.SimpleNamespace(pw_uid=os.geteuid())
    driver.data = {"uv_bin": "/owned/uv", "checkout": "/owned/checkout"}
    run = Mock(return_value=subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""))
    monkeypatch.setattr(helper.subprocess, "run", run)
    monkeypatch.delenv("UV_PYTHON_DOWNLOADS", raising=False)
    monkeypatch.setenv("OWNED_EXISTING_CONTEXT", "kept")
    driver.managed(["/owned/uv", "sync", "--frozen", "--no-dev"])
    assert run.call_args.args[0] == ["/owned/uv", "sync", "--frozen", "--no-dev"]
    assert run.call_args.kwargs["env"]["UV_PYTHON_DOWNLOADS"] == "never"
    assert run.call_args.kwargs["env"]["UV_PYTHON_PREFERENCE"] == "only-managed"
    assert run.call_args.kwargs["env"]["OWNED_EXISTING_CONTEXT"] == "kept"
    assert "timeout" not in run.call_args.kwargs
    driver.managed(["/owned/uv", "python", "install", "--no-bin", "3.14.7"])
    assert "UV_PYTHON_DOWNLOADS" not in run.call_args.kwargs["env"]
    monkeypatch.setenv("UV_PYTHON_DOWNLOADS", "never")
    driver.managed(["/owned/uv", "python", "install", "--no-bin", "3.14.7"])
    assert run.call_args.kwargs["env"]["UV_PYTHON_DOWNLOADS"] == "never"
    run.return_value = subprocess.CompletedProcess([], 17, stdout=b"OWNED-DISCARDED", stderr=b"OWNED-DISCARDED")
    with pytest.raises(helper.RuntimeCodeError, match="runtime_code_command_failed"):
        driver.managed(["/owned/uv", "sync", "--frozen"])


@pytest.mark.parametrize(("rc", "expected"), [(0, True), (1, False), (2, None)])
def test_original_lock_check_rc_contract_never_treats_unavailable_as_drift(
    helper: Any, rc: int, expected: bool | None
) -> None:
    driver = helper.RuntimeCodeProbes.__new__(helper.RuntimeCodeProbes)
    driver.data = {
        "uv_bin": "/owned/uv",
        "checkout": "/owned/checkout",
        "python_version": "3.14.7",
        "python": "/owned/checkout/.venv/bin/python",
    }
    driver.run = Mock(return_value=subprocess.CompletedProcess([], rc))
    if expected is None:
        with pytest.raises(helper.RuntimeCodeError, match="lock_check_unavailable"):
            driver.locked_environment_current()
    else:
        assert driver.locked_environment_current() is expected
    argv = driver.run.call_args.args[0]
    assert argv.count("--no-python-downloads") == 1
    assert "--no-build" not in argv
    assert "--check" in argv
    assert "--frozen" in argv
    assert "--offline" in argv


def test_original_interpreter_home_must_match_exact_managed_selector(
    helper: Any, monkeypatch: Any, tmp_path: Any
) -> None:
    driver = helper.RuntimeCodeProbes.__new__(helper.RuntimeCodeProbes)
    driver.data = {
        "uv_bin": "/owned/uv",
        "checkout": "/owned/checkout",
        "python_version": "3.14.7",
        "python": "/owned/checkout/.venv/bin/python",
    }
    binary = tmp_path / "owned-python"
    binary.write_text("owned synthetic interpreter, never executed")
    binary.chmod(0o755)
    driver.data["python"] = str(binary)
    path = "/owned/uv/python/cpython-3.14.7-owned/bin/python3.14"
    driver.run = Mock(return_value=subprocess.CompletedProcess([], 0, path.encode()))
    observer: Any = types.ModuleType("ops_daybook_observer")
    observer.safe_file = Mock(return_value=(object(), b"home = /owned/uv/python/cpython-3.14.7-owned/bin\n"))
    monkeypatch.setitem(sys.modules, observer.__name__, observer)
    assert driver.runtime_current() is True
    observer.safe_file.return_value = (object(), b"home = /other/uv/python/cpython-3.14.7-owned/bin\n")
    assert driver.runtime_current() is False
    observer.safe_file.return_value = None
    assert driver.runtime_current() is False


def test_actual_original_role_uses_same_replacement_and_in_use_predicates() -> None:
    from pathlib import Path

    import jinja2.nativetypes
    import yaml

    role = os.environ.get("OPS_LIBRARY_PATH")
    if not role:
        pytest.skip("Actual role oracle is qualified explicitly")
    tasks = yaml.safe_load((Path(role) / "roles/daybook_operations_runtime_deploy/tasks/code.yml").read_text())
    facts = {key: value for task in tasks for key, value in task.get("ansible.builtin.set_fact", {}).items()}
    env = jinja2.nativetypes.NativeEnvironment()
    replacing: Any = env.from_string(facts["daybook_operations_runtime_code_replacing"])
    in_use: Any = env.from_string(facts["daybook_operations_runtime_code_in_use"])
    desired = "a" * 40
    for rc, installed, expected in [(0, desired, False), (0, "b" * 40, True), (1, "", False)]:
        assert (
            replacing.render(
                daybook_operations_runtime_code_revision={"rc": rc, "stdout": installed},
                daybook_operations_runtime_revision=desired,
            )
            is expected
        )
    for loaded, serving, expected in [(113, 1, False), (0, 1, True), (113, 0, True), (0, 0, True)]:
        assert (
            in_use.render(
                daybook_operations_runtime_code_label={"rc": loaded},
                daybook_operations_runtime_code_serving={"rc": serving},
            )
            is expected
        )
    pinned = next(task for task in tasks if task["name"] == "code | Install the pinned interpreter")
    assert pinned["ansible.builtin.command"]["argv"][1:4] == ["python", "install", "--no-bin"]
    assert pinned["environment"]["UV_PYTHON_PREFERENCE"] == "only-managed"
    sync = next(task for task in tasks if task["name"] == "code | Synchronize the locked environment")
    assert sync["environment"]["UV_PYTHON_DOWNLOADS"] == "never"
    assert sync["ansible.builtin.command"]["argv"][1:4] == ["sync", "--frozen", "--no-dev"]


def test_uv_find_check_install_sync_keep_same_inherited_location_context(helper: Any, monkeypatch: Any) -> None:
    driver = helper.RuntimeCodeProbes.__new__(helper.RuntimeCodeProbes)
    driver.account = types.SimpleNamespace(pw_uid=os.geteuid())
    driver.data = {"uv_bin": "/owned/uv", "checkout": "/owned/checkout"}
    selected = {
        "XDG_DATA_HOME": "/owned/xdg-data",
        "UV_PYTHON_INSTALL_DIR": "/owned/uv/python",
        "UV_CACHE_DIR": "/owned/uv/cache",
        "UV_CONFIG_FILE": "/owned/uv/config.toml",
    }
    for key, value in selected.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("UV_PYTHON_DOWNLOADS", raising=False)
    execute = Mock(return_value=subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""))
    monkeypatch.setattr(helper.subprocess, "run", execute)
    for argv in (["/owned/uv", "python", "find", "--no-project", "3.14.7"], ["/owned/uv", "sync", "--check"]):
        driver.run(argv, user=True)
    driver.managed(["/owned/uv", "python", "install", "--no-bin", "3.14.7"])
    driver.managed(["/owned/uv", "sync", "--frozen"])
    assert execute.call_count == 4
    for call in execute.call_args_list:
        assert {key: call.kwargs["env"][key] for key in selected} == selected
        assert call.kwargs["env"]["UV_PROJECT_ENVIRONMENT"] == "/owned/checkout/.venv"
        assert call.kwargs["env"]["UV_PYTHON_PREFERENCE"] == "only-managed"
    assert all(call.kwargs["env"]["UV_PYTHON_DOWNLOADS"] == "never" for call in execute.call_args_list[:2])
    assert "UV_PYTHON_DOWNLOADS" not in execute.call_args_list[2].kwargs["env"]
    assert execute.call_args_list[3].kwargs["env"]["UV_PYTHON_DOWNLOADS"] == "never"


@pytest.mark.parametrize("fault", ["missing-selector", "home-drift", "missing-venv-python"])
def test_original_interpreter_drift_skips_lock_check_entirely(helper: Any, monkeypatch: Any, fault: str) -> None:
    driver = helper.RuntimeCodeProbes.__new__(helper.RuntimeCodeProbes)
    driver.data = {
        "uv_bin": "/owned/uv",
        "checkout": "/owned/checkout",
        "python_version": "3.14.7",
        "python": "/owned/checkout/.venv/bin/python",
    }
    driver.run = Mock(
        return_value=subprocess.CompletedProcess(
            [], 1 if fault == "missing-selector" else 0, b"/owned/uv/python/cpython-3.14.7-owned/bin/python3.14"
        )
    )
    driver.locked_environment_current = Mock(side_effect=AssertionError("must not check lock on interpreter drift"))
    observer: Any = types.ModuleType("ops_daybook_observer")
    body = (
        b"home = /owned/uv/python/cpython-3.14.7-owned/bin\n"
        if fault == "missing-venv-python"
        else b"home = /other/python/bin\n"
    )
    observer.safe_file = Mock(return_value=(object(), body))
    monkeypatch.setitem(sys.modules, observer.__name__, observer)
    assert driver.runtime_current() is False
    assert driver.run.call_count == 1
    driver.locked_environment_current.assert_not_called()
