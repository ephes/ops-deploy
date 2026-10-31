"""Real SDK recording and owned diagnostic boundaries, without native claims."""

from __future__ import annotations

import runpy
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.homeassistant import HomeAssistantDeployConfig, interpreter
from tests.integration.homeassistant import (
    diagnose_interpreter,
    fixture,
    frozen_interpreter,
    harness,
    interpreter_probe,
    matrix,
)


@pytest.mark.parametrize("failure", [None, "admit", "matrix"])
def test_module_entry_uses_canonical_phase_receipts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str | None
) -> None:
    phases: list[dict[str, Any]] = []
    receipts: dict[str, Any] = {}
    monkeypatch.setattr(harness, "PHASES", phases)
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", "upgrade")
    monkeypatch.setattr(harness, "ROOT", tmp_path)
    monkeypatch.setattr(harness, "EVIDENCE", tmp_path)
    monkeypatch.setattr(fixture, "EVIDENCE", tmp_path)
    fields = ("programs", "public_custom_component", "private_file_metadata", "units", "packages", "installed")
    monkeypatch.setattr(harness, "snapshot", lambda: harness.Snapshot({key: [] for key in fields}, {}))
    monkeypatch.setattr(harness, "deploy_homeassistant", lambda cfg: None)

    def admit() -> None:
        if failure == "admit":
            raise RuntimeError("owned admission failure")

    def run() -> None:
        matrix.typed("03-normal-plan", HomeAssistantDeployConfig(), plan=True)  # type: ignore[attr-defined]
        if failure == "matrix":
            raise RuntimeError("owned later phase failure")

    monkeypatch.setattr(harness, "admit", admit)
    monkeypatch.setattr(matrix, "run", run)
    monkeypatch.setattr(harness, "write", lambda name, data: receipts.update({name: data}))
    if failure:
        with (
            pytest.warns(RuntimeWarning, match="found in sys.modules"),
            pytest.raises(RuntimeError, match="owned"),
        ):
            runpy.run_module(harness.__name__, run_name="__main__")
    else:
        with pytest.warns(RuntimeWarning, match="found in sys.modules"):
            runpy.run_module(harness.__name__, run_name="__main__")
    if failure == "admit":
        assert receipts == {}
        assert phases == []
    else:
        assert receipts["summary.json"]["completed"] is (failure is None)
        recorded = receipts["summary.json"]["phases"]
        assert len(recorded) == 1
        assert recorded[0]["label"] == "03-normal-plan"
        assert recorded[0]["managed"] == []
        assert receipts["03-normal-plan.json"]["comparisons"] == dict.fromkeys(
            (*fields, "private_file_bodies_equal"), True
        )


@pytest.mark.parametrize("available", [True, False])
def test_actual_local_connector_records_frozen_find_and_operation_completion(
    monkeypatch: pytest.MonkeyPatch, available: bool
) -> None:
    def command(cfg: Any, action: str) -> str:
        if action == "install":
            return "printf 'owned install complete\\n'"
        return "printf '/owned/python\\n'" if available else "printf 'owned find failure\\n' >&2; exit 7"

    monkeypatch.setattr(interpreter, "interpreter_command", command)
    monkeypatch.setattr(frozen_interpreter.load(), "interpreter_command", command)
    monkeypatch.setenv("UV_OWNED_TEST", "value must never be exported")
    monkeypatch.setenv("XDG_OWNED_TEST", "private value")
    report = interpreter_probe.probe(install=False)
    assert report["error"] is None
    assert report["find"] == ("/owned/python" if available else None)
    assert report["reviewed_find"] == report["find"]
    assert report["operations"] == [{"complete": True, "executed": True, "success": True}]
    assert "UV_OWNED_TEST" in report["environment_keys"]
    assert "XDG_OWNED_TEST" in report["environment_keys"]
    assert "value must never be exported" not in str(report)
    assert len(report["commands"]) == 2
    assert all(item["success"] is available for item in report["commands"])
    assert all(item["stderr"] == ("" if available else "owned find failure") for item in report["commands"])
    install = interpreter_probe.probe(install=True)
    if available:
        assert install["error"] is None
        assert install["operations"] == [{"complete": True, "executed": False, "success": True}]
    else:
        # Preserve the existing generator accounting defect as diagnostic
        # evidence. This is deliberately not a repaired production operation.
        assert "still unavailable" in install["error"]
        assert install["operations"] == [{"complete": False, "executed": False, "success": None}]
        assert install["failed_hosts"] == []
        assert any("install complete" in item["stdout"] for item in install["commands"])


@pytest.mark.parametrize("failure", [None, "timeout", "truncated"])
def test_diagnostic_capture_retains_output_before_bound_failure(
    monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    receipts = {}
    result = {
        "exit": 7,
        "output": "owned stderr",
        "timed_out": failure == "timeout",
        "truncated": failure == "truncated",
    }
    monkeypatch.setattr(diagnose_interpreter, "bounded_command", lambda argv, timeout: result)
    monkeypatch.setattr(diagnose_interpreter, "write", lambda name, value: receipts.update({name: value}))
    if failure:
        with pytest.raises(RuntimeError, match="bound"):
            diagnose_interpreter.capture("owned", ["owned-fixed-command"], 1)
    else:
        assert diagnose_interpreter.capture("owned", ["owned-fixed-command"], 1)["exit"] == 7
    assert receipts["owned.json"]["output"] == "owned stderr"


def test_diagnostic_admission_failure_stops_all_work(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse() -> None:
        raise RuntimeError("owned admission refusal")

    monkeypatch.setattr(diagnose_interpreter, "admit", refuse)
    monkeypatch.setattr(diagnose_interpreter, "seed_uv_account", lambda: pytest.fail("must not seed"))
    monkeypatch.setattr(diagnose_interpreter, "write", lambda *args: pytest.fail("must not write"))
    with pytest.raises(RuntimeError, match="admission"):
        diagnose_interpreter.run()


def test_reviewed_transport_oracle_is_exact() -> None:
    import hashlib

    from tests.integration.homeassistant import reviewed_transport

    assert (
        hashlib.sha256(Path(reviewed_transport.__file__).read_bytes()).hexdigest()
        == "95a033a67cb36b3b879babf85bbfedd2b6ec5d034dab8c5150c55150c6c48183"
    )


def test_direct_probe_admission_precedes_all_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tests.integration.homeassistant.interpreter_probe.os.getuid", lambda: 1000)
    monkeypatch.setattr(interpreter_probe, "probe", lambda **kwargs: pytest.fail("must not probe"))
    with pytest.raises(AssertionError):
        interpreter_probe.main()


@pytest.mark.parametrize("failure", [None, "wrong-case", "seed", "interpreter-seed", "interpreter-sdk-process"])
def test_diagnostic_sequence_and_failure_receipts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str | None
) -> None:
    from types import SimpleNamespace

    receipts: dict[str, Any] = {}
    calls = []
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", "upgrade" if failure == "wrong-case" else "current")
    monkeypatch.setattr(diagnose_interpreter, "admit", lambda: calls.append("admit"))
    monkeypatch.setattr(diagnose_interpreter, "write", lambda name, value: receipts.update({name: value}))
    monkeypatch.setattr(diagnose_interpreter, "Path", lambda path: tmp_path / "site")
    monkeypatch.setattr(
        "tests.integration.homeassistant.diagnose_interpreter.pwd.getpwnam",
        lambda user: SimpleNamespace(pw_uid=1000, pw_gid=1000),
    )
    monkeypatch.setattr("tests.integration.homeassistant.diagnose_interpreter.os.chown", lambda *args: None)

    def seed() -> dict[str, object]:
        calls.append("seed")
        if failure == "seed":
            raise RuntimeError("owned seed failure")
        return {}

    def capture(name: str, argv: list[str], timeout: float) -> dict[str, Any]:
        calls.append(name)
        assert 0 < timeout <= 900
        if name == "interpreter-seed":
            assert argv[:6] == diagnose_interpreter.PREFIX
            assert argv[-2] == "3.14.8"
        if name == "interpreter-sdk-process":
            assert argv[-1] == "tests.integration.homeassistant.interpreter_probe"
        return {"exit": 7 if name == failure else 0}

    monkeypatch.setattr(diagnose_interpreter, "verify_original_contexts", lambda: calls.append("original"))
    monkeypatch.setattr(diagnose_interpreter, "seed_uv_account", seed)
    monkeypatch.setattr(diagnose_interpreter, "capture", capture)
    if failure:
        with pytest.raises((AssertionError, RuntimeError)):
            diagnose_interpreter.run()
    else:
        diagnose_interpreter.run()
    assert calls[0] == "admit"
    assert receipts["summary.json"]["completed"] is (failure is None)
    assert receipts["summary.json"]["typed_application_phases_executed"] == 0
    assert receipts["summary.json"]["selected_original_phases_executed"] == 0
    if failure == "wrong-case":
        assert calls == ["admit"]
    elif failure == "seed":
        assert calls == ["admit", "seed"]
    elif failure == "interpreter-seed":
        assert calls == ["admit", "seed", "interpreter-seed"]
    else:
        assert calls[-1] == "interpreter-sdk-process"
        assert len(calls) == 8


@pytest.mark.parametrize("mode", ["present", "cold", "failed-install", "failed-postfind"])
def test_fixed_actual_sdk_local_commands_complete_and_repeat(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    import shlex

    marker = tmp_path / "installed"
    if mode == "present":
        marker.touch()

    def command(cfg: Any, action: str) -> str:
        if action == "install":
            return "exit 9" if mode == "failed-install" else "touch " + shlex.quote(str(marker))
        if mode == "failed-postfind":
            return "exit 7"
        return "test -f " + shlex.quote(str(marker)) + " && printf '/owned/python\\n'"

    monkeypatch.setattr(interpreter, "interpreter_command", command)
    result = interpreter_probe.probe(install=True, frozen=False, retries=1)
    assert result["operations"][0]["complete"] is True
    assert result["planned_changes"] == [True]
    assert result["planning_progress"] == []
    assert result["actual_host_keys"] is True
    assert result["installed_hosts"] == (["@local"] if mode in ("cold", "failed-postfind") else [])
    assert result["changes"] == [mode == "cold"]
    if mode.startswith("failed"):
        assert result["operations"] == [{"complete": True, "executed": True, "success": False}]
        assert result["failed_hosts"] == ["@local"]
    else:
        assert result["error"] is None
        assert result["failed_hosts"] == []
        assert result["operations"] == [{"complete": True, "executed": mode == "cold", "success": True}]
        repeat = interpreter_probe.probe(install=True, frozen=False)
        assert repeat["operations"] == [{"complete": True, "executed": False, "success": True}]
        assert repeat["error"] is None


def test_frozen_negative_is_exact_committed_source() -> None:
    import hashlib

    from tests.integration.homeassistant import frozen_interpreter

    source = Path(frozen_interpreter.__file__).with_name("interpreter_cafbe.py.txt").read_bytes()
    assert hashlib.sha256(source).hexdigest() == frozen_interpreter.SOURCE_SHA


def test_original_command_probe_preserves_actual_task_cwd_semantics(tmp_path: Path) -> None:
    from tests.integration.homeassistant.interpreter_original import play

    value = play(tmp_path / "owned.json")[0]
    assert value["become_user"] == "homeassistant"
    first, find, retain = value["tasks"]
    assert first["ansible.builtin.command"] == {"argv": ["pwd"]}
    assert find["ansible.builtin.command"] == {"cmd": "/usr/local/bin/uv python find 3.14.8"}
    assert find["failed_when"] is False
    assert retain["become"] is False


def test_original_identity_failure_precedes_playbook_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.integration.homeassistant import interpreter_original

    receipts = {}
    monkeypatch.setattr(interpreter_original, "write", lambda name, data: receipts.update({name: data}))
    monkeypatch.setattr(
        interpreter_original,
        "bounded_command",
        lambda *a, **k: {"exit": 1, "truncated": False, "timed_out": False, "output": "owned identity mismatch"},
    )
    monkeypatch.setattr(
        "tests.integration.homeassistant.interpreter_original.os.open",
        lambda *a: pytest.fail("must not create playbook"),
    )
    with pytest.raises(RuntimeError, match="identity"):
        interpreter_original.verify_original_contexts()
    assert receipts["interpreter-original-identity.json"]["exit"] == 1


@pytest.mark.parametrize("bad", [None, "cwd", "find"])
def test_original_context_loop_cwd_outcomes_and_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, bad: str | None
) -> None:
    import json
    import os

    from tests.integration.homeassistant import interpreter_original as original

    contexts = {name: tmp_path / name for name in ("controller", "private-playbook", "user-home")}
    for directory in contexts.values():
        directory.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    before = Path.cwd()
    calls = []
    monkeypatch.setattr(original, "CONTEXTS", contexts)
    monkeypatch.setattr(original, "EVIDENCE", evidence)
    monkeypatch.setattr(original, "write", lambda *args: None)

    def command(argv: list[str], *, timeout: float) -> dict[str, Any]:
        if "-c" in argv and argv[-1] == original.IDENTITY:
            return {
                "exit": 0,
                "truncated": False,
                "timed_out": False,
                "output": json.dumps({"count": 801, "identity": original.CORE_HASH}),
            }
        directory = Path.cwd()
        name = directory.name
        calls.append(name)
        assert directory == contexts[name]
        value = {
            "effective_cwd": "/home/homeassistant/.ansible/tmp/ansible-moduletmp-owned"
            if name == "private-playbook"
            else str(directory),
            "cwd_rc": 0,
            "find_rc": 2 if name == "controller" else 0,
            "find_stdout": "" if name == "controller" else "/owned/python",
            "find_stderr": "Permission denied" if name == "controller" else "",
        }
        if bad == "cwd":
            value["effective_cwd"] = "/wrong"
        elif bad == "find":
            value["find_rc"] = 0 if name == "controller" else 2
        (evidence / ("interpreter-original-" + name + ".json")).write_text(json.dumps(value))
        return {"exit": 0, "truncated": False, "timed_out": False, "output": ""}

    monkeypatch.setattr(original, "bounded_command", command)
    if bad:
        with pytest.raises(AssertionError):
            original.verify_original_contexts()
        assert calls == ["controller"]
    else:
        original.verify_original_contexts()
        assert calls == list(contexts)
    assert Path(os.getcwd()) == before
    assert all(not (directory / "owned-interpreter-original.yml").exists() for directory in contexts.values())
