"""The controller side of detached Traefik transactions (``traefik_tx.transport``).

The host side is ``test_traefik_tx_runner``; here a fake :data:`Runner` answers as the
host program would, and the scripts are checked for what they carry. The last tests
run the real scripts with a local bash: the plumbing (base64 blocks, the private
directory, the argument words) works and the runner's refusals come through.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from ops_deploy.backups.remote import CommandResult, RemoteCommandError, SubprocessRunner
from ops_deploy.infra.traefik_tx import engine, runner, transport
from ops_deploy.infra.traefik_tx.transport import TransactionStatus, TransportError

TX = "6f1c2c1e-0a3b-4c5d-8e9f-0123456789ab"
SHA = "a" * 64
REQUEST: dict[str, Any] = {
    "action": "binary",
    "policy": {"host": "canary", "binary_path": "/usr/local/bin/traefik"},
    "controller_state": {"phase": "clear", "revision": "r1"},
    "evidence": {"owner": "standing approval", "recovery_access": "fresh root SSH"},
    "release": {"version": "3.7.16", "arch": "amd64", "sha256": SHA},
}


@dataclass
class FakeRunner:
    """Answers each call with the next of ``answers`` (a result or an exception) and records it."""

    answers: list[CommandResult | Exception]
    calls: list[tuple[str, list[str], float]] = field(default_factory=list)

    def __call__(self, script: str, args: Sequence[str], timeout: float) -> CommandResult:
        self.calls.append((script, list(args), timeout))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def ok(value: dict[str, Any]) -> CommandResult:
    return CommandResult(0, json.dumps(value), "")


def blocks(script: str) -> dict[str, bytes]:
    """The files a script writes into its private directory, decoded."""

    found = re.findall(r"base64 -d >\"\$dir/([^\"]+)\" <<'OPS_DEPLOY_(\w+)'\n(.*?)OPS_DEPLOY_\2\n", script, re.S)
    return {name: base64.b64decode(data) for name, _, data in found}


def staged_answer(**change: Any) -> dict[str, Any]:
    answer = {
        "schema": 1,
        "id": TX,
        "action": "binary",
        "engine_sha256": transport.ENGINE_SHA256,
        "runner_sha256": transport.RUNNER_SHA256,
        "request_sha256": hashlib.sha256(transport.staged_request(REQUEST, TX)).hexdigest(),
        "archive_sha256": SHA,
        "staged_at": 1,
    }
    answer.update(change)
    return answer


def polled(status: str = "finished", **change: Any) -> dict[str, Any]:
    answer: dict[str, Any] = {
        "schema": 1,
        "id": TX,
        "status": status,
        "staged": True,
        "started": True,
        "result": None,
        "safe_restore": None,
    }
    answer.update(change)
    return answer


# -- scripts --------------------------------------------------------------------------


def test_the_programs_are_the_packaged_ones() -> None:
    assert Path(engine.__file__).read_bytes() == transport.ENGINE
    assert Path(runner.__file__).read_bytes() == transport.RUNNER
    assert hashlib.sha256(transport.RUNNER).hexdigest() == transport.RUNNER_SHA256
    assert str(runner.TRANSPORT_ROOT) == transport.TRANSPORT_ROOT
    assert transport.PYTHON == runner.PYTHON


def test_a_script_carries_the_runner_and_its_files() -> None:
    script = transport.script('stage "$1" "$dir"', {"engine.py": b"engine", "request.json": b'{"x": 1}'})

    assert blocks(script) == {"runner.py": transport.RUNNER, "engine.py": b"engine", "request.json": b'{"x": 1}'}
    assert script.startswith("set -euo pipefail\numask 077\n")
    assert "dir=$(mktemp -d -t traefik-tx-XXXXXXXXXX)\ntrap 'rm -rf -- \"$dir\"' EXIT\n" in script
    assert "/usr/bin/python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'" in script
    assert script.endswith('/usr/bin/python3 -I "$dir/runner.py" stage "$1" "$dir"\n')
    # No backslash: hosts may run sshd's command line through fish.
    assert "\\" not in script


def test_stage_sends_the_request_on_stdin_and_checks_what_was_staged() -> None:
    runner_ = FakeRunner([ok(staged_answer())])

    staged = transport.stage_transaction(runner_, REQUEST, TX)

    assert staged == transport.Staged(TX, "binary", staged_answer()["request_sha256"], SHA)
    script, args, timeout = runner_.calls[0]
    assert (args, timeout) == ([TX], 600)
    files = blocks(script)
    assert files["engine.py"] == transport.ENGINE
    assert json.loads(files["request.json"]) == REQUEST
    assert script.endswith('runner.py" stage "$1" "$dir"\n')
    assert "standing approval" not in " ".join(args)


def test_the_expected_request_is_the_one_the_host_program_writes(tmp_path: Path) -> None:
    """``staged_request`` and the runner's ``stage`` serialise alike (here with the runner's code)."""

    source, root = tmp_path / "source", tmp_path / "transport"
    source.mkdir(mode=0o700)
    for name, data in (("engine.py", transport.ENGINE), ("runner.py", transport.RUNNER)):
        (source / name).write_bytes(data)
    for request in (
        {**REQUEST, "action": "resume", "archive_path": "/elsewhere"},
        {**REQUEST, "evidence": {"owner": "Jöchen ✓", "verified_at": 1800000000}},
    ):
        (source / "request.json").write_bytes(transport._request_bytes(request))
        with (
            patch.object(runner, "TRANSPORT_ROOT", root),
            patch.object(transport, "TRANSPORT_ROOT", str(root)),
            patch.object(runner, "require_root", lambda: None),
            patch.object(runner, "private_dir", lambda path, parents=True: None),
            patch.object(runner, "install_template", lambda: False),
            patch.object(runner, "fetch_release", lambda release, destination: SHA),
        ):
            staged = runner.stage(TX, source)
            expected = transport.staged_request(request, TX)
        written = (root / TX / "request.json").read_bytes()
        assert written == expected
        assert staged["request_sha256"] == hashlib.sha256(written).hexdigest()
        (root / TX / "staged.json").unlink()
        for path in (root / TX).iterdir():
            path.unlink()
        (root / TX).rmdir()


@pytest.mark.parametrize(
    "change",
    [
        {"id": "0b7e4f7a-1c2d-4e3f-9a4b-5c6d7e8f9a0b"},
        {"action": "resume"},
        {"engine_sha256": "c" * 64},
        {"runner_sha256": "c" * 64},
        {"request_sha256": "b" * 64},
        {"archive_sha256": "c" * 64},
        {"archive_sha256": None},
    ],
)
def test_stage_refuses_a_different_staging(change: dict[str, Any]) -> None:
    with pytest.raises(TransportError, match=r"^stage: the staged files are not the ones sent$"):
        transport.stage_transaction(FakeRunner([ok(staged_answer(**change))]), REQUEST, TX)


@pytest.mark.parametrize("action", ["resume", "rebaseline"])
def test_stage_resume_and_rebaseline_have_no_archive(action: str) -> None:
    request = {**REQUEST, "action": action, "recovery_review_reference": "reviewed", "archive_path": "/x"}
    digest = hashlib.sha256(transport.staged_request(request, TX)).hexdigest()
    answer = staged_answer(action=action, archive_sha256=None, request_sha256=digest)

    assert transport.stage_transaction(FakeRunner([ok(answer)]), request, TX).archive_sha256 is None


@pytest.mark.parametrize(
    ("request_", "transaction_id", "message"),
    [
        ({**REQUEST, "action": "inspect"}, TX, "stage: only binary, resume and rebaseline transactions run detached"),
        ({**REQUEST, "action": "alias"}, TX, "stage: only binary, resume and rebaseline transactions run detached"),
        ({**REQUEST, "evidence": {"verified_at": object()}}, TX, "stage: the request is not JSON"),
        (REQUEST, TX.upper(), "invalid transaction id"),
        (REQUEST, "../" + TX, "invalid transaction id"),
    ],
)
def test_stage_refuses_before_connecting(request_: dict[str, Any], transaction_id: str, message: str) -> None:
    runner_ = FakeRunner([])

    with pytest.raises(TransportError, match=rf"^{re.escape(message)}$"):
        transport.stage_transaction(runner_, request_, transaction_id)

    assert runner_.calls == []


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (
            RemoteCommandError("ssh root@secret.example: no result within 600s; stopped"),
            "no result (ssh failed or timed out)",
        ),
        (CommandResult(1, "", "traefik tx: release archive checksum mismatch\n"), "release archive checksum mismatch"),
        (
            CommandResult(1, "", "noise\ntraefik tx: /usr/bin/python3 3.11 or newer is required\n"),
            "/usr/bin/python3 3.11 or newer is required",
        ),
        (
            CommandResult(255, "", "ssh: connect to host secret.example port 22: Connection refused\n"),
            "failed (exit 255)",
        ),
        (CommandResult(0, "not json", ""), "unusable result"),
        (CommandResult(0, "[]", ""), "unusable result"),
        (CommandResult(0, json.dumps({"id": TX}), ""), "unusable result"),
    ],
)
def test_failures_are_fixed_reasons_without_host_data(answer: CommandResult | Exception, message: str) -> None:
    with pytest.raises(TransportError) as raised:
        transport.stage_transaction(FakeRunner([answer]), REQUEST, TX)

    assert str(raised.value) == f"stage: {message}"
    assert "secret.example" not in str(raised.value)
    assert raised.value.__cause__ is None


# -- start, poll, cleanup -------------------------------------------------------------


def test_start_passes_the_id_and_the_runtime() -> None:
    runner_ = FakeRunner([ok({"schema": 1, "id": TX, "started": True, "unit": f"traefik-tx-{TX}.service"})])

    transport.start_transaction(runner_, TX, runtime_max_sec=1200)

    script, args, timeout = runner_.calls[0]
    assert (args, timeout) == ([TX, "1200"], 120)
    assert script.endswith('runner.py" start "$1" "$2"\n')
    assert set(blocks(script)) == {"runner.py"}


@pytest.mark.parametrize("seconds", [59, 3601, True, 900.0])
def test_start_bounds_the_runtime(seconds: Any) -> None:
    with pytest.raises(TransportError, match=r"^start: runtime_max_sec must be between 60 and 3600$"):
        transport.start_transaction(FakeRunner([]), TX, runtime_max_sec=seconds)


def test_start_needs_its_confirmation() -> None:
    with pytest.raises(TransportError, match=r"^start: unusable result$"):
        transport.start_transaction(FakeRunner([ok({"schema": 1, "id": TX, "started": False})]), TX)


def test_poll_reads_the_status() -> None:
    result = {"engine_exit": 0, "response": {"changed": True, "state": {"phase": "clear"}}, "restore_expected": False}
    runner_ = FakeRunner([ok(polled(result=result))])

    status = transport.poll_transaction(runner_, TX)

    assert status == TransactionStatus(TX, "finished", True, True, result, None)
    assert (status.final, status.engine_exit, status.response) == (True, 0, result["response"])
    assert status.host_record == {"phase": "clear"}
    script, args, timeout = runner_.calls[0]
    assert (args, timeout) == ([TX], 60)
    assert script.endswith('runner.py" poll "$1"\n')


@pytest.mark.parametrize(
    "change",
    [
        {"status": "done"},
        {"status": "unknown"},
        {"id": "0b7e4f7a-1c2d-4e3f-9a4b-5c6d7e8f9a0b"},
        {"staged": None},
        {"started": "yes"},
        {"result": []},
        {"safe_restore": "restored"},
    ],
)
def test_poll_refuses_an_unusable_status(change: dict[str, Any]) -> None:
    with pytest.raises(TransportError, match=r"^poll: unusable result$"):
        transport.poll_transaction(FakeRunner([ok(polled(**change))]), TX)


def test_cleanup_reports_whether_it_removed_anything() -> None:
    answers: list[CommandResult | Exception] = [
        ok({"schema": 1, "id": TX, "removed": True}),
        ok({"schema": 1, "id": TX, "removed": False}),
        ok({"schema": 1, "id": TX}),
        CommandResult(1, "", "traefik tx: transaction is still running or restoring\n"),
    ]
    runner_ = FakeRunner(answers)

    assert transport.cleanup_transaction(runner_, TX) is True
    assert transport.cleanup_transaction(runner_, TX) is False
    with pytest.raises(TransportError, match=r"^cleanup: unusable result$"):
        transport.cleanup_transaction(runner_, TX)
    with pytest.raises(TransportError, match=r"^cleanup: transaction is still running or restoring$"):
        transport.cleanup_transaction(runner_, TX)
    assert runner_.calls[0][0].endswith('runner.py" cleanup "$1"\n')


def test_inspect_sends_only_the_policy() -> None:
    response = {"identity": {"version": "3.7.14"}, "state": None}
    runner_ = FakeRunner([ok({"schema": 1, "engine_exit": 0, "response": response})])

    found = transport.inspect_host(runner_, REQUEST["policy"])

    assert found == transport.EngineRun(0, response)
    script, args, timeout = runner_.calls[0]
    assert (args, timeout) == ([], 300)
    assert json.loads(blocks(script)["request.json"]) == {"action": "inspect", "policy": REQUEST["policy"]}
    assert script.endswith('runner.py" inspect "$dir"\n')


def test_inspect_passes_the_engines_refusal_on() -> None:
    response = {"failed": True, "error": "Traefik is not running"}
    runner_ = FakeRunner([ok({"schema": 1, "engine_exit": 2, "response": response})])

    assert transport.inspect_host(runner_, REQUEST["policy"]) == transport.EngineRun(2, response)
    with pytest.raises(TransportError, match=r"^inspect: unusable result$"):
        transport.inspect_host(FakeRunner([ok({"schema": 1, "engine_exit": 0})]), REQUEST["policy"])


# -- the outcome ----------------------------------------------------------------------

STATE = {"schema": 1, "host": "canary", "phase": "clear", "revision": "r2"}
RECOVERY = {**STATE, "phase": "recovery", "revision": "r3", "reason": "EngineInterrupted"}


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (TransactionStatus(TX, "finished", result={"response": {"changed": True, "state": STATE}}), STATE),
        (TransactionStatus(TX, "finished", result={"response": {"failed": True, "state": RECOVERY}}), RECOVERY),
        # Refused: the host record did not change, but the outcome names none.
        (TransactionStatus(TX, "finished", result={"response": {"failed": True, "error": "refused"}}), None),
        (
            TransactionStatus(
                TX,
                "finished",
                result={"response": {"failed": True, "error": "x"}},
                safe_restore={"acted": True, "state": RECOVERY},
            ),
            RECOVERY,
        ),
        (TransactionStatus(TX, "interrupted", safe_restore={"acted": True, "state": RECOVERY}), RECOVERY),
        (TransactionStatus(TX, "interrupted", safe_restore={"acted": True, "state": None}), None),
        (TransactionStatus(TX, "interrupted", safe_restore={"acted": False, "state": None}), None),
        (TransactionStatus(TX, "interrupted"), None),
        (TransactionStatus(TX, "running", result={"response": {"state": STATE}}), None),
        (TransactionStatus(TX, "restoring", safe_restore={"acted": True, "state": RECOVERY}), None),
        (TransactionStatus(TX, "absent"), None),
        (TransactionStatus(TX, "unknown"), None),
        (TransactionStatus(TX, "finished", result={"response": "not an object"}), None),
    ],
)
def test_the_host_record_of_an_outcome(status: TransactionStatus, expected: dict[str, Any] | None) -> None:
    assert status.host_record == expected


def test_final_statuses() -> None:
    final = {status for status in [*transport.STATUSES, "unknown"] if TransactionStatus(TX, status).final}  # type: ignore[arg-type]

    assert final == {"absent", "finished", "interrupted"}


@dataclass
class Clock:
    now: float = 0.0
    sleeps: list[float] = field(default_factory=list)

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_wait_polls_over_new_connections_until_final() -> None:
    clock = Clock()
    answers: list[CommandResult | Exception] = [
        RemoteCommandError("ssh failed"),
        ok(polled("running")),
        CommandResult(1, "", "traefik tx: unexpected error (OSError)\n"),
        ok(polled("restoring")),
        ok(polled("interrupted", safe_restore={"acted": True, "state": RECOVERY})),
    ]
    runner_ = FakeRunner(answers)

    status = transport.wait_for_transaction(runner_, TX, timeout=600, interval=5, clock=clock, sleep=clock.sleep)

    assert (status.status, status.host_record) == ("interrupted", RECOVERY)
    assert clock.sleeps == [5, 5, 5, 5]
    assert len(runner_.calls) == 5
    assert all(timeout == 60 for _, _, timeout in runner_.calls)


def test_wait_gives_up_at_the_deadline_with_the_last_status() -> None:
    clock = Clock()
    runner_ = FakeRunner([ok(polled("running")) for _ in range(10)])

    status = transport.wait_for_transaction(runner_, TX, timeout=12, interval=5, clock=clock, sleep=clock.sleep)

    assert (status.status, status.final, status.host_record) == ("running", False, None)
    assert clock.sleeps == [5, 5, 5]
    assert len(runner_.calls) == 4


def test_wait_without_any_answer_is_unknown() -> None:
    clock = Clock()
    runner_ = FakeRunner([RemoteCommandError("ssh failed") for _ in range(3)])

    status = transport.wait_for_transaction(runner_, TX, timeout=10, interval=5, clock=clock, sleep=clock.sleep)

    assert status == TransactionStatus(TX, "unknown")
    assert len(runner_.calls) == 3


# -- the real scripts, with a local bash -----------------------------------------------


@pytest.fixture
def local_python() -> Any:
    """The scripts' interpreter is ``/usr/bin/python3`` on the host; here the test's."""

    with patch.object(transport, "PYTHON", sys.executable):
        yield


def test_poll_through_a_local_bash(local_python: None) -> None:
    status = transport.poll_transaction(SubprocessRunner(), TX)

    assert status == TransactionStatus(TX, "absent")


@pytest.mark.skipif(os.geteuid() == 0, reason="the refusal needs a non-root user")
def test_refusals_come_through_a_local_bash(local_python: None) -> None:
    with pytest.raises(TransportError, match=r"^stage: root is required$"):
        transport.stage_transaction(SubprocessRunner(), REQUEST, TX)
    with pytest.raises(TransportError, match=r"^start: root is required$"):
        transport.start_transaction(SubprocessRunner(), TX)


def test_a_too_old_python_is_refused_by_the_script() -> None:
    old = Path(__file__).parent / "parity" / "no-such-python"
    with (
        patch.object(transport, "PYTHON", str(old)),
        pytest.raises(TransportError, match=rf"^poll: {re.escape(str(old))} 3.11 or newer is required$"),
    ):
        transport.poll_transaction(SubprocessRunner(), TX)
