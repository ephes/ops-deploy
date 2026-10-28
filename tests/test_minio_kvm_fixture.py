"""Owned QMP protocol admission; no VM, Docker or inventory actions in tests."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import io
import json
import socket
import subprocess
import tarfile
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any
from unittest.mock import Mock

import pytest

SPEC = importlib.util.spec_from_file_location(
    "minio_kvm_tooling", Path(__file__).parent / "integration/minio/kvm/tooling.py"
)
assert SPEC is not None
assert SPEC.loader is not None
TOOLING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLING)


class Replies(io.BytesIO):
    def __init__(self, native: Any, *, identified: bool = True) -> None:
        messages = [
            {"QMP": {}},
            {"event": "READY"},
            {"return": {}, "id": "capabilities"},
            {"return": native, "id": "native" if identified else "wrong"},
        ]
        super().__init__(b"".join((json.dumps(message) + "\n").encode() for message in messages))
        self.commands: list[Any] = []

    def write(self, data: Any) -> int:
        self.commands.append(json.loads(data))
        return len(data)


def test_actual_query_sequence_requires_enabled_kvm_and_matching_reply_ids() -> None:
    stream = Replies({"enabled": True, "present": True})
    assert TOOLING.query_kvm(stream) == {"enabled": True, "present": True}
    assert stream.commands == [
        {"execute": "qmp_capabilities", "id": "capabilities"},
        {"execute": "query-kvm", "id": "native"},
    ]
    with pytest.raises((ValueError, RuntimeError)):
        TOOLING.query_kvm(Replies({"enabled": True, "present": True}, identified=False))


@pytest.mark.parametrize(
    "result",
    [{"enabled": False, "present": True}, {"enabled": True, "present": False}, {"enabled": 1, "present": 1}, {}],
)
def test_device_or_emulation_presence_never_counts_as_enabled_kvm(result: Any) -> None:
    with pytest.raises(RuntimeError, match="KVM"):
        TOOLING.query_kvm(Replies(result))


def test_evidence_metadata_is_bounded_before_any_body_extraction() -> None:
    table = "/2/040755/0/0/.//\n/2/040755/0/0/..//\n/3/100600/0/0/summary.json/42/\n"
    assert TOOLING.evidence_entries(table) == {"summary.json": 42}
    for bad in (
        "/3/120777/0/0/link/8/\n",
        "/3/040755/0/0/subdir//\n",
        "/3/100600/0/0/unsafe name/8/\n",
        "/3/100600/0/0/huge/999999999/\n",
        table + "/4/100600/0/0/summary.json/42/\n",
    ):
        with pytest.raises(RuntimeError):
            TOOLING.evidence_entries(bad)


def test_copy_out_stream_bounds_and_refuses_links_or_path_escape(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location(
        "minio_kvm_collect", Path(__file__).parent / "integration/minio/kvm/collect-evidence.py"
    )
    assert spec is not None
    assert spec.loader is not None
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)

    def archive(name: str, kind: bytes = tarfile.REGTYPE, size: int = 5) -> io.BytesIO:
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as bundle:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.size = size
            if size > 1024:
                # Header only: admission must reject before reading its body.
                bundle.fileobj.write(entry.tobuf())
            else:
                bundle.addfile(entry, io.BytesIO(b"owned"))
        data.seek(0)
        return data

    collector.collect(archive("./guest/receipt.json"), tmp_path)
    assert (tmp_path / "guest/receipt.json").read_bytes() == b"owned"
    for name, kind, size in (
        ("../outside", tarfile.REGTYPE, 5),
        ("link", tarfile.SYMTYPE, 0),
        ("hardlink", tarfile.LNKTYPE, 0),
        ("large", tarfile.REGTYPE, 300 * 1024 * 1024),
    ):
        with pytest.raises(RuntimeError):
            collector.collect(archive(name, kind, size), tmp_path)
    assert not (tmp_path / "large").exists()


def test_recorded_qmp_uses_one_total_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(TOOLING.time, "monotonic", lambda: clock[0])
    connection = Mock()
    trace = io.StringIO()
    connection.send.return_value = len(b"request\n")
    admission = TOOLING.RecordedQmpStream(connection, trace)
    admission.write(b"request\n")
    connection.settimeout.assert_called_with(60.0)
    clock[0] = 30.0
    admission.flush()
    connection.settimeout.assert_called_with(30.0)
    clock[0] = 61.0
    with pytest.raises(TimeoutError, match="total QMP"):
        admission.readline()
    assert [json.loads(line)["event"] for line in trace.getvalue().splitlines()[-2:]] == ["deadline", "read-error"]


def test_actual_socket_qmp_exchange_records_requests_and_strict_reply() -> None:
    left, right = socket.socketpair()
    left.settimeout(2)
    right.settimeout(2)
    requests: list[Any] = []
    errors: list[str] = []

    def serve() -> None:
        try:
            with right, right.makefile("rwb") as stream:
                stream.write(b'{"QMP":{}}\r\n')
                stream.flush()
                for expected in ("qmp_capabilities", "query-kvm"):
                    request = json.loads(stream.readline())
                    requests.append(request)
                    assert request["execute"] == expected
                    result = {} if expected == "qmp_capabilities" else {"enabled": True, "present": True}
                    stream.write((json.dumps({"return": result, "id": request["id"]}) + "\r\n").encode())
                    stream.flush()
        except BaseException as error:
            errors.append(type(error).__name__)

    peer = threading.Thread(target=serve)
    peer.start()
    trace = io.StringIO()
    try:
        with left:
            recorded = TOOLING.RecordedQmpStream(left, trace, seconds=2)
            assert TOOLING.query_kvm(recorded) == {"enabled": True, "present": True}
    finally:
        peer.join(timeout=3)
    assert not peer.is_alive()
    assert errors == []
    assert [request["execute"] for request in requests] == ["qmp_capabilities", "query-kvm"]
    events = [json.loads(line) for line in trace.getvalue().splitlines()]
    assert [event["event"] for event in events] == [
        "read",
        "write",
        "flush",
        "read",
        "write",
        "flush",
        "read",
    ]
    assert all(0 <= event["elapsed_seconds"] <= 2 for event in events)


def test_actual_trickled_socket_bytes_cannot_extend_total_qmp_budget() -> None:
    left, right = socket.socketpair()
    stop = threading.Event()

    def trickle() -> None:
        with right:
            while not stop.wait(0.02):
                try:
                    right.sendall(b"x")
                except OSError:
                    return

    peer = threading.Thread(target=trickle)
    peer.start()
    trace = io.StringIO()
    started = time.monotonic()
    try:
        with left:
            recorded = TOOLING.RecordedQmpStream(left, trace, seconds=0.15)
            with pytest.raises(TimeoutError):
                recorded.readline()
    finally:
        stop.set()
        peer.join(timeout=2)
    assert not peer.is_alive()
    assert time.monotonic() - started < 2
    assert json.loads(trace.getvalue().splitlines()[-1])["event"] == "read-error"


def test_qmp_write_failure_is_retained_in_transcript() -> None:
    connection = Mock()
    connection.send.side_effect = BrokenPipeError()
    trace = io.StringIO()
    recorded = TOOLING.RecordedQmpStream(connection, trace)
    with pytest.raises(BrokenPipeError):
        recorded.write(b"request\n")
    assert json.loads(trace.getvalue().splitlines()[-1])["event"] == "write-error"


def test_foreign_alias_baseline_survives_root_rotation_and_detects_real_tampering(tmp_path: Path) -> None:
    # Execute the real harness comparator and baseline statement, without booting
    # its main program or importing the runtime deployment into this unit test.
    source = Path(__file__).parent / "integration/minio/harness.py"
    tree = ast.parse(source.read_text())
    comparator = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "foreign_alias_observation"
    )
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    baseline = next(
        node
        for node in main.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "FOREIGN_ALIAS" for target in node.targets)
    )
    original = {
        "url": "http://127.0.0.1:9001",
        "accessKey": "synthetic-root",
        "secretKey": "synthetic-old",
        "api": "s3v4",
        "path": "auto",
    }
    namespace: dict[str, Any] = {
        "Path": Path,
        "Mapping": Mapping,
        "Any": Any,
        "json": json,
        "MappingProxyType": MappingProxyType,
        "alias": original.copy(),
    }
    exec(compile(ast.Module(body=[comparator, baseline], type_ignores=[]), str(source), "exec"), namespace)
    expected = namespace["FOREIGN_ALIAS"]
    namespace["alias"]["secretKey"] = "synthetic-new"
    with pytest.raises(TypeError):
        expected["secretKey"] = "synthetic-new"
    path = tmp_path / "config.json"
    config = {"aliases": {"untouched": original.copy(), "local": namespace["alias"]}}
    path.write_text(json.dumps(config))
    observe = namespace["foreign_alias_observation"]
    assert observe(path, expected) == {"present": True, "equal": True, "different_fields": []}
    # This is the old final assertion's bad expectation, reproduced separately.
    assert observe(path, namespace["alias"])["equal"] is False
    config["aliases"]["untouched"]["secretKey"] = "synthetic-tampered"
    path.write_text(json.dumps(config))
    assert observe(path, expected) == {"present": True, "equal": False, "different_fields": ["secretKey"]}
    del config["aliases"]["untouched"]
    path.write_text(json.dumps(config))
    assert observe(path, expected) == {
        "present": False,
        "equal": False,
        "different_fields": ["<missing-or-invalid-alias>"],
    }

    for invalid in ("{", "[]", '{"aliases": []}', '{"aliases": null}'):
        path.write_text(invalid)
        assert observe(path, expected) == {
            "present": False,
            "equal": False,
            "different_fields": ["<unreadable-config>"],
        }
    path.unlink()
    assert observe(path, expected) == {"present": False, "equal": False, "different_fields": ["<unreadable-config>"]}


def test_s4_component_binds_exact_inputs_and_passes_credentials_only_on_stdin(tmp_path: Path) -> None:
    directory = Path(__file__).parent / "integration/minio"
    tree = ast.parse((directory / "harness.py").read_text())
    function = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_lag_component"
    )
    for name in ("s4-lag-driver.py.txt", "s4-lag-probe.py.txt"):
        body = (directory / name).read_bytes()
        compile(body, name, "exec")
        (tmp_path / name).write_bytes(body)
    creds = Mock()
    creds.root_user.get_secret_value.return_value = "synthetic-root"
    creds.root_password.get_secret_value.return_value = "synthetic-password"
    process = Mock(return_value=subprocess.CompletedProcess([], 0, stdout='{"scope":"synthetic"}', stderr=""))
    record = Mock()
    namespace: dict[str, Any] = {
        "Path": Path,
        "MinioCredentials": Any,
        "__file__": str(tmp_path / "harness.py"),
        "hashlib": hashlib,
        "subprocess": Mock(run=process),
        "sys": Mock(executable="owned-python"),
        "json": json,
        "VALUES": ["synthetic-password"],
        "write": record,
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), "harness-component", "exec"), namespace)
    namespace["run_lag_component"](creds)
    args, kwargs = process.call_args
    assert args[0][:2] == ["owned-python", str(tmp_path / "s4-lag-driver.py.txt")]
    assert "synthetic-password" not in repr(args)
    assert json.loads(kwargs["input"]) == {
        "endpoint": "http://127.0.0.1:9001",
        "user": "synthetic-root",
        "password": "synthetic-password",
    }
    assert kwargs["timeout"] == 600
    assert record.call_args.args[0] == "s4-lag-component.json"
    for name in ("s4-lag-driver.py.txt", "s4-lag-probe.py.txt"):
        original = (tmp_path / name).read_bytes()
        (tmp_path / name).write_bytes(original + b"\n")
        process.reset_mock()
        with pytest.raises(AssertionError):
            namespace["run_lag_component"](creds)
        process.assert_not_called()
        (tmp_path / name).write_bytes(original)
