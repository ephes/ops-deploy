"""Owned QMP protocol admission; no VM, Docker or inventory actions in tests."""

from __future__ import annotations

import importlib.util
import io
import json
import socket
import tarfile
import threading
import time
from pathlib import Path
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
