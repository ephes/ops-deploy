"""Owned QMP protocol admission; no VM, Docker or inventory actions in tests."""

from __future__ import annotations

import importlib.util
import io
import json
import tarfile
from pathlib import Path
from typing import Any

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
