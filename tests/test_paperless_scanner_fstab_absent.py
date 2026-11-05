"""The removal's fstab helper on synthetic fstab bytes; never the local /etc/fstab."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from typing import Any

import pytest

SPEC = importlib.util.spec_from_file_location(
    "paperless_scanner_fstab_absent",
    Path(__file__).parents[1] / "src/ops_deploy/services/paperless/files/scanner_fstab_absent.py",
)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

SOURCE = "/mnt/cryptdata/paperless/consume"
TARGET = "/srv/sftp-scanner/inbox"
LINE = f"{SOURCE} {TARGET} none bind 0 0\n"
FIELDS = [SOURCE, TARGET, "none", "bind", "0", "0"]
# Lines that look like the scanner's but are not exactly it: they all stay.
PEERS = (
    "# synthetic fstab\n"
    "UUID=0000-fixture / ext4 defaults 0 1\n"
    f"# {LINE}"
    f"{SOURCE} {TARGET} none bind,nofail 0 0\n"
    f"{SOURCE} {TARGET}2 none bind 0 0\n"
    f"{SOURCE}2 {TARGET} none bind 0 0\n"
    f"{SOURCE} {TARGET} none bind 0 0 extra\n"
    f"/x{SOURCE} {TARGET} none bind 0 0\n"
    "\n"
)


def table(tmp_path: Path, body: str, mode: int = 0o644) -> Path:
    path = tmp_path / "fstab"
    path.write_text(body)
    path.chmod(mode)
    return path


def test_only_the_exact_line_goes_and_peers_stay_byte_for_byte(tmp_path: Path) -> None:
    path = table(tmp_path, PEERS + LINE + "tmpfs /tmp tmpfs defaults 0 0\n", 0o640)
    assert MODULE.fstab_absent(path, FIELDS, False) is True
    assert path.read_text() == PEERS + LINE + "tmpfs /tmp tmpfs defaults 0 0\n"
    assert MODULE.fstab_absent(path, FIELDS, True) is True
    assert path.read_text() == PEERS + "tmpfs /tmp tmpfs defaults 0 0\n"
    assert path.stat().st_mode & 0o777 == 0o640
    assert not list(tmp_path.glob(".paperless-fstab-*"))


def test_a_second_run_changes_nothing(tmp_path: Path) -> None:
    path = table(tmp_path, PEERS + LINE)
    assert MODULE.fstab_absent(path, FIELDS, True) is True
    before = path.stat()
    assert MODULE.fstab_absent(path, FIELDS, False) is False
    assert MODULE.fstab_absent(path, FIELDS, True) is False
    assert path.read_text() == PEERS
    assert path.stat().st_ino == before.st_ino
    assert path.stat().st_mtime_ns == before.st_mtime_ns


@pytest.mark.parametrize(
    "line",
    [
        f"{SOURCE}\t{TARGET}\tnone\tbind\t0\t0\n",
        f"  {SOURCE} {TARGET} none bind 0 0 # written by the deploy\n",
        f"{SOURCE} {TARGET} none bind 0 0",  # last line without a newline
    ],
)
def test_the_same_fields_in_another_spacing_are_the_line(line: str, tmp_path: Path) -> None:
    path = table(tmp_path, PEERS + line)
    assert MODULE.fstab_absent(path, FIELDS, True) is True
    assert path.read_text() == PEERS


def test_duplicates_of_the_exact_line_all_go(tmp_path: Path) -> None:
    path = table(tmp_path, LINE + PEERS + LINE)
    assert MODULE.fstab_absent(path, FIELDS, True) is True
    assert path.read_text() == PEERS


def test_symlinked_or_unbounded_fstab_is_refused_without_write(tmp_path: Path) -> None:
    real = table(tmp_path, LINE)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(OSError, match="symbolic links"):
        MODULE.fstab_absent(link, FIELDS, True)
    big = tmp_path / "big"
    big.write_text(LINE + "#" * (1024 * 1024))
    with pytest.raises(MODULE.Refusal, match="bounded"):
        MODULE.fstab_absent(big, FIELDS, True)
    assert real.read_text() == LINE


@pytest.mark.parametrize(
    "settings",
    [
        {"source": SOURCE, "target": TARGET},
        {"source": SOURCE, "target": TARGET, "apply": "yes"},
        {"source": SOURCE, "target": "/srv/../etc", "apply": True},
        {"source": "relative", "target": TARGET, "apply": True},
        {"source": SOURCE, "target": TARGET + " x", "apply": True},
        {"source": SOURCE, "target": TARGET, "apply": True, "more": 1},
    ],
)
def test_invalid_payloads_are_refused(settings: dict[str, Any]) -> None:
    with pytest.raises(MODULE.Refusal):
        MODULE.wanted(settings)


def run_main(monkeypatch: pytest.MonkeyPatch, path: Path, payload: Any, capsys: pytest.CaptureFixture[str]) -> Any:
    monkeypatch.setattr(MODULE, "FSTAB", path)
    stdin = io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()))
    monkeypatch.setattr(MODULE.sys, "stdin", stdin)
    code = MODULE.main()
    out, err = capsys.readouterr()
    return code, out, err


def test_main_answers_then_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = table(tmp_path, PEERS + LINE)
    settings = {"source": SOURCE, "target": TARGET, "apply": False}
    assert run_main(monkeypatch, path, settings, capsys) == (0, '{"change": true}\n', "")
    assert path.read_text() == PEERS + LINE
    assert run_main(monkeypatch, path, {**settings, "apply": True}, capsys) == (0, '{"change": true}\n', "")
    assert path.read_text() == PEERS
    assert run_main(monkeypatch, path, {**settings, "apply": True}, capsys) == (0, '{"change": false}\n', "")


def test_main_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    missing = tmp_path / "missing"
    settings = {"source": SOURCE, "target": TARGET, "apply": True}
    code, out, err = run_main(monkeypatch, missing, settings, capsys)
    assert (code, out) == (1, "")
    assert "failed" in err
    path = table(tmp_path, LINE)
    path.write_bytes(LINE.encode() + b"\xff\n")
    code, out, _ = run_main(monkeypatch, path, settings, capsys)
    assert (code, out) == (1, "")
    assert path.read_bytes() == LINE.encode() + b"\xff\n"
    assert not list(tmp_path.glob(".paperless-fstab-*"))
