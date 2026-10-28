"""Original Inbox root selector/copy guards, separate from user uv semantics."""

from __future__ import annotations

import os
import pwd
import runpy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from tests.test_daybook_runtime_observer import SCRIPT


@pytest.fixture
def module() -> dict[str, Any]:
    return runpy.run_path(str(SCRIPT))


def data(tmp_path: Path, owner: str = "root") -> dict[str, str]:
    checkout = tmp_path.resolve() / "Daybook/voice-memo-inbox/daybook"
    python = checkout / ".venv/bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"OWNED-COPY")
    uv = tmp_path.resolve() / "uv"
    uv.write_text("# owned uv declaration\n")
    home = checkout.parent.parent / "python/cpython-3.14.7-macos-aarch64-none/bin"
    (python.parent.parent / "pyvenv.cfg").write_text("home = " + str(home) + "\n")
    return {
        "user": pwd.getpwuid(os.getuid()).pw_name,
        "owner": owner,
        "python": str(python),
        "python_version": "3.14.7",
        "uv_bin": str(uv),
        "checkout": str(checkout),
    }


def probe(module: dict[str, Any], values: dict[str, str], **overrides: Any) -> Any:
    native_probes: Any = module["NativeProbes"]

    class Probes(native_probes):  # type: ignore[misc]
        def __init__(self, values: dict[str, str]) -> None:
            super().__init__(values)
            self.calls: list[tuple[list[str], bool, Any]] = []
            self.hashes: list[tuple[str, bool]] = []

        def run(self, argv: list[str], user: bool = False, extra: Any = None) -> SimpleNamespace:
            self.calls.append((argv, user, extra))
            if argv[1:3] == ["python", "find"]:
                found = str(self.root_python_tree() / "cpython-3.14.7-macos-aarch64-none/bin/python3.14")
                return SimpleNamespace(
                    returncode=overrides.get("find_rc", 0), stdout=overrides.get("found", found).encode()
                )
            return SimpleNamespace(returncode=overrides.get("interpreter_rc", 0), stdout=b"")

        def root_metadata_current(self) -> bool:
            # Unit selector/copy matrix. Actual root tree metadata is exercised
            # separately, including the disposable native fixture.
            return bool(overrides.get("metadata_current", True))

        def protected_binary_hash(self, name: str, *, copied: bool) -> bytes | None:
            self.hashes.append((name, copied))
            return cast(bytes | None, overrides.get("copy_hash" if copied else "source_hash", b"OWNED-EQUAL-DIGEST"))

    return Probes(values)


def test_root_tree_derives_actual_original_cf3_sibling_meaning(module: dict[str, Any]) -> None:
    values = {
        "user": pwd.getpwuid(os.getuid()).pw_name,
        "checkout": "/Library/Application Support/Daybook/voice-memo-inbox/daybook",
    }
    instance = module["NativeProbes"](values)
    assert str(instance.root_python_tree()) == "/Library/Application Support/Daybook/python"
    assert instance.root_python_env() == {
        "HOME": "/var/root",
        "UV_NO_PROGRESS": "1",
        "UV_PYTHON_INSTALL_DIR": "/Library/Application Support/Daybook/python",
        "UV_PYTHON_PREFERENCE": "only-managed",
        "UV_PYTHON_DOWNLOADS": "never",
    }


def test_root_exact_source_copy_home_then_gui_stdlib_probe_and_original_root_lock_env(
    module: dict[str, Any], tmp_path: Path
) -> None:
    instance = probe(module, data(tmp_path))
    assert instance.runtime_current() is True
    assert len(instance.hashes) == 2
    assert instance.hashes[0][1] is False
    assert instance.hashes[1][1] is True
    found, stdlib, lock = instance.calls
    assert found[0][1:3] == ["python", "find"]
    assert found[1] is False
    assert found[2] == instance.root_python_env()
    assert stdlib[1] is True
    assert stdlib[0][1:4] == ["-I", "-B", "-S"]
    assert "sys.base_prefix==sys.argv[2]" in stdlib[0][5]
    assert stdlib[0][-1] == str(instance.root_python_tree() / "cpython-3.14.7-macos-aarch64-none")
    assert lock[1] is False
    assert lock[2] == instance.root_python_env()
    assert "--check" in lock[0]
    assert "--offline" in lock[0]


@pytest.mark.parametrize(
    "overrides",
    [
        {"find_rc": 1},
        {"found": "/Users/other/.local/share/uv/python/cpython-3.14.7-x/bin/python3.14"},
        {"source_hash": None},
        {"copy_hash": None},
        {"copy_hash": b"different"},
    ],
)
def test_root_rejects_unbound_source_or_copy_before_any_interpreter_execution(
    module: dict[str, Any], tmp_path: Path, overrides: dict[str, Any]
) -> None:
    instance = probe(module, data(tmp_path), **overrides)
    assert instance.runtime_current() is False
    assert len(instance.calls) == 1
    assert instance.calls[0][0][1:3] == ["python", "find"]


def test_wrong_venv_home_refuses_before_interpreter_execution(module: dict[str, Any], tmp_path: Path) -> None:
    values = data(tmp_path)
    (Path(values["python"]).parent.parent / "pyvenv.cfg").write_text("home = /wrong\n")
    instance = probe(module, values)
    assert instance.runtime_current() is False
    assert len(instance.calls) == 1


def test_user_branch_keeps_original_uv_selector_and_gui_environment(module: dict[str, Any], tmp_path: Path) -> None:
    instance = probe(module, data(tmp_path, "user"))
    assert instance.runtime_current() is True
    assert instance.hashes == []
    stdlib, lock = instance.calls
    assert "'/uv/python/cpython-'+v+'-' in sys.base_prefix" in stdlib[0][5]
    assert stdlib[0][-1] == "3.14.7"
    assert stdlib[1] is True
    assert lock[1] is True
    assert lock[2] is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("st_uid", 501),
        ("st_mode", 0o100775),
        ("st_mode", 0o100644),
        ("st_mode", 0o010755),
        ("st_nlink", 2),
        ("st_size", 256 * 1024 * 1024 + 1),
    ],
)
def test_copy_metadata_refuses_before_any_binary_body_read(
    module: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: int
) -> None:
    values = data(tmp_path)
    instance = module["NativeProbes"](values)
    leaf = Path(values["python"])
    current = leaf.stat()
    metadata = {"st_uid": 0, "st_mode": 0o100755, "st_nlink": 1, "st_size": current.st_size, field: value}
    monkeypatch.setattr(module["os"], "fstat", lambda fd: SimpleNamespace(**metadata))

    def no_body(fd: int, count: int) -> bytes:
        raise AssertionError("unsafe copied binary was read")

    monkeypatch.setattr(module["os"], "read", no_body)
    assert instance.protected_binary_hash(leaf, copied=True) is None


def test_root_copy_digest_reads_actual_owned_bytes_without_mutation(
    module: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hashlib

    values = data(tmp_path)
    instance = module["NativeProbes"](values)
    leaf = Path(values["python"])
    before = leaf.stat()
    original = os.fstat

    # UID0 is a unit boundary simulation only. Actual root-owned files are
    # qualified by the separate disposable Darwin case, not this local test.
    def owned(fd: int) -> SimpleNamespace:
        info = original(fd)
        return SimpleNamespace(st_uid=0, st_mode=0o100755, st_nlink=info.st_nlink, st_size=info.st_size)

    monkeypatch.setattr(module["os"], "fstat", owned)
    assert instance.protected_binary_hash(leaf, copied=True) == hashlib.sha256(b"OWNED-COPY").digest()
    after = leaf.stat()
    assert (after.st_ino, after.st_mtime_ns, after.st_ctime_ns) == (
        before.st_ino,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    link = leaf.with_name("linked-copy")
    link.symlink_to(leaf)
    assert instance.protected_binary_hash(link, copied=True) is None


def test_actual_root_native_fixture_refuses_local_host_before_managed_setup(tmp_path: Path) -> None:
    import json
    import subprocess
    import sys

    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_root_python_native_fixture.py"
    evidence = tmp_path / "evidence"
    result = subprocess.run(
        [sys.executable, str(fixture)],
        capture_output=True,
        timeout=20,
        env={
            **os.environ,
            "GITHUB_ACTIONS": "false",
            "RUNNER_ENVIRONMENT": "local",
            "GITHUB_RUN_ID": "1",
            "IMPLEMENTATION_SHA": "a" * 40,
            "MAC_APPS_EVIDENCE_DIR": str(evidence),
        },
    )
    assert result.returncode != 0
    records = list(evidence.glob("*.json"))
    assert len(records) == 1
    receipt = json.loads(records[0].read_text())
    assert receipt["failure_type"] == "RefusedHost"
    assert receipt["status"] == "failed"
    assert "root_python" not in receipt


def test_wrong_patch_under_the_exact_root_prefix_refuses_before_execution(
    module: dict[str, Any], tmp_path: Path
) -> None:
    values = data(tmp_path)
    tree = Path(values["checkout"]).parent.parent / "python"
    instance = probe(module, values, found=str(tree / "cpython-3.14.8-x/bin/python3.14"))
    assert instance.runtime_current() is False
    assert len(instance.calls) == 1
    assert instance.hashes == []


def test_untrusted_root_tree_refuses_before_any_root_uv_or_interpreter_execution(
    module: dict[str, Any], tmp_path: Path
) -> None:
    instance = probe(module, data(tmp_path), metadata_current=False)
    assert instance.runtime_current() is False
    assert instance.calls == []
    assert instance.hashes == []


@pytest.mark.parametrize("failure", [OSError("owned IO failure"), RuntimeError("owned marker")])
def test_root_safe_file_os_or_observation_failures_are_genuine_noncurrent(
    module: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: BaseException
) -> None:
    instance = probe(module, data(tmp_path))
    raised = failure if isinstance(failure, OSError) else module["ObservationError"]("owned invalid file")

    def invalid(*args: Any) -> None:
        raise raised

    monkeypatch.setitem(instance._root_interpreter_home.__globals__, "safe_file", invalid)
    assert instance.runtime_current() is False
    assert len(instance.calls) == 1


@pytest.mark.parametrize("fault", ["none", "bin-mode", "cfg-mode", "cfg-owner", "source-mode", "package-owner"])
def test_root_metadata_tree_is_checked_without_file_body_reads(
    module: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    values = data(tmp_path)
    instance = module["NativeProbes"](values)
    tree = instance.root_python_tree()
    tree.mkdir(parents=True)
    cfg = Path(values["python"]).parent.parent / "pyvenv.cfg"
    package = Path(values["python"]).parent.parent / "lib/owned-package"
    package.parent.mkdir(parents=True)
    package.write_bytes(b"OWNED-PACKAGE-NOT-READ")
    real_lstat = Path.lstat

    def root_metadata(path: Path) -> os.stat_result:
        info = list(real_lstat(path))
        info[4] = 0  # unit UID simulation; actual root ownership is native-only
        if (fault == "cfg-owner" and path == cfg) or (fault == "package-owner" and path == package):
            info[4] = 501
        return os.stat_result(info)

    monkeypatch.setattr(Path, "lstat", root_metadata)
    if fault == "bin-mode":
        Path(values["python"]).parent.chmod(0o775)
    elif fault == "cfg-mode":
        cfg.chmod(0o666)
    elif fault == "source-mode":
        tree.chmod(0o775)

    def forbidden_open(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("metadata guard must not open file bodies")

    monkeypatch.setattr(module["os"], "open", forbidden_open)
    assert instance.root_metadata_current() is (fault == "none")
