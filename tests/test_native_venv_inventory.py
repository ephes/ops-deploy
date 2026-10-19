"""Inventory classification without importing packages or running a venv executable."""

from __future__ import annotations

import contextlib
import os
import shlex
from collections.abc import Iterator
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.native_app import inventory
from ops_deploy.services.native_app.inventory import VenvInventoryRequest, probe_venv_inventory, venv_inventory_command


def request(**changes: Any) -> VenvInventoryRequest:
    return VenvInventoryRequest.model_validate(
        {
            "venv": "/opt/fixture/.venv",
            "owner_uid": os.getuid(),
            "python_version": "3.12.3",
            "distributions": {"Fixture_Package": "1.2.3"},
            **changes,
        }
    )


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "venv"
    (root / "bin").mkdir(parents=True)
    (root / "lib/python3.12/site-packages/fixture_package-1.2.3.dist-info").mkdir(parents=True)
    (root / "pyvenv.cfg").write_text("version_info = 3.12.3\ninclude-system-site-packages = false\n")
    (root / "bin/python").write_text("#!/bin/sh\nexit 99\n")
    (root / "bin/python").chmod(0o755)
    (root / "lib/python3.12/site-packages/fixture_package-1.2.3.dist-info/METADATA").write_text(
        "Metadata-Version: 2.1\nName: fixture-package\nVersion: 1.2.3\n\nFixture description.\n"
    )
    return root


@pytest.fixture
def observer(tree: Path) -> dict[str, Any]:
    namespace: dict[str, Any] = {"__name__": "inventory_test"}
    source = files("ops_deploy.services.native_app").joinpath("files/venv_inventory_host.py").read_text()
    exec(compile(source, "venv_inventory_host.py", "exec"), namespace)

    @contextlib.contextmanager
    def fixture_root(path: str, uid: int) -> Iterator[int]:
        # Unit tests isolate the inspected tree from pytest's /tmp ancestor.
        # Linux smoke exercises the actual absolute-path traversal and fact API.
        fd = os.open(tree, namespace["DIR_FLAGS"])
        try:
            namespace["trusted"](os.fstat(fd), uid)
            yield fd
        finally:
            os.close(fd)

    namespace["venv_root"] = fixture_root
    return namespace


def observe(observer: dict[str, Any], **changes: Any) -> dict[str, Any]:
    return dict(observer["observe"](request(**changes).model_dump(mode="json")))


def metadata(tree: Path) -> Path:
    return tree / "lib/python3.12/site-packages/fixture_package-1.2.3.dist-info/METADATA"


def test_candidate_is_only_declared_metadata(observer: dict[str, Any], tree: Path) -> None:
    result = observe(observer)
    assert result["status"] == "matching_candidate"
    assert result["declared_python"] == "3.12.3"
    assert result["distribution_count"] == 1
    assert len(result["inventory_identity"]) == 64
    assert result["python_entry"] == "regular"
    # The executable intentionally exits with an error; no venv code is run.
    before = metadata(tree).stat()
    assert observe(observer) == result
    after = metadata(tree).stat()
    assert (before.st_ino, before.st_mtime_ns, before.st_size) == (after.st_ino, after.st_mtime_ns, after.st_size)


@pytest.mark.parametrize(
    ("installed", "status"),
    [("0.9.0", "different_inventory"), ("2.0.0", "recognizable_newer"), ("1.2.3rc1", "unknown"), ("master", "unknown")],
)
def test_changed_versions_are_controlled(observer: dict[str, Any], tree: Path, installed: str, status: str) -> None:
    metadata(tree).write_text(f"Name: fixture-package\nVersion: {installed}\n\n")
    assert observe(observer)["status"] == status


def test_complete_distribution_set_and_name_normalization(observer: dict[str, Any], tree: Path) -> None:
    initial = observe(observer)
    metadata(tree).write_text("Name: FIXTURE.Package\nVersion: 1.2.3\n\n")
    assert observe(observer) == initial
    assert observe(observer, distributions={})["status"] == "different_inventory"
    extra = observe(observer, distributions={"fixture-package": "1.2.3", "extra": "1.0"})
    assert extra["status"] == "different_inventory"


@pytest.mark.parametrize(("version", "status"), [("3.12.4", "recognizable_newer"), ("3.11.9", "different_inventory")])
def test_declared_python_difference(observer: dict[str, Any], tree: Path, version: str, status: str) -> None:
    (tree / "pyvenv.cfg").write_text(f"version = {version}\ninclude-system-site-packages = false\n")
    declared_lib = "python" + ".".join(version.split(".")[:2])
    (tree / "lib/python3.12").rename(tree / "lib" / declared_lib)
    assert observe(observer)["status"] == status


@pytest.mark.parametrize(
    "body",
    [b"Name: fixture-package\nVersion: \xff\n", b"Name: fixture-package\nName: other\nVersion: 1.2.3\n", b"broken"],
)
def test_malformed_metadata_does_not_escape(observer: dict[str, Any], tree: Path, body: bytes) -> None:
    metadata(tree).write_bytes(body)
    assert observe(observer) == {"status": "unknown", "reason": "malformed_metadata"}


def test_missing_internal_file_is_not_an_absent_venv(observer: dict[str, Any], tree: Path) -> None:
    metadata(tree).unlink()
    assert observe(observer) == {"status": "unknown", "reason": "unsupported_layout"}


def test_unsafe_mode_refuses_before_metadata_read(observer: dict[str, Any], tree: Path) -> None:
    metadata(tree).write_bytes(b"\xff")
    metadata(tree).chmod(0o666)
    assert observe(observer) == {"status": "refused_untrusted", "reason": "unsafe_owner_or_mode"}
    metadata(tree).chmod(0o644)
    tree.chmod(0o777)
    assert observe(observer)["status"] == "refused_untrusted"


def test_metadata_symlink_and_fifo_refuse(observer: dict[str, Any], tree: Path) -> None:
    target = tree / "foreign"
    target.write_text("Name: fixture-package\nVersion: 1.2.3\n")
    path = metadata(tree)
    path.unlink()
    path.symlink_to(target)
    assert observe(observer)["status"] == "refused_untrusted"
    path.unlink()
    os.mkfifo(path)
    assert observe(observer)["status"] == "refused_untrusted"


def test_python_link_is_observed_without_following_or_executing(observer: dict[str, Any], tree: Path) -> None:
    binary = tree / "bin/python"
    binary.unlink()
    binary.symlink_to("/missing/unverified/interpreter")
    result = observe(observer)
    assert result["status"] == "matching_candidate"
    assert result["python_entry"] == "symlink"


def test_path_hooks_remain_unsupported_and_are_not_executed(observer: dict[str, Any], tree: Path) -> None:
    sentinel = tree / "executed"
    hook = tree / "lib/python3.12/site-packages/fixture.pth"
    hook.write_text(f"import pathlib; pathlib.Path({str(sentinel)!r}).touch()\n")
    result = observe(observer)
    assert result["status"] == "unknown"
    assert result["reason"] == "unsupported_layout"
    assert result["distribution_count"] == 1
    assert not sentinel.exists()


def test_bounded_reads_and_entry_iteration(observer: dict[str, Any], tree: Path) -> None:
    observer["MAX_METADATA"] = 16
    assert observe(observer)["reason"] == "limits_exceeded"
    observer["MAX_METADATA"] = 256 * 1024
    observer["MAX_ENTRIES"] = 1
    (tree / "lib/python3.12/site-packages/extra.py").write_text("raise RuntimeError\n")
    assert observe(observer)["reason"] == "limits_exceeded"


def test_duplicate_distribution_identity_refuses(observer: dict[str, Any], tree: Path) -> None:
    extra = tree / "lib/python3.12/site-packages/duplicate.dist-info"
    extra.mkdir()
    (extra / "METADATA").write_bytes(metadata(tree).read_bytes())
    assert observe(observer)["reason"] == "malformed_metadata"


@pytest.mark.parametrize(
    "changes",
    [
        {"venv": "/opt/../etc"},
        {"owner_uid": "0"},
        {"distributions": {"name": "https://fixture.invalid/pkg"}},
        {"distributions": {"name": "master"}},
        {"distributions": {"pkg_name": "1.0", "PKG-NAME": "1.0"}},
        {"python_version": "3.12"},
        {"unexpected": True},
    ],
)
def test_request_validation(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        request(**changes)


def test_public_fact_caller_uses_only_isolated_system_python(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[str] = []

    def fact(kind: Any, *, command: str) -> str:
        commands.append(command)
        return '{"status":"absent","reason":"absent"}'

    monkeypatch.setattr(inventory, "host", SimpleNamespace(get_fact=fact))
    result = probe_venv_inventory(request())
    assert result.status == "absent"
    argv = shlex.split(commands[0])
    assert argv[:5] == ["/usr/bin/python3", "-I", "-S", "-B", "-c"]
    assert commands == [venv_inventory_command(request())]


@pytest.mark.parametrize(
    "output",
    [
        None,
        "x" * 4097,
        "invalid",
        "[]",
        '{"status":"adopt"}',
        '{"status":"matching_candidate","reason":"metadata_matches"}',
    ],
)
def test_public_caller_invalid_output_never_becomes_candidate(monkeypatch: pytest.MonkeyPatch, output: Any) -> None:
    monkeypatch.setattr(inventory, "host", SimpleNamespace(get_fact=lambda *args, **kwargs: output))
    with pytest.raises(ValueError, match="invalid bounded result"):
        probe_venv_inventory(request())


@pytest.mark.parametrize(
    "hook", ["sitecustomize.py", "sitecustomize.pyc", "sitecustomize.so", "sitecustomize", "usercustomize.py"]
)
def test_startup_hooks_are_unknown(observer: dict[str, Any], tree: Path, hook: str) -> None:
    path = metadata(tree).parent.parent / hook
    if hook == "sitecustomize":
        path.mkdir()
        (path / "__init__.py").write_text("raise AssertionError('must never import')")
    else:
        path.write_text("raise AssertionError('must never import')")
    assert observe(observer)["status"] == "unknown"
    assert observe(observer)["reason"] == "unsupported_layout"


def test_ambiguous_version_outweighs_another_newer_declaration(observer: dict[str, Any], tree: Path) -> None:
    metadata(tree).write_text("Name: fixture-package\nVersion: 2.0.0\n\n")
    extra = metadata(tree).parent.parent / "z-1.0rc1.dist-info"
    extra.mkdir()
    (extra / "METADATA").write_text("Name: z\nVersion: 1.0rc1\n\n")
    result = observe(observer, distributions={"fixture-package": "1.2.3", "z": "1.0"})
    assert result["status"] == "unknown"
    assert result["reason"] == "uncomparable_version"


@pytest.mark.parametrize("unsafe", ["write_mode", "hook"])
def test_python_version_drift_never_bypasses_internal_checks(observer: dict[str, Any], tree: Path, unsafe: str) -> None:
    (tree / "pyvenv.cfg").write_text("version = 3.12.4\ninclude-system-site-packages = false\n")
    if unsafe == "write_mode":
        metadata(tree).chmod(0o666)
        assert observe(observer)["status"] == "refused_untrusted"
    else:
        (metadata(tree).parent.parent / "unknown.pth").write_text("never import")
        assert observe(observer)["status"] == "unknown"


def test_minor_only_uv_declaration_is_unknown(observer: dict[str, Any], tree: Path) -> None:
    (tree / "pyvenv.cfg").write_text("version_info = 3.12\ninclude-system-site-packages = false\n")
    assert observe(observer) == {"status": "unknown", "reason": "malformed_metadata"}
