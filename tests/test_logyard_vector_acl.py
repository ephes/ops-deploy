"""The ACL helper's decisions (files/logyard_vector_acl.py), with getfacl and the account faked."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).parent.parent / "src/ops_deploy/services/logyard/files/logyard_vector_acl.py"


@pytest.fixture
def helper() -> ModuleType:
    spec = importlib.util.spec_from_file_location("logyard_vector_acl_test", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeAccount:
    def __init__(self, uid: int = 64000, gids: set[int] | None = None, groups: set[str] | None = None) -> None:
        self.name, self.uid = "vector", uid
        self.gids = gids or {64000}
        self.groups = groups or {"vector"}


def node(tmp_path: Path, mode: int) -> int:
    path = tmp_path / "file.log"
    path.write_text("x")
    path.chmod(mode)
    return os.open(path, os.O_RDONLY)


def plan(helper: ModuleType, monkeypatch: pytest.MonkeyPatch, fd: int, entries: dict[Any, int], **account: Any) -> Any:
    monkeypatch.setattr(helper, "acl", lambda _fd: entries)
    return helper.plan(fd, "file.log", FakeAccount(**account), "r--", False)


def test_access_through_other_needs_no_entry(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fd = node(tmp_path, 0o604)
    assert plan(helper, monkeypatch, fd, {}) is None


def test_a_file_without_acl_gets_a_named_entry(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fd = node(tmp_path, 0o640)
    assert plan(helper, monkeypatch, fd, {}) == "u:vector:r"


def test_group_bits_that_would_void_the_grant_are_refused(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fd = node(tmp_path, 0o600)
    with pytest.raises(SystemExit, match="narrower"):
        plan(helper, monkeypatch, fd, {})


def test_a_narrow_mask_is_refused_not_widened(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fd = node(tmp_path, 0o640)
    with pytest.raises(SystemExit, match="narrower"):
        plan(helper, monkeypatch, fd, {("mask", ""): 0, ("group", ""): 4})


def test_existing_rights_of_the_entry_are_kept(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fd = node(tmp_path, 0o660)
    entries = {("user", "vector"): 2, ("mask", ""): 6, ("group", ""): 6}
    assert plan(helper, monkeypatch, fd, entries) == "u:vector:rw"


def test_an_entry_that_already_reads_is_current(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fd = node(tmp_path, 0o640)
    assert plan(helper, monkeypatch, fd, {("user", "vector"): 4, ("mask", ""): 4, ("group", ""): 4}) is None


def test_a_member_of_the_owning_group_reads_already(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fd = node(tmp_path, 0o640)
    assert plan(helper, monkeypatch, fd, {}, gids={os.fstat(fd).st_gid}) is None


def test_default_entries_merge_and_respect_the_default_mask(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fd = node(tmp_path, 0o755)
    monkeypatch.setattr(helper, "acl", lambda _fd: {("default:user", "vector"): 1, ("default:mask", ""): 5})
    assert helper.plan(fd, "dir", FakeAccount(), "r--", True) == "d:u:vector:rx"
    monkeypatch.setattr(helper, "acl", lambda _fd: {("default:user", "vector"): 4, ("default:mask", ""): 1})
    with pytest.raises(SystemExit, match="default mask"):
        helper.plan(fd, "dir", FakeAccount(), "r--", True)


def test_a_default_acl_without_mask_takes_it_from_its_group_entry(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fd = node(tmp_path, 0o755)
    base = {("default:user", ""): 7, ("default:other", ""): 5}
    monkeypatch.setattr(helper, "acl", lambda _fd: {**base, ("default:group", ""): 5})
    assert helper.plan(fd, "dir", FakeAccount(), "r--", True) == "d:u:vector:r"
    monkeypatch.setattr(helper, "acl", lambda _fd: {**base, ("default:group", ""): 0})
    with pytest.raises(SystemExit, match="default mask"):
        helper.plan(fd, "dir", FakeAccount(), "r--", True)


def test_a_first_default_acl_is_explicit_and_tight(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(helper, "acl", lambda _fd: {})
    assert (
        helper.plan(node(tmp_path, 0o755), "dir", FakeAccount(), "r--", True)
        == "d:u::rwx,d:g::---,d:o::---,d:m::r--,d:u:vector:r"
    )


def test_paths_are_opened_without_following_links(helper: ModuleType, tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(SystemExit, match="without following links"):
        helper.open_dir(str(tmp_path / "link" / "."))
    with pytest.raises(SystemExit, match="without following links"):
        helper.open_dir(str(tmp_path / "link"))
    with pytest.raises(SystemExit, match="missing directory"):
        helper.open_dir(str(tmp_path / "absent"))
    os.close(helper.open_dir(str(real.resolve())))


def test_getfacl_output_is_parsed_without_effective_comments(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = "user::rw-\nuser:vector:r--\ngroup::r-x\t#effective:r--\nmask::r--\nother::---\ndefault:user:vector:r--\n"

    class Done:
        stdout = output

    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k: Done())
    assert helper.acl(3) == {
        ("user", ""): 6,
        ("user", "vector"): 4,
        ("group", ""): 5,
        ("mask", ""): 4,
        ("other", ""): 0,
        ("default:user", "vector"): 4,
    }


def test_rights_through_other_are_not_replaced(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fd = node(tmp_path, 0o662)
    with pytest.raises(SystemExit, match="through other"):
        plan(helper, monkeypatch, fd, {})


def test_an_owner_without_the_bits_is_refused(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fd = node(tmp_path, 0o640)
    (tmp_path / "file.log").chmod(0o040)  # the open descriptor stays usable
    with pytest.raises(SystemExit, match="owned by"):
        plan(helper, monkeypatch, fd, {}, uid=os.fstat(fd).st_uid)


def test_one_group_entry_must_cover_the_whole_request(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fd = node(tmp_path, 0o750)
    entries = {("group", "a"): 4, ("group", "b"): 1, ("mask", ""): 5, ("group", ""): 5}
    monkeypatch.setattr(helper, "acl", lambda _fd: entries)
    with pytest.raises(SystemExit, match="through group"):
        helper.plan(fd, "dir", FakeAccount(groups={"a", "b"}), "r-x", False)
