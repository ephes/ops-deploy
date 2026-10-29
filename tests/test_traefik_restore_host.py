"""Real synthetic archive/filesystem controls for the ACME-only restore helper."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Literal

import pytest

from ops_deploy.infra import TraefikRestoreConfig
from ops_deploy.infra.traefik_backup import RESTORE_SCRIPT

SPEC = importlib.util.spec_from_file_location(
    "traefik_restore_host", Path(__file__).parents[1] / "src/ops_deploy/infra/files/traefik_restore_host.py"
)
assert SPEC is not None
assert SPEC.loader is not None
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)
TarWriteMode = Literal["w", "w:gz", "w:bz2", "w:xz"]
BODY = b'{"synthetic": "fixture-only ACME state"}\n'


def request(tmp_path: Path, **values: Any) -> dict[str, Any]:
    inputs = dict(
        root=str(tmp_path / "archives"),
        staging_dir=str(tmp_path / "staging"),
        acme_path=str(tmp_path / "live/acme.json"),
        acme_owner=str(os.getuid()),
        acme_group=str(os.getgid()),
        include_acme=True,
    )
    inputs.update(values)
    return TraefikRestoreConfig(**inputs).model_dump(mode="json")


def archive(tmp_path: Path, mode: TarWriteMode = "w:gz", suffix: str = "tar.gz") -> Path:
    root = tmp_path / "archives"
    root.mkdir(exist_ok=True)
    path = root / ("manual-fixture." + suffix)
    if suffix == "zip":
        with zipfile.ZipFile(path, "w") as handle:
            handle.writestr("manual-fixture/acme/acme.json", BODY)
            handle.writestr("manual-fixture/dynamic/unowned-route.yml", b"synthetic route\n")
    else:
        with tarfile.open(path, mode) as handle:
            for name, content in [
                ("manual-fixture/acme/acme.json", BODY),
                ("manual-fixture/dynamic/unowned-route.yml", b"synthetic route\n"),
            ]:
                member = tarfile.TarInfo(name)
                member.size = len(content)
                member.mode = 0o600
                handle.addfile(member, io.BytesIO(content))
    path.chmod(0o600)
    return path


def identity(path: Path) -> tuple[int, ...]:
    value = path.stat()
    return value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns


@pytest.mark.parametrize(
    ("mode", "suffix"), [("w:gz", "tar.gz"), ("w:bz2", "tar.bz2"), ("w:xz", "tar.xz"), ("w", "tar"), ("w", "zip")]
)
def test_supported_original_archive_formats_validate_without_any_publication(
    tmp_path: Path, mode: TarWriteMode, suffix: str
) -> None:
    path = archive(tmp_path, mode, suffix)
    cfg = request(tmp_path, archive_extension=suffix)
    before = identity(path)
    result = HOST.restore(cfg, "validate")
    assert result == {"valid": True, "archive": str(path)}
    assert identity(path) == before
    assert not Path(cfg["staging_dir"]).exists()
    assert not Path(cfg["acme_path"]).exists()


def test_apply_is_acme_only_and_repeat_keeps_published_inode_and_metadata(tmp_path: Path) -> None:
    archive(tmp_path)
    cfg = request(tmp_path)
    live = Path(cfg["acme_path"]).parent
    live.mkdir()
    route = live / "dynamic.yml"
    route.write_bytes(b"unowned current route")
    original_route = identity(route)
    assert HOST.restore(cfg, "apply") == {"staged": True, "acme_published": True}
    destination = Path(cfg["acme_path"])
    assert destination.read_bytes() == BODY
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert stat.S_IMODE(live.stat().st_mode) == 0o700
    before = identity(destination), identity(live), identity(route)
    HOST.restore(cfg, "apply")
    assert (identity(destination), identity(live), identity(route)) == before
    assert identity(route) == original_route
    assert not Path(cfg["staging_dir"]).exists()


def test_default_disabled_acme_stages_then_cleans_without_looking_up_unused_owner(tmp_path: Path) -> None:
    archive(tmp_path)
    cfg = request(tmp_path, include_acme=False, acme_owner="unused-missing-user")
    assert HOST.restore(cfg, "apply") == {"staged": True, "acme_published": False}
    assert not Path(cfg["staging_dir"]).exists()
    assert not Path(cfg["acme_path"]).exists()


@pytest.mark.parametrize(
    "kind",
    [
        "traversal",
        "absolute",
        "symlink",
        "hardlink",
        "fifo",
        "duplicate",
        "parent-file",
        "multiple-root",
        "missing-acme",
        "corrupt",
    ],
)
def test_bad_archive_refuses_before_resetting_staging(tmp_path: Path, kind: str) -> None:
    path = archive(tmp_path)
    cfg = request(tmp_path)
    staging = Path(cfg["staging_dir"])
    staging.mkdir()
    sentinel = staging / "original"
    sentinel.write_bytes(b"synthetic preexisting staging")
    before = identity(staging), identity(sentinel)
    if kind == "corrupt":
        path.write_bytes(b"not an archive")
    else:
        with tarfile.open(path, "w:gz") as handle:
            names = {
                "traversal": ["../escape"],
                "absolute": ["/escaped"],
                "symlink": ["payload/link"],
                "hardlink": ["payload/link"],
                "fifo": ["payload/fifo"],
                "duplicate": ["payload/acme/acme.json", "payload/acme/acme.json"],
                "parent-file": ["payload/acme", "payload/acme/acme.json"],
                "multiple-root": ["one/data", "two/data"],
                "missing-acme": ["payload/data"],
            }[kind]
            for name in names:
                member = tarfile.TarInfo(name)
                member.size = 1
                if kind in {"symlink", "hardlink", "fifo"}:
                    member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE}[
                        kind
                    ]
                    member.linkname = "../../escaped"
                    member.size = 0
                handle.addfile(member, io.BytesIO(b"x"))
    with pytest.raises((ValueError, tarfile.TarError)):
        HOST.restore(cfg, "apply")
    assert (identity(staging), identity(sentinel)) == before
    assert sentinel.read_bytes() == b"synthetic preexisting staging"
    assert not Path(cfg["acme_path"]).exists()
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "missing-owner"])
def test_invalid_publication_refuses_before_staging(tmp_path: Path, kind: str) -> None:
    archive(tmp_path)
    cfg = request(tmp_path)
    destination = Path(cfg["acme_path"])
    destination.parent.mkdir()
    target = tmp_path / "unowned"
    target.write_bytes(b"unowned synthetic state")
    if kind == "symlink":
        destination.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, destination)
    else:
        cfg["acme_owner"] = "missing-fixture-account"
    before = identity(target)
    with pytest.raises((ValueError, KeyError)):
        HOST.restore(cfg, "apply")
    assert identity(target) == before
    assert target.read_bytes() == b"unowned synthetic state"
    assert not Path(cfg["staging_dir"]).exists()


def test_cli_result_contains_no_fixture_body_or_credential_digest(tmp_path: Path) -> None:
    archive(tmp_path)
    cfg = request(tmp_path)
    result = subprocess.run(
        [sys.executable, "-I", "-c", RESTORE_SCRIPT, "apply"],
        input=json.dumps(cfg),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"staged": True, "acme_published": True}
    assert not result.stderr
    assert BODY.decode().strip() not in result.stdout


def test_gzip_crc_failure_is_detected_before_staging(tmp_path: Path) -> None:
    path = archive(tmp_path)
    body = bytearray(path.read_bytes())
    body[-8] ^= 0xFF
    path.write_bytes(body)
    cfg = request(tmp_path)
    with pytest.raises((OSError, EOFError, tarfile.TarError)):
        HOST.restore(cfg, "validate")
    assert not Path(cfg["staging_dir"]).exists()


@pytest.mark.parametrize("kind", ["traversal", "link", "parent-file", "multiple-root"])
def test_zip_member_integrity_is_checked_before_staging(tmp_path: Path, kind: str) -> None:
    path = archive(tmp_path, suffix="zip")
    cfg = request(tmp_path, archive_extension="zip")
    with zipfile.ZipFile(path, "w") as handle:
        if kind == "link":
            member = zipfile.ZipInfo("payload/acme/acme.json")
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            handle.writestr(member, "../../unowned")
        else:
            names = {
                "traversal": ["../escaped"],
                "parent-file": ["payload/acme", "payload/acme/acme.json"],
                "multiple-root": ["one/data", "two/data"],
            }[kind]
            for name in names:
                handle.writestr(name, b"synthetic")
    with pytest.raises(ValueError, match=r"Unsupported archive member|Archive parent|Ambiguous restore"):
        HOST.restore(cfg, "apply")
    assert not Path(cfg["staging_dir"]).exists()
    assert not Path(cfg["acme_path"]).exists()


def test_spaced_archive_staging_and_acme_paths_use_literal_filesystem_names(tmp_path: Path) -> None:
    spaced = tmp_path / "owned root with spaces"
    spaced.mkdir()
    path = archive(spaced)
    renamed = path.with_name("chosen archive.tar.gz")
    path.rename(renamed)
    cfg = request(
        spaced,
        archive=renamed.name,
        staging_dir=str(spaced / "restore stage"),
        acme_path=str(spaced / "live directory/acme state.json"),
    )
    # The original archive chooses the destination basename; construct the matching synthetic member.
    with tarfile.open(renamed, "w:gz") as handle:
        member = tarfile.TarInfo("payload/acme/acme state.json")
        member.size = len(BODY)
        handle.addfile(member, io.BytesIO(BODY))
    assert HOST.restore(cfg, "apply")["acme_published"]
    destination = Path(cfg["acme_path"])
    before = identity(destination)
    assert destination.read_bytes() == BODY
    HOST.restore(cfg, "apply")
    assert identity(destination) == before
    assert not Path(cfg["staging_dir"]).exists()
