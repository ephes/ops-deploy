"""Explicit Darwin branch plus its target-interpreter-compatible host helper."""

import grp
import hashlib
import io
import os
import platform
import pwd
import tarfile
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.base import UvInstallConfig, deploy_uv_install
from ops_deploy.base import uv_install_darwin as native
from ops_deploy.testing import run_deploy_fake

TARGET = "aarch64-apple-darwin"
SHA = "743f85035a1996ecb350659e01cd9faea9709829be09b1b4b03c73eaf3c9cd73"


def config(tmp_path: Path) -> dict[str, Any]:
    return {
        "install_dir": str(tmp_path / "bin"),
        "owner": pwd.getpwuid(os.getuid()).pw_name,
        "group": grp.getgrgid(os.getgid()).gr_name,
        "version": "0.13.5",
        "checksums": {TARGET: SHA},
        "force_reinstall": False,
        "update_existing": True,
    }


def binaries(directory: Path, version: str = "0.13.5") -> None:
    directory.mkdir(exist_ok=True)
    for name in ("uv", "uvx"):
        path = directory / name
        path.write_text(f"#!/bin/sh\necho '{name} {version}'\n")
        path.chmod(0o755)


def archive(version: str = "0.13.5", *, invalid_uvx: bool = False) -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as bundle:
        for name in ("uv", "uvx"):
            content = f"#!/bin/sh\necho '{name} {version}'\n".encode()
            if name == "uvx" and invalid_uvx:
                content = b"#!/bin/sh\nexit 1\n"
            entry = tarfile.TarInfo(f"uv-{TARGET}/{name}")
            entry.size = len(content)
            bundle.addfile(entry, io.BytesIO(content))
    return result.getvalue()


def fixture_release(monkeypatch: pytest.MonkeyPatch, cfg: dict[str, Any], content: bytes) -> list[str]:
    urls: list[str] = []
    cfg["checksums"][TARGET] = hashlib.sha256(content).hexdigest()
    monkeypatch.setattr(platform, "machine", lambda: "arm64")

    def download(url: str, **kwargs: Any) -> io.BytesIO:
        urls.append(url)
        return io.BytesIO(content)

    monkeypatch.setattr(urllib.request, "urlopen", download)
    return urls


def snapshot(path: Path) -> dict[str, tuple[int, int, int, int, int]]:
    return {
        str(p.relative_to(path)): (s.st_ino, s.st_mode, s.st_uid, s.st_mtime_ns, s.st_ctime_ns)
        for p in [path, *path.rglob("*")]
        for s in [p.lstat()]
    }


def test_matching_installation_never_downloads_stages_or_repairs_metadata(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    directory = Path(cfg["install_dir"])
    binaries(directory)
    directory.chmod(0o750)
    (directory / "uv").chmod(0o750)
    before = snapshot(tmp_path)
    assert not native.needed(cfg)
    native.install(cfg)
    assert snapshot(tmp_path) == before


def test_fresh_release_and_repeat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = config(tmp_path)
    urls = fixture_release(monkeypatch, cfg, archive())
    assert native.needed(cfg)
    native.install(cfg)
    assert native.version(Path(cfg["install_dir"]) / "uv") == "0.13.5"
    before = snapshot(tmp_path)
    native.install(cfg)
    assert snapshot(tmp_path) == before
    assert urls == ["https://github.com/astral-sh/uv/releases/download/0.13.5/uv-aarch64-apple-darwin.tar.gz"]


@pytest.mark.parametrize("failure", ["checksum", "version", "uvx", "archive"])
def test_invalid_release_retains_both_old_binaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    cfg = config(tmp_path)
    directory = Path(cfg["install_dir"])
    binaries(directory, "0.12.0")
    old = {name: (directory / name).read_bytes() for name in ("uv", "uvx")}
    content = archive("0.12.9" if failure == "version" else "0.13.5", invalid_uvx=failure == "uvx")
    if failure == "archive":
        content = b"not a tar archive"
    fixture_release(monkeypatch, cfg, content)
    if failure == "checksum":
        cfg["checksums"][TARGET] = "0" * 64
    with pytest.raises((RuntimeError, tarfile.ReadError)):
        native.install(cfg)
    assert {name: (directory / name).read_bytes() for name in old} == old
    assert set(directory.iterdir()) == {directory / "uv", directory / "uvx"}


def test_update_force_symlink_and_missing_uvx_contract(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    directory = Path(cfg["install_dir"])
    binaries(directory, "0.12.0")
    assert native.needed(cfg)
    cfg["update_existing"] = False
    assert not native.needed(cfg)
    cfg["force_reinstall"] = True
    assert native.needed(cfg)
    cfg["force_reinstall"] = False
    (directory / "uvx").unlink()
    assert native.needed(cfg)
    (directory / "uvx").symlink_to("elsewhere")
    assert native.needed(cfg)
    (directory / "uv").unlink()
    (directory / "uv").symlink_to("elsewhere")
    assert native.needed(cfg)


def test_unknown_platform_requires_explicit_pin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "machine", lambda: "riscv64")
    with pytest.raises(RuntimeError, match="no pinned checksum for unsupported-apple-darwin"):
        native.target(config(tmp_path))
    assert list(tmp_path.iterdir()) == []


def test_darwin_is_explicit_and_linux_defaults_are_unchanged() -> None:
    cfg = UvInstallConfig()
    assert cfg.version == "0.13.4"
    assert cfg.group == "root"
    assert cfg.darwin is False
    native_cfg = UvInstallConfig(darwin=True, version="0.13.5", group="wheel", checksums={TARGET: SHA})
    run = run_deploy_fake(deploy_uv_install, native_cfg)
    assert run.succeeded, run.error
    assert len(run.changed_ops) == 1
    assert "Install native uv" in str(run.changed_ops)
    assert all("apt-get" not in command and "sha256sum" not in command for command in run.executed_commands)
