"""Real owned private transfer IO; root publication identity is simulated here."""

from __future__ import annotations

import grp
import hashlib
import os
import runpy
import sys
import types
import uuid
from contextlib import nullcontext
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest


@pytest.fixture
def transfer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    fs = types.ModuleType("ops_photos_filesystem")
    fs.__dict__.update(
        runpy.run_path(str(files("ops_deploy.services.daybook_sessions").joinpath("files/resources_host.py")))
    )
    monkeypatch.setitem(sys.modules, "ops_photos_filesystem", fs)
    module = runpy.run_path(
        str(files("ops_deploy.services.daybook_photos_offload").joinpath("files/photos_transfer.py"))
    )
    root = Path("/tmp") / ("ops-deploy-daybook-photos-" + uuid.uuid4().hex)
    body = b"OWNED public source bundle, no credentials or photos\n"
    data = {
        "transfer_dir": str(root),
        "uploaded_bundle": str(root / "source.bundle"),
        "transfer_uid": os.getuid(),
        "bundle_sha256": hashlib.sha256(body).hexdigest(),
        "bundle": str(tmp_path / "source.bundle"),
        "system_group": grp.getgrgid(os.getgid()).gr_name,
    }
    module["prepare_transfer"](data)
    uploaded = root / "source.bundle"
    uploaded.write_bytes(body)
    uploaded.chmod(0o600)
    calls: list[Any] = []

    class Controls:
        def require_quiescent(self) -> None:
            calls.append("Photos-only-quiescence")

    result = SimpleNamespace(
        module=module,
        root=root,
        body=body,
        data=data,
        uploaded=uploaded,
        calls=calls,
        controls=Controls(),
        parent=tmp_path,
    )
    yield result
    # Known unique owned fixture cleanup, never a product recursive deletion.
    for path in root.iterdir() if root.exists() else ():
        path.unlink()
    module["cleanup_transfer"](data)
    assert not root.exists()


def publish(c: Any) -> None:
    native_fstat = os.fstat
    parent_inode = c.parent.stat().st_ino

    def fstat(descriptor: int) -> Any:
        info = native_fstat(descriptor)
        if info.st_ino != parent_inode:
            return info
        return SimpleNamespace(st_uid=0, st_mode=info.st_mode)

    # Real descriptor IO and bytes. Native supplies actual root ownership and
    # GUI/connecting-identity transitions; neither is claimed by this mock.
    with patch("os.geteuid", return_value=0), patch("os.fstat", side_effect=fstat), patch("os.fchown") as chown:
        c.module["publish_bundle"](c.data, c.controls)
        chown.assert_called_once()
        assert chown.call_args.args[1:] == (0, os.getgid())


def test_real_private_upload_publish_and_exact_cleanup(transfer: Any) -> None:
    c = transfer
    info = c.root.stat()
    assert info.st_uid == os.getuid()
    assert info.st_mode & 0o777 == 0o700
    publish(c)
    dest = Path(c.data["bundle"])
    assert dest.read_bytes() == c.body
    assert dest.stat().st_mode & 0o777 == 0o600
    assert dest.stat().st_nlink == 1
    assert c.calls == ["Photos-only-quiescence"]
    assert list(c.parent.glob(".photos-bundle-*")) == []
    c.module["cleanup_transfer"](c.data)
    assert not c.root.exists()
    c.module["cleanup_transfer"](c.data)


@pytest.mark.parametrize("fault", ["hash", "mode", "hardlink", "link", "short-read"])
def test_failed_copy_or_unsafe_upload_never_replaces_existing_bundle(transfer: Any, fault: str) -> None:
    c = transfer
    dest = Path(c.data["bundle"])
    dest.write_text("OWNED existing source")
    before = dest.read_bytes(), dest.stat().st_ino
    if fault == "hash":
        c.data["bundle_sha256"] = "f" * 64
    elif fault == "mode":
        c.uploaded.chmod(0o644)
    elif fault == "hardlink":
        os.link(c.uploaded, c.parent / "upload-hardlink")
    elif fault == "link":
        c.uploaded.unlink()
        c.uploaded.symlink_to(dest)
    read_context = patch("os.read", return_value=b"") if fault == "short-read" else nullcontext()
    with read_context, pytest.raises((c.module["PhotosTransferError"], OSError)):
        publish(c)
    assert (dest.read_bytes(), dest.stat().st_ino) == before
    assert list(c.parent.glob(".photos-bundle-*")) == []


@pytest.mark.parametrize("fault", ["destination-link", "destination-hardlink", "extra-member", "existing-parent"])
def test_substitution_and_cleanup_never_adopt_unowned_members(transfer: Any, fault: str) -> None:
    c = transfer
    dest = Path(c.data["bundle"])
    outside = c.parent / "outside"
    outside.write_text("OWNED preserved")
    if fault.startswith("destination"):
        if fault == "destination-link":
            dest.symlink_to(outside)
        else:
            os.link(outside, dest)
        with pytest.raises(c.module["PhotosTransferError"], match="destination_substituted"):
            publish(c)
    elif fault == "extra-member":
        (c.root / "unexpected").write_text("OWNED unknown member")
        with pytest.raises(OSError, match="Directory not empty"):
            c.module["cleanup_transfer"](c.data)
        assert (c.root / "unexpected").exists()
    else:
        before = c.root.stat()
        with pytest.raises(FileExistsError):
            c.module["prepare_transfer"](c.data)
        assert c.root.stat().st_ctime_ns == before.st_ctime_ns
    assert outside.read_text() == "OWNED preserved"
