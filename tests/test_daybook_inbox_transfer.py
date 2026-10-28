"""Actual owned private transfer setup/cleanup; root publication is native-only."""

from __future__ import annotations

import importlib.util
import os
import sys
import types
import uuid
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.daybook_voice_memo_inbox.config import PACKAGE


@pytest.fixture
def helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    for name, package, resource in (
        ("ops_inbox_controls", PACKAGE, "files/inbox_controls.py"),
        ("ops_inbox_filesystem", "ops_deploy.services.daybook_sessions", "files/resources_host.py"),
    ):
        module = types.ModuleType(name)
        monkeypatch.setitem(sys.modules, name, module)
        path = files(package).joinpath(resource)
        exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    spec = importlib.util.spec_from_file_location(
        "owned_inbox_transfer", str(files(PACKAGE).joinpath("files/inbox_transfer.py"))
    )
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def transfer(helper: Any) -> Any:
    root = Path("/tmp") / ("ops-deploy-daybook-inbox-" + uuid.uuid4().hex)
    data = {
        "transfer_dir": str(root),
        "uploaded_bundle": str(root / "source.bundle"),
        "transfer_uid": os.getuid(),
        "bundle_sha256": "a" * 64,
    }
    yield data
    helper.cleanup_transfer(data)
    assert not root.exists()


def test_actual_existing_identity_preparation_is_private_and_cleanup_is_exact(helper: Any, transfer: Any) -> None:
    root = Path(transfer["transfer_dir"])
    helper.prepare_transfer(transfer)
    info = root.stat()
    assert info.st_uid == os.getuid()
    assert info.st_mode & 0o777 == 0o700
    bundle = root / "source.bundle"
    bundle.write_bytes(b"OWNED-PUBLIC-CODE-BUNDLE")
    bundle.chmod(0o600)
    helper.cleanup_transfer(transfer)
    assert not root.exists()
    helper.cleanup_transfer(transfer)  # original owned absence, no parent mutation


def test_existing_directory_is_never_adopted_or_chmodded(helper: Any, transfer: Any) -> None:
    helper.prepare_transfer(transfer)
    root = Path(transfer["transfer_dir"])
    before = root.stat()
    with pytest.raises(FileExistsError):
        helper.prepare_transfer(transfer)
    after = root.stat()
    assert (after.st_ino, after.st_mtime_ns, after.st_ctime_ns, after.st_mode) == (
        before.st_ino,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_mode,
    )


@pytest.mark.parametrize(
    "change",
    [
        {"transfer_dir": "/tmp"},
        {"uploaded_bundle": "/tmp/unowned"},
        {"transfer_uid": True},
        {"bundle_sha256": "not-a-public-code-hash"},
    ],
)
def test_invalid_transfer_declaration_refuses_before_any_creation(helper: Any, transfer: Any, change: Any) -> None:
    with pytest.raises(helper.InboxTransferError, match="declaration_invalid"):
        helper.prepare_transfer({**transfer, **change})
    assert not Path(transfer["transfer_dir"]).exists()


def test_nonroot_cannot_publish_into_protected_install_tree(helper: Any, transfer: Any) -> None:
    if os.geteuid() == 0:
        pytest.skip("The owned native positive/fault fixture covers original root execution")
    with pytest.raises(helper.InboxTransferError, match="original_root_required"):
        helper.publish_bundle(transfer, object())
    assert not Path(transfer["transfer_dir"]).exists()
