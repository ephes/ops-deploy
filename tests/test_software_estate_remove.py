"""Exact original path admission and owned removal primitive, never the real path."""

import shlex
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from ops_deploy.infra.software_estate_remove import SoftwareEstateRemoveConfig, remove_software_estate
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

TARGET = "/usr/local/lib/software-estate"


@pytest.mark.parametrize("path", ["/usr/local/lib", TARGET + "/", TARGET + "/../other", "/tmp/software-estate"])
def test_refuses_every_other_path(path: str) -> None:
    with pytest.raises(ValidationError):
        SoftwareEstateRemoveConfig.model_validate({"install_dir": path})


def test_absent_path_is_zero_change() -> None:
    result = run_deploy_fake(remove_software_estate, SoftwareEstateRemoveConfig())
    assert result.succeeded, result.error
    assert result.changed_ops == []
    assert result.executed_commands == []


@pytest.mark.parametrize(
    ("kind", "mode"), [("directory", "drwxr-xr-x"), ("file", "-rw-r--r--"), ("link", "lrwxrwxrwx")]
)
def test_exact_operation_removes_only_owned_leaf(kind: str, mode: str, tmp_path: Path) -> None:
    result = run_deploy_fake(
        remove_software_estate, SoftwareEstateRemoveConfig(), responses=fakehost.stat(TARGET, mode=mode)
    )
    assert result.succeeded, result.error
    assert len(result.changed_ops) == 1
    assert len(result.executed_commands) == 1
    argv = shlex.split(result.executed_commands[0])
    assert argv == ["rm", "-rf", TARGET]
    # The standard operation's actual argv is exercised only against an owned
    # temporary leaf. This is filesystem-primitive proof, not production removal
    # or a claim that fake fact collection is native host qualification.
    target = tmp_path / "owned-install"
    peer = tmp_path / "peer"
    peer.mkdir()
    sentinel = peer / "keep"
    sentinel.write_text("synthetic peer")
    before = sentinel.stat()
    if kind == "directory":
        target.mkdir()
        (target / "collector").write_text("synthetic old collector")
    elif kind == "file":
        target.write_text("synthetic wrong-type leaf")
    else:
        target.symlink_to(peer, target_is_directory=True)
    subprocess.run([*argv[:-1], str(target)], check=True, timeout=10)
    assert not target.exists()
    assert not target.is_symlink()
    assert sentinel.stat() == before
    assert sentinel.read_text() == "synthetic peer"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["peer"]


@pytest.mark.parametrize("kind", ["directory", "file", "link", "absent"])
def test_real_local_operation_and_repeat_in_owned_directory(kind: str, tmp_path: Path) -> None:
    from typing import Any
    from unittest.mock import patch

    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops
    from pyinfra.operations import files

    from ops_deploy.testing.harness import collect_ops

    owned = tmp_path / "owned-leaf"
    peer = tmp_path / "peer"
    peer.mkdir()
    sentinel = peer / "sentinel"
    sentinel.write_text("synthetic peer")
    before = sentinel.stat()
    if kind == "directory":
        owned.mkdir()
        (owned / "collector").write_text("synthetic collector")
    elif kind == "file":
        owned.write_text("synthetic wrong-type leaf")
    elif kind == "link":
        owned.symlink_to(peer, target_is_directory=True)
    original = files.directory

    def owned_operation(**kwargs: Any) -> Any:
        # Only the fixed target is translated into the owned fixture. The real
        # standard operation, native facts and execution remain unmocked.
        assert kwargs["path"] == TARGET
        return original(**{**kwargs, "path": str(owned)})

    for repeat in (False, True):
        state = State(Inventory((["@local"], {})), Config())
        try:
            connect_all(state)
            with patch("ops_deploy.infra.software_estate_remove.files.directory", owned_operation):
                add_deploy(state, remove_software_estate, SoftwareEstateRemoveConfig())
                run_ops(state)
            ops = collect_ops(state, "@local")
            assert len(ops) == 1
            assert all(op.succeeded for op in ops)
            assert sum(op.changed for op in ops) == (0 if repeat or kind == "absent" else 1)
        finally:
            disconnect_all(state)
        assert not owned.exists()
        assert not owned.is_symlink()
        assert sentinel.stat() == before
        assert sorted(path.name for path in tmp_path.iterdir()) == ["peer"]
