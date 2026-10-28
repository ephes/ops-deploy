"""Identity lifecycle admission and private transfer failure boundaries."""

from __future__ import annotations

import io
import json
import runpy
import stat
import tarfile
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError
from pyinfra.api import DeployError, StringCommand
from pyinfra.api.host import Host
from pyinfra.api.state import State
from pyinfra.connectors.util import CommandOutput

from ops_deploy.infra.tailscale.lifecycle import PrivateArchiveDownload
from ops_deploy.infra.tailscale.lifecycle_config import TailscaleBackupConfig, TailscaleManualRestoreConfig


def helper() -> dict[str, Any]:
    loaded = runpy.run_path(str(Path(__file__).parents[1] / "src/ops_deploy/infra/files/tailscale_lifecycle.py"))
    return cast(dict[str, Any], loaded["restore_plan"].__globals__)


@pytest.mark.parametrize(
    "values",
    [dict(root="/var/lib/tailscale/archive"), dict(root="/var/lib"), dict(fetch_local=True, create_archive=False)],
)
def test_backup_refuses_recursive_destination_and_nonexistent_fetch(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TailscaleBackupConfig(**values)


def archive_fixture(path: Path, members: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w:gz") as bundle:
        top = tarfile.TarInfo("owned-20260101T000000/state")
        top.type = tarfile.DIRTYPE
        bundle.addfile(top)
        for name, body in members:
            entry = tarfile.TarInfo(name)
            entry.size = len(body)
            bundle.addfile(entry, io.BytesIO(body))


@pytest.mark.parametrize("member", ["/outside", "owned-20260101T000000/../../outside", "foreign/state/file"])
def test_unsafe_archive_refuses_before_any_native_service_call(tmp_path: Path, member: str) -> None:
    module = helper()
    # These tests isolate archive structure; native prerequisite/staging-owner
    # admission is qualified separately on the owned root Linux fixture.
    module["staging_admission"] = lambda path: Path(path)
    module["require_rsync"] = lambda: None
    root = tmp_path / "archives"
    root.mkdir()
    path = root / "owned-20260101T000000.tar.gz"
    archive_fixture(path, [(member, b"synthetic")])
    module["run"] = lambda _: pytest.fail("No daemon/native extraction before archive admission")
    cfg = TailscaleManualRestoreConfig(
        inventory_name="owned",
        root=str(root),
        state_dir=str(tmp_path / "live"),
        staging_dir=str(tmp_path / "stage"),
        sysconfig_path=str(tmp_path / "env"),
        systemd_dropin_dir=str(tmp_path / "dropins"),
    )
    with pytest.raises((module["Refused"], tarfile.FilterError)):
        module["restore_plan"](cfg.model_dump())
    assert not (tmp_path / "stage").exists()


def test_archive_duplicate_cannot_replace_validated_state_directory(tmp_path: Path) -> None:
    module = helper()
    # These tests isolate archive structure; native prerequisite/staging-owner
    # admission is qualified separately on the owned root Linux fixture.
    module["staging_admission"] = lambda path: Path(path)
    module["require_rsync"] = lambda: None
    root = tmp_path / "archives"
    root.mkdir()
    path = root / "owned-20260101T000000.tar.gz"
    archive_fixture(path, [("owned-20260101T000000/state", b"duplicate")])
    cfg = TailscaleManualRestoreConfig(
        inventory_name="owned",
        root=str(root),
        state_dir=str(tmp_path / "live"),
        staging_dir=str(tmp_path / "stage"),
        sysconfig_path=str(tmp_path / "env"),
        systemd_dropin_dir=str(tmp_path / "dropins"),
    )
    with pytest.raises(module["Refused"], match="duplicate"):
        module["restore_plan"](cfg.model_dump())


class DownloadHost:
    def __init__(self, *, mkdir: bool = True, cleanup: bool = True) -> None:
        self.calls: list[str] = []
        self.mkdir = mkdir
        self.cleanup = cleanup

    def run_shell_command(self, command: StringCommand, **kwargs: Any) -> tuple[bool, CommandOutput]:
        value = command.get_raw_value()
        self.calls.append(value)
        assert kwargs["_sudo"] is True
        if "mkdir --" in value:
            return self.mkdir, CommandOutput([])
        if value.startswith("rm -rf"):
            return self.cleanup, CommandOutput([])
        return True, CommandOutput([])


def test_private_archive_download_failure_cleans_only_owned_private_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failed_download(self: Any, state: State, host: Host, arguments: Any) -> bool:
        assert not arguments.get("_sudo", False)
        assert "_su_user" not in arguments
        return False

    monkeypatch.setattr("ops_deploy.infra.tailscale.lifecycle.FileDownloadCommand.execute", failed_download)
    host = DownloadHost()
    target = tmp_path / "backups/owned.tar.gz"
    command = PrivateArchiveDownload("/opt/backups/owned.tar.gz", target, "operator", target.parent / "latest.tar.gz")
    with pytest.raises(DeployError, match="download failed"):
        command.execute(cast(State, None), cast(Host, host), {"_sudo": True, "_su_user": "root"})
    assert len(host.calls) == 3
    assert host.calls[-1] == "rm -rf -- " + command.remote
    assert all("chmod +r" not in value for value in host.calls)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700


def test_handoff_name_collision_never_removes_existing_path(tmp_path: Path) -> None:
    host = DownloadHost(mkdir=False)
    target = tmp_path / "backups/owned.tar.gz"
    command = PrivateArchiveDownload("/opt/backups/owned.tar.gz", target, "operator", target.parent / "latest.tar.gz")
    with pytest.raises(DeployError, match="existing path preserved"):
        command.execute(cast(State, None), cast(Host, host), {"_sudo": True})
    assert len(host.calls) == 1


def test_operator_backup_directory_has_no_workspace_requirement(tmp_path: Path) -> None:
    # Standard operator paths are valid; our own qualification merely uses a
    # disposable tmp directory. Never gate product behavior on agent worktrees.
    cfg = TailscaleBackupConfig(local_dir=Path.home() / "backups/tailscale")
    assert cfg.local_dir == Path.home() / "backups/tailscale"


def test_actual_vendor_purge_source_provenance() -> None:
    root = Path(__file__).parent / "parity"
    import hashlib

    receipt = json.loads((root / "tailscale_postrm_1_104_2.json").read_text())
    source = (root / "tailscale_postrm_1_104_2.txt").read_bytes()
    assert hashlib.sha256(source).hexdigest() == receipt["sha256"]
    assert b'if [ "$1" = "purge" ]; then' in source
    assert b"rm -rf /var/lib/tailscale" in source
