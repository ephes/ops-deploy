"""Certbot lifecycle caller boundaries and real synthetic archive/preservation work."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from ops_deploy.infra import (
    CertbotDnsBackupConfig,
    CertbotDnsRestoreConfig,
    deploy_certbot_dns_backup,
    deploy_certbot_dns_restore,
)
from ops_deploy.infra import certbot_lifecycle as lifecycle
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

STAMP = "20261030T010203"
LINUX_ONLY = pytest.mark.skipif(
    sys.platform != "linux", reason="real GNU mv/findmnt semantics; owned Linux qualification"
)


def fake_plan(cfg: Any, result: Any, restore: bool = False) -> FakeRun:
    def answer(*args: Any, **kwargs: Any) -> str | None:
        return json.dumps(result) if result is not None else None

    with patch.object(lifecycle, "probe", side_effect=answer):
        return run_deploy_fake(
            deploy_certbot_dns_restore if restore else deploy_certbot_dns_backup, cfg, responses=fakehost.LINUX
        )


def backup_response(cfg: CertbotDnsBackupConfig, managed: bool = True) -> dict[str, Any]:
    return {
        "valid": True,
        "timestamp": STAMP,
        "archive": f"{cfg.root}/{cfg.prefix}-{STAMP}.{cfg.archive_extension}",
        "managed": managed,
        "restrict": [],
    }


def restore_response(cfg: CertbotDnsRestoreConfig) -> dict[str, Any]:
    return {"valid": True, "archive": f"{cfg.root}/selected.tar.gz", "tops": [Path(cfg.directory).name]}


def host_module() -> Any:
    path = lifecycle.FILES / "certbot_lifecycle_host.py"
    spec = importlib.util.spec_from_file_location("owned_certbot_host_test", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.ARCHIVE_MEMBERS_SOURCE = (lifecycle.FILES / "certbot_archive_members.py").read_text()  # type: ignore[attr-defined]
    module.PRESERVE_SOURCE = (lifecycle.FILES / "certbot_preserve.py").read_text()  # type: ignore[attr-defined]
    spec.loader.exec_module(module)
    return module


def payloads(tmp_path: Path) -> tuple[Any, dict[str, Any], dict[str, Any], Path]:
    source = tmp_path / "cert state"
    (source / "archive/example").mkdir(parents=True)
    (source / "live/example").mkdir(parents=True)
    (source / "archive/example/cert1.pem").write_bytes(b"synthetic certificate body\n")
    (source / "live/example/cert.pem").symlink_to("../../archive/example/cert1.pem")
    (source / "dns-credentials.ini").write_text("synthetic-provider-entry\n")
    backup = CertbotDnsBackupConfig(
        root=str(tmp_path / "backup root"),
        src=str(source),
        owner=str(os.getuid()),
        group=str(os.getgid()),
        fetch_local=False,
    ).model_dump(mode="json")
    backup["_timestamp"] = STAMP
    target = tmp_path / "target parent" / source.name
    target.parent.mkdir()
    restore = CertbotDnsRestoreConfig(
        archive="latest",
        root=backup["root"],
        directory=str(target),
        credentials_file=str(target / "dns-credentials.ini"),
        rfc2136_credentials_file="",
        owner=str(os.getuid()),
        group=str(os.getgid()),
        run_dry_renew=False,
    ).model_dump(mode="json")
    return host_module(), backup, restore, source


def test_declared_defaults_and_explicit_required_archive() -> None:
    backup = CertbotDnsBackupConfig()
    assert backup.root == "/opt/backups/certbot-dns"
    assert backup.src == "/etc/letsencrypt"
    assert backup.dir_mode == "0700"
    assert backup.fetch_local
    assert backup.create_archive
    with pytest.raises(ValidationError):
        CertbotDnsRestoreConfig()  # type: ignore[call-arg]
    restore = CertbotDnsRestoreConfig(archive="latest")
    assert restore.run_dry_renew
    assert not restore.reload_postfix
    assert not restore.dry_run
    assert "required_mount" not in CertbotDnsRestoreConfig.model_fields


def test_configured_modes_numeric_identity_and_literal_spaces() -> None:
    cfg = CertbotDnsRestoreConfig(
        archive="chosen archive.tar.gz",
        directory="/owned/cert state",
        owner=1234,
        group=2345,
        dir_mode=0o750,
        credentials_mode=0o640,
    )
    assert cfg.owner == "1234"
    assert cfg.group == "2345"
    assert cfg.dir_mode == "0750"
    assert cfg.credentials_mode == "0640"
    assert cfg.directory == "/owned/cert state"


@pytest.mark.parametrize("value", ["/", "//etc/", "/tmp/../etc/letsencrypt", "/owned/tree.pre-restore-copy"])
def test_mutable_root_and_preservation_copy_refusals(value: str) -> None:
    with pytest.raises(ValidationError):
        CertbotDnsRestoreConfig(archive="latest", directory=value)


def test_backup_creation_and_no_archive_repeat_follow_actual_plan() -> None:
    cfg = CertbotDnsBackupConfig(fetch_local=False)
    result = fake_plan(cfg, backup_response(cfg))
    assert result.succeeded, result.error
    assert result.executed_commands == [lifecycle._command("backup-apply")]
    assert not result.uploads
    cfg = CertbotDnsBackupConfig(create_archive=False, fetch_local=False)
    result = fake_plan(cfg, backup_response(cfg, managed=False))
    assert result.succeeded, result.error
    assert not result.changed_ops
    assert not result.executed_commands


@pytest.mark.parametrize("response", [None, {}, {"valid": True, "archive": "/wrong"}])
def test_missing_or_malformed_backup_plan_refuses_before_effects(response: Any) -> None:
    result = fake_plan(CertbotDnsBackupConfig(fetch_local=False), response)
    assert not result.succeeded
    assert not result.executed_commands
    assert not result.uploads


def test_inconsistent_backup_plan_cannot_skip_archive_or_fetch_another_path() -> None:
    cfg = CertbotDnsBackupConfig(fetch_local=False)
    for key, value in [("managed", False), ("archive", "/unselected/private.tar.gz"), ("timestamp", "../invalid")]:
        response = backup_response(cfg)
        response[key] = value
        result = fake_plan(cfg, response)
        assert not result.succeeded
        assert not result.executed_commands


def test_restore_validation_is_read_only_but_normal_apply_is_managed() -> None:
    cfg = CertbotDnsRestoreConfig(archive="latest", dry_run=True, reload_postfix=True)
    result = fake_plan(cfg, restore_response(cfg), restore=True)
    assert result.succeeded, result.error
    assert not result.mutating_changed_ops
    assert all(command != lifecycle._command("restore-apply") for command in result.executed_commands)
    cfg = CertbotDnsRestoreConfig(archive="latest")
    result = fake_plan(cfg, restore_response(cfg), restore=True)
    assert result.succeeded, result.error
    assert result.executed_commands == [lifecycle._command("restore-apply")]
    assert result.mutating_changed_ops


def test_wrong_restore_top_refuses_before_staging() -> None:
    cfg = CertbotDnsRestoreConfig(archive="latest")
    result = fake_plan(cfg, {**restore_response(cfg), "tops": ["unrelated"]}, restore=True)
    assert not result.succeeded
    assert not result.executed_commands


@pytest.mark.parametrize("kind", ["gz", "bz2", "xz", "tar"])
def test_real_backup_payload_internal_links_and_fixed_archive_privacy(tmp_path: Path, kind: str) -> None:
    host, backup, restore, source = payloads(tmp_path)
    backup["archive_format"] = kind
    backup["archive_extension"] = "tar" if kind == "tar" else "tar." + kind
    created = host.backup_apply(backup)
    archive = Path(created["archive"])
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    with tarfile.open(archive) as handle:
        members = {member.name: member for member in handle.getmembers()}
        assert source.name not in members  # Exact original archive walker, no added top header.
        link = members[source.name + "/live/example/cert.pem"]
        assert link.issym()
        assert link.linkname == "../../archive/example/cert1.pem"
    restore["archive_extension"] = backup["archive_extension"]
    before = {str(path): path.lstat() for path in source.rglob("*")}
    checked = host.restore_validate(restore)
    assert checked["tops"] == [source.name]
    assert not Path(restore["directory"]).exists()
    assert all(path.lstat().st_mtime_ns == before[str(path)].st_mtime_ns for path in source.rglob("*"))


def test_existing_archive_restriction_skips_links_hidden_and_unrelated_files(tmp_path: Path) -> None:
    host, backup, _restore, _source = payloads(tmp_path)
    root = Path(backup["root"])
    root.mkdir(mode=0o700)
    archive = root / "older archive.tgz"
    archive.write_text("synthetic previous archive")
    archive.chmod(0o644)
    hidden = root / ".hidden.tgz"
    hidden.write_text("unselected hidden archive")
    hidden.chmod(0o644)
    other = root / "unrelated.txt"
    other.write_text("unselected")
    other.chmod(0o644)
    (root / "linked.tar.gz").symlink_to(other)
    backup["create_archive"] = False
    root_before = root.stat()
    host.backup_apply(backup)
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    assert stat.S_IMODE(hidden.stat().st_mode) == 0o644
    assert stat.S_IMODE(other.stat().st_mode) == 0o644
    assert root.stat().st_ctime_ns == root_before.st_ctime_ns
    assert not host.backup_plan(backup)["managed"]


@pytest.mark.parametrize(
    ("member", "link_target"), [("../escape", None), ("wrong/entry", None), ("cert state/live/link", "../../../escape")]
)
def test_original_validator_rejects_bad_archive_before_live_changes(
    tmp_path: Path, member: str, link_target: str | None
) -> None:
    host, backup, restore, _source = payloads(tmp_path)
    root = Path(backup["root"])
    root.mkdir()
    archive = root / "bad.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        entry = tarfile.TarInfo(member)
        if link_target is None:
            entry.size = 1
            handle.addfile(entry, io.BytesIO(b"x"))
        else:
            entry.type = tarfile.SYMTYPE
            entry.linkname = link_target
            handle.addfile(entry)
    with pytest.raises(ValueError, match=r"archive|outside|symlink"):
        host.restore_validate(restore)
    assert not Path(restore["directory"]).exists()
    assert not list(Path(restore["directory"]).parent.glob(".restore-staging-*"))


@LINUX_ONLY
def test_real_original_preservation_publish_and_retained_copy(tmp_path: Path) -> None:
    host, backup, restore, source = payloads(tmp_path)
    host.backup_apply(backup)
    live = Path(restore["directory"])
    live.mkdir()
    old = live / "previous-secret.txt"
    old.write_text("synthetic old body")
    old.chmod(0o640)
    restored = host.restore_apply(restore)
    saved = Path(restored["preserved"]["path"])
    assert restored["preserved"]["method"] == "rename"
    assert (saved / old.name).read_text() == "synthetic old body"
    assert stat.S_IMODE((saved / old.name).stat().st_mode) == 0o640
    assert not old.exists()
    assert (live / "live/example/cert.pem").read_bytes() == (source / "archive/example/cert1.pem").read_bytes()
    assert (live / "live/example/cert.pem").is_symlink()
    assert stat.S_IMODE((live / "dns-credentials.ini").stat().st_mode) == 0o600
    assert stat.S_IMODE(live.stat().st_mode) == 0o700
    assert not list(live.parent.glob(".restore-staging-*"))


@LINUX_ONLY
def test_failed_publication_keeps_preservation_report_and_cleans_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host, backup, restore, _source = payloads(tmp_path)
    host.backup_apply(backup)
    live = Path(restore["directory"])
    live.mkdir()
    (live / "old").write_text("kept after actual injected mv failure")
    original = host.subprocess.run
    reached = []

    def fail_move(argv: list[str], **kwargs: Any) -> Any:
        if argv[0] == "mv":
            reached.append(argv)
            raise RuntimeError("owned injected publication failure")
        return original(argv, **kwargs)

    monkeypatch.setattr(host.subprocess, "run", fail_move)
    with pytest.raises(RuntimeError, match="publication failure"):
        host.restore_apply(restore)
    assert reached
    saved = list(live.parent.glob(live.name + ".pre-restore-*"))
    assert len(saved) == 1
    assert (saved[0] / "old").read_text() == "kept after actual injected mv failure"
    assert not list(live.parent.glob(".restore-staging-*"))


@LINUX_ONLY
def test_renewal_and_edge_reload_use_original_argv_and_propagate_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host, backup, restore, _source = payloads(tmp_path)
    host.backup_apply(backup)
    restore.update(run_dry_renew=True, reload_postfix=True)
    calls = []
    original = host.subprocess.run

    def commands(argv: list[str], **kwargs: Any) -> Any:
        if argv[0] in {"certbot", "systemctl"}:
            calls.append(argv)
            return SimpleNamespace(returncode=0)
        return original(argv, **kwargs)

    monkeypatch.setattr(host.subprocess, "run", commands)
    host.restore_apply(restore)
    assert calls == [["certbot", "renew", "--dry-run"], ["systemctl", "reload", "postfix"]]


def test_vendored_original_validator_and_preserver_are_exact() -> None:
    import hashlib

    snapshots = Path(__file__).parent / "parity/certbot_lifecycle"
    manifest = json.loads((snapshots / "provenance.json").read_text())
    for original, installed in [
        ("archive_members.py", "certbot_archive_members.py"),
        ("preserve.py", "certbot_preserve.py"),
    ]:
        name = "roles__restore_preserve_internal__files__" + original + ".txt"
        expected = manifest["files"][name]["sha256"]
        assert hashlib.sha256((lifecycle.FILES / installed).read_bytes()).hexdigest() == expected
        assert (lifecycle.FILES / installed).read_bytes() == (snapshots / name).read_bytes()


def test_reading_a_retained_source_does_not_mutate_or_prune_it(tmp_path: Path) -> None:
    host, backup, _restore, source = payloads(tmp_path)
    saved = source.with_name(source.name + ".pre-restore-original")
    source.rename(saved)
    CertbotDnsBackupConfig(src=str(saved), root=backup["root"])
    # Direct host orchestration source reads a retained copy; only mutable
    # destination fields must reject preservation paths.
    backup["src"] = str(saved)
    before = (saved / "archive/example/cert1.pem").read_bytes()
    host.backup_apply(backup)
    assert (saved / "archive/example/cert1.pem").read_bytes() == before


def test_direct_host_apply_dry_flag_validates_without_creating_live_or_staging(tmp_path: Path) -> None:
    host, backup, restore, _source = payloads(tmp_path)
    host.backup_apply(backup)
    restore.update(dry_run=True, run_dry_renew=True, reload_postfix=True)
    result = host.restore_apply(restore)
    assert result["valid"]
    live = Path(restore["directory"])
    assert not live.exists()
    assert not list(live.parent.glob(".restore-staging-*"))
    assert not list(live.parent.glob(live.name + ".pre-restore-*"))


def test_no_archive_flag_does_not_touch_or_follow_unused_destination_alias(tmp_path: Path) -> None:
    host, backup, _restore, _source = payloads(tmp_path)
    backup["create_archive"] = False
    root = Path(backup["root"])
    root.mkdir(mode=0o700)
    foreign = tmp_path / "unowned.txt"
    foreign.write_text("unselected body")
    foreign.chmod(0o644)
    archive = root / ("manual-" + STAMP + ".tar.gz")
    archive.symlink_to(foreign)
    assert not host.backup_plan(backup)["managed"]
    assert archive.is_symlink()
    assert stat.S_IMODE(foreign.stat().st_mode) == 0o644


def test_prepare_fetch_destination_is_private_before_transfer_and_refuses_aliases(tmp_path: Path) -> None:
    destination = tmp_path / "future archive.tar.gz"
    lifecycle._prepare_local_archive(str(destination))
    assert destination.read_bytes() == b""
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    destination.chmod(0o644)
    destination.write_bytes(b"existing synthetic archive")
    lifecycle._prepare_local_archive(str(destination))
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert destination.read_bytes() == b"existing synthetic archive"
    link = tmp_path / "alias.tar.gz"
    link.symlink_to(destination)
    with pytest.raises(OSError, match="symbolic links"):
        lifecycle._prepare_local_archive(str(link))
    hard = tmp_path / "hardlink.tar.gz"
    os.link(destination, hard)
    from pyinfra.api import DeployError

    with pytest.raises(DeployError, match="singly-linked"):
        lifecycle._prepare_local_archive(str(destination))


@pytest.mark.parametrize("kind", ["gz", "bz2", "xz", "tar", "zip"])
def test_failed_archive_creation_never_publishes_partial_latest(tmp_path: Path, kind: str) -> None:
    host, backup, _restore, _source = payloads(tmp_path)
    backup.update(archive_format=kind, archive_extension="tar.gz")
    root = Path(backup["root"])
    host.backup_apply(backup)
    archive = Path(host.backup_plan(backup)["archive"])
    previous = archive.read_bytes()

    def partial(source: Path, destination: str, archive_format: str) -> None:
        Path(destination).write_bytes(b"partial compressed archive")
        raise OSError("owned interrupted archive creation")

    with patch.object(host, "create_archive", side_effect=partial), pytest.raises(OSError, match="interrupted"):
        host.backup_apply(backup)
    assert archive.read_bytes() == previous
    assert sorted(root.iterdir()) == [archive]
    archive.unlink()
    with patch.object(host, "create_archive", side_effect=partial), pytest.raises(OSError, match="interrupted"):
        host.backup_apply(backup)
    assert not list(root.iterdir())
