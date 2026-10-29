"""Backup payload selection and real copy/tar commands, confined to pytest temp trees."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.infra import TraefikBackupConfig, TraefikRestoreConfig
from ops_deploy.infra.traefik_backup import (
    _dynamic_copy,
    _dynamic_tree_check,
    _private_local_file,
    _resolved_paths,
    _unsafe_root_check,
)
from tests.test_infra_traefik_lifecycle import STAMP, backup


def _realpath_missing_supported() -> bool:
    if shutil.which("realpath") is None:
        return False
    return subprocess.run(["realpath", "-m", "--", "/nonexistent-dir/child"], capture_output=True).returncode == 0


@pytest.mark.parametrize("include_dynamic", [True, False])
@pytest.mark.parametrize("trailing_slash", [True, False])
def test_real_archive_contains_selected_tree_and_private_metadata(
    tmp_path: Path, include_dynamic: bool, trailing_slash: bool
) -> None:
    source = tmp_path / "selected-routes"
    (source / "nested").mkdir(parents=True)
    source.chmod(0o755)
    contents = {
        "service.yml": b"http: {middlewares: {auth: {basicAuth: {users: [synthetic-auth-hash]}}}}\n",
        "nested/route.toml": b"[http.services.private]\n",
        ".route-note": b"hidden source entry\n",
    }
    for relative, data in contents.items():
        path = source / relative
        path.write_bytes(data)
        path.chmod(0o640)
    excluded = tmp_path / "not-selected"
    excluded.mkdir()
    (excluded / "acme.json").write_bytes(b"synthetic-private-key-never-copy")
    (excluded / "traefik.toml").write_bytes(b"static-config-not-a-route")
    root = tmp_path / "backups"
    cfg = TraefikBackupConfig(
        root=str(root),
        prefix="-manual",
        dynamic_dir=str(source) + ("/" if trailing_slash else ""),
        include_dynamic=include_dynamic,
        acme_path=str(excluded / "acme.json"),
        fetch_local=False,
    )
    result = backup(cfg)
    assert result.succeeded, result.error
    name = f"-manual-{STAMP}"
    payload = root / name
    for directory in (payload, payload / "acme", payload / "dynamic"):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    metadata = payload / "metadata.yml"
    metadata.write_bytes(result.upload(str(metadata)))
    metadata.chmod(0o600)
    # Execute only the generated copy/archive commands, not fake connector
    # mkdir/chown/system operations. Everything resolves inside tmp_path. The
    # test is not root, so a stub stands in for ``chown root:root``; the real
    # ``chmod`` of the dynamic container still runs.
    stub = tmp_path / "stub-bin"
    stub.mkdir()
    (stub / "chown").write_text("#!/bin/sh\nexit 0\n")
    (stub / "chown").chmod(0o700)
    commands = [c for c in result.executed_commands if "cp -a " in c or "tar -czf " in c]
    for command in commands:
        subprocess.run(
            ["sh", "-c", command],
            check=True,
            capture_output=True,
            # BSD tar's macOS resource-fork sidecars do not exist on the Linux
            # target. Disable only that test-platform metadata behavior.
            env={**os.environ, "COPYFILE_DISABLE": "1", "PATH": f"{stub}:{os.environ['PATH']}"},
        )
    archive = root / f"{name}.tar.gz"
    assert archive.stat().st_mode & 0o777 == 0o600
    with tarfile.open(archive) as packed:
        members = {member.name.rstrip("/"): member for member in packed.getmembers()}
        assert {key.split("/", 1)[0] for key in members} == {name}
        assert members[name].mode & 0o777 == 0o700
        assert members[f"{name}/metadata.yml"].mode & 0o777 == 0o600
        # The 0755 source directory's mode must not replace the private container.
        assert members[f"{name}/dynamic"].mode & 0o777 == 0o700
        if include_dynamic:
            assert members[f"{name}/dynamic/nested"].mode & 0o777 == source.joinpath("nested").stat().st_mode & 0o777
        files = {key for key, member in members.items() if member.isfile()}
        expected = {f"{name}/metadata.yml"}
        if include_dynamic:
            expected |= {f"{name}/dynamic/{relative}" for relative in contents}
        assert files == expected
        for relative, expected_bytes in contents.items():
            if include_dynamic:
                member = members[f"{name}/dynamic/{relative}"]
                stream = packed.extractfile(member)
                assert stream is not None
                assert stream.read() == expected_bytes
                assert member.mode & 0o777 == 0o640
        document = yaml.safe_load(metadata.read_text())
        assert document["dynamic_dir"] == cfg.dynamic_dir
        assert document["include_dynamic"] is include_dynamic
        assert document["include_acme"] is False
    assert b"synthetic-auth-hash" not in metadata.read_bytes()
    assert all("synthetic-private-key" not in command for command in result.executed_commands)
    assert (excluded / "acme.json").read_bytes() == b"synthetic-private-key-never-copy"


def test_missing_dynamic_tree_refuses_before_operations_or_controller_writes(tmp_path: Path) -> None:
    local = tmp_path / "local"
    cfg = TraefikBackupConfig(local_dir=local)
    result = backup(cfg, {_dynamic_tree_check(cfg.dynamic_dir) + " && echo yes": []})
    assert not result.succeeded
    assert "dynamic source" in str(result.error)
    assert result.executed_commands == []
    assert not local.exists()


@pytest.mark.parametrize("kind", ["file-link", "directory-link", "source-link", "fifo"])
def test_unsafe_tree_cannot_copy_or_create_an_archive(tmp_path: Path, kind: str) -> None:
    source, dest = tmp_path / "source", tmp_path / "destination"
    source.mkdir()
    dest.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "private-key"
    secret.write_bytes(b"synthetic-secret")
    if kind == "file-link":
        (source / "route.yml").symlink_to(secret)
    elif kind == "directory-link":
        (source / "nested").symlink_to(outside, target_is_directory=True)
    elif kind == "source-link":
        source.rmdir()
        source.symlink_to(outside, target_is_directory=True)
    else:
        os.mkfifo(source / "special")
    archive = tmp_path / "never-created.tar.gz"
    command = _dynamic_copy(str(source), str(dest)) + f" && tar -czf {archive} -C {dest} ."
    result = subprocess.run(["sh", "-c", command], capture_output=True)
    assert result.returncode != 0
    assert not list(dest.iterdir())
    assert not archive.exists()
    assert secret.read_bytes() == b"synthetic-secret"
    assert b"synthetic-secret" not in result.stdout + result.stderr


@pytest.mark.parametrize("source_mode", [0o2755, 0o4755, 0o6755])
def test_set_id_bits_of_the_source_directory_are_cleared_on_the_container(tmp_path: Path, source_mode: int) -> None:
    source, dest = tmp_path / "source", tmp_path / "dynamic"
    (source / "nested").mkdir(parents=True)
    (source / "route.yml").write_bytes(b"synthetic")
    source.chmod(source_mode)
    # The check is only meaningful when the platform kept the set-ID bits.
    assert stat.S_IMODE(source.stat().st_mode) == source_mode
    dest.mkdir()
    dest.chmod(0o700)
    stub = tmp_path / "stub-bin"
    stub.mkdir()
    (stub / "chown").write_text("#!/bin/sh\nexit 0\n")
    (stub / "chown").chmod(0o700)
    archive = tmp_path / "dynamic.tar.gz"
    command = _dynamic_copy(str(source), str(dest)) + f" && tar -czf {archive} -C {tmp_path} {dest.name}"
    subprocess.run(
        ["sh", "-c", command],
        check=True,
        capture_output=True,
        env={**os.environ, "COPYFILE_DISABLE": "1", "PATH": f"{stub}:{os.environ['PATH']}"},
    )
    # Full mode, not masked to the permission bits.
    assert stat.S_IMODE(dest.stat().st_mode) == 0o700
    with tarfile.open(archive) as packed:
        assert packed.getmember(dest.name).mode == 0o700
        assert packed.getmember(f"{dest.name}/nested").isdir()


@pytest.mark.parametrize("spelling", ["", "/", "/.", "//./"])
def test_linked_paths_refuse_whatever_their_spelling(tmp_path: Path, spelling: str) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "route.yml").write_bytes(b"synthetic")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    path = str(link) + spelling
    root_check = subprocess.run(["sh", "-c", _unsafe_root_check(path)], capture_output=True, text=True)
    assert root_check.stdout.strip() == "unsafe"
    source_check = subprocess.run(["sh", "-c", _dynamic_tree_check(path)], capture_output=True)
    assert source_check.returncode != 0


@pytest.mark.parametrize(("root", "source"), [("/srv/routes/backups", "/srv/routes"), ("/srv", "/srv/routes")])
def test_resolved_overlap_refuses_before_writes(tmp_path: Path, root: str, source: str) -> None:
    cfg = TraefikBackupConfig(root="/alias/backups", dynamic_dir="/srv/routes", local_dir=tmp_path / "local")
    result = backup(cfg, {_resolved_paths(cfg.root, cfg.dynamic_dir): [root, source]})
    assert not result.succeeded
    assert "resolved dynamic source and backup root" in str(result.error)
    assert result.executed_commands == []
    assert not (tmp_path / "local").exists()


@pytest.mark.parametrize("response", [[], ["/opt/backups/traefik"], ["relative", "/etc/traefik/dynamic"]])
def test_unresolvable_paths_refuse_before_writes(response: list[str]) -> None:
    cfg = TraefikBackupConfig(fetch_local=False)
    result = backup(cfg, {_resolved_paths(cfg.root, cfg.dynamic_dir): response})
    assert not result.succeeded
    assert "resolved dynamic source" in str(result.error)
    assert result.executed_commands == []


@pytest.mark.skipif(not _realpath_missing_supported(), reason="needs GNU realpath -m, as on the Linux target")
def test_resolved_paths_follow_an_aliased_ancestor_of_an_absent_root(tmp_path: Path) -> None:
    source = tmp_path / "routes"
    source.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(source, target_is_directory=True)
    command = _resolved_paths(str(alias / "backups"), str(source) + "/.")
    lines = subprocess.run(["sh", "-c", command], check=True, capture_output=True, text=True).stdout.splitlines()
    resolved = Path(os.path.realpath(source))
    assert lines == [str(resolved / "backups"), str(resolved)]
    assert not (source / "backups").exists()


def test_copy_failure_never_archives_or_fetches(tmp_path: Path) -> None:
    cfg = TraefikBackupConfig(local_dir=tmp_path / "local")
    target = f"{cfg.root}/{cfg.prefix}-{STAMP}/dynamic"
    result = backup(cfg, {_dynamic_copy(cfg.dynamic_dir, target): {"success": False}})
    assert not result.succeeded
    assert not any("tar -czf " in command for command in result.executed_commands)
    assert not (tmp_path / "local").exists()


def test_disabled_tree_does_not_probe_or_copy_it() -> None:
    cfg = TraefikBackupConfig(dynamic_dir="/missing/routes", include_dynamic=False, fetch_local=False)
    result = backup(cfg)
    assert result.succeeded, result.error
    assert not any("cp -a " in command for command in result.executed_commands)
    assert not any("/missing/routes" in event.value for event in result.events if event.kind == "fact")


def test_directory_only_backup_does_not_create_or_fetch_archive(tmp_path: Path) -> None:
    result = backup(TraefikBackupConfig(create_archive=False, local_dir=tmp_path / "local"))
    assert result.succeeded, result.error
    assert not any("tar -czf " in command for command in result.executed_commands)
    assert not (tmp_path / "local").exists()


@pytest.mark.parametrize(
    ("dynamic", "root"),
    [("/etc/traefik", "/etc/traefik/backups"), ("/backup/tree", "/backup"), ("/etc/x/../dynamic", "/backup")],
)
def test_backup_paths_cannot_recurse_or_traverse(dynamic: str, root: str) -> None:
    with pytest.raises(ValidationError, match=r"overlap|parent traversal"):
        TraefikBackupConfig(dynamic_dir=dynamic, root=root)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_unsafe_local_archive_is_refused_before_fetch(tmp_path: Path, kind: str) -> None:
    local = tmp_path / "local"
    local.mkdir()
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"unchanged")
    foreign.chmod(0o644)
    target = local / f"manual-{STAMP}.tar.gz"
    if kind == "symlink":
        target.symlink_to(foreign)
    elif kind == "hardlink":
        os.link(foreign, target)
    else:
        os.mkfifo(target)
    result = backup(TraefikBackupConfig(local_dir=local))
    assert not result.succeeded
    assert "Traefik backup | Fetch the backup archive" not in result.changed_ops
    assert foreign.read_bytes() == b"unchanged"
    assert foreign.stat().st_mode & 0o777 == 0o644


def test_missing_fetched_archive_is_not_success(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        _private_local_file(str(tmp_path / "missing"))


def test_restore_does_not_claim_dynamic_support_and_has_explicit_validation_only_option() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        TraefikRestoreConfig.model_validate({"include_dynamic": True})
    assert TraefikRestoreConfig(dry_run=True).dry_run
    assert not TraefikRestoreConfig().dry_run


@pytest.mark.parametrize("target", ["directory", "archive"])
def test_existing_attempt_never_overwrites_history_or_fetches(tmp_path: Path, target: str) -> None:
    cfg = TraefikBackupConfig(local_dir=tmp_path / "local")
    path = f"{cfg.root}/manual-{STAMP}" + (".tar.gz" if target == "archive" else "")
    result = backup(cfg, {f"if [ -e {path} ] || [ -L {path} ]": ["exists"]})
    assert not result.succeeded
    assert "already exists" in str(result.error)
    assert result.executed_commands == []
    assert not (tmp_path / "local").exists()


def test_unsafe_backup_root_never_writes(tmp_path: Path) -> None:
    cfg = TraefikBackupConfig(local_dir=tmp_path / "local")
    result = backup(cfg, {f"if [ -L {cfg.root} ]": ["unsafe"]})
    assert not result.succeeded
    assert "backup root" in str(result.error)
    assert result.executed_commands == []
    assert not (tmp_path / "local").exists()


def test_archive_failure_never_fetches_or_creates_controller_destination(tmp_path: Path) -> None:
    result = backup(TraefikBackupConfig(local_dir=tmp_path / "local"), {"tar -czf": {"success": False}})
    assert not result.succeeded
    assert not (tmp_path / "local").exists()


def test_linked_local_directory_refuses_without_fetch_or_foreign_permission_changes(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    foreign = tmp_path / "foreign-backups"
    foreign.mkdir(mode=0o755)
    foreign.chmod(0o755)
    sentinel = foreign / "keep.txt"
    sentinel.write_bytes(b"unchanged")
    local = tmp_path / "local-backups"
    local.symlink_to(foreign, target_is_directory=True)
    result = backup(TraefikBackupConfig(local_dir=local))
    assert not result.succeeded
    assert "local backup directory must be an accessible real directory (no link)" in caplog.text
    assert "Traefik backup | Fetch the backup archive" not in result.changed_ops
    assert list(foreign.iterdir()) == [sentinel]
    assert sentinel.read_bytes() == b"unchanged"
    assert foreign.stat().st_mode & 0o777 == 0o755
    assert local.is_symlink()
