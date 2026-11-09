"""Minecraft Java backup and restore: configs, plans, and the host program against tmp dirs.

The host program runs for real here (tar, gzip, cp, chown, the vendored
preserver, its RCON client against a fake RCON server); ``systemctl`` and
``findmnt`` are stubs on ``PATH`` that log their calls and environment.
"""

from __future__ import annotations

import importlib.util
import io
import json
import logging
import os
import pwd
import shlex
import socket
import struct
import subprocess
import tarfile
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services._lifecycle.local_backup import SnapshotRetention, retention
from ops_deploy.services.minecraft_java import (
    MinecraftJavaBackupConfig,
    MinecraftJavaRestoreConfig,
    deploy_minecraft_java_backup,
    deploy_minecraft_java_restore,
    lifecycle,
)
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests.test_local_backup import needs_gnu, run_bash, shell_env

STAMP = "20261109T120000"
TIME = {"date -u +%Y%m%dT%H%M%S": [STAMP]}
PASSWORD = "fixture-rcon-password"  # pragma: allowlist secret
WORLD = "world_forge_2026_02_22"
ME = pwd.getpwuid(os.getuid()).pw_name
GID = str(os.getgid())
MOUNT = "/opt/backups"


def secrets(password: str = PASSWORD) -> SecretValues:
    return SecretValues(SecretRef("secrets/prod/minecraft_java.yml"), {"rcon_password": password})


def backup_config(**changes: Any) -> MinecraftJavaBackupConfig:
    return MinecraftJavaBackupConfig.model_validate({"world_name": WORLD, **changes})


def restore_config(**changes: Any) -> MinecraftJavaRestoreConfig:
    return MinecraftJavaRestoreConfig.model_validate({"world_name": WORLD, **changes})


def payload_of(result: FakeRun, action: str) -> tuple[str, dict[str, Any]]:
    ((command, stdin),) = [(c, s) for c, s in result.stdin if shlex.split(c)[-1] == action]
    return command, json.loads(stdin)


def names(ops: list[str]) -> list[str]:
    return [op.split(" | ", 1)[1] for op in ops]


# --- configs -----------------------------------------------------------------


def test_defaults_are_the_roles_except_the_world_which_is_required() -> None:
    backup, restore = backup_config(), restore_config()

    assert (backup.prefix, backup.root, backup.server_dir, backup.service_name, backup.rcon_port) == (
        "manual",
        "/opt/backups/minecraft-java",
        "/home/minecraft/server",
        "minecraft-java",
        25575,
    )
    assert (backup.save_wait, backup.save_timeout, backup.retention, backup.required_mount) == (2, 30, False, None)
    assert (restore.archive, restore.user, restore.group, restore.dry_run, restore.confirm) == (
        "latest",
        "minecraft",
        "minecraft",
        False,
        False,
    )
    assert restore.staging_dir == "/opt/backups/minecraft-java/.restore-work"
    # The work directory follows a custom root unless it is set.
    moved = restore_config(root="/mnt/disk/minecraft-java", required_mount="/mnt/disk")
    assert moved.staging_dir == "/mnt/disk/minecraft-java/.restore-work"
    assert restore_config(root="/mnt/disk/minecraft-java", staging_dir="/mnt/disk/work").staging_dir == "/mnt/disk/work"
    # The role's default world (``world``) is what the playbook archived by mistake: no default here.
    with pytest.raises(ValidationError):
        MinecraftJavaBackupConfig.model_validate({})
    with pytest.raises(ValidationError):
        MinecraftJavaRestoreConfig.model_validate({})


@pytest.mark.parametrize(
    "archive",
    [
        "latest",
        "manual-20261109T120000.tar.gz",
        "PREFIX=pre-witherstorm-2026-02-21-20260221T155011.tar.gz",
        "pre-removal-extra-worlds-20261105T082514Z.tar.gz",
        "/opt/backups/minecraft-java/manual-20261109T120000.tar.gz",
    ],
)
def test_restore_accepts_latest_names_and_paths_below_the_root(archive: str) -> None:
    assert restore_config(archive=archive).archive == archive


@pytest.mark.parametrize(
    "changes",
    [
        {"archive": "../../etc/shadow.tar.gz"},
        {"archive": ".hidden.tar.gz"},
        {"archive": "manual.tar"},
        {"archive": "x; rm -rf /.tar.gz"},
        {"archive": "/etc/minecraft.tar.gz"},
        {"archive": "/opt/backups/minecraft-java/../x.tar.gz"},
        {"archive": "/opt/backups/minecraft-java/.restore-work/x.tar.gz"},
        {"root": "/opt/backups"},
        {"root": "/home/minecraft/server/backups"},
        {"staging_dir": "/tmp"},
        {"staging_dir": "/home/minecraft/server/.restore"},
        {"staging_dir": "/opt/backups/minecraft-java"},
        {"server_dir": "/home"},
        {"user": "root"},
        {"world_name": "../world"},
        {"world_name": "world forge"},
        {"required_mount": MOUNT, "staging_dir": "/tmp/minecraft-restore"},
        {"dry_run": "yes"},
    ],
)
def test_restore_refuses_unsafe_settings(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        restore_config(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"root": "/opt/backups"},
        {"root": "/home/minecraft/server/backups"},
        {"root": "/opt/backups/minecraft-java", "required_mount": "/srv"},
        {"prefix": "../x"},
        {"world_name": "world/../other"},
        {"rcon_port": 25565},
        {"retain_count": -1},
    ],
)
def test_backup_refuses_unsafe_settings(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        backup_config(**changes)


# --- plans -------------------------------------------------------------------


def test_backup_plan_guards_the_mount_writes_with_the_secret_on_stdin_and_prunes_recorded_snapshots() -> None:
    cfg = backup_config(required_mount=MOUNT, retain_count=3, retain_days=14)

    result = run_deploy_fake(deploy_minecraft_java_backup, cfg, secrets(), responses=TIME)

    assert result.succeeded, result.error
    archive = f"/opt/backups/minecraft-java/manual-{STAMP}.tar.gz"
    assert names(result.changed_ops) == [
        "Check the backup mount and name",
        f"Back up the Minecraft worlds (playing {WORLD}) into {archive}",
        "Record the snapshot and prune recorded snapshots",
    ]
    preflight, backup, prune = result.executed_commands
    assert "require_mount /opt/backups /opt/backups/minecraft-java" in preflight
    assert f"require_new_snapshot /opt/backups/minecraft-java manual-{STAMP}" in preflight
    assert f"record_snapshot /opt/backups/minecraft-java manual-{STAMP}" in prune
    assert f"prune_snapshots /opt/backups/minecraft-java 3 20261026T120000 manual-{STAMP}" in prune
    command, payload = payload_of(result, "backup")
    assert command.startswith("python3 -I -c ")
    assert payload == {
        "root": "/opt/backups/minecraft-java",
        "archive": archive,
        "server_dir": "/home/minecraft/server",
        "world": WORLD,
        "unit": "minecraft-java",
        "port": 25565,
        "rcon_port": 25575,
        "save_wait": 2,
        "save_timeout": 30,
        "rcon_password": PASSWORD,
    }
    # The password travels on stdin only: no command, fact, op name or argument carries it.
    assert PASSWORD not in result.all_text()
    assert backup == command


def test_backup_without_policy_plans_only_the_archive() -> None:
    result = run_deploy_fake(
        deploy_minecraft_java_backup, backup_config(prefix="pre-update"), secrets(), responses=TIME
    )

    assert result.succeeded, result.error
    assert names(result.changed_ops) == [
        f"Back up the Minecraft worlds (playing {WORLD}) into /opt/backups/minecraft-java/pre-update-{STAMP}.tar.gz"
    ]


@pytest.mark.parametrize("store", [None, secrets("short"), secrets("CHANGEME"), secrets("has space in it")])
def test_backup_refuses_a_missing_or_unsafe_password_before_any_step(store: SecretValues | None) -> None:
    result = run_deploy_fake(deploy_minecraft_java_backup, backup_config(), store, responses=TIME)

    assert not result.succeeded
    assert result.fact_commands == []
    assert result.stdin == []
    if store is not None:
        assert store["rcon_password"] not in str(result.error)


def test_backup_refuses_an_unreadable_host_clock() -> None:
    result = run_deploy_fake(deploy_minecraft_java_backup, backup_config(), secrets())

    assert not result.succeeded
    assert "cannot read the host's time" in str(result.error)
    assert result.stdin == []


def test_unconfirmed_restore_stops_before_any_probe() -> None:
    result = run_deploy_fake(deploy_minecraft_java_restore, restore_config())

    assert not result.succeeded
    assert "not confirmed" in str(result.error)
    assert result.fact_commands == []
    assert result.stdin == []


PLAN = {
    "archive": f"/opt/backups/minecraft-java/manual-{STAMP}.tar.gz",
    "size_bytes": 10,
    "world": WORLD,
    "worlds": [WORLD, "world_vanilla"],
    "world_entries": {WORLD: 3, "world_vanilla": 1},
    "live_worlds": [WORLD],
    "server_properties": True,
    "player_files": ["ops.json"],
    "ignored_top_level": [],
    "server_dir": "/home/minecraft/server",
    "unit": "loaded/inactive",
    "stop": False,
    "start_after": False,
}


def test_dry_run_restore_only_checks(caplog: pytest.LogCaptureFixture) -> None:
    cfg = restore_config(dry_run=True, required_mount=MOUNT)
    responses = {" check ) ||": [lifecycle.PLAN_MARKER + json.dumps(PLAN)]}

    with caplog.at_level(logging.INFO):
        result = run_deploy_fake(deploy_minecraft_java_restore, cfg, responses=responses)

    assert result.succeeded, result.error
    assert f"worlds into /home/minecraft/server: {WORLD} (3 entries, live copy: True), world_vanilla" in caplog.text
    assert all(op.read_only for op in result.ops), result.ops
    assert result.mutating_changed_ops == []
    check, restore = lifecycle._command("check"), lifecycle._command("restore")
    assert result.stdin
    assert all(check in command for command, _ in result.stdin)
    assert not any(restore in command for command in [*result.fact_commands, *result.executed_commands])
    mount = result.executed_commands[0]
    assert "require_mount /opt/backups /opt/backups/minecraft-java" in mount
    assert ".restore-work" not in mount


def test_confirmed_restore_runs_the_program_with_the_settings_on_stdin() -> None:
    cfg = restore_config(confirm=True, archive="PREFIX=x.tar.gz", required_mount=MOUNT)

    result = run_deploy_fake(deploy_minecraft_java_restore, cfg)

    assert result.succeeded, result.error
    command, payload = payload_of(result, "restore")
    assert command.startswith("python3 -I -c ")
    assert payload == {
        "root": "/opt/backups/minecraft-java",
        "archive": "PREFIX=x.tar.gz",
        "staging": "/opt/backups/minecraft-java/.restore-work",
        "server_dir": "/home/minecraft/server",
        "world": WORLD,
        "unit": "minecraft-java",
        "user": "minecraft",
        "group": "minecraft",
        "port": 25565,
        "start_timeout": 300,
    }
    assert (
        "require_mount /opt/backups /opt/backups/minecraft-java /opt/backups/minecraft-java/.restore-work"
        in (result.executed_commands[0])
    )
    assert (
        names(result.mutating_changed_ops)[-1] == f"Restore the Minecraft worlds (playing {WORLD}) from PREFIX=x.tar.gz"
    )


# --- retention ---------------------------------------------------------------


def write(path: Path, text: str, mode: int = 0o644) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


@needs_gnu
def test_retention_never_touches_archives_this_route_did_not_write(tmp_path: Path) -> None:
    root = tmp_path / "minecraft-java"
    handmade = [
        "pre-removal-extra-worlds-20261105T082514Z.tar.gz",
        "PREFIX=pre-witherstorm-2026-02-21-20260221T155011.tar.gz",
        "manual-20251128T054607.tar.gz",
        "manual-20251203T102636.tar.gz",
    ]
    for name in handmade:
        write(root / name, "keep", 0o644)
    records = root / ".ops-deploy-snapshots"
    for day in ("01", "02", "03", "04"):
        write(root / f"manual-202611{day}T120000.tar.gz", "ours", 0o600)
        records.mkdir(exist_ok=True)
        (records / f"manual-202611{day}T120000").touch()
    current = f"manual-{STAMP}"
    write(root / f"{current}.tar.gz", "ours", 0o600)
    cfg = SnapshotRetention(required_mount=None, retain_count=3, retain_days=14)

    result = run_bash(retention(cfg, str(root), current, STAMP), shell_env(tmp_path, mounted=True))

    assert result.returncode == 0, result.stderr
    assert {p.name for p in root.iterdir()} == {
        *handmade,
        ".ops-deploy-snapshots",
        "manual-20261103T120000.tar.gz",
        "manual-20261104T120000.tar.gz",
        f"{current}.tar.gz",
    }
    for name in handmade:
        assert (root / name).stat().st_mode & 0o777 == 0o644
        assert (root / name).read_text() == "keep"


# --- host program ------------------------------------------------------------

STUBS = {
    # systemctl show: LoadState/ActiveState from flags; every call (with its environment) is logged.
    "systemctl": 'if [ "$1" = show ]; then [ -n "${STUB_FAIL_SHOW:-}" ] && exit 1; '
    'echo "LoadState=${STUB_LOAD:-loaded}"; echo "ActiveState=$(cat "$STATE")"; exit 0; fi\n'
    'if [ "$1" = stop ]; then [ -n "${STUB_FAIL_STOP:-}" ] && exit 1; echo "${STUB_STOPPED:-inactive}" > "$STATE"; fi\n'
    'if [ "$1" = start ]; then echo active > "$STATE"; fi\nexit 0',
    "findmnt": 'echo \'{"filesystems": [{"target": "/"}]}\'',
}


@pytest.fixture
def stubs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    flags = tmp_path / "flags"
    flags.mkdir()
    state = tmp_path / "unit-state"
    state.write_text("inactive\n")
    for name, body in STUBS.items():
        path = bin_dir / name
        header = f'for f in {flags}/*; do [ -f "$f" ] && export "$(basename "$f")=$(cat "$f")"; done\nSTATE={state}\n'
        path.write_text(f'#!/bin/bash\n{header}echo "{name} $* ENV:$(env | tr "\\n" " ")" >> {log}\n{body}\n')
        path.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    log.write_text("")
    return log


def unit(tmp_path: Path, state: str) -> None:
    (tmp_path / "unit-state").write_text(state + "\n")


def flag(tmp_path: Path, name: str, value: str = "1") -> None:
    (tmp_path / "flags" / name).write_text(value)


def calls(log: Path) -> list[str]:
    return [
        line.split(" ENV:", 1)[0]
        for line in log.read_text().splitlines()
        if line.startswith("systemctl ") and not line.startswith("systemctl show")
    ]


def host() -> Any:
    path = lifecycle.FILES / "lifecycle_host.py"
    spec = importlib.util.spec_from_file_location("minecraft_lifecycle_host_test", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.PRESERVE_SOURCE = lifecycle.PRESERVE_PY  # type: ignore[attr-defined]
    spec.loader.exec_module(module)
    # The backup root, archives and work directory belong to the test's own account here.
    module.ROOT_UID, module.ROOT_GID = os.getuid(), os.getgid()  # type: ignore[attr-defined]
    return module


def free_port() -> int:
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        port: int = probe_socket.getsockname()[1]
        return port


def server_tree(base: Path, marker: str, *, world: str = WORLD, level: str = WORLD) -> Path:
    server_dir = base / "server"
    write(server_dir / world / "level.dat", f"level {marker}")
    write(server_dir / world / "region" / "r.0.0.mca", f"region {marker}")
    (server_dir / world / "empty").mkdir(parents=True, exist_ok=True)
    write(
        server_dir / "server.properties", f"#Minecraft server properties\nlevel-name={level}\nrcon.password=x\n", 0o640
    )
    write(server_dir / "ops.json", f'["{marker}"]')
    write(server_dir / "whitelist.json", "[]")
    write(server_dir / "world_forge_test" / "level.dat", "other world")
    return server_dir


def backup_cfg(base: Path, server_dir: Path, **extra: Any) -> dict[str, Any]:
    root = base / "backups" / "minecraft-java"
    root.parent.mkdir(parents=True, exist_ok=True)
    cfg = {
        "root": str(root),
        "archive": f"{root}/manual-{STAMP}.tar.gz",
        "server_dir": str(server_dir),
        "world": WORLD,
        "unit": "minecraft-java",
        "port": free_port(),
        "rcon_port": free_port(),
        "save_wait": 0,
        "save_timeout": 5,
        "rcon_password": PASSWORD,
    }
    cfg.update(extra)
    return cfg


def members(archive: Path) -> list[str]:
    with tarfile.open(archive) as packed:
        return packed.getnames()


class FakeRcon:
    """A Minecraft RCON server on 127.0.0.1 that records the commands it got (one per connection)."""

    def __init__(self, password: str = PASSWORD, answers: dict[str, str] | None = None) -> None:
        self.password = password
        self.answers = {
            "save-off": "Automatic saving is now disabled",
            "save-all flush": "Saving the game (this may take a moment!)Saved the game",
            "save-on": "Automatic saving is now enabled",
            **(answers or {}),
        }
        self.commands: list[str] = []
        self.logins: list[str] = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.port: int = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def read(self, conn: socket.socket) -> tuple[int, int, str]:
        size = struct.unpack("<i", conn.recv(4, socket.MSG_WAITALL))[0]
        data = conn.recv(size, socket.MSG_WAITALL)
        request, kind = struct.unpack("<ii", data[:8])
        return request, kind, data[8:-2].decode()

    def send(self, conn: socket.socket, request: int, kind: int, body: str) -> None:
        payload = body.encode()
        conn.sendall(struct.pack("<iii", len(payload) + 10, request, kind) + payload + b"\x00\x00")

    def serve(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                request, _kind, password = self.read(conn)
                self.logins.append(password)
                if password != self.password:
                    self.send(conn, -1, 2, "")
                    continue
                self.send(conn, request, 2, "")
                request, _kind, command = self.read(conn)
                self.commands.append(command)
                answer = self.answers.get(command)
                if answer is None:
                    continue  # close without an answer
                self.send(conn, request, 0, answer)

    def close(self) -> None:
        self.listener.close()


@pytest.fixture
def rcon() -> Iterator[FakeRcon]:
    server = FakeRcon()
    yield server
    server.close()


def test_stopped_backup_packs_every_world_in_the_role_layout_without_rcon_or_start(tmp_path: Path, stubs: Path) -> None:
    server_dir = server_tree(tmp_path, "one")
    # Not worlds: no level.dat, hidden, a pre-restore copy, a link to a world.
    write(server_dir / "mods" / "witherstorm.jar", "jar")
    write(server_dir / ".cache" / "level.dat", "hidden")
    write(server_dir / f"{WORLD}.pre-restore-20261101T000000000000Z-abc" / "level.dat", "old copy")
    (server_dir / "linked_world").symlink_to(server_dir / "world_forge_test")
    root = tmp_path / "backups" / "minecraft-java"
    handmade = write(root / "pre-removal-extra-worlds-20261105T082514Z.tar.gz", "keep", 0o644)
    root.chmod(0o755)
    cfg = backup_cfg(tmp_path, server_dir)

    host().backup(dict(cfg))

    archive = root / f"manual-{STAMP}.tar.gz"
    assert archive.stat().st_mode & 0o777 == 0o600
    assert root.stat().st_mode & 0o777 == 0o700
    # Archives this route did not write keep their mode and content.
    assert handmade.stat().st_mode & 0o777 == 0o644
    assert handmade.read_text() == "keep"
    names = members(archive)
    # The archive module's layout: relative to the server directory, the world's own entry left out.
    assert WORLD not in names
    assert sorted(names) == sorted(
        [
            f"{WORLD}/level.dat",
            f"{WORLD}/region",
            f"{WORLD}/region/r.0.0.mca",
            f"{WORLD}/empty",
            "server.properties",
            "ops.json",
            "whitelist.json",
            # The extra world of the server: every world, not just the one it plays.
            "world_forge_test/level.dat",
        ]
    )
    assert calls(stubs) == []
    assert not list(root.glob(".*.partial"))


def test_backup_refuses_the_wrong_world_and_missing_inputs_before_writing(tmp_path: Path, stubs: Path) -> None:
    module = host()
    stale = server_tree(tmp_path / "stale", "one", level="world")
    with pytest.raises(module.Failure, match="selects level-name 'world'"):
        module.backup(backup_cfg(tmp_path / "stale", stale))
    missing = server_tree(tmp_path / "missing", "one")
    for path in sorted((missing / WORLD).rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    (missing / WORLD).rmdir()
    with pytest.raises(module.Failure, match="World directory not found"):
        module.backup(backup_cfg(tmp_path / "missing", missing))
    linked = server_tree(tmp_path / "linked", "one")
    (linked / WORLD / "escape").symlink_to("/etc")
    with pytest.raises(module.Failure, match="link or special file"):
        module.backup(backup_cfg(tmp_path / "linked", linked))
    for base in ("stale", "missing"):
        # Refused before the first change: the backup root is not even created.
        assert not (tmp_path / base / "backups" / "minecraft-java").exists()
    root = tmp_path / "linked" / "backups" / "minecraft-java"
    assert not list(root.glob("*.tar.gz"))
    assert not list(root.glob(".*"))


def test_backup_refuses_an_inactive_unit_while_a_server_answers(tmp_path: Path, stubs: Path) -> None:
    server_dir = server_tree(tmp_path, "one")
    cfg = backup_cfg(tmp_path, server_dir)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", cfg["rcon_port"]))
        listener.listen()
        module = host()
        with pytest.raises(module.Failure, match="something answers"):
            module.backup(cfg)


@pytest.mark.parametrize("state", ["activating", "deactivating"])
def test_backup_refuses_a_unit_between_states(tmp_path: Path, stubs: Path, state: str) -> None:
    unit(tmp_path, state)
    module = host()
    with pytest.raises(module.Failure, match=state):
        module.backup(backup_cfg(tmp_path, server_tree(tmp_path, "one")))


def test_running_backup_brackets_the_archive_with_save_off_flush_and_save_on(
    tmp_path: Path, stubs: Path, rcon: FakeRcon
) -> None:
    unit(tmp_path, "active")
    server_dir = server_tree(tmp_path, "one")
    cfg = backup_cfg(tmp_path, server_dir, rcon_port=rcon.port)

    host().backup(cfg)

    assert rcon.commands == ["save-off", "save-all flush", "save-on"]
    assert rcon.logins == [PASSWORD] * 3
    assert (tmp_path / "backups" / "minecraft-java" / f"manual-{STAMP}.tar.gz").is_file()
    assert calls(stubs) == []  # never started, stopped or restarted
    # The password reached no child process: not in an argument and not in an environment.
    assert PASSWORD not in stubs.read_text()


def test_unconfirmed_save_all_fails_without_an_archive_and_still_saves_on(tmp_path: Path, stubs: Path) -> None:
    unit(tmp_path, "active")
    rcon = FakeRcon(answers={"save-all flush": "Unable to save the game (is there enough disk space?)"})
    try:
        cfg = backup_cfg(tmp_path, server_tree(tmp_path, "one"), rcon_port=rcon.port)
        module = host()
        with pytest.raises(module.Failure, match="did not confirm"):
            module.backup(cfg)
    finally:
        rcon.close()
    assert rcon.commands == ["save-off", "save-all flush", "save-on"]
    assert not list((tmp_path / "backups" / "minecraft-java").glob("*.tar.gz"))


def test_failed_archive_still_saves_on(tmp_path: Path, stubs: Path, rcon: FakeRcon) -> None:
    unit(tmp_path, "active")
    cfg = backup_cfg(tmp_path, server_tree(tmp_path, "one"), rcon_port=rcon.port)
    existing = write(Path(cfg["archive"]), "older run", 0o600)
    module = host()

    with pytest.raises(module.Failure, match="already exists"):
        module.backup(cfg)

    assert rcon.commands == ["save-off", "save-all flush", "save-on"]
    assert existing.read_text() == "older run"
    assert not list(existing.parent.glob(".*.partial"))


def test_failed_save_on_fails_the_run_after_the_archive(tmp_path: Path, stubs: Path) -> None:
    unit(tmp_path, "active")
    rcon = FakeRcon(answers={"save-on": None})  # type: ignore[dict-item]
    try:
        cfg = backup_cfg(tmp_path, server_tree(tmp_path, "one"), rcon_port=rcon.port)
        module = host()
        with pytest.raises(module.Failure, match="auto-save could not be re-enabled"):
            module.backup(cfg)
    finally:
        rcon.close()
    assert Path(cfg["archive"]).is_file()


def test_a_wrong_password_never_archives_and_tries_save_on(tmp_path: Path, stubs: Path) -> None:
    unit(tmp_path, "active")
    rcon = FakeRcon(password="another-password")  # pragma: allowlist secret
    try:
        cfg = backup_cfg(tmp_path, server_tree(tmp_path, "one"), rcon_port=rcon.port)
        module = host()
        with pytest.raises(module.Failure, match="refused the password") as raised:
            module.backup(cfg)
    finally:
        rcon.close()
    assert PASSWORD not in str(raised.value)
    assert rcon.commands == []
    assert len(rcon.logins) == 2  # save-off, then the save-on attempt
    assert not Path(cfg["archive"]).exists()


def test_host_main_reads_the_password_from_stdin_and_never_prints_it(
    tmp_path: Path, stubs: Path, rcon: FakeRcon, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    unit(tmp_path, "active")
    cfg = backup_cfg(tmp_path, server_tree(tmp_path, "one"), rcon_port=rcon.port)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(cfg) + "\n"))

    assert host().main("backup") == 0

    output = capsys.readouterr()
    assert PASSWORD not in output.out + output.err
    assert "Backup created" in output.out


# --- restore -----------------------------------------------------------------


def make_archive(path: Path, entries: dict[str, str | None], *, symlink: str | None = None) -> Path:
    """A gzip tar with ``entries`` (``None``: a directory) and optionally a symlink member."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as packed:
        for name, text in entries.items():
            info = tarfile.TarInfo(name)
            if text is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                packed.addfile(info)
            else:
                data = text.encode()
                info.size = len(data)
                info.mode = 0o644
                packed.addfile(info, io.BytesIO(data))
        if symlink:
            info = tarfile.TarInfo(symlink)
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            packed.addfile(info)
    return path


def world_entries(marker: str, world: str = WORLD, level: str = WORLD) -> dict[str, str | None]:
    return {
        f"{world}/level.dat": f"level {marker}",
        f"{world}/region": None,
        f"{world}/region/r.0.0.mca": f"region {marker}",
        "server.properties": f"level-name={level}\nmotd={marker}\n",
        "ops.json": f'["{marker}"]',
        # An extra world of the server (restored too) and what is not a world (left out).
        "world_vanilla/level.dat": f"extra {marker}",
        "logs/latest.log": "not a world",
        f"{world}.pre-restore-20261101T000000000000Z-abc/level.dat": "a pre-restore copy",
    }


def restore_cfg(base: Path, server_dir: Path, archive: str = "latest", **extra: Any) -> dict[str, Any]:
    root = base / "backups" / "minecraft-java"
    root.mkdir(parents=True, exist_ok=True)
    cfg = {
        "root": str(root),
        "archive": archive,
        "staging": f"{root}/.restore-work",
        "server_dir": str(server_dir),
        "world": WORLD,
        "unit": "minecraft-java",
        "user": ME,
        "group": GID,
        "port": free_port(),
        "start_timeout": 5,
    }
    cfg.update(extra)
    return cfg


def snapshot(base: Path) -> dict[str, tuple[int, int, float, bytes | None]]:
    state: dict[str, tuple[int, int, float, bytes | None]] = {}
    for path in sorted(base.rglob("*")):
        if "bin" in path.relative_to(base).parts[:1] or path.name in ("calls.log", "unit-state"):
            continue
        details = path.lstat()
        content = path.read_bytes() if path.is_file() and not path.is_symlink() else None
        state[str(path)] = (details.st_mode, details.st_size, details.st_mtime, content)
    return state


def test_check_is_read_only_and_reports_the_plan(
    tmp_path: Path, stubs: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    server_dir = server_tree(tmp_path, "live")
    root = tmp_path / "backups" / "minecraft-java"
    make_archive(root / "manual-20261101T120000.tar.gz", world_entries("old"))
    newest = make_archive(root / f"manual-{STAMP}.tar.gz", world_entries("new"))
    hidden = make_archive(root / ".newer.tar.gz", world_entries("hidden"))
    os.utime(hidden, (2_000_000_000, 2_000_000_000))
    write(root / "notes.txt", "x")
    unit(tmp_path, "active")
    before = snapshot(tmp_path)

    host().check(restore_cfg(tmp_path, server_dir))

    assert snapshot(tmp_path) == before
    assert calls(stubs) == []
    out = capsys.readouterr().out
    (line,) = [line for line in out.splitlines() if line.startswith(lifecycle.PLAN_MARKER)]
    plan = json.loads(line.removeprefix(lifecycle.PLAN_MARKER))
    assert plan == {
        "archive": str(newest),
        "size_bytes": newest.stat().st_size,
        "world": WORLD,
        "worlds": [WORLD, "world_vanilla"],
        "world_entries": {WORLD: 3, "world_vanilla": 1},
        "live_worlds": [WORLD],
        "server_properties": True,
        "player_files": ["ops.json"],
        "ignored_top_level": ["logs", f"{WORLD}.pre-restore-20261101T000000000000Z-abc"],
        "server_dir": str(server_dir),
        "unit": "loaded/active",
        "stop": True,
        "start_after": True,
    }
    assert "DRY RUN" in out


@pytest.mark.parametrize(
    ("entries", "symlink", "message"),
    [
        ({"world/level.dat": "stale"}, None, "not found in archive"),
        ({f"{WORLD}/region/r.0.0.mca": "no level.dat"}, None, "not found in archive"),
        (world_entries("x", level="world"), None, "selects level-name 'world'"),
        (world_entries("x"), f"{WORLD}/escape", "link or special file"),
        (world_entries("x"), "world_vanilla/escape", "link or special file"),
        ({**world_entries("x"), "../evil": "x"}, None, "unsafe path"),
        ({**world_entries("x"), "/etc/evil": "x"}, None, "unsafe path"),
    ],
)
def test_check_refuses_archives_it_cannot_restore_safely(
    tmp_path: Path, stubs: Path, entries: dict[str, str | None], symlink: str | None, message: str
) -> None:
    server_dir = server_tree(tmp_path, "live")
    make_archive(tmp_path / "backups" / "minecraft-java" / "bad.tar.gz", entries, symlink=symlink)
    module = host()

    with pytest.raises(module.Failure, match=message):
        module.check(restore_cfg(tmp_path, server_dir, "bad.tar.gz"))


def test_check_refuses_a_truncated_archive(tmp_path: Path, stubs: Path) -> None:
    server_dir = server_tree(tmp_path, "live")
    good = make_archive(tmp_path / "good.tar.gz", world_entries("x"))
    root = tmp_path / "backups" / "minecraft-java"
    root.mkdir(parents=True)
    (root / "cut.tar.gz").write_bytes(good.read_bytes()[:-12])
    module = host()

    with pytest.raises(module.Failure, match="not a readable gzip tar"):
        module.check(restore_cfg(tmp_path, server_dir, "cut.tar.gz"))


def test_check_refuses_links_paths_outside_the_root_and_no_archive(tmp_path: Path, stubs: Path) -> None:
    server_dir = server_tree(tmp_path, "live")
    outside = make_archive(tmp_path / "elsewhere" / "x.tar.gz", world_entries("x"))
    cfg = restore_cfg(tmp_path, server_dir)
    root = Path(cfg["root"])
    (root / "link.tar.gz").symlink_to(outside)
    module = host()

    with pytest.raises(module.Failure, match="No backups found"):
        module.check(cfg)  # the only *.tar.gz is a link
    with pytest.raises(module.Failure, match="not a file below"):
        module.check({**cfg, "archive": "link.tar.gz"})
    with pytest.raises(module.Failure, match="not a file below"):
        module.check({**cfg, "archive": str(outside)})
    with pytest.raises(module.Failure, match="Archive not found"):
        module.check({**cfg, "archive": "missing.tar.gz"})


@pytest.mark.parametrize(("load", "active"), [("masked", "inactive"), ("not-found", "failed"), ("error", "inactive")])
def test_check_fails_closed_on_unsafe_units(tmp_path: Path, stubs: Path, load: str, active: str) -> None:
    server_dir = server_tree(tmp_path, "live")
    make_archive(tmp_path / "backups" / "minecraft-java" / "a.tar.gz", world_entries("x"))
    flag(tmp_path, "STUB_LOAD", load)
    unit(tmp_path, active)
    module = host()

    with pytest.raises(module.Failure, match="unsafe for a restore"):
        module.check(restore_cfg(tmp_path, server_dir))


@pytest.mark.parametrize("state", ["inactive", "failed"])
def test_check_refuses_a_server_outside_the_unit(tmp_path: Path, stubs: Path, state: str) -> None:
    server_dir = server_tree(tmp_path, "live")
    make_archive(tmp_path / "backups" / "minecraft-java" / "a.tar.gz", world_entries("x"))
    unit(tmp_path, state)
    module = host()
    with socket.socket() as game:
        game.bind(("127.0.0.1", 0))
        game.listen()
        cfg = restore_cfg(tmp_path, server_dir, port=game.getsockname()[1])

        with pytest.raises(module.Failure, match="something answers"):
            module.check(cfg)
        with pytest.raises(module.Failure, match="something answers"):
            module.restore(cfg)

    assert (server_dir / WORLD / "level.dat").read_text() == "level live"
    assert calls(stubs) == []


def test_check_refuses_a_live_server_that_plays_another_world(tmp_path: Path, stubs: Path) -> None:
    server_dir = server_tree(tmp_path, "live", level="world_forge")
    make_archive(tmp_path / "backups" / "minecraft-java" / "a.tar.gz", world_entries("x"))
    module = host()

    with pytest.raises(module.Failure, match="selects level-name 'world_forge'"):
        module.check(restore_cfg(tmp_path, server_dir))


def test_restore_of_a_stopped_server_keeps_a_copy_and_leaves_it_stopped(
    tmp_path: Path, stubs: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    server_dir = server_tree(tmp_path, "live")
    write(server_dir / WORLD / "only-live.txt", "gone after the restore")
    archive = make_archive(tmp_path / "backups" / "minecraft-java" / f"manual-{STAMP}.tar.gz", world_entries("old"))
    unit(tmp_path, "inactive")
    other = (server_dir / "world_forge_test" / "level.dat").read_bytes()

    host().restore(restore_cfg(tmp_path, server_dir))

    world = server_dir / WORLD
    assert (world / "level.dat").read_text() == "level old"
    assert (world / "region" / "r.0.0.mca").read_text() == "region old"
    assert not (world / "only-live.txt").exists()
    (kept,) = [path for path in server_dir.iterdir() if path.name.startswith(f"{WORLD}.pre-restore-")]
    assert (kept / "level.dat").read_text() == "level live"
    assert (kept / "only-live.txt").exists()
    properties = server_dir / "server.properties"
    assert properties.read_text() == f"level-name={WORLD}\nmotd=old\n"
    assert properties.stat().st_mode & 0o777 == 0o640
    (previous,) = server_dir.glob("server.properties.pre-restore-*")
    assert "rcon.password=x" in previous.read_text()
    assert previous.stat().st_mode & 0o777 == 0o640
    assert (server_dir / "ops.json").read_text() == '["old"]'
    assert (server_dir / "whitelist.json").read_text() == "[]"  # not in the archive: left alone
    # The archive's extra world comes back too; a live world the archive lacks is left alone.
    assert (server_dir / "world_vanilla" / "level.dat").read_text() == "extra old"
    assert (server_dir / "world_forge_test" / "level.dat").read_bytes() == other
    assert not (server_dir / "logs").exists()
    assert not (server_dir / f"{WORLD}.pre-restore-20261101T000000000000Z-abc").exists()
    assert calls(stubs) == []  # never stopped (it was stopped), never started, never enabled
    assert archive.is_file()
    assert not (tmp_path / "backups" / "minecraft-java" / ".restore-work").exists()
    assert "stays stopped" in capsys.readouterr().out


def test_restore_of_a_running_server_stops_and_starts_it_again(tmp_path: Path, stubs: Path) -> None:
    server_dir = server_tree(tmp_path, "live")
    make_archive(tmp_path / "backups" / "minecraft-java" / "a.tar.gz", world_entries("old"))
    unit(tmp_path, "active")
    with socket.socket() as game:
        game.bind(("127.0.0.1", 0))
        game.listen()
        cfg = restore_cfg(tmp_path, server_dir, port=game.getsockname()[1])

        host().restore(cfg)

    assert calls(stubs) == ["systemctl stop -- minecraft-java", "systemctl start -- minecraft-java"]
    assert (server_dir / WORLD / "level.dat").read_text() == "level old"


def test_restore_without_a_live_world_has_nothing_to_keep(
    tmp_path: Path, stubs: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    server_dir = tmp_path / "server"
    server_dir.mkdir()
    make_archive(tmp_path / "backups" / "minecraft-java" / "a.tar.gz", world_entries("old"))

    host().restore(restore_cfg(tmp_path, server_dir))

    assert (server_dir / WORLD / "level.dat").read_text() == "level old"
    out = capsys.readouterr().out
    assert f"Pre-restore copy of {WORLD}: nothing to snapshot" in out
    assert "Pre-restore copy of world_vanilla: nothing to snapshot" in out
    assert not [path for path in server_dir.iterdir() if ".pre-restore-" in path.name]


def test_failed_world_copy_rolls_back_and_never_starts_the_server(
    tmp_path: Path, stubs: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    server_dir = server_tree(tmp_path, "live")
    write(server_dir / WORLD / "only-live.txt", "still here")
    before = snapshot(server_dir)
    make_archive(tmp_path / "backups" / "minecraft-java" / "a.tar.gz", world_entries("old"))
    unit(tmp_path, "active")
    bin_dir = tmp_path / "bin"
    (bin_dir / "cp").write_text("#!/bin/sh\nexit 1\n")
    (bin_dir / "cp").chmod(0o755)
    module = host()

    with pytest.raises(subprocess.CalledProcessError):
        module.restore(restore_cfg(tmp_path, server_dir))

    assert calls(stubs) == ["systemctl stop -- minecraft-java"]
    # The renamed copy moved back: the live world as it was, no copy left over.
    assert {k: v[3] for k, v in snapshot(server_dir).items()} == {k: v[3] for k, v in before.items()}
    assert not [path for path in server_dir.iterdir() if ".pre-restore-" in path.name]
    assert not (tmp_path / "backups" / "minecraft-java" / ".restore-work").exists()
    out = capsys.readouterr().out
    assert "Rolled back: the worlds and files are as before the restore" in out
    assert "stays stopped" in out


def test_failure_after_the_worlds_rolls_back_worlds_and_files(tmp_path: Path, stubs: Path) -> None:
    server_dir = server_tree(tmp_path, "live")
    properties = (server_dir / "server.properties").read_text()
    # ops.json is a directory: the player files fail after both worlds and server.properties were replaced.
    (server_dir / "ops.json").unlink()
    (server_dir / "ops.json").mkdir()
    make_archive(tmp_path / "backups" / "minecraft-java" / "a.tar.gz", world_entries("old"))
    unit(tmp_path, "inactive")
    module = host()

    with pytest.raises(module.Failure, match="not a regular file"):
        module.restore(restore_cfg(tmp_path, server_dir))

    assert (server_dir / WORLD / "level.dat").read_text() == "level live"
    assert (server_dir / WORLD / "empty").is_dir()
    assert not (server_dir / "world_vanilla").exists()  # absent before: gone again
    assert (server_dir / "server.properties").read_text() == properties
    assert (server_dir / "server.properties").stat().st_mode & 0o777 == 0o640
    assert not [path for path in server_dir.iterdir() if path.name.startswith(f"{WORLD}.pre-restore-")]
    assert calls(stubs) == []


def test_no_rollback_while_the_unit_runs(tmp_path: Path, stubs: Path) -> None:
    unit(tmp_path, "active")
    live = tmp_path / "server" / WORLD
    write(live / "level.dat", "restored")

    errors = host().rollback({"unit": "minecraft-java"}, [(str(live), {"method": "absent", "path": None})], {})

    assert errors == ["minecraft-java is loaded/active, so nothing was rolled back"]
    assert (live / "level.dat").read_text() == "restored"


def test_restore_reads_an_archive_of_the_backup(tmp_path: Path, stubs: Path) -> None:
    source = server_tree(tmp_path / "source", "backed-up")
    host().backup(backup_cfg(tmp_path, source))
    target = server_tree(tmp_path / "target", "live")

    host().restore(restore_cfg(tmp_path, target))

    assert (target / WORLD / "level.dat").read_text() == "level backed-up"
    assert (target / "ops.json").read_text() == '["backed-up"]'
    assert (target / WORLD / "empty").is_dir()
    assert (target / "world_forge_test" / "level.dat").read_text() == "other world"


def test_restore_reads_the_roles_archive(tmp_path: Path, stubs: Path) -> None:
    """The role's archive module: one world without its own entry, server.properties, the player files."""

    server_dir = server_tree(tmp_path, "live")
    entries: dict[str, str | None] = {
        f"{WORLD}/level.dat": "level role",
        f"{WORLD}/DIM-1": None,
        f"{WORLD}/DIM-1/r.mca": "nether",
        "server.properties": f"level-name={WORLD}\n",
        "banned-players.json": "[]",
    }
    make_archive(tmp_path / "backups" / "minecraft-java" / "manual-20251203T102636.tar.gz", entries)

    host().restore(restore_cfg(tmp_path, server_dir))

    assert (server_dir / WORLD / "level.dat").read_text() == "level role"
    assert (server_dir / WORLD / "DIM-1" / "r.mca").read_text() == "nether"
    assert (server_dir / "banned-players.json").read_text() == "[]"
    assert (server_dir / "world_forge_test" / "level.dat").read_text() == "other world"
