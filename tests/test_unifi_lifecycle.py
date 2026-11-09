"""UniFi backup and restore: configs, planned operations and the host program end to end.

The host program runs in-process against temporary trees with real ``tar``
and ``rsync``. ``systemctl``, ``mongodump``, ``mongorestore``, ``mongosh``,
``dpkg-query`` and ``curl`` are stubs on ``PATH`` that keep their state in a
directory (the unit's state, a "database" per name) and log every call with
its arguments, environment and, for the MongoDB tools, whether the password
reached them through the private config file or stdin. The backup and
restore owners are the test account.
"""

from __future__ import annotations

import grp
import hashlib
import importlib
import io
import json
import os
import pwd
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services.unifi import (
    UnifiBackupConfig,
    UnifiRestoreConfig,
    deploy_unifi_backup,
    deploy_unifi_restore,
    lifecycle,
)
from ops_deploy.testing import FakeRun, run_deploy_fake

host = importlib.import_module("ops_deploy.services.unifi.files.lifecycle_host")

STAMP = "20261109T120000"
LATER = "20261109T130000"
TIME = {"date +%Y%m%dT%H%M%S": [STAMP]}
PASSWORD = "fixture-mongo-pass/word+1"  # pragma: allowlist secret
ME = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
VERSION = "9.5.21-31260-1"
# The keys of the role's metadata.yml (unifi_backup/tasks/metadata.yml).
ROLE_METADATA_KEYS = {
    "timestamp",
    "host",
    "unifi_version",
    "data_path",
    "mongodb_port",
    "mongodb_database",
    "service_stopped",
    "include_logs",
    "include_autobackups",
    "restore_methods",
}
ZERO_TIMING = {key: (1 if key.endswith("attempts") else 0) for key in lifecycle.TIMING}


def secrets(**values: str) -> SecretValues:
    return SecretValues(SecretRef("secrets/prod/unifi.yml"), {"mongodb_password": PASSWORD, **values})


def payload_of(result: FakeRun, action: str) -> tuple[str, dict[str, Any]]:
    ((command, stdin),) = [(c, s) for c, s in result.stdin if shlex.split(c)[-1] == action]
    return command, json.loads(stdin)


# --- configs -------------------------------------------------------------------


def test_defaults_are_the_roles() -> None:
    backup = UnifiBackupConfig(host_name="macmini")
    restore = UnifiRestoreConfig(host_name="macmini")

    assert (backup.root, backup.prefix, backup.service_name, backup.data_path) == (
        "/opt/backups/unifi",
        "manual",
        "unifi.service",
        "/usr/lib/unifi/data",
    )
    assert (backup.include_logs, backup.include_env, backup.include_autobackups, backup.include_keystore) == (
        False,
        False,
        True,
        True,
    )
    assert (backup.disk_overhead_ratio, backup.stop_pause, backup.mongodb_port) == (1.5, 10, 27017)
    assert backup.jvm_args_path == "/etc/unifi-secrets/mongodb.jvmargs"
    assert (restore.archive, restore.work_dir, restore.safety_backup_prefix) == (
        "latest",
        "/tmp/unifi-restore",
        "pre-restore",
    )
    assert (restore.confirm, restore.dry_run, restore.rollback_on_failure, restore.drop_database) == (
        False,
        False,
        True,
        True,
    )
    assert restore.jvm_args_group == "unifi"
    # The role's https://localhost:8443/; the port pins the address.
    assert restore.health_url == "https://127.0.0.1:8443/"


@pytest.mark.parametrize(
    "archive", ["latest", "manual-20261109T120000", "manual-20261109T120000.tar.gz", "/opt/backups/unifi/x.tar.gz"]
)
def test_restore_accepts_latest_names_and_paths_below_the_root(archive: str) -> None:
    assert UnifiRestoreConfig(host_name="m", archive=archive).archive == archive


@pytest.mark.parametrize(
    "changes",
    [
        {"archive": "../etc/passwd"},
        {"archive": "/etc/passwd"},
        {"archive": "/opt/backups/unifi"},
        {"archive": "a b"},
        {"work_dir": "/opt/backups"},
        {"work_dir": "/opt/backups/unifi"},
        {"work_dir": "/usr/lib/unifi/data/tmp"},
        {"work_dir": "/etc"},
        {"rollback_on_failure": True, "create_safety_backup": False},
        {"root": "/usr/lib/unifi/data/backups"},
        {"root": "/home"},
        {"required_mount": "/mnt/other"},
        {"confirm": "yes"},
    ],
)
def test_restore_refuses_unsafe_settings(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        UnifiRestoreConfig.model_validate({"host_name": "m", **changes})


@pytest.mark.parametrize(
    "changes",
    [
        {"root": "/usr/lib/unifi"},
        {"root": "/"},
        {"prefix": "a/b"},
        {"required_mount": "/mnt/other"},
        {"service_name": "unifi; reboot"},
    ],
)
def test_backup_refuses_unsafe_settings(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        UnifiBackupConfig.model_validate({"host_name": "m", **changes})


# --- planned operations ----------------------------------------------------------


def test_backup_plan_guards_the_mount_keeps_the_password_on_stdin_fetches_and_prunes(tmp_path: Path) -> None:
    local = tmp_path / "local"
    cfg = UnifiBackupConfig(
        host_name="macmini", required_mount="/opt/backups", retain_count=3, retain_days=14, local_dir=local
    )

    result = run_deploy_fake(deploy_unifi_backup, cfg, secrets(), responses=TIME)

    assert result.succeeded, result.error
    assert [op.split(" | ", 1)[1] for op in result.changed_ops] == [
        "Check /opt/backups/unifi before the backup",
        f"Back up UniFi into /opt/backups/unifi/manual-{STAMP}",
        f"Ensure {local} (0700)",
        "Fetch the UniFi backup archive",
        "Restrict the local archive copy (0600)",
        "Prune recorded manual UniFi snapshots",
    ]
    preflight, program, prune = result.executed_commands
    assert "require_mount /opt/backups /opt/backups/unifi" in preflight
    assert f"require_new_snapshot /opt/backups/unifi manual-{STAMP}" in preflight
    assert f"record_snapshot /opt/backups/unifi manual-{STAMP}" in prune
    assert f"prune_snapshots /opt/backups/unifi 3 20261026T120000 manual-{STAMP}" in prune
    assert shlex.split(program)[:3] == ["python3", "-I", "-c"]
    assert shlex.split(program)[-1] == "backup"
    _command, payload = payload_of(result, "backup")
    assert payload["credentials"] == {"username": "unifi", "password": PASSWORD, "auth_db": "admin"}
    assert payload["mongodb"] == {"host": "127.0.0.1", "port": 27017, "database": "unifi"}
    assert payload["backup"]["dir"] == f"/opt/backups/unifi/manual-{STAMP}"
    assert payload["backup"]["paths"]["db"] == "/usr/lib/unifi/data/db"
    assert payload["backup"]["paths"]["autobackup"] == "/usr/lib/unifi/data/backup/autobackup"
    assert payload["backup"]["safety"] is False
    # The secret travels on stdin only.
    assert not any(PASSWORD in command for command in result.executed_commands + result.fact_commands)
    assert local.stat().st_mode & 0o777 == 0o700


def test_backup_takes_the_playbooks_secret_overrides() -> None:
    store = secrets(mongodb_username="owner", mongodb_auth_db="auth", mongodb_database="ctrl")
    result = run_deploy_fake(
        deploy_unifi_backup, UnifiBackupConfig(host_name="m", fetch_local=False), store, responses=TIME
    )

    assert result.succeeded, result.error
    _command, payload = payload_of(result, "backup")
    assert payload["credentials"] == {"username": "owner", "password": PASSWORD, "auth_db": "auth"}
    assert payload["mongodb"]["database"] == payload["backup"]["database"] == "ctrl"
    assert not any("Fetch" in op for op in result.changed_ops)


@pytest.mark.parametrize(
    "store",
    [
        None,
        SecretValues(SecretRef("secrets/prod/unifi.yml"), {"mongodb_password": ""}),
        secrets(mongodb_password="a\nb"),
        secrets(mongodb_database="unifi;drop"),
        secrets(mongodb_username="a b"),
    ],
)
def test_backup_refuses_missing_or_unsafe_credentials_before_any_step(store: SecretValues | None) -> None:
    result = run_deploy_fake(deploy_unifi_backup, UnifiBackupConfig(host_name="m"), store, responses=TIME)

    assert not result.succeeded
    assert result.executed_commands == []
    assert result.stdin == []


def test_backup_refuses_an_unreadable_host_clock() -> None:
    result = run_deploy_fake(
        deploy_unifi_backup, UnifiBackupConfig(host_name="m"), secrets(), responses={"date +%Y%m%dT%H%M%S": ["x"]}
    )

    assert "cannot read the host's time" in str(result.error)


def test_unconfirmed_restore_stops_before_any_probe() -> None:
    result = run_deploy_fake(deploy_unifi_restore, UnifiRestoreConfig(host_name="m"), secrets(), responses=TIME)

    assert not result.succeeded
    assert "confirm the restore" in str(result.error)
    assert not result.events
    assert not result.ops


def test_dry_run_needs_no_password_or_confirmation_and_never_takes_the_route_lock() -> None:
    cfg = UnifiRestoreConfig(
        host_name="macmini",
        dry_run=True,
        archive="manual-20261109T120000",
        required_mount="/opt/backups",
        work_dir="/opt/backups/unifi/.restore-work",
    )

    result = run_deploy_fake(deploy_unifi_restore, cfg, None, responses=TIME)

    assert result.succeeded, result.error
    assert [op.split(" | ", 1)[1] for op in result.changed_ops] == [
        "Require /opt/backups below /opt/backups/unifi and /opt/backups/unifi/.restore-work",
        "Validate the UniFi restore (dry run)",
    ]
    command, payload = payload_of(result, "restore")
    assert payload["dry_run"] is True
    assert payload["credentials"] is None
    assert payload["route_guard"] == []
    assert route_guard_command() not in command
    assert payload["archive"] == "manual-20261109T120000"


def test_confirmed_restore_plans_the_safety_backup_rollback_and_route_lock() -> None:
    cfg = UnifiRestoreConfig(
        host_name="macmini", confirm=True, required_mount="/opt/backups", work_dir="/opt/backups/unifi/.restore-work"
    )

    result = run_deploy_fake(deploy_unifi_restore, cfg, secrets(), responses=TIME)

    assert result.succeeded, result.error
    command, payload = payload_of(result, "restore")
    assert command.startswith(route_guard_command() + " && python3 -I -c ")
    assert payload["route_guard"] == shlex.split(route_guard_command())
    assert payload["credentials"]["password"] == PASSWORD
    assert payload["manage_jvm_args_dir"] is True
    safety = payload["safety"]
    assert safety["safety"] is True
    assert safety["dir"] == f"/opt/backups/unifi/pre-restore-{STAMP}"
    assert (safety["create_archive"], safety["stop_service"], safety["generate_checksums"]) == (False, True, True)
    assert (payload["rollback_on_failure"], payload["cleanup_safety_backup"]) == (True, True)
    assert not any(PASSWORD in c for c in result.executed_commands + result.fact_commands)


def test_restore_without_a_safety_backup_has_no_rollback() -> None:
    cfg = UnifiRestoreConfig(host_name="m", confirm=True, create_safety_backup=False, rollback_on_failure=False)

    result = run_deploy_fake(deploy_unifi_restore, cfg, secrets(), responses=TIME)

    assert result.succeeded, result.error
    assert payload_of(result, "restore")[1]["safety"] is None


def test_a_confirmed_restore_needs_the_password() -> None:
    cfg = UnifiRestoreConfig(host_name="m", confirm=True)

    result = run_deploy_fake(deploy_unifi_restore, cfg, None, responses=TIME)

    assert "mongodb_password is required" in str(result.error)
    assert result.stdin == []


# --- the host program --------------------------------------------------------------

STUB = r"""#!{python}
import json, os, re, shutil, sys
from urllib.parse import quote
STATE = {state!r}
tool = os.path.basename(sys.argv[0])
args = sys.argv[1:]
stdin = sys.stdin.read() if tool == "mongosh" else ""
config = ""
for arg in args:
    if arg.startswith("--config="):
        with open(arg.split("=", 1)[1]) as handle:
            config = handle.read()
def read(name, default=""):
    try:
        with open(os.path.join(STATE, name)) as handle:
            return handle.read().strip()
    except FileNotFoundError:
        return default
password = read("password")
secret = (quote(password, safe="") in config) if config else (password in stdin)
with open(os.path.join(STATE, "log.jsonl"), "a") as log:
    log.write(json.dumps(dict(tool=tool, argv=sys.argv, env=dict(os.environ), secret=secret)) + "\n")
fail = os.path.join(STATE, "fail-" + tool)
if os.path.exists(fail):
    marker = read("fail-" + tool)
    if not marker or any(marker in arg for arg in args):
        print(tool + " failed on purpose", file=sys.stderr)
        sys.exit(1)
def option(name):
    return next((arg.split("=", 1)[1] for arg in args if arg.startswith(name + "=")), None)
mongo = os.path.join(STATE, "mongo")
if tool == "systemctl":
    if args[0] == "show":
        print("LoadState=" + read("load", "loaded"))
        print("ActiveState=" + read("unit", "active"))
    elif args[0] in ("stop", "start"):
        with open(os.path.join(STATE, "unit"), "w") as handle:
            handle.write("inactive" if args[0] == "stop" else "active")
elif tool == "dpkg-query":
    sys.stdout.write(read("version"))
    sys.exit(0 if read("version") else 1)
elif tool == "curl":
    sys.stdout.write(read("http", "200"))
elif tool in ("mongodump", "mongorestore") and not secret:
    print("authentication failed", file=sys.stderr)
    sys.exit(1)
elif tool == "mongodump":
    out, db = option("--out"), option("--db")
    if out is not None:
        os.makedirs(out, exist_ok=True)
        if os.path.isdir(os.path.join(mongo, db)):
            shutil.copytree(os.path.join(mongo, db), os.path.join(out, db))
elif tool == "mongorestore":
    db, source = option("--db"), option("--dir")
    target = os.path.join(mongo, db)
    os.makedirs(target, exist_ok=True)
    for name in os.listdir(source):
        shutil.copy(os.path.join(source, name), os.path.join(target, name))
elif tool == "mongosh":
    if not secret:
        sys.exit(20)
    db = json.loads(re.search(r"getSiblingDB\((\"[^\"]*\")\)\.dropDatabase", stdin).group(1))
    shutil.rmtree(os.path.join(mongo, db), ignore_errors=True)
    print("OPS_UNIFI_DROPPED")
"""
TOOLS = ("systemctl", "mongodump", "mongorestore", "mongosh", "dpkg-query", "curl")


class Host:
    """The stubs' state, the live UniFi paths and the backup root below one temporary directory."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.state = base / "state"
        self.bin = base / "bin"
        self.root = base / "backups" / "unifi"
        self.data = base / "lib" / "data"
        self.etc = base / "etc"
        self.run = base / "run"
        self.local = base / "local"
        for directory in (self.state / "mongo", self.bin, self.etc / "secrets", self.etc / "dynamic", self.run):
            directory.mkdir(parents=True)
        for tool in TOOLS:
            stub = self.bin / tool
            stub.write_text(STUB.format(python=sys.executable, state=str(self.state)))
            stub.chmod(0o755)
        self.set("password", PASSWORD)
        self.set("version", VERSION)
        self.set("unit", "active")
        self.mongo_up = True

    def set(self, name: str, value: str) -> None:
        (self.state / name).write_text(value)

    def install(self, marker: str = "live") -> None:
        """A running controller whose data, database and system files all carry ``marker``."""

        (self.data / "db").mkdir(parents=True)
        (self.data / "db" / "WiredTiger").write_text("mongo files")
        (self.data / "sites" / "default").mkdir(parents=True)
        (self.data / "sites" / "default" / "config.json").write_text(marker)
        (self.data / "system.properties").write_text(f"is_default={marker}\n")
        (self.data / "keystore").write_bytes(b"keystore-" + marker.encode())
        autobackup = self.data / "backup" / "autobackup"
        autobackup.mkdir(parents=True)
        (autobackup / "new.unf").write_text("new")
        old = autobackup / "old.unf"
        old.write_text("old")
        os.utime(old, (time.time() - 8 * 86400,) * 2)
        self.unit.write_text(f"[Service]\n# {marker}\nExecStart=/usr/bin/java @{self.jvm_args}\n")
        self.jvm_args.write_text(f"-Ddb.mongo.uri=mongodb://unifi:{marker}@127.0.0.1/unifi\n")
        self.route.write_text(f"http: # {marker}\n")
        self.database("unifi", marker)

    def database(self, name: str, marker: str) -> None:
        (self.state / "mongo" / name).mkdir(parents=True, exist_ok=True)
        (self.state / "mongo" / name / "device.bson").write_text(marker)

    def db_marker(self, name: str = "unifi") -> str | None:
        path = self.state / "mongo" / name / "device.bson"
        return path.read_text() if path.exists() else None

    @property
    def unit(self) -> Path:
        return self.etc / "unifi.service"

    @property
    def jvm_args(self) -> Path:
        return self.etc / "secrets" / "mongodb.jvmargs"

    @property
    def route(self) -> Path:
        return self.etc / "dynamic" / "unifi.yml"

    def paths(self) -> dict[str, Any]:
        return {
            "host_name": "macmini",
            "root": str(self.root),
            "data_path": str(self.data),
            "systemd_unit_path": str(self.unit),
            "jvm_args_path": str(self.jvm_args),
            "traefik_config_path": str(self.route),
            "credentials_dir": str(self.run),
            "stop_pause": 0,
        }

    def log(self) -> list[dict[str, Any]]:
        path = self.state / "log.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def calls(self, tool: str) -> list[list[str]]:
        return [entry["argv"][1:] for entry in self.log() if entry["tool"] == tool]

    def systemctl(self) -> list[str]:
        return [" ".join(argv) for argv in self.calls("systemctl") if argv[0] != "show"]

    def backup_payload(self, **changes: Any) -> dict[str, Any]:
        cfg = UnifiBackupConfig.model_validate(
            {
                **self.paths(),
                "logs_path": str(self.base / "lib" / "logs"),
                "env_file": str(self.etc / "default-unifi"),
                "local_dir": self.local,
                **changes,
            }
        )
        result = run_deploy_fake(deploy_unifi_backup, cfg, secrets(), responses=TIME)
        assert result.succeeded, result.error
        payload = payload_of(result, "backup")[1]
        payload["backup"]["timing"] = ZERO_TIMING
        return payload

    def restore_payload(self, *, stamp: str = LATER, **changes: Any) -> dict[str, Any]:
        values = {
            **self.paths(),
            "work_dir": str(self.base / "work"),
            "unifi_user": ME,
            "unifi_group": GROUP,
            "jvm_args_group": GROUP,
            "confirm": not changes.get("dry_run", False),
            **changes,
        }
        cfg = UnifiRestoreConfig.model_validate(values)
        result = run_deploy_fake(deploy_unifi_restore, cfg, secrets(), responses={"date +%Y%m%dT%H%M%S": [stamp]})
        assert result.succeeded, result.error
        payload = payload_of(result, "restore")[1]
        payload["timing"] = ZERO_TIMING
        if payload["safety"]:
            payload["safety"]["timing"] = ZERO_TIMING
        return payload


@pytest.fixture
def unifi(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Host:
    if shutil.which("rsync") is None or shutil.which("tar") is None:
        pytest.skip("needs rsync and tar, as on the targets")
    machine = Host(tmp_path)
    monkeypatch.setattr(host, "ROOT_USER", ME)
    monkeypatch.setattr(host, "ROOT_GROUP", GROUP)
    monkeypatch.setattr(host, "reachable", lambda *_args, **_kwargs: machine.mongo_up)
    monkeypatch.setenv("PATH", f"{machine.bin}{os.pathsep}{os.environ['PATH']}")
    # macOS tar would add AppleDouble members for extended attributes.
    monkeypatch.setenv("COPYFILE_DISABLE", "1")
    return machine


def run_host(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], action: str, payload: dict[str, Any]
) -> tuple[int, str]:
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload) + "\n"))
    code = host.main(action)
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert PASSWORD not in output
    return code, output


def assert_secret_stayed_private(machine: Host) -> None:
    for entry in machine.log():
        assert not any(PASSWORD in arg for arg in entry["argv"]), entry["argv"]
        assert PASSWORD not in json.dumps(entry["env"])
        if entry["tool"] in ("mongodump", "mongorestore", "mongosh"):
            assert entry["secret"], entry
            assert set(entry["env"]) <= {"HOME", "PATH", "LC_ALL", "__CF_USER_TEXT_ENCODING"}
    # The private credential directory is gone.
    assert list(machine.run.iterdir()) == []


def manifest_ok(snapshot: Path) -> None:
    """What the role's ``sha256sum --check manifest.sha256`` checks."""

    lines = (snapshot / "manifest.sha256").read_text().splitlines()
    listed = []
    for line in lines:
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((snapshot / name).read_bytes()).hexdigest() == digest, name
        listed.append(name)
    found = sorted("./" + str(path.relative_to(snapshot)) for path in snapshot.rglob("*") if path.is_file())
    assert sorted(listed) == [name for name in found if name != "./manifest.sha256"]
    assert listed == sorted(listed, key=str.encode)


def backup(machine: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], **changes: Any) -> Path:
    code, output = run_host(monkeypatch, capsys, "backup", machine.backup_payload(**changes))
    assert code == 0, output
    return machine.root / f"{changes.get('prefix', 'manual')}-{STAMP}.tar.gz"


def unpack(archive: Path, into: Path) -> Path:
    into.mkdir()
    with tarfile.open(archive) as handle:
        tops = {member.name.split("/")[0] for member in handle.getmembers()}
        handle.extractall(into, filter="tar")
    (top,) = tops
    return into / top


def test_backup_writes_the_role_layout_dumping_before_the_stop(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    unifi.install()

    archive = backup(unifi, monkeypatch, capsys)

    assert archive.stat().st_mode & 0o777 == 0o600
    directory = unifi.root / f"manual-{STAMP}"
    assert directory.stat().st_mode & 0o777 == 0o700
    assert unifi.root.stat().st_mode & 0o777 == 0o700
    assert sorted(path.name for path in directory.iterdir()) == sorted(
        [*host.SUBDIRS, "metadata.yml", "manifest.sha256"]
    )
    assert (directory / "database" / "unifi" / "device.bson").read_text() == "live"
    assert (directory / "data" / "sites" / "default" / "config.json").read_text() == "live"
    # db/ itself, never its files (rsync --exclude='db/*').
    assert (directory / "data" / "db").is_dir()
    assert not any((directory / "data" / "db").iterdir())
    assert [path.name for path in (directory / "autobackups").iterdir()] == ["new.unf"]
    assert sorted(path.name for path in (directory / "config").iterdir()) == ["keystore", "system.properties"]
    assert sorted(path.name for path in (directory / "systemd").iterdir()) == ["mongodb.jvmargs", "unifi.service"]
    assert [path.name for path in (directory / "traefik").iterdir()] == ["unifi.yml"]
    # What the backup writes itself is owner-only; data/ keeps its modes (rsync -a), below the 0700 tree.
    for path in directory.rglob("*"):
        if path.is_file() and path.relative_to(directory).parts[0] != "data":
            assert path.stat().st_mode & 0o777 == 0o600, path
    metadata = yaml.safe_load((directory / "metadata.yml").read_text())
    assert set(metadata) == ROLE_METADATA_KEYS
    assert metadata["unifi_version"] == VERSION
    assert metadata["timestamp"] == STAMP
    assert metadata["service_stopped"] is True
    manifest_ok(directory)
    # The archive holds the directory as its only top-level entry.
    assert unpack(archive, tmp_path / "x").name == f"manual-{STAMP}"
    # The dump runs while UniFi does, before the stop (the role's order).
    calls = [(entry["tool"], entry["argv"][1]) for entry in unifi.log()]
    assert calls.index(("mongodump", "--config=" + unifi.calls("mongodump")[0][0].split("=", 1)[1])) < calls.index(
        ("systemctl", "stop")
    )
    assert unifi.systemctl() == ["stop unifi.service", "start unifi.service"]
    assert unifi.calls("mongodump")[0][1:] == ["--db=unifi", f"--out={directory}/database"]
    assert_secret_stayed_private(unifi)


def test_a_stopped_controller_is_backed_up_without_a_dump_and_stays_stopped(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    unifi.set("unit", "inactive")

    code, output = run_host(monkeypatch, capsys, "backup", unifi.backup_payload())

    assert code == 0, output
    assert "no MongoDB dump" in output
    assert unifi.calls("mongodump") == []
    assert unifi.systemctl() == []
    assert not any((unifi.root / f"manual-{STAMP}" / "database").iterdir())


def test_a_backup_while_mongodb_is_unreachable_fails_before_writing(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    unifi.mongo_up = False

    code, output = run_host(monkeypatch, capsys, "backup", unifi.backup_payload())

    assert code == 1
    assert "not reachable" in output
    assert not unifi.root.exists()
    assert unifi.systemctl() == []


def test_a_failed_dump_stops_the_backup_without_stopping_unifi(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    unifi.set("fail-mongodump", "")

    code, output = run_host(monkeypatch, capsys, "backup", unifi.backup_payload())

    assert code == 1
    assert "mongodump failed" in output
    assert unifi.systemctl() == []
    assert not list(unifi.root.glob("*.tar.gz"))
    assert "Removed the incomplete snapshot" in output
    assert not (unifi.root / f"manual-{STAMP}").exists()
    assert_secret_stayed_private(unifi)


def test_a_failed_copy_still_starts_unifi_and_leaves_no_archive(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    real = host.copy_into

    def broken(source: str, destination: str, mode: int = 0o600) -> None:
        if destination.endswith("unifi.service"):
            raise OSError("disk full")
        real(source, destination, mode)

    monkeypatch.setattr(host, "copy_into", broken)

    code, output = run_host(monkeypatch, capsys, "backup", unifi.backup_payload())

    assert code == 1
    assert "disk full" in output
    assert unifi.systemctl() == ["stop unifi.service", "start unifi.service"]
    assert (unifi.state / "unit").read_text() == "active"
    assert not list(unifi.root.glob("*.tar.gz"))
    # The half-written snapshot (with the dump and the JVM argument file) is gone.
    assert not (unifi.root / f"manual-{STAMP}").exists()


@pytest.mark.parametrize("missing", ["data", "db"])
def test_a_backup_without_the_required_paths_fails_before_writing(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], missing: str
) -> None:
    unifi.install()
    shutil.rmtree(unifi.data / "db" if missing == "db" else unifi.data)

    code, output = run_host(monkeypatch, capsys, "backup", unifi.backup_payload())

    assert code == 1
    assert "is missing" in output
    assert not unifi.root.exists()


def test_a_backup_never_overwrites_an_existing_snapshot(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    (unifi.root / f"manual-{STAMP}").mkdir(parents=True)

    code, output = run_host(monkeypatch, capsys, "backup", unifi.backup_payload())

    assert code == 1
    assert "File exists" in output
    assert unifi.systemctl() == []
    assert (unifi.root / f"manual-{STAMP}").is_dir()


def test_older_archives_in_the_root_are_restricted(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    unifi.root.mkdir(parents=True)
    old = unifi.root / "manual-20250101T000000.tar.gz"
    old.write_bytes(b"old")
    old.chmod(0o644)

    backup(unifi, monkeypatch, capsys)

    assert old.stat().st_mode & 0o777 == 0o600


# --- restore ------------------------------------------------------------------------


def snapshot_of_live(machine: Host) -> dict[str, Any]:
    return {
        "data": sorted(
            (str(path.relative_to(machine.data)), path.read_bytes() if path.is_file() else None)
            for path in machine.data.rglob("*")
        )
        if machine.data.exists()
        else None,
        "db": machine.db_marker(),
        "unit": machine.unit.read_text() if machine.unit.exists() else None,
        "jvm_args": machine.jvm_args.read_text() if machine.jvm_args.exists() else None,
        "route": machine.route.read_text() if machine.route.exists() else None,
    }


def change_live(machine: Host) -> None:
    """The controller after the backup: other data, database and system files."""

    (machine.data / "sites" / "default" / "config.json").write_text("changed")
    (machine.data / "sites" / "default" / "extra.json").write_text("extra")
    machine.database("unifi", "changed")
    machine.unit.write_text("[Service]\n# changed\n")
    machine.jvm_args.write_text("changed\n")
    machine.route.write_text("changed\n")


def test_dry_run_validates_and_changes_nothing(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    backup(unifi, monkeypatch, capsys)
    change_live(unifi)
    before = snapshot_of_live(unifi)
    listing = sorted(str(path) for path in unifi.root.rglob("*"))
    (unifi.state / "log.jsonl").unlink()
    payload = unifi.restore_payload(dry_run=True)
    payload["credentials"] = None

    code, output = run_host(monkeypatch, capsys, "restore", payload)

    assert code == 0, output
    assert "UniFi restore plan:" in output
    assert "checksums: " in output
    assert "files match manifest.sha256" in output
    assert f"safety backup: {unifi.root}/pre-restore-{LATER}" in output
    assert "Dry run: the artifact is valid" in output
    assert snapshot_of_live(unifi) == before
    assert sorted(str(path) for path in unifi.root.rglob("*")) == listing
    assert not (unifi.base / "work").exists()
    # Only the read-only probes ran.
    assert {entry["tool"] for entry in unifi.log()} <= {"systemctl", "dpkg-query"}
    assert all(argv[0] == "show" for argv in unifi.calls("systemctl"))


def test_dry_run_refuses_a_tampered_archive(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    unifi.install()
    archive = backup(unifi, monkeypatch, capsys)
    snapshot = unpack(archive, tmp_path / "tampered")
    (snapshot / "data" / "sites" / "default" / "config.json").write_text("evil")
    archive.unlink()
    subprocess.run(["tar", "-C", str(snapshot.parent), "-czf", str(archive), snapshot.name], check=True)

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload(dry_run=True))

    assert code == 1
    assert "Checksum validation failed for 1 file(s): ./data/sites/default/config.json" in output


def test_dry_run_refuses_another_major_version(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    backup(unifi, monkeypatch, capsys)
    unifi.set("version", "10.0.1-1")

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload(dry_run=True))

    assert code == 1
    assert "does not match installed version 10.0.1-1" in output


@pytest.mark.parametrize("archive", ["missing", "../x"])
def test_restore_refuses_an_unknown_or_escaping_artifact(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], archive: str
) -> None:
    unifi.install()
    backup(unifi, monkeypatch, capsys)
    payload = unifi.restore_payload(dry_run=True)
    payload["archive"] = archive

    code, output = run_host(monkeypatch, capsys, "restore", payload)

    assert code == 1
    assert "Unable to locate" in output or "not below" in output


def test_restore_refuses_an_archive_member_outside_the_extraction(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.root.mkdir(parents=True)
    archive = unifi.root / f"manual-{STAMP}.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        info = tarfile.TarInfo("manual/../../escape")
        handle.addfile(info, io.BytesIO(b""))

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload(dry_run=True))

    assert code == 1
    assert "escapes the extraction directory" in output
    assert not (unifi.base / "escape").exists()


def test_confirmed_restore_replaces_database_data_and_system_files_and_drops_the_safety_backup(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    backup(unifi, monkeypatch, capsys)
    restored = snapshot_of_live(unifi)
    change_live(unifi)
    # Files of any db/ directory are never in a backup and stay live.
    nested = unifi.data / "sites" / "default" / "db"
    nested.mkdir()
    (nested / "live.bin").write_text("nested")
    (unifi.state / "log.jsonl").unlink()

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload())

    assert code == 0, output
    assert (nested / "live.bin").read_text() == "nested"
    (nested / "live.bin").unlink()
    nested.rmdir()
    assert snapshot_of_live(unifi) == restored
    assert (unifi.data / "db" / "WiredTiger").read_text() == "mongo files"
    assert unifi.jvm_args.stat().st_mode & 0o777 == 0o640
    assert unifi.unit.stat().st_mode & 0o777 == 0o644
    assert f"Safety backup: {unifi.root}/pre-restore-{LATER}" in output
    assert f"Removed the safety backup {unifi.root}/pre-restore-{LATER}" in output
    assert not (unifi.root / f"pre-restore-{LATER}").exists()
    assert not (unifi.base / "work").exists()
    assert unifi.systemctl() == [
        # The safety backup's stop and start, then the restore's.
        "stop unifi.service",
        "start unifi.service",
        "stop unifi.service",
        "daemon-reload",
        "start unifi.service",
    ]
    tools = [entry["tool"] for entry in unifi.log() if entry["tool"] in ("mongosh", "mongorestore", "curl")]
    assert tools == ["mongosh", "mongorestore", "curl"]
    assert unifi.calls("mongodump")[-1][1:] == ["--db=unifi", "--archive=/dev/null", "--gzip"]
    assert_secret_stayed_private(unifi)


def test_restore_of_a_snapshot_directory_by_name(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    backup(unifi, monkeypatch, capsys, create_archive=False)
    restored = snapshot_of_live(unifi)
    change_live(unifi)

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload(archive=f"manual-{STAMP}"))

    assert code == 0, output
    assert snapshot_of_live(unifi) == restored
    assert (unifi.root / f"manual-{STAMP}").is_dir()


def test_a_fresh_installation_has_nothing_to_snapshot_and_is_restored(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    backup(unifi, monkeypatch, capsys)
    restored = snapshot_of_live(unifi)
    # A freshly deployed controller: no data directory, no database, no route yet.
    shutil.rmtree(unifi.data)
    shutil.rmtree(unifi.state / "mongo" / "unifi")
    unifi.route.unlink()

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload())

    assert code == 0, output
    assert "does not exist: nothing to snapshot (fresh installation)" in output
    assert "database: absent" in output
    assert f"The data directory {unifi.data} does not exist: nothing to snapshot" in output
    restored_now = snapshot_of_live(unifi)
    assert {key: value for key, value in restored_now.items() if key != "data"} == {
        key: value for key, value in restored.items() if key != "data"
    }
    assert (unifi.data / "sites" / "default" / "config.json").read_text() == "live"


def test_a_failed_restore_rolls_back_from_the_safety_backup_and_keeps_it(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    backup(unifi, monkeypatch, capsys)
    change_live(unifi)
    before = snapshot_of_live(unifi)
    # mongorestore fails for the unpacked archive only (it lies below the work directory).
    unifi.set("fail-mongorestore", str(unifi.base / "work"))

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload())

    assert code == 1
    assert "UniFi restore failed" in output
    assert "Rolled back: unifi.service runs from the safety backup again." in output
    assert f"Safety backup retained at {unifi.root}/pre-restore-{LATER} due to restore failure." in output
    assert snapshot_of_live(unifi) == before
    assert (unifi.root / f"pre-restore-{LATER}").is_dir()
    assert (unifi.state / "unit").read_text() == "active"
    assert not (unifi.base / "work").exists()
    assert_secret_stayed_private(unifi)


def test_a_failed_verification_rolls_back_and_a_failed_rollback_is_reported(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    backup(unifi, monkeypatch, capsys)
    change_live(unifi)
    unifi.set("http", "502")

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload())

    assert code == 1
    assert "did not answer with 200, 302 or 303 (last: 502)" in output
    assert "Rollback failed too" in output
    assert (unifi.root / f"pre-restore-{LATER}").is_dir()
    # The rollback replayed the safety backup's database before its own verification failed.
    assert unifi.db_marker() == "changed"


def test_restore_without_rollback_leaves_the_failure(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    backup(unifi, monkeypatch, capsys)
    change_live(unifi)
    unifi.set("fail-mongorestore", str(unifi.base / "work"))

    code, output = run_host(
        monkeypatch,
        capsys,
        "restore",
        unifi.restore_payload(rollback_on_failure=False, create_safety_backup=False),
    )

    assert code == 1
    assert "Rolling back" not in output
    assert not list(unifi.root.glob("pre-restore-*"))


def test_restore_refuses_an_uninstalled_unit_or_an_unreachable_mongodb_before_changing_anything(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    backup(unifi, monkeypatch, capsys)
    change_live(unifi)
    before = snapshot_of_live(unifi)
    unifi.set("load", "not-found")

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload())

    assert code == 1
    assert "deploy UniFi first. Nothing was changed." in output
    unifi.set("load", "loaded")
    unifi.mongo_up = False

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload())

    assert code == 1
    assert "is not reachable. Nothing was changed." in output
    assert snapshot_of_live(unifi) == before
    assert not list(unifi.root.glob("pre-restore-*"))
    assert unifi.systemctl() == ["stop unifi.service", "start unifi.service"]  # the backup's only


def test_a_unit_with_an_inline_uri_is_not_restored(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    unifi.unit.write_text("[Service]\nExecStart=/usr/bin/java -Ddb.mongo.uri=mongodb://u:p@h/unifi\n")
    backup(unifi, monkeypatch, capsys)
    unifi.unit.write_text("[Service]\n# current\n")

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload())

    assert code == 0, output
    assert "carries an inline MongoDB URI" in output
    assert unifi.unit.read_text() == "[Service]\n# current\n"


def test_the_password_never_reaches_the_output_even_when_a_tool_echoes_it(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    # A mongodump that prints its URI (password included) on failure.
    stub = unifi.bin / "mongodump"
    stub.write_text(
        f"#!{sys.executable}\nimport sys\n"
        "config = open(next(a for a in sys.argv if a.startswith('--config=')).split('=', 1)[1]).read()\n"
        "sys.stderr.write('error connecting to ' + config)\nsys.exit(1)\n"
    )

    code, output = run_host(monkeypatch, capsys, "backup", unifi.backup_payload())

    assert code == 1
    assert "********" in output
    assert quote(PASSWORD, safe="") not in output
    assert list(unifi.run.iterdir()) == []


# --- archive compatibility with the roles ---------------------------------------------


def role_archive(machine: Host, name: str) -> Path:
    """An archive as the unifi_backup role writes it: its directories, files, metadata and manifest."""

    directory = machine.root / name
    for sub in host.SUBDIRS:
        (directory / sub).mkdir(parents=True)
    (directory / "database" / "unifi").mkdir()
    (directory / "database" / "unifi" / "device.bson").write_text("from-role")
    subprocess.run(["rsync", "-a", "--exclude=db/*", f"{machine.data}/", f"{directory / 'data'}/"], check=True)
    (directory / "data" / "sites" / "default" / "config.json").write_text("from-role")
    shutil.copy(machine.data / "system.properties", directory / "config" / "system.properties")
    (directory / "systemd" / "unifi.service").write_text("[Service]\n# from-role\n")
    (directory / "systemd" / "mongodb.jvmargs").write_text("from-role\n")
    (directory / "traefik" / "unifi.yml").write_text("http: # from-role\n")
    metadata = {
        "timestamp": STAMP,
        "host": "macmini",
        "unifi_version": VERSION,
        "data_path": str(machine.data),
        # Jinja renders "{{ unifi_mongodb_port }}" as a string.
        "mongodb_port": "27017",
        "mongodb_database": "unifi",
        "service_stopped": True,
        "include_logs": False,
        "include_autobackups": True,
        "restore_methods": {
            "automated": "MongoDB import + data directory rsync",
            "semi_manual": "Extract .unf from autobackups/, upload via web UI",
        },
    }
    # to_nice_yaml
    (directory / "metadata.yml").write_text(
        yaml.dump(metadata, indent=4, allow_unicode=True, default_flow_style=False, sort_keys=True)
    )
    # find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum
    names = sorted(
        ("./" + str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file()), key=str.encode
    )
    (directory / "manifest.sha256").write_text(
        "".join(f"{hashlib.sha256((directory / n).read_bytes()).hexdigest()}  {n}\n" for n in names)
    )
    archive = machine.root / f"{name}.tar.gz"
    subprocess.run(["tar", "-C", str(machine.root), "-czf", archive.name, name], check=True, cwd=machine.root)
    shutil.rmtree(directory)
    return archive


def test_an_archive_of_the_role_is_validated_and_restored(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    unifi.root.mkdir(parents=True, mode=0o700)
    role_archive(unifi, f"manual-{STAMP}")

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload(dry_run=True))

    assert code == 0, output
    assert "backup: unifi_version=9.5.21-31260-1 timestamp=20261109T120000 host=macmini" in output

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload())

    assert code == 0, output
    assert unifi.db_marker() == "from-role"
    assert (unifi.data / "sites" / "default" / "config.json").read_text() == "from-role"
    assert unifi.unit.read_text() == "[Service]\n# from-role\n"
    assert unifi.route.read_text() == "http: # from-role\n"


def test_an_archive_of_the_port_passes_the_roles_validation(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    unifi.install()
    archive = backup(unifi, monkeypatch, capsys)
    # host_local_validate: tar -C <stage> -xf <archive>; the directory of the
    # metadata.yml found below the stage; from_yaml; sha256sum --check.
    stage = tmp_path / "stage"
    stage.mkdir()
    subprocess.run(["tar", "-C", str(stage), "-xf", str(archive)], check=True)
    (metadata,) = stage.rglob("metadata.yml")
    snapshot = metadata.parent
    assert snapshot == stage / archive.name.removesuffix(".tar.gz")
    values = yaml.safe_load(metadata.read_text())
    assert set(values) == ROLE_METADATA_KEYS
    assert str(values["unifi_version"]).split(".")[0] == "9"
    checker = ["sha256sum", "--check"] if shutil.which("sha256sum") else ["shasum", "-a", "256", "--check"]
    subprocess.run([*checker, "manifest.sha256"], cwd=snapshot, check=True, capture_output=True)
    manifest_ok(snapshot)
    # What the role's restore.yml reads.
    for relative in (
        "database/unifi",
        "data",
        "systemd/unifi.service",
        "systemd/mongodb.jvmargs",
        "traefik/unifi.yml",
        "autobackups/new.unf",
    ):
        assert (snapshot / relative).exists(), relative


def test_the_metadata_is_the_roles_to_nice_yaml() -> None:
    cfg = {
        "paths": {"data": "/usr/lib/unifi/data"},
        "host": "macmini",
        "include": {"autobackups": True, "logs": False},
        "database": "unifi",
        "mongodb_port": 27017,
        "stop_service": True,
        "stamp": STAMP,
    }

    text = host.metadata_text(cfg, VERSION)

    expected = {
        "data_path": "/usr/lib/unifi/data",
        "host": "macmini",
        "include_autobackups": True,
        "include_logs": False,
        "mongodb_database": "unifi",
        "mongodb_port": 27017,
        "restore_methods": {
            "automated": "MongoDB import + data directory rsync",
            "semi_manual": "Extract .unf from autobackups/, upload via web UI",
        },
        "service_stopped": True,
        "timestamp": STAMP,
        "unifi_version": VERSION,
    }
    assert yaml.safe_load(text) == expected
    assert text == yaml.dump(expected, indent=4, default_flow_style=False, sort_keys=True)
    assert yaml.safe_load(host.metadata_text(cfg, ""))["unifi_version"] == "unknown"
    assert yaml.safe_load(host.metadata_text({**cfg, "host": "yes"}, "1.0"))["host"] == "yes"


def test_a_missing_tool_refuses_the_backup_before_writing(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unifi.install()
    real = shutil.which
    monkeypatch.setattr(host.shutil, "which", lambda name: None if name == "mongodump" else real(name))

    code, output = run_host(monkeypatch, capsys, "backup", unifi.backup_payload())

    assert code == 1
    assert "Missing on the host: mongodump. Nothing was changed." in output
    assert not unifi.root.exists()
    assert unifi.systemctl() == []


@pytest.mark.parametrize("dry_run", [True, False])
def test_a_missing_tool_refuses_the_restore_and_its_dry_run_before_any_change(
    unifi: Host, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], dry_run: bool
) -> None:
    unifi.install()
    backup(unifi, monkeypatch, capsys)
    change_live(unifi)
    before = snapshot_of_live(unifi)
    real = shutil.which
    monkeypatch.setattr(host.shutil, "which", lambda name: None if name == "mongosh" else real(name))

    code, output = run_host(monkeypatch, capsys, "restore", unifi.restore_payload(dry_run=dry_run))

    assert code == 1
    assert "Missing on the host: mongosh. Nothing was changed." in output
    assert snapshot_of_live(unifi) == before
    assert not list(unifi.root.glob("pre-restore-*"))
    assert not (unifi.base / "work").exists()
