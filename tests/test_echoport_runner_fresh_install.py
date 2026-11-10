"""Restores onto a fresh install through the UniFi and Minecraft Java runners: nothing to snapshot is no error.

Both runners take a safety snapshot before a restore changes anything. On a
fresh install there is nothing to snapshot: the UniFi database has no
collections (``mongodump --db`` then writes no dump directory, Echoport
restore run 306) and the Minecraft world directory does not exist (restore
run 307). The restore logs "nothing to snapshot (fresh install)" for the
``safety_snapshot`` step and goes on; when it fails later, the rollback
restores that empty state (the UniFi database is dropped; the restored world
is removed and Minecraft's snapshotted runtime directories and config are put
back) instead of failing on a missing snapshot. A snapshot source that is
present but cannot be snapshotted still fails the restore before anything is
changed.

The scripts are the runners rendered with the parity fixture's values
(``tests/parity/echoport_runner/inputs.json``), loaded as modules, with the
host's commands replaced.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import types
import warnings
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services._echoport_runner.render import render_runner

INPUTS: dict[str, Any] = json.loads((Path(__file__).parent / "parity/echoport_runner/inputs.json").read_text())[
    "runners"
]
CHECKSUM = "0" * 64
RESTORE_ENV = {
    "ECHOPORT_ACTION": "restore",
    "ECHOPORT_KEY": "t/2026-11-09T02-00-00.tar.gz",
    "ECHOPORT_CHECKSUM": CHECKSUM,
    "ECHOPORT_RESTORE_ID": "306",
}
PASSWORD = "fixture-value"  # pragma: allowlist secret
CREDS: dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 27017,
    "database": "unifi",
    "username": "unifi",
    "password": PASSWORD,
    "auth_db": "admin",
}
FRESH = "nothing to snapshot (fresh install)"


def load_runner(name: str) -> Any:
    """The rendered runner as a module (``Any``: its names come from the template)."""

    spec = INPUTS[name]
    module = types.ModuleType(name.replace("-", "_") + "_fresh_install_test")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        exec(compile(render_runner(spec["template"], spec["inputs"]), spec["template"], "exec"), module.__dict__)
    return module


def _fail(message: str) -> Any:
    def fail(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError(message)

    return fail


class Restore:
    """A runner whose host commands are recorded and whose run dir is a temporary directory."""

    def __init__(self, name: str, base: Path) -> None:
        runner = load_runner(name)
        self.events: list[dict[str, Any]] = []
        self.commands: list[list[str]] = []
        work = base / "work"
        work.mkdir()

        def run_cmd(args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            self.commands.append(list(args))
            return subprocess.CompletedProcess(args, 0, "", "")

        runner._emit = self.events.append
        runner.run_cmd = run_cmd
        runner.create_run_dir = lambda prefix: Path(tempfile.mkdtemp(prefix=prefix, dir=work))
        runner.validate_config_paths = lambda: None
        runner.ensure_binaries = lambda: None
        runner.download_from_minio = lambda bucket, key, dest: dest.write_bytes(b"archive")
        runner.calculate_sha256 = lambda path: CHECKSUM
        runner.disk_space_precheck = lambda *args: None
        runner.verify_checksum_manifest = lambda *args: None
        runner.service_is_active = lambda: False
        runner.wait_service_active = lambda *args: None
        self.runner = runner

    def run(self) -> int:
        result: int = self.runner.restore_flow(dict(RESTORE_ENV))
        return result

    def steps(self, name: str) -> list[tuple[str, str]]:
        return [(e["state"], e.get("message", "")) for e in self.events if e.get("name") == name]

    def error(self) -> str:
        (failure,) = self.steps("error")
        return failure[1]


# -- UniFi: an empty database ----------------------------------------------------------------------


class Unifi(Restore):
    def __init__(self, base: Path) -> None:
        super().__init__("unifi-backup", base)
        runner = self.runner
        self.mongo: list[Any] = []
        self.count = 0
        runner.read_mongo_credentials = lambda: dict(CREDS)

        def extract(tarball: Path, extract_dir: Path) -> None:
            (extract_dir / "database/unifi").mkdir(parents=True)
            (extract_dir / "data").mkdir()

        def dump(creds: dict[str, Any], out: Path) -> None:
            self.mongo.append("dump")
            (out / creds["database"]).mkdir(parents=True)

        runner.safe_extract_tarball = extract
        runner.mongo_collection_count = lambda creds: self.count
        runner.mongo_dump = dump
        runner.mongo_drop_database = lambda creds: self.mongo.append("drop")
        runner.mongo_restore = lambda creds, path: self.mongo.append(("restore", path.parent.name))
        runner.rsync_dir = lambda *args, **kwargs: None
        runner.copy_file_optional = lambda src, dst: False
        runner.restore_private_file = lambda src, dst: False
        runner.apply_ownership = lambda path: None
        runner.wait_tcp_port = lambda *args: None
        runner.mongo_dump_check = lambda creds: None
        runner.run_health_check = lambda: None


@pytest.fixture
def unifi(tmp_path: Path) -> Unifi:
    return Unifi(tmp_path)


def test_unifi_an_empty_database_is_not_snapshotted_and_the_restore_goes_on(unifi: Unifi) -> None:
    assert unifi.run() == 0
    assert unifi.steps("safety_snapshot") == [
        ("running", "Creating pre-restore MongoDB safety snapshot"),
        ("success", f"Database unifi has no collections: {FRESH}"),
    ]
    assert unifi.mongo == ["drop", ("restore", "database")]
    assert unifi.steps("rollback") == [("success", "Rollback not required")]


def test_unifi_a_failing_fresh_restore_drops_the_restored_database(unifi: Unifi) -> None:
    unifi.runner.run_health_check = _fail("controller not healthy")

    assert unifi.run() == 1
    assert unifi.mongo == ["drop", ("restore", "database"), "drop"]
    assert unifi.steps("rollback") == [
        ("running", "Restore failed; dropping the restored database (fresh install, no snapshot)"),
        ("success", "MongoDB rollback completed: empty database restored"),
    ]
    assert unifi.error() == "controller not healthy (rollback executed)"


def test_unifi_a_failing_drop_in_the_fresh_rollback_is_reported(unifi: Unifi) -> None:
    drops: list[int] = []

    def drop(creds: dict[str, Any]) -> None:
        drops.append(1)
        if len(drops) > 1:
            raise RuntimeError("drop refused")

    unifi.runner.mongo_drop_database = drop
    unifi.runner.mongo_restore = _fail("restore failed")

    assert unifi.run() == 1
    assert unifi.steps("rollback")[-1] == ("failure", "MongoDB rollback failed: drop refused")
    assert unifi.error() == "restore failed; rollback failed: drop refused"


def test_unifi_a_database_with_collections_is_snapshotted_and_rolled_back(unifi: Unifi) -> None:
    unifi.count = 3
    unifi.runner.run_health_check = _fail("unhealthy")

    assert unifi.run() == 1
    assert unifi.mongo == ["dump", "drop", ("restore", "database"), "drop", ("restore", "safety_db")]
    assert unifi.steps("safety_snapshot")[-1] == ("success", "MongoDB safety snapshot created")
    assert unifi.steps("rollback")[-1] == ("success", "MongoDB rollback completed")


def test_unifi_a_failing_snapshot_of_a_present_database_fails_before_any_change(unifi: Unifi) -> None:
    unifi.count = 3
    unifi.runner.mongo_dump = _fail("mongodump completed but dump directory missing")

    assert unifi.run() == 1
    assert unifi.mongo == []
    assert unifi.steps("rollback") == [("success", "Rollback not required")]
    assert unifi.error() == "mongodump completed but dump directory missing"


def test_unifi_an_unreadable_collection_count_fails_before_any_change(unifi: Unifi) -> None:
    unifi.runner.mongo_collection_count = _fail("Could not read the MongoDB collection count for the safety snapshot")

    assert unifi.run() == 1
    assert unifi.mongo == []
    assert "collection count" in unifi.error()


class Call:
    """One host command: argv, stdin, environment and the private files it could read while it ran."""

    def __init__(self, args: list[str], kwargs: dict[str, Any]) -> None:
        self.args = args
        self.input: str = kwargs.get("input") or ""
        self.env: dict[str, str] = kwargs.get("env") or {}
        self.config = ""
        self.config_mode = 0
        self.dir_mode = 0
        for arg in args:
            if arg.startswith("--config="):
                path = Path(arg.removeprefix("--config="))
                self.config = path.read_text()
                self.config_mode = path.stat().st_mode & 0o777
                self.dir_mode = path.parent.stat().st_mode & 0o777
        settings = Path(self.env["HOME"]) / ".mongodb" / "mongosh" / "config"
        self.mongosh_config = json.loads(settings.read_text())
        self.home_dir_mode = Path(self.env["HOME"]).parent.stat().st_mode & 0o777


def _counting(work: Path, stdout: str, returncode: int = 0, stderr: str = "") -> tuple[Any, list[Call]]:
    runner = load_runner("unifi-backup")
    (work / "work").mkdir(exist_ok=True)
    runner.WORK_DIR = str(work / "work")
    calls: list[Call] = []

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(Call(list(args), kwargs))
        return subprocess.CompletedProcess(args, returncode, stdout, stderr or ("auth failed" if returncode else ""))

    runner.subprocess = types.SimpleNamespace(
        run=run, CalledProcessError=subprocess.CalledProcessError, DEVNULL=subprocess.DEVNULL
    )
    return runner, calls


def test_unifi_the_collection_count_comes_from_mongosh_for_the_database(tmp_path: Path) -> None:
    runner, calls = _counting(tmp_path, "0\n")

    assert runner.mongo_collection_count(dict(CREDS)) == 0
    (call,) = calls
    assert call.args[0] == "mongosh"
    assert call.args[-2:] == ["--file", "/dev/stdin"]
    assert 'db.getSiblingDB("admin")' in call.input
    assert 'db.getSiblingDB("unifi")' in call.input
    assert "getCollectionNames().length" in call.input
    runner, _ = _counting(tmp_path, "Some notice\n42\n")
    assert runner.mongo_collection_count(dict(CREDS)) == 42


@pytest.mark.parametrize("stdout", ["", "MongoServerError: not authorized\n", "-1\n"])
def test_unifi_an_unreadable_answer_is_not_an_empty_database(stdout: str, tmp_path: Path) -> None:
    runner, _ = _counting(tmp_path, stdout)

    with pytest.raises(RuntimeError, match="collection count"):
        runner.mongo_collection_count(dict(CREDS))


def test_unifi_a_failing_mongosh_is_not_an_empty_database(tmp_path: Path) -> None:
    runner, _ = _counting(tmp_path, "", returncode=1)

    with pytest.raises(subprocess.CalledProcessError):
        runner.mongo_collection_count(dict(CREDS))


# -- UniFi: the MongoDB password stays off argv and the environment ----------------------------------


def _all_mongo_calls(runner: Any, base: Path) -> None:
    dump = base / "dump"
    (dump / "unifi").mkdir(parents=True)
    runner.mongo_dump(dict(CREDS), dump)
    runner.mongo_restore(dict(CREDS), dump / "unifi")
    runner.mongo_dump_check(dict(CREDS))
    runner.mongo_collection_count(dict(CREDS))
    runner.mongo_drop_database(dict(CREDS))


def test_unifi_the_mongo_password_is_never_on_argv_or_in_the_environment(tmp_path: Path) -> None:
    runner, calls = _counting(tmp_path, "OPS_UNIFI_DROPPED\n3\n")

    _all_mongo_calls(runner, tmp_path / "calls")

    assert [c.args[0] for c in calls] == ["mongodump", "mongorestore", "mongodump", "mongosh", "mongosh"]
    for call in calls:
        assert not any(PASSWORD in arg for arg in call.args), call.args
        assert not any(arg.startswith("--password") for arg in call.args), call.args
        assert not any(PASSWORD in value for value in call.env.values())
        assert set(call.env) == {"HOME", "PATH", "LC_ALL"}
        assert call.mongosh_config == {"disableLogging": True, "enableTelemetry": False, "updateURL": ""}
        assert call.home_dir_mode == 0o700


def test_unifi_mongodump_and_mongorestore_read_the_password_from_a_private_config_file(tmp_path: Path) -> None:
    runner, calls = _counting(tmp_path, "OPS_UNIFI_DROPPED\n3\n")

    _all_mongo_calls(runner, tmp_path / "calls")

    tools = [c for c in calls if c.args[0] != "mongosh"]
    assert len(tools) == 3
    for call in tools:
        assert call.config == f'password: "{PASSWORD}"\n'
        assert call.config_mode == 0o600
        assert call.dir_mode == 0o700
        assert "--username=unifi" in call.args
        assert "--authenticationDatabase=admin" in call.args
        assert call.input == ""


def test_unifi_mongosh_gets_the_password_in_its_script_on_stdin(tmp_path: Path) -> None:
    runner, calls = _counting(tmp_path, "OPS_UNIFI_DROPPED\n3\n")

    _all_mongo_calls(runner, tmp_path / "calls")

    shells = [c for c in calls if c.args[0] == "mongosh"]
    assert len(shells) == 2
    for call in shells:
        assert call.config == ""
        assert call.input.startswith('if (config.get("disableLogging") !== true')
        assert f'.auth("unifi", "{PASSWORD}")' in call.input
    assert "dropDatabase()" in shells[1].input


def test_unifi_the_private_auth_directories_are_removed_after_each_call(tmp_path: Path) -> None:
    runner, calls = _counting(tmp_path, "OPS_UNIFI_DROPPED\n3\n")

    _all_mongo_calls(runner, tmp_path / "calls")

    assert len(calls) == 5
    assert list(Path(runner.WORK_DIR).iterdir()) == []
    assert runner.MONGO_AUTH_PREFIX.startswith(runner.RUN_DIR_PREFIXES)


def test_unifi_a_failing_tool_reports_without_the_password(tmp_path: Path) -> None:
    runner, _ = _counting(tmp_path, "", returncode=1, stderr=f"Failed: bad login {PASSWORD}")

    with pytest.raises(subprocess.CalledProcessError) as raised:
        runner.mongo_dump_check(dict(CREDS))

    assert PASSWORD not in runner.safe_error(raised.value)
    assert not any(PASSWORD in arg for arg in raised.value.cmd)
    assert list(Path(runner.WORK_DIR).iterdir()) == []


def test_unifi_a_drop_without_confirmation_fails(tmp_path: Path) -> None:
    runner, _ = _counting(tmp_path, "")

    with pytest.raises(RuntimeError, match="did not confirm dropping"):
        runner.mongo_drop_database(dict(CREDS))


def test_unifi_the_escaped_password_is_redacted_too(tmp_path: Path) -> None:
    runner, _ = _counting(tmp_path, "")
    creds = dict(CREDS, password='fixture"pass\\word')  # pragma: allowlist secret
    escaped = json.dumps(creds["password"])[1:-1]

    text = runner.redact(f"raw {creds['password']} script {escaped}", creds)

    assert text == "raw ******** script ********"


# -- Minecraft Java: a missing world ---------------------------------------------------------------

WORLD = "world_forge_2026_02_22"


class Minecraft(Restore):
    def __init__(self, base: Path) -> None:
        super().__init__("minecraft-java-backup", base)
        runner = self.runner
        self.server = base / "server"
        self.server.mkdir()
        (self.server / "server.properties").write_text("level-name=world\n")
        (self.server / "mods").mkdir()
        (self.server / "mods/live.jar").write_text("live")
        runner.ALLOWED_ROOTS = [str(base)]
        runner.SERVER_DIR = str(self.server)
        runner.SERVER_PROPERTIES = str(self.server / "server.properties")
        runner.ENV_FILE = str(base / "minecraft.env")
        runner.SYSTEMD_UNIT = str(base / "minecraft-java.service")
        runner.read_manifest_from_tarball = lambda path: {"world_name": WORLD}

        def extract(tarball: Path, extract_dir: Path) -> None:
            world = extract_dir / "world" / WORLD
            world.mkdir(parents=True)
            (world / "level.dat").write_text("restored")
            (extract_dir / "world/mods").mkdir()
            (extract_dir / "world/mods/restored.jar").write_text("restored")
            (extract_dir / "world/defaultconfigs").mkdir()
            (extract_dir / "world/defaultconfigs/restored.toml").write_text("restored")
            (extract_dir / "config").mkdir()
            (extract_dir / "config/server.properties").write_text(f"level-name={WORLD}\n")
            (extract_dir / "config/ops.json").write_text("[]")
            (extract_dir / "manifest.json").write_text(json.dumps({"world_name": WORLD}))

        def rsync_dir(src: Path, dst: Path, delete: bool = True) -> None:
            if src.is_dir():
                if delete and dst.exists():
                    shutil.rmtree(dst)
                shutil.copytree(src, dst, dirs_exist_ok=True)

        runner.safe_extract_tarball = extract
        runner.rsync_dir = rsync_dir
        runner.wait_tcp_port = lambda *args: None

    @property
    def target(self) -> Path:
        return self.server / WORLD

    def fail_start(self) -> None:
        """The restored server never opens its port; the rollback's start succeeds."""

        calls: list[int] = []

        def wait_tcp_port(*args: Any) -> None:
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("port 25565 not reachable")

        self.runner.wait_tcp_port = wait_tcp_port


@pytest.fixture
def minecraft(tmp_path: Path) -> Minecraft:
    return Minecraft(tmp_path)


def test_minecraft_a_missing_world_is_not_snapshotted_and_the_restore_goes_on(minecraft: Minecraft) -> None:
    assert minecraft.run() == 0
    assert minecraft.steps("safety_snapshot") == [
        ("running", "Creating pre-restore safety snapshot"),
        (
            "success",
            f"World {WORLD} not present: nothing to snapshot (fresh install, or a world this server"
            " does not have yet); runtime directories and config snapshotted",
        ),
    ]
    assert (minecraft.target / "level.dat").read_text() == "restored"
    assert (minecraft.server / "server.properties").read_text() == f"level-name={WORLD}\n"


def test_minecraft_a_failing_fresh_restore_removes_the_world_and_restores_the_config(minecraft: Minecraft) -> None:
    minecraft.fail_start()

    assert minecraft.run() == 1
    assert not minecraft.target.exists()
    assert minecraft.server.is_dir()
    assert (minecraft.server / "server.properties").read_text() == "level-name=world\n"
    assert sorted(p.name for p in (minecraft.server / "mods").iterdir()) == ["live.jar"]
    # Absent before the restore: removed again.
    assert not (minecraft.server / "defaultconfigs").exists()
    assert not (minecraft.server / "ops.json").exists()
    assert minecraft.steps("rollback") == [
        (
            "running",
            f"Restore failed; removing the restored world {WORLD} (fresh install, no world snapshot)"
            " and restoring the snapshotted config",
        ),
        ("success", f"Rollback completed: restored world {WORLD} removed"),
    ]
    assert minecraft.error() == "port 25565 not reachable (rollback executed)"


def test_minecraft_a_present_world_is_snapshotted_and_rolled_back(minecraft: Minecraft) -> None:
    minecraft.target.mkdir()
    (minecraft.target / "level.dat").write_text("live")
    minecraft.fail_start()

    assert minecraft.run() == 1
    assert minecraft.steps("safety_snapshot")[-1] == ("success", "Safety snapshot created")
    assert minecraft.steps("rollback") == [
        ("running", "Restore failed; attempting rollback from safety snapshot"),
        ("success", "Rollback completed"),
    ]
    assert (minecraft.target / "level.dat").read_text() == "live"
    assert not (minecraft.server / "defaultconfigs").exists()
    assert not (minecraft.server / "ops.json").exists()


def test_minecraft_an_entry_that_existed_but_could_not_be_snapshotted_is_kept(minecraft: Minecraft) -> None:
    # ops.json as a directory: copy_file_optional skips it; the rollback must not remove it.
    (minecraft.server / "ops.json").mkdir()
    (minecraft.server / "ops.json/keep").write_text("keep")
    minecraft.fail_start()

    assert minecraft.run() == 1
    assert (minecraft.server / "ops.json/keep").read_text() == "keep"


def test_minecraft_a_world_that_is_not_a_directory_fails_before_any_change(minecraft: Minecraft) -> None:
    minecraft.target.write_text("not a world")

    assert minecraft.run() == 1
    assert "not a directory" in minecraft.error()
    assert minecraft.target.read_text() == "not a world"
    assert ["systemctl", "stop", "minecraft-java"] not in minecraft.commands
    assert minecraft.steps("rollback") == []


def test_minecraft_a_failing_snapshot_of_a_present_world_fails_before_any_change(minecraft: Minecraft) -> None:
    minecraft.target.mkdir()
    (minecraft.target / "level.dat").write_text("live")

    def failing_rsync(src: Path, dst: Path, delete: bool = True) -> None:
        raise subprocess.CalledProcessError(23, ["rsync"], "", "rsync error")

    minecraft.runner.rsync_dir = failing_rsync

    assert minecraft.run() == 1
    assert (minecraft.target / "level.dat").read_text() == "live"
    assert not any(cmd[:2] == ["systemctl", "stop"] for cmd in minecraft.commands)
    assert minecraft.steps("rollback") == []
    assert minecraft.steps("safety_snapshot") == [("running", "Creating pre-restore safety snapshot")]
