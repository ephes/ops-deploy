"""The villakunterbunt fork's restore-scratch action, through the vendored guard.

The runner is rendered as pyinfra renders it; every remote command it sends is
decided by the guard's ``--restore-scratch`` mode (``check_scratch``) and
carried out on a temporary root. The scratch restore must verify the copy,
remove it, never send a live path or a systemctl, and leave the live files as
they were. A scratch request's poisoned live fields stop the backup path that
older runners run for the unknown action before anything reaches the host.
"""

from __future__ import annotations

import contextlib
import grp
import hashlib
import io
import json
import os
import pwd
import shlex
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import types
import warnings
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from ops_deploy.base.echoport_command_guard import _guard_module
from ops_deploy.services._echoport_runner.render import render_runner

TEMPLATE = "villakunterbunt_staging_backup.py.j2"
GUARD = _guard_module()
POISON_DB = "/nonexistent/echoport-restore-scratch-needs-a-scratch-runner/db.sqlite3"
POISON_UNIT = "echoport-restore-scratch-needs-a-scratch-runner!"
BASE_VARS = {
    "echoport_backup_mc_install_path": "/usr/local/bin/mc",
    "echoport_backup_minio_alias": "minio",
    "echoport_backup_default_bucket": "backups",
    "echoport_backup_temp_dir": "/tmp/villakunterbunt-staging-backup",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(variables: dict[str, Any]) -> types.ModuleType:
    module = types.ModuleType("villakunterbunt_runner_under_test")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        exec(compile(render_runner(TEMPLATE, {**BASE_VARS, **variables}), TEMPLATE, "exec"), module.__dict__)
    return module


def fingerprint(root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for directory, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".restore-scratch-")]
        for name in dirnames + filenames:
            path = Path(directory) / name
            st = os.lstat(path)
            if stat.S_ISDIR(st.st_mode):
                result[str(path)] = ("dir", stat.S_IMODE(st.st_mode))
            else:
                result[str(path)] = ("file", sha(path), stat.S_IMODE(st.st_mode), st.st_mtime_ns)
    return result


_REAL_RUN = subprocess.run  # the runner's subprocess.run is patched below


class ScratchHost:
    """Staging behind the scratch key: the guard decides, the temp root holds the files."""

    def __init__(self, policy: Any, archive: Path) -> None:
        self.policy = policy
        self.archive = archive
        self.commands: list[str] = []
        self.refusals: list[str] = []
        self.connections: list[list[str]] = []

    def decide(self, command: str) -> Any:
        self.commands.append(command)
        try:
            return GUARD.check_scratch(command, self.policy)
        except GUARD.Refused:
            self.refusals.append(command)
            return None

    def execute(self, decision: Any) -> subprocess.CompletedProcess[str]:
        if decision.output is not None:
            return subprocess.CompletedProcess([], 0, decision.output + "\n", "")
        if decision.mutation is not None:
            GUARD.perform(decision.mutation)
            return subprocess.CompletedProcess([], 0, "", "")
        argv = decision.argv[4:] if decision.argv[0] == "runuser" else decision.argv
        if argv[0] == "mkdir" and len(argv) == 2:
            try:
                os.mkdir(argv[1])
            except FileExistsError:
                return subprocess.CompletedProcess(argv, 1, "", "File exists")
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[0] == "mkdir":
            os.makedirs(argv[2], exist_ok=True)
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[0] == "test":
            return subprocess.CompletedProcess(argv, 0 if os.path.lexists(argv[2]) else 1, "", "")
        raise AssertionError(argv)

    def run(self, args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert isinstance(args, list), args
        refused = subprocess.CompletedProcess(args, 1, "", "refused")
        if args[0] == "sqlite3":  # the shared integrity check on the downloaded copy
            return _REAL_RUN(args, **kwargs)
        if args[1] == "cp":
            shutil.copy(self.archive, args[3])
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[0] == "ssh" and "-G" in args:
            given = dict(args[i + 1].split("=", 1) for i, a in enumerate(args) if a == "-o")
            lines = [f"identityfile {given['IdentityFile']}", "identitiesonly yes", "identityagent none"]
            return subprocess.CompletedProcess(args, 0, "\n".join(lines) + "\n", "")
        if args[0] == "ssh":
            self.connections.append(args)
            decision = self.decide(args[-1])
            return refused if decision is None else self.execute(decision)
        if args[0] == "scp":
            self.connections.append(args)
            remote = args[-1].split(":", 1)[1]
            if self.decide(f"scp -t {remote}") is None:
                return refused
            shutil.copy(args[-2], remote)
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[0] == "rsync":
            e = args.index("-e")
            self.connections.append(shlex.split(args[e + 1]))
            options, source, target = tuple(args[1:e]), args[e + 2], args[e + 3]
            if options == ("-a", "--no-D"):
                remote = target.split(":", 1)[1]
                decision = self.decide(f"rsync --server -logtpre.iLsfxCIvu . {remote}")
                src, dst = source, remote
            else:
                assert options == ("-a",)
                remote = source.split(":", 1)[1]
                decision = self.decide(f"rsync --server --sender -logDtpre.iLsfxCIvu . {remote}")
                src, dst = remote, target
            if decision is None:
                return refused
            shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(f"unexpected local command: {args}")


@pytest.fixture
def site(tmp_path: Path) -> dict[str, Any]:
    base = Path(os.path.realpath(tmp_path))
    root = base / "data"
    (root / "media" / "photos").mkdir(parents=True)
    (root / "media" / "photos" / "live.jpg").write_bytes(b"live")
    (root / "private_media").mkdir()
    (root / "private_media" / "only-live.pdf").write_bytes(b"live only")
    (root / "db.sqlite3").write_bytes(b"live db")
    (root / "db.sqlite3-wal").write_bytes(b"wal")
    owner = f"{pwd.getpwuid(os.geteuid()).pw_name}:{grp.getgrgid(os.getegid()).gr_name}"
    stage = base / "stage"
    (stage / "media" / "photos").mkdir(parents=True)
    (stage / "media" / "photos" / "a.jpg").write_bytes(b"backup photo")
    (stage / "private_media" / "docs").mkdir(parents=True)
    (stage / "private_media" / "docs" / "contract.pdf").write_bytes(b"backup pdf")
    db = stage / "db_backup.sqlite3"
    with contextlib.closing(sqlite3.connect(db)) as connection:
        connection.execute("CREATE TABLE t (x)")
        connection.execute("CREATE TABLE u (y)")
        connection.commit()
    manifest = {"database": {"filename": "db_backup.sqlite3"}, "files": [f"{root}/media", f"{root}/private_media"]}
    (stage / "manifest.json").write_text(json.dumps(manifest))
    archive = base / "backup.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name in ("manifest.json", "db_backup.sqlite3", "media", "private_media"):
            tar.add(stage / name, arcname=name)
    ssh_dir = base / "ssh"
    ssh_dir.mkdir(mode=0o700)
    for name, content in (("config", "Host *\n"), ("scratch", "scratch key"), ("live", "live key")):
        (ssh_dir / name).write_text(content)
        (ssh_dir / name).chmod(0o600)
    runner = load(
        {
            "villakunterbunt_staging_backup_default_host": "staging.wersdoerfer.de",
            "villakunterbunt_staging_backup_allowed_roots": [f"{root}/"],
            "villakunterbunt_staging_backup_restore_owner": owner,
            "villakunterbunt_staging_backup_scratch_ssh_config": str(ssh_dir / "config"),
            "villakunterbunt_staging_backup_scratch_ssh_key": str(ssh_dir / "scratch"),
            "villakunterbunt_staging_backup_live_ssh_key": str(ssh_dir / "live"),
        }
    )
    policy = GUARD.Policy.from_dict(
        {
            "path_roots": [{"path": str(root), "owner": owner}],
            "units": ["villakunterbunt-next.service", "villakunterbunt-django.service"],
        }
    )
    work = base / "work"
    work.mkdir()
    return {
        "root": root,
        "owner": owner,
        "archive": archive,
        "db_sha": sha(db),
        "runner": runner,
        "policy": policy,
        "work": work,
        "ssh_dir": ssh_dir,
    }


def run_main(site: dict[str, Any], host: ScratchHost, env: dict[str, str]) -> tuple[int, dict[str, Any]]:
    runner = site["runner"]
    with (
        mock.patch.object(runner, "read_config_file", return_value={"context": {"env": env}}),
        mock.patch.object(runner.subprocess, "run", side_effect=host.run),
        mock.patch.object(runner, "ssh", side_effect=AssertionError("live ssh helper used")),
        mock.patch.object(runner, "TEMP_DIR", str(site["work"])),
        contextlib.redirect_stdout(io.StringIO()) as out,
        contextlib.redirect_stderr(io.StringIO()),
    ):
        rc = runner.main()
    # No archive, extraction or verify copy left on the runner host.
    assert list(site["work"].iterdir()) == []
    lines = [line for line in out.getvalue().splitlines() if "ECHOPORT_RESULT:" in line]
    assert len(lines) == 1, out.getvalue()
    return rc, json.loads(json.loads(lines[0])["message"].split("ECHOPORT_RESULT:", 1)[1])


def scratch_env(site: dict[str, Any], **overrides: str) -> dict[str, str]:
    env = {
        "ECHOPORT_ACTION": "restore-scratch",
        "ECHOPORT_RESTORE_DESTINATION": "scratch",
        "ECHOPORT_RESTORE_KEEP_SCRATCH": "0",
        "ECHOPORT_RESTORE_SCRATCH_DB_PATH": f"{site['root']}/db.sqlite3",
        "ECHOPORT_RESTORE_ID": "7",
        "ECHOPORT_KEY": "villakunterbunt-staging/2026-11-11T03-00-00.tar.gz",
        "ECHOPORT_CHECKSUM": sha(site["archive"]),
        "ECHOPORT_RESTORE_OWNER": site["owner"],
        "ECHOPORT_DB_PATH": POISON_DB,
        "ECHOPORT_SERVICE_NAME": POISON_UNIT,
        "ECHOPORT_BACKUP_FILES": "",
    }
    env.update(overrides)
    return env


def test_scratch_restore_verifies_cleans_up_and_leaves_live_alone(site: dict[str, Any]) -> None:
    before = fingerprint(site["root"])
    host = ScratchHost(site["policy"], site["archive"])
    rc, result = run_main(site, host, scratch_env(site))
    assert rc == 0, result
    assert host.refusals == []
    assert result["destination"] == "scratch"
    assert result["cleaned"] is True
    assert result["scratch_path"].startswith(f"{site['root']}/.restore-scratch-")
    assert result["scratch_path"].endswith("-7")
    verification = result["verification"]
    assert verification["ok"] is True, verification
    assert (verification["db_sha256"], verification["integrity"], verification["tables"]) == (site["db_sha"], "ok", 2)
    assert result["file_count"] == 3
    assert host.commands[0] == "echoport-guard-mode"
    assert host.commands[1] == f"mkdir {result['scratch_path']}"
    for command in host.commands[1:]:
        assert result["scratch_path"] in command
        assert "systemctl" not in command
        assert "--delete" not in command
    for argv in host.connections:
        assert str(site["ssh_dir"] / "config") in argv
        assert f"IdentityFile={site['ssh_dir'] / 'scratch'}" in argv
    assert fingerprint(site["root"]) == before
    assert not any(p.name.startswith(".restore-scratch-") for p in site["root"].iterdir())


def test_service_owned_target_uses_the_runners_db_path(site: dict[str, Any]) -> None:
    """villakunterbunt-staging is service-owned: Echoport sends an empty db_path."""
    site["runner"] = load(
        {
            "villakunterbunt_staging_backup_default_host": "staging.wersdoerfer.de",
            "villakunterbunt_staging_backup_allowed_roots": [f"{site['root']}/"],
            "villakunterbunt_staging_backup_default_db_path": f"{site['root']}/db.sqlite3",
            "villakunterbunt_staging_backup_restore_owner": site["owner"],
            "villakunterbunt_staging_backup_scratch_ssh_config": str(site["ssh_dir"] / "config"),
            "villakunterbunt_staging_backup_scratch_ssh_key": str(site["ssh_dir"] / "scratch"),
            "villakunterbunt_staging_backup_live_ssh_key": str(site["ssh_dir"] / "live"),
        }
    )
    host = ScratchHost(site["policy"], site["archive"])
    env = scratch_env(site, ECHOPORT_RESTORE_SCRATCH_DB_PATH="", ECHOPORT_RESTORE_OWNER="")
    rc, result = run_main(site, host, env)
    assert rc == 0, result
    assert result["verification"]["ok"] is True


def test_keep_scratch(site: dict[str, Any]) -> None:
    host = ScratchHost(site["policy"], site["archive"])
    rc, result = run_main(site, host, scratch_env(site, ECHOPORT_RESTORE_KEEP_SCRATCH="1"))
    assert rc == 0, result
    scratch = Path(result["scratch_path"])
    assert sha(scratch / "db.sqlite3") == site["db_sha"]
    assert (scratch / "private_media" / "docs" / "contract.pdf").read_bytes() == b"backup pdf"
    assert not (scratch / "private_media" / "only-live.pdf").exists()
    assert (site["root"] / "private_media" / "only-live.pdf").read_bytes() == b"live only"


def test_poisoned_live_fields_stop_the_backup_path_before_any_command(site: dict[str, Any]) -> None:
    """What a runner without the action runs for it: its backup path."""
    runner = site["runner"]
    sent: list[str] = []
    env = {"ECHOPORT_ACTION": "backup", "ECHOPORT_DB_PATH": POISON_DB, "ECHOPORT_SERVICE_NAME": POISON_UNIT}
    with (
        mock.patch.object(runner, "read_config_file", return_value={"context": {"env": env}}),
        mock.patch.object(runner, "ssh", side_effect=lambda *a, **k: sent.append(a[2])),
        contextlib.redirect_stdout(io.StringIO()),
        contextlib.redirect_stderr(io.StringIO()),
        pytest.raises(ValueError, match="Invalid systemd service name"),
    ):
        runner.main()
    assert sent == []


def test_backups_report_the_capability(site: dict[str, Any]) -> None:
    text = render_runner(TEMPLATE, BASE_VARS)
    assert '"capabilities": RUNNER_CAPABILITIES,' in text
    assert site["runner"].RUNNER_CAPABILITIES == ["restore-scratch"]
