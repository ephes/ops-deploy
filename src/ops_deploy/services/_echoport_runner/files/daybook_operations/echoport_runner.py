#!/usr/bin/python3 -I
"""Fixed-source backup bridge. Restore remains an attended lifecycle operation."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
import pwd
import signal
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path

POLICY = Path("/etc/daybook-operations-backup.json")
LIMIT = 6 * 1024**3
ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}


def emit(name, state, message=""):
    print(json.dumps({"name": name, "state": state, "message": message}), flush=True)


def command(args, *, account=None, output=None):
    options = {}
    if account:
        options = {"user": account.pw_uid, "group": account.pw_gid, "extra_groups": []}
    with subprocess.Popen(
        args,
        stdout=output if output is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=ENV,
        cwd="/",
        start_new_session=True,
        **options,
    ) as child:
        try:
            stdout, _ = child.communicate(timeout=240)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise ValueError("backup_command_timeout") from None
        except BaseException:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise
        if child.returncode:
            raise ValueError("backup_command_failed")
        return stdout


def read_json(path, *, root_owned=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            raise ValueError("invalid_configuration")
        if root_owned and (info.st_uid != 0 or info.st_mode & 0o022):
            raise ValueError("invalid_configuration")
        return json.load(stream)


def validate_context(config, policy):
    context = config.get("context") if isinstance(config, dict) else None
    values = context.get("env", context) if isinstance(context, dict) else None
    required = {"ECHOPORT_ACTION", "ECHOPORT_TARGET", "ECHOPORT_BUCKET"}
    if not isinstance(values, dict) or not required <= values.keys():
        raise ValueError("invalid_context")
    if values["ECHOPORT_ACTION"] != "backup":
        raise ValueError("restore_requires_attended_lifecycle")
    if values["ECHOPORT_TARGET"] != policy["target"]:
        raise ValueError("wrong_target")
    if values["ECHOPORT_BUCKET"] != policy["bucket"]:
        raise ValueError("wrong_bucket")
    # Caller paths, timestamps, keys and executable choices are never used.


def backup(policy):
    account = pwd.getpwnam(policy["user"])
    with tempfile.TemporaryDirectory(
        prefix="echoport-", dir=policy["backup_root"]
    ) as work:
        os.chown(work, account.pw_uid, account.pw_gid)
        source = Path(work) / "snapshot.tar"
        base = [policy["python"], "-I", policy["lifecycle"]]
        emit("backup", "running")
        command(
            base + ["backup", "--config", policy["config"], "--archive", str(source)],
            account=account,
        )
        command(
            base + ["validate", "--config", policy["config"], "--archive", str(source)],
            account=account,
        )
        with tempfile.TemporaryDirectory(
            prefix="upload-", dir=policy["staging_root"]
        ) as stage:
            archive = Path(stage) / "snapshot.tar"
            # Open the source as the service account, never as root. Only root owns
            # the resulting upload directory/file, including during mc execution.
            with archive.open("xb") as stream:
                command(
                    ["/usr/bin/head", "-c", str(LIMIT + 1), str(source)],
                    account=account,
                    output=stream,
                )
            size = archive.stat().st_size
            if not 0 < size <= LIMIT:
                raise ValueError("archive_capacity")
            with archive.open("rb") as stream:
                checksum = hashlib.file_digest(stream, "sha256").hexdigest()
            key = f"{policy['target']}/{datetime.datetime.now(datetime.UTC):%Y-%m-%dT%H-%M-%S}-{uuid.uuid4().hex}.tar"
            destination = f"{policy['alias']}/{policy['bucket']}/{key}"
            emit("upload", "running")
            command([policy["mc"], "cp", "--quiet", str(archive), destination])
            downloaded = Path(stage) / "verify.tar"
            command([policy["mc"], "cp", "--quiet", destination, str(downloaded)])
            with downloaded.open("rb") as stream:
                received = hashlib.file_digest(stream, "sha256").hexdigest()
            if downloaded.stat().st_size != size or received != checksum:
                raise ValueError("upload_verification_failed")
            emit("verify", "success")
            return {
                "success": True,
                "bucket": policy["bucket"],
                "key": key,
                "size_bytes": size,
                "checksum_sha256": checksum,
                "file_count": 4,
            }


def interrupted(signum, frame):
    raise ValueError("backup_interrupted")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        return subprocess.call(
            [
                "/usr/bin/sudo",
                "-n",
                str(Path(__file__).resolve()),
                "--config",
                args.config,
            ]
        )
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        policy = read_json(POLICY, root_owned=True)
        validate_context(read_json(args.config), policy)
        with open(policy["lock"], "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("backup_already_running") from None
            result = backup(policy)
        emit("result", "success", "ECHOPORT_RESULT:" + json.dumps(result))
        print(json.dumps({"event": "finish", "status": "success"}), flush=True)
        return 0
    except Exception as exc:  # noqa: BLE001 - emit only fixed public categories
        allowed = {
            "backup_command_timeout",
            "backup_interrupted",
            "backup_command_failed",
            "invalid_configuration",
            "invalid_context",
            "restore_requires_attended_lifecycle",
            "wrong_target",
            "wrong_bucket",
            "archive_capacity",
            "upload_verification_failed",
            "backup_already_running",
        }
        error = (
            str(exc)
            if isinstance(exc, (ValueError, TypeError)) and str(exc) in allowed
            else "backup_failed"
        )
        emit(
            "result",
            "failure",
            "ECHOPORT_RESULT:" + json.dumps({"success": False, "error": error}),
        )
        print(json.dumps({"event": "finish", "status": "failure"}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
