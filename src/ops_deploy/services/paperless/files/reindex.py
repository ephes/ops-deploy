"""Managed Paperless reindex with the original stop-all/resume-running contract.

This is an execution helper, never a read-only probe. Application output is
discarded because upstream progress/errors can contain document metadata.
Ordinary failures remain nonzero after every previously running unit has been
offered a restart. Abrupt process/host loss cannot guarantee that finally runs.
"""

import json
import re
import shlex
import subprocess
import sys


class ReindexFailure(RuntimeError):
    pass


def validate(settings):
    if not isinstance(settings, dict) or set(settings) != {
        "username",
        "service_name",
        "env_file",
        "python_bin",
        "manage_dir",
        "index_dir",
    }:
        raise ValueError("invalid reindex settings")
    for name in ("username", "service_name"):
        if not isinstance(settings[name], str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", settings[name]):
            raise ValueError("invalid reindex identity")
        if settings[name] == "root":
            raise ValueError("reindex requires a non-root identity")
    for name in ("env_file", "python_bin", "manage_dir", "index_dir"):
        value = settings[name]
        if not isinstance(value, str) or not re.fullmatch(r"(?:/[A-Za-z0-9_.+-]+)+", value):
            raise ValueError("invalid reindex path")
        if any(part in {".", ".."} for part in value.split("/")[1:]):
            raise ValueError("invalid reindex path")
    if not settings["index_dir"].endswith("/data/index"):
        raise ValueError("invalid configured index directory")
    return tuple(
        settings["service_name"] + suffix + ".service" for suffix in ("", "-worker", "-scheduler", "-consumer")
    )


# This child runs as the configured service user, after all units stop. Only the
# absent leaf may be created. Every existing ancestor and the leaf are opened
# without following links; no parent creation, chown, chmod or existing-dir touch.
# This does not claim to pin upstream's subsequent index traversal against a
# concurrent same-user application writer; the configured units are stopped.
PREPARE_AND_REINDEX = """import os
import sys


def ensure_index(path):
    parts = path.split('/')
    if parts[0] != '' or parts[-2:] != ['data', 'index'] or any(part in ('', '.', '..') for part in parts[1:]):
        raise ValueError('invalid index path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open('/', flags)
    try:
        for part in parts[1:-1]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        try:
            leaf = os.open('index', flags, dir_fd=parent)
        except FileNotFoundError:
            try:
                os.mkdir('index', mode=0o755, dir_fd=parent)
            except FileExistsError:
                pass
            leaf = os.open('index', flags, dir_fd=parent)
        os.close(leaf)
    finally:
        os.close(parent)


if __name__ == '__main__':
    ensure_index(sys.argv[1])
    os.execv(sys.executable, [sys.executable, 'manage.py', 'document_index', 'reindex'])
"""


def call(argv, *, capture=False, cwd=None):
    return subprocess.run(
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )


def reindex(settings):
    units = validate(settings)
    running = []
    for unit in units:
        result = call(["systemctl", "show", "--property=ActiveState", "--value", unit], capture=True)
        state = result.stdout.strip()
        if result.returncode or state not in {"active", "inactive", "failed"}:
            raise ReindexFailure("cannot establish stable pre-reindex service state")
        if state == "active":
            running.append(unit)
    primary_failure = None
    resume_failed = False
    try:
        for unit in units:
            result = call(["systemctl", "stop", unit])
            if result.returncode:
                raise ReindexFailure("could not stop a configured Paperless unit")
        script = (
            "set -a; . "
            + shlex.quote(settings["env_file"])
            + "; set +a; exec "
            + shlex.join([settings["python_bin"], "-c", PREPARE_AND_REINDEX, settings["index_dir"]])
        )
        result = call(
            ["runuser", "-u", settings["username"], "--", "bash", "-euc", script],
            cwd=settings["manage_dir"],
        )
        if result.returncode:
            raise ReindexFailure("Paperless reindex failed; application output suppressed")
    except BaseException as error:
        # Preserve the original failure while still attempting every resume.
        primary_failure = error
    finally:
        for unit in running:
            try:
                if call(["systemctl", "start", unit]).returncode:
                    resume_failed = True
            except OSError:
                resume_failed = True
    if primary_failure is not None:
        if resume_failed:
            raise ReindexFailure(
                "reindex failed and at least one previous service could not resume"
            ) from primary_failure
        raise primary_failure
    if resume_failed:
        raise ReindexFailure("reindex completed but at least one previous service could not resume")
    return {"reindexed": True, "resumed_units": len(running)}


def main():
    try:
        payload = sys.stdin.buffer.read(65537)
        if len(payload) > 65536:
            raise ValueError("reindex settings exceed size limit")
        result = reindex(json.loads(payload))
    except (ValueError, OSError, ReindexFailure):
        # Neither exceptions nor captured command output may expose documents,
        # environment values or credentials to deployment logs.
        print("Paperless managed reindex failed; inspect service status locally", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
