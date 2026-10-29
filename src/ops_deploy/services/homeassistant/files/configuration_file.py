"""Host-local original template/replace filesystem behavior over protected stdin.

No current/rendered body, body digest, backup name or exception text is emitted.
A failed write can already have created a backup or replaced bytes; fixed effect
flags preserve that distinction. This helper is not a complete HA deployment.
"""

from __future__ import annotations

import errno
import grp
import json
import os
import pwd
import re
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


def _backup(path: Path) -> None:
    destination = str(path) + f".{os.getpid()}." + time.strftime("%Y-%m-%d@%H:%M:%S~")
    shutil.copy2(path, destination)
    source = path.stat()
    copied = os.stat(destination)
    if (copied.st_uid, copied.st_gid) != (source.st_uid, source.st_gid):
        try:
            os.chown(destination, source.st_uid, source.st_gid)
        except OSError as error:
            if error.errno != errno.EPERM:
                raise


def process(payload: dict[str, Any], effects: dict[str, bool]) -> None:
    """Check or apply exactly one original template/replace task.

    One process per task retains the original PID/time-based backup convention.
    Template replaces a leaf symlink; replace follows it. Ancestor links retain
    normal filesystem behavior, as in the original modules. No parents are made.
    """
    kind, action = payload["kind"], payload["action"]
    if kind not in {"template", "replace"} or action not in {"check", "apply"}:
        raise ValueError("unsupported configuration action")
    path = Path(payload["path"])
    link = path.is_symlink()
    try:
        current = path.read_bytes()
        previous = path.stat()
    except FileNotFoundError:
        if kind == "replace":
            raise
        current, previous = None, None
    if kind == "template":
        desired = payload["content"].encode("utf-8")
        uid = pwd.getpwnam(payload["user"]).pw_uid
        gid = grp.getgrnam(payload["group"]).gr_gid
        mode = int(payload["mode"], 8)
        body_change = current != desired or link
        metadata_change = previous is None or (previous.st_uid, previous.st_gid, stat.S_IMODE(previous.st_mode)) != (
            uid,
            gid,
            mode,
        )
        destination = path
    else:
        assert current is not None and previous is not None
        content = current.decode("utf-8", errors="surrogateescape")
        desired = re.sub(payload["pattern"], "", content, flags=re.MULTILINE).encode("utf-8", errors="surrogateescape")
        body_change = desired != current
        metadata_change = False
        uid, gid, mode = previous.st_uid, previous.st_gid, stat.S_IMODE(previous.st_mode)
        destination = Path(os.path.realpath(path))
    effects["changed"] = body_change or metadata_change
    if action == "check" or not effects["changed"]:
        return
    # Any later error may follow a partial backup/metadata syscall. Keep this
    # separate from completed effects; a failed operation is never zero-effect
    # merely because its completion flags are still false.
    effects["effects_started"] = True
    if body_change:
        if previous is not None:
            _backup(path)
            effects["backup_created"] = True
        descriptor, temporary = tempfile.mkstemp(prefix=".ops-ha-config-", dir=destination.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(desired)
            # Original atomic_move keeps current regular-file attributes, then
            # updates write timestamps. Template's replaced leaf link does not
            # import its target's attributes into the new configuration file.
            if previous is not None and (kind == "replace" or not link):
                try:
                    os.chown(temporary, previous.st_uid, previous.st_gid)
                    shutil.copystat(destination, temporary)
                    os.utime(temporary, None)
                except OSError as error:
                    if error.errno != errno.EPERM:
                        raise
            os.replace(temporary, destination)
            effects["body_written"] = True
        finally:
            if os.path.lexists(temporary):
                os.unlink(temporary)
    # Original replace has no explicit owner/group/mode arguments. Its
    # atomic_move attribute copy is best effort for EPERM; do not turn it into
    # a second mandatory repair after the content has been replaced.
    if kind == "replace":
        return
    actual = destination.stat()
    if (actual.st_uid, actual.st_gid) != (uid, gid):
        os.chown(destination, uid, gid)
        effects["metadata_written"] = True
    if stat.S_IMODE(destination.stat().st_mode) != mode:
        os.chmod(destination, mode)
        effects["metadata_written"] = True


def main() -> None:
    effects = {
        "changed": False,
        "effects_started": False,
        "backup_created": False,
        "body_written": False,
        "metadata_written": False,
    }
    try:
        payload = json.load(sys.stdin)
        process(payload, effects)
    except Exception as error:
        print(json.dumps({"success": False, "error": type(error).__name__, **effects}))
        raise SystemExit(1) from None
    print(json.dumps({"success": True, **effects}))


if __name__ == "__main__":
    main()
