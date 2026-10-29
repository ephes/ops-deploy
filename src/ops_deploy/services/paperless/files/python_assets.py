"""Venv metadata ownership and the original exact OCR compatibility patch.

The traversal covers only the installed Python environment, never Paperless
media/data/consume. Symlinks are not traversed. Only differing ownership is
changed; healthy files retain inode/ctime/mtime. No paths or bodies are output.
"""

import grp
import json
import os
from pathlib import Path
import pwd
import stat
import sys
import tempfile

OLD = (
    "                warnings.filterwarnings('ignore', message=r'pikepdf.*JBIG2.*')\n"
    "                messages = pdf.check()\n"
)
NEW = (
    "                warnings.filterwarnings('ignore', message=r'pikepdf.*JBIG2.*')\n"
    "                check_fn = getattr(pdf, 'check', None)\n"
    "                if check_fn is None:\n"
    "                    log.warning('pikepdf %s lacks Pdf.check(); skipping validation step', pikepdf.__version__)\n"
    "                    return True\n"
    "                messages = check_fn()\n"
)


def ownership(root, uid, gid, apply):
    changed = False
    def refuse(error):
        raise error
    # Pin every ancestor, not only the final venv component. A service-owned
    # parent renamed during this walk cannot redirect root's ownership writes.
    rootfd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in root.parts[1:]:
            nextfd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rootfd)
            os.close(rootfd)
            rootfd = nextfd
        for _, directories, names, directory_fd in os.fwalk(".", dir_fd=rootfd, follow_symlinks=False, onerror=refuse):
            meta = os.fstat(directory_fd)
            if (meta.st_uid, meta.st_gid) != (uid, gid):
                changed = True
                if apply:
                    os.fchown(directory_fd, uid, gid)
            for name in directories + names:
                meta = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                # Actual directories are handled through their opened fd on
                # descent. A symlink receives lchown, never target ownership.
                if stat.S_ISDIR(meta.st_mode):
                    continue
                if (meta.st_uid, meta.st_gid) != (uid, gid):
                    changed = True
                    if apply:
                        os.chown(name, uid, gid, dir_fd=directory_fd, follow_symlinks=False)
    finally:
        os.close(rootfd)
    return changed


def patch_ocr(root, apply):
    target = root / "lib/python3.14/site-packages/ocrmypdf/helpers.py"
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError("OCR helper escapes the Python environment")
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8 * 1024 * 1024:
            raise ValueError("OCR helper is not a bounded regular program file")
        with os.fdopen(fd, "r", closefd=False) as stream:
            original = stream.read(8 * 1024 * 1024 + 1)
    finally:
        os.close(fd)
    updated = original.replace(OLD, NEW)
    if original == updated:
        # Like the original Ansible replace, a newer source without the old
        # block remains untouched. This is not a claim that a patch was applied.
        return False
    if not apply:
        return True
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".paperless-ocr-", dir=target.parent)
        with os.fdopen(fd, "w") as stream:
            stream.write(updated)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, metadata.st_uid, metadata.st_gid)
        os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
        current = target.lstat()
        if (current.st_ino, current.st_mtime_ns, current.st_ctime_ns) != (
            metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns
        ):
            raise ValueError("OCR helper changed during inspection")
        os.replace(temporary, target)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    return True


def reconcile(settings):
    if not isinstance(settings, dict) or set(settings) != {"venv", "username", "group", "action", "apply"}:
        raise ValueError("invalid Python assets payload")
    root = Path(settings["venv"])
    if not root.is_absolute() or root.name != ".venv" or root.is_symlink() or not root.is_dir():
        raise ValueError("Python environment is missing or unsafe")
    if type(settings["apply"]) is not bool:
        raise ValueError("invalid apply selector")
    if settings["action"] == "ownership":
        changed = ownership(root, pwd.getpwnam(settings["username"]).pw_uid,
                            grp.getgrnam(settings["group"]).gr_gid, settings["apply"])
    elif settings["action"] == "ocr":
        changed = patch_ocr(root, settings["apply"])
    else:
        raise ValueError("unknown Python asset action")
    return "changed" if changed and settings["apply"] else "pending" if changed else "current"


def main():
    try:
        body = sys.stdin.buffer.read(65537)
        if len(body) > 65536:
            raise ValueError("payload exceeds size limit")
        result = reconcile(json.loads(body))
    except (ValueError, OSError, KeyError, TypeError, RecursionError):
        print("Paperless Python assets inspection/update failed", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
