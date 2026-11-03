"""Pinned GPS Timeline integration and Location Timeline Card, run on the host.

Reads one JSON payload on stdin and prints one JSON report
(``success``, ``changed``, and ``error`` on failure). ``action`` is ``check``
(read only) or ``apply``; ``kind`` is ``component`` (a custom integration from a
release archive) or ``file`` (one pinned file, the card).

Every download lands in a temporary file next to its destination and replaces
it only after the sha256 matches. A component is extracted into a staging
directory and swapped in whole; only that component directory, its archive and
the card file are ever replaced. The integration's data directory
(``config/gps_timeline``) is never touched. Errors print no URL.
"""

import grp
import hashlib
import json
import os
import pwd
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request

STAMP = ".ops-pinned-version"


def checksum(path):
    try:
        with open(path, "rb") as handle:
            digest = hashlib.sha256()
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
            return digest.hexdigest()
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        return None


def account(payload):
    """(uid, gid) of the service account, or None while it does not exist yet."""
    try:
        return pwd.getpwnam(payload["user"]).pw_uid, grp.getgrnam(payload["group"]).gr_gid
    except KeyError:
        return None


def metadata_current(path, ids, mode):
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        return False
    return (
        ids is not None
        and stat.S_ISREG(current.st_mode)
        and (current.st_uid, current.st_gid) == ids
        and stat.S_IMODE(current.st_mode) == mode
    )


def set_metadata(path, ids, mode):
    current = os.lstat(path)
    changed = False
    if (current.st_uid, current.st_gid) != ids:
        os.lchown(path, *ids)
        changed = True
    if stat.S_IMODE(current.st_mode) != mode:
        os.chmod(path, mode)
        changed = True
    return changed


def fetch(url, dest, wanted, ids):
    """Make ``dest`` the verified pinned file; True when anything changed."""
    if checksum(dest) == wanted and not os.path.islink(dest):
        return set_metadata(dest, ids, 0o644)
    descriptor, temporary = tempfile.mkstemp(prefix=".ops-ha-", dir=os.path.dirname(dest))
    try:
        with os.fdopen(descriptor, "wb") as output:
            request = urllib.request.Request(url, headers={"User-Agent": "ops-deploy"})
            with urllib.request.urlopen(request, timeout=60) as response:
                shutil.copyfileobj(response, output)
        if checksum(temporary) != wanted:
            raise ValueError("checksum mismatch")
        os.chown(temporary, *ids)
        os.chmod(temporary, 0o644)
        os.replace(temporary, dest)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)
    return True


def expected_stamp(payload):
    return payload["version"] + " " + payload["sha256"]


def component_current(payload):
    component = payload["component"]
    if os.path.islink(component) or not os.path.isdir(component):
        return False
    try:
        with open(os.path.join(component, STAMP), encoding="utf-8") as handle:
            return handle.read().strip() == expected_stamp(payload)
    except (OSError, UnicodeError):
        return False


def extract(archive, member, target):
    """Copy the regular files and directories below ``member`` into ``target``.

    Links, devices and paths that leave ``target`` refuse the archive.
    """
    prefix = member.rstrip("/") + "/"
    found = False
    with tarfile.open(archive, "r:gz") as tar:
        for entry in tar.getmembers():
            name = entry.name[2:] if entry.name.startswith("./") else entry.name
            if not name.startswith(prefix):
                continue
            relative = name[len(prefix):].rstrip("/")
            if not relative:
                continue
            parts = relative.split("/")
            if relative.startswith("/") or any(part in ("", ".", "..") for part in parts):
                raise ValueError("unsafe archive member")
            path = os.path.join(target, *parts)
            if entry.isdir():
                os.makedirs(path, mode=0o755, exist_ok=True)
            elif entry.isfile():
                os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
                source = tar.extractfile(entry)
                with source, open(path, "xb") as output:
                    shutil.copyfileobj(source, output)
                found = found or relative == "manifest.json"
            else:
                raise ValueError("unsupported archive member")
    if not found:
        raise ValueError("component manifest missing from archive")


def own_tree(root, ids):
    for current, dirs, names in os.walk(root):
        os.lchown(current, *ids)
        os.chmod(current, 0o755)
        for name in names:
            path = os.path.join(current, name)
            os.lchown(path, *ids)
            os.chmod(path, 0o644)


def install_component(payload, ids):
    fetch(payload["url"], payload["archive"], payload["sha256"], ids)
    parent, component = payload["parent"], payload["component"]
    # Dot names are no Python package names: Home Assistant never loads them.
    staging = tempfile.mkdtemp(prefix=".ops-ha-new-", dir=parent)
    retired = None
    try:
        extract(payload["archive"], payload["member"], staging)
        with open(os.path.join(staging, STAMP), "w", encoding="utf-8") as handle:
            handle.write(expected_stamp(payload) + "\n")
        own_tree(staging, ids)
        if os.path.islink(component) or os.path.isfile(component):
            os.unlink(component)
        elif os.path.isdir(component):
            reserved = tempfile.mkdtemp(prefix=".ops-ha-old-", dir=parent)
            try:
                os.rename(component, reserved)
            except OSError:
                os.rmdir(reserved)
                raise
            retired = reserved
        try:
            os.rename(staging, component)
        except OSError:
            # Put the working version back. Should that fail too, the retired
            # copy stays (a dot name Home Assistant ignores) for recovery.
            if retired is not None and not os.path.lexists(component):
                os.rename(retired, component)
            raise
        staging = None
        if retired is not None:
            shutil.rmtree(retired)
    finally:
        if staging is not None and os.path.isdir(staging):
            shutil.rmtree(staging)


def run(payload):
    report = {"success": False, "changed": False}
    try:
        action, kind = payload["action"], payload["kind"]
        if action not in ("check", "apply") or kind not in ("component", "file"):
            raise ValueError("unknown action")
        ids = account(payload)
        if kind == "component":
            current = component_current(payload)
        else:
            current = (
                os.path.isdir(os.path.dirname(payload["dest"]))
                and checksum(payload["dest"]) == payload["sha256"]
                and metadata_current(payload["dest"], ids, 0o644)
            )
        if action == "check" or current:
            report["changed"] = not current
        elif ids is None:
            raise KeyError("service account missing")
        elif kind == "component":
            install_component(payload, ids)
            report["changed"] = True
        else:
            report["changed"] = fetch(payload["url"], payload["dest"], payload["sha256"], ids)
        report["success"] = True
    except Exception as exc:
        report["error"] = type(exc).__name__
    return report


if __name__ == "__main__":
    value = run(json.load(sys.stdin))
    print(json.dumps(value))
    raise SystemExit(0 if value["success"] else 1)
