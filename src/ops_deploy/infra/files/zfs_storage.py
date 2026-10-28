"""Bounded native pool/dataset reconciliation; key material is stdin/RAM only.

No destroy, import/export, unload-key, change-key, snapshot, scrub or data walk.
"""

import grp
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from decimal import Decimal
from pathlib import Path

SIZE_KEYS = {
    "quota",
    "refquota",
    "reservation",
    "refreservation",
    "recordsize",
    "volblocksize",
    "volsize",
    "special_small_blocks",
}
SIZE_RE = re.compile(r"^([0-9]+(?:[.][0-9]+)?)[ ]*([KMGTPEZ]?)(?:I?B)?$", re.I)
POWERS = {u: i for i, u in enumerate(" KMGTPEZ")}
POWERS[""] = 0
VDEV_WORDS = {"mirror", "raidz", "raidz1", "raidz2", "raidz3", "spare", "log", "cache"}


class Refused(Exception):
    pass


def run(argv, material=None):
    result = subprocess.run(argv, input=material, capture_output=True, timeout=90, env={**os.environ, "LC_ALL": "C"})
    if result.returncode:
        raise Refused("native ZFS command failed; no command/key/output export")
    return result.stdout.decode("utf-8")


def identity(value, dataset=False):
    pattern = r"[A-Za-z][A-Za-z0-9_.:-]*(/[A-Za-z0-9_][A-Za-z0-9_.:-]*)+" if dataset else r"[A-Za-z][A-Za-z0-9_.:-]*"
    if (
        not isinstance(value, str)
        or not re.fullmatch(pattern, value)
        or any(p in {".", ".."} for p in value.split("/"))
    ):
        raise Refused("invalid storage identity")
    return value


def exists(kind, name):
    argv = [kind, "list", "-H", "-o", "name", name]
    p = subprocess.run(argv, capture_output=True, timeout=30, env={**os.environ, "LC_ALL": "C"})
    if p.returncode == 0:
        if p.stdout.decode().strip() != name:
            raise Refused("unexpected native storage identity")
        return True
    error = p.stderr.decode("utf-8", "replace")
    absent = (
        ("cannot open '" + name + "': no such pool")
        if kind == "zpool"
        else ("cannot open '" + name + "': dataset does not exist")
    )
    if p.returncode == 1 and error.strip() == absent:
        return False
    raise Refused("unknown storage absence/tool/permission/I/O error")


def properties(kind, name, keys):
    names = sorted(set(keys))
    if not names:
        return {}
    if any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]*", key) for key in names):
        raise Refused("invalid property name")
    text = run([kind, "get", "-H", "-p", "-o", "property,value", ",".join(names), name])
    value = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or fields[0] in value or fields[0] not in names:
            raise Refused("unexpected native property response")
        value[fields[0]] = fields[1]
    if set(value) != set(names):
        raise Refused("incomplete native property response")
    return value


def compare(key, value):
    text = str(value)
    if key in SIZE_KEYS:
        if text.lower() == "none":
            return "0"
        found = SIZE_RE.fullmatch(text)
        if found:
            return str(int(Decimal(found[1]) * 1024 ** POWERS[found[2].upper()]))
    return text


def path(value, optional=False):
    p = Path(value)
    if not p.is_absolute() or str(p) != os.path.normpath(str(p)) or ".." in p.parts:
        raise Refused("invalid managed storage path")
    for part in [*reversed(p.parents), p]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            if optional:
                return p, None
            raise Refused("required managed path absent") from None
        if stat.S_ISLNK(info.st_mode):
            raise Refused("managed key path/ancestor is linked")
    return p, info


def key_bytes(v):
    value = v.get("credential")
    if not isinstance(value, str) or not value or value == "CHANGEME":
        raise Refused("native encryption requires a non-placeholder source key")
    raw = value.encode("utf-8")
    if v["keyformat"] == "raw":
        if len(raw) != 32:
            raise Refused("raw native encryption key must be exactly32 source bytes")
    elif not 8 <= len(raw.split(b"\n", 1)[0]) <= 512 or b"\0" in raw:
        raise Refused("invalid native passphrase")
    return raw


def verify_key(v):
    # OpenZFS2.2.2 owned loaded/unloaded correct/wrong native proof: no key-state mutation.
    raw = key_bytes(v)
    data = raw + (b"\n" if v["keyformat"] == "passphrase" else b"")
    run(["zfs", "load-key", "-n", "-L", "file:///dev/stdin", v["name"]], data)


def key_file(v):
    p, info = path(v["keyfile_path"], True)
    if info is None:
        return False, False
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096:
        raise Refused("invalid existing key file metadata")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        current = os.fstat(fd)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise Refused("key path changed")
        content = os.read(fd, 4097)
        return content == key_bytes(v), (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (
            0,
            grp.getgrnam(v["keyfile_group"]).gr_gid,
            0o400,
        )
    finally:
        os.close(fd)


def key_current(v):
    content, metadata = key_file(v)
    _parent, info = path(str(Path(v["keyfile_path"]).parent), True)
    return bool(
        content
        and metadata
        and info is not None
        and stat.S_ISDIR(info.st_mode)
        and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o700)
    )


def publish_key(v):
    target, _info = path(v["keyfile_path"], True)
    parent = target.parent
    # Parent path admission precedes mkdir/chmod; preserve original0700 directory policy.
    path(str(parent), True)
    parent.mkdir(parents=True, exist_ok=True)
    os.chown(parent, 0, 0)
    os.chmod(parent, 0o700)
    content, _metadata = key_file(v)
    if content:
        # Preserve the existing inode/body when only declared ownership/mode drifted.
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fchmod(fd, 0o400)
            os.fchown(fd, 0, grp.getgrnam(v["keyfile_group"]).gr_gid)
        finally:
            os.close(fd)
        return
    fd, temporary = tempfile.mkstemp(prefix=".zfs-key-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(key_bytes(v))
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o400)
            os.fchown(stream.fileno(), 0, grp.getgrnam(v["keyfile_group"]).gr_gid)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def create_pool(v, dry=False):
    argv = ["zpool", "create"] + (["-n"] if dry else []) + (["-f"] if v["force_create"] else [])
    argv += ["-o", "ashift=" + str(v["ashift"]), "-o", "autotrim=" + ("on" if v["autotrim"] else "off")]
    for key, value in v["properties"].items():
        argv += ["-o", key + "=" + str(value)]
    argv += ["-O", "mountpoint=" + v["mountpoint"]]
    if v["encryption_enabled"]:
        location = (
            "file:///dev/stdin"
            if dry
            else (Path(v["keyfile_path"]).as_uri() if v["keylocation_type"] == "file" else "prompt")
        )
        argv += [
            "-O",
            "encryption=" + v["encryption_algorithm"],
            "-O",
            "keyformat=" + v["keyformat"],
            "-O",
            "keylocation=" + location,
        ]
    for key, value in v["filesystem_properties"].items():
        argv += ["-O", key + "=" + str(value)]
    argv += [v["name"], *v["vdevs"]]
    material = key_bytes(v) + (b"\n" if v["keyformat"] == "passphrase" else b"") if v["encryption_enabled"] else None
    run(argv, material)


def prerequisite(packages):
    if not shutil.which("zpool") or not shutil.which("zfs"):
        package = subprocess.run(
            ["dpkg-query", "-W", "-f=${db:Status-Status}\n", *packages], capture_output=True, timeout=15
        )
        if (
            package.returncode == 0
            and package.stdout.splitlines()
            and all(status == b"installed" for status in package.stdout.splitlines())
        ):
            raise Refused("installed native storage tools unavailable")
        if package.returncode not in (0, 1):
            raise Refused("unknown native prerequisite state")
        return "native packages"
    try:
        Path("/sys/module/zfs").stat()
    except FileNotFoundError:
        return "native module"
    return None


def pool_state(v):
    identity(v["name"])
    pending_prerequisite = prerequisite(v["packages"])
    if pending_prerequisite:
        return {"pending": True, "present": None, "deferred_prerequisite": pending_prerequisite}
    if not v["allow_create"] and not v["validate_only"]:
        raise Refused("original explicit pool allow_create flag missing")
    for device in [p for p in v["vdevs"] if p not in VDEV_WORDS]:
        info = os.stat(device)
        if not (stat.S_ISBLK(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise Refused("declared vdev is not block device/owned file")
    present = exists("zpool", v["name"])
    if not present:
        if v["validate_only"]:
            return {"pending": False, "present": False}
        create_pool(v, True)  # native no-write label/topology admission before any key publication.
        return {"pending": True, "present": False}
    pkeys = ["autotrim", *v["properties"]]
    pool = properties("zpool", v["name"], pkeys)
    root = properties(
        "zfs",
        v["name"],
        [*v["filesystem_properties"], "encryption", "encryptionroot", "keyformat", "keylocation", "keystatus"],
    )
    key_pending = False
    if v["encryption_enabled"]:
        if root["encryption"] == "off" or root["encryptionroot"] != v["name"] or root["keyformat"] != v["keyformat"]:
            raise Refused("existing encryption identity does not match declared source")
        verify_key(v)  # Even a loaded root validates desired source material, no change-key/unload/load.
        if v["keylocation_type"] == "file":
            key_pending = not key_current(v)
    pending = key_pending or pool["autotrim"] != ("on" if v["autotrim"] else "off")
    pending |= any(pool[k] != str(value) for k, value in v["properties"].items())
    pending |= any(
        (k == "refreservation" and str(value).lower() == "auto") or root[k] != compare(k, value)
        for k, value in v["filesystem_properties"].items()
    )
    return {"pending": bool(pending and not v["validate_only"]), "present": True}


def pool_apply(v):
    state = pool_state(v)
    if state.get("deferred_prerequisite"):
        raise Refused("native prerequisites still unavailable before storage writes")
    if v["validate_only"]:
        return
    if v["encryption_enabled"] and v["keylocation_type"] == "file" and not key_current(v):
        publish_key(v)
    if not state["present"]:
        create_pool(v)
    desired = {"autotrim": "on" if v["autotrim"] else "off", **v["properties"]}
    current = properties("zpool", v["name"], desired)
    for key, value in desired.items():
        if current[key] != str(value):
            run(["zpool", "set", key + "=" + str(value), v["name"]])
    desired = v["filesystem_properties"]
    current = properties("zfs", v["name"], desired)
    for key, value in desired.items():
        if (key == "refreservation" and str(value).lower() == "auto") or current[key] != compare(key, value):
            run(["zfs", "set", key + "=" + str(value), v["name"]])


def dataset_state(v, planning=True):
    identity(v["name"], True)
    parent = v["name"].split("/")[0]
    declared = v.get("planned_parent") == parent
    missing = prerequisite(v.get("parent_packages", ["zfsutils-linux"]))
    if missing:
        if planning and declared:
            return {"pending": True, "present": None, "deferred_prerequisite": missing}
        raise Refused("native dataset prerequisites unavailable")
    if not exists("zpool", parent):
        if planning and declared:
            return {"pending": True, "present": None, "deferred_prerequisite": "declared parent pool creation"}
        raise Refused("parent pool absent; create via explicit pool deployment first")
    present = exists("zfs", v["name"])
    if not present:
        return {"pending": not v["validate_only"], "present": False, "casesensitivity_mismatch": False}
    desired = {k: value for k, value in v["effective_properties"].items() if k != "casesensitivity"}
    current = properties("zfs", v["name"], [*desired, "casesensitivity", "mountpoint", "mounted"])
    pending = any(
        (k == "refreservation" and str(value).lower() == "auto") or current[k] != compare(k, value)
        for k, value in desired.items()
    )
    pending |= bool(v["mountpoint"] and current["mountpoint"] != v["mountpoint"]) or bool(
        v["mounted"] and current["mounted"] == "no"
    )
    return {
        "pending": bool(pending and not v["validate_only"]),
        "present": True,
        "casesensitivity_mismatch": bool(v["macos_compat"] and current["casesensitivity"] != "mixed"),
    }


def dataset_apply(v):
    state = dataset_state(v, planning=False)
    if v["validate_only"]:
        return
    desired = {k: value for k, value in v["effective_properties"].items() if k != "casesensitivity"}
    if not state["present"]:
        argv = ["zfs", "create"]
        if v["mountpoint"]:
            argv += ["-o", "mountpoint=" + v["mountpoint"]]
        if v["macos_compat"]:
            argv += ["-o", "casesensitivity=mixed"]
        for key, value in desired.items():
            argv += ["-o", key + "=" + str(value)]
        run([*argv, v["name"]])  # No -p, -u or encryption=off behavior not present in original role.
    current = properties("zfs", v["name"], [*desired, "mountpoint", "mounted"])
    for key, value in desired.items():
        if (key == "refreservation" and str(value).lower() == "auto") or current[key] != compare(key, value):
            run(["zfs", "set", key + "=" + str(value), v["name"]])
    if v["mountpoint"] and current["mountpoint"] != v["mountpoint"]:
        run(["zfs", "set", "mountpoint=" + v["mountpoint"], v["name"]])
    if v["mounted"] and current["mounted"] == "no":
        run(["zfs", "mount", v["name"]])


def main():
    if os.geteuid() != 0:
        raise Refused("native storage deployment requires existing root identity")
    action = sys.argv[1]
    v = json.load(sys.stdin)
    if action == "module-check":
        try:
            Path("/sys/module/zfs").stat()
            print("current")
        except FileNotFoundError:
            print("pending")
    elif action == "pool-check":
        print(json.dumps(pool_state(v)))
    elif action == "pool-apply":
        pool_apply(v)
        print("current")
    elif action == "dataset-check":
        print(json.dumps(dataset_state(v)))
    elif action == "dataset-apply":
        dataset_apply(v)
        print("current")
    elif action == "verify":
        for item in v["pools"]:
            selected = {
                **item,
                "filesystem_properties": {
                    k: x
                    for k, x in item["filesystem_properties"].items()
                    if not (k == "refreservation" and str(x).lower() == "auto")
                },
            }
            if pool_state(selected)["pending"]:
                raise Refused("declared pool remains pending")
        for item in v["datasets"]:
            selected = {
                **item,
                "effective_properties": {
                    k: x
                    for k, x in item["effective_properties"].items()
                    if not (k == "refreservation" and str(x).lower() == "auto")
                },
            }
            if dataset_state(selected, planning=False)["pending"]:
                raise Refused("declared dataset remains pending")
        print("current")
    else:
        raise Refused("unknown storage action")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Native storage state/refusal failed; key material and command output suppressed", file=sys.stderr)
        raise SystemExit(2) from None
