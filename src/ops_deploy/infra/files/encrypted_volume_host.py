# Host side of ops_deploy.infra.encrypted_volume (python3 -I -B, standard library only).
#
#   encrypted_volume_host.py check|apply <config as base64 JSON>
#
# check is read-only: it identifies the device with blkid -p, lsblk and findmnt
# (no cryptsetup call, so no LUKS lock file either) and prints
#   pending=<comma separated steps>
#   changed=false | changed=true
# or, for a state it never touches, one line "refused: <reason>" (exit 0).
# apply re-runs the same admission, then opens the mapper when it is closed,
# writes the crypttab line and the fstab entry when they differ, mounts the
# volume when it is not mounted and remounts it only when an existing fstab
# entry was rewritten (an added entry leaves the mount as it is); it ends with the check output of the result. It never formats,
# closes, unmounts or switches the device path. The config carries no secret:
# the passphrase reaches the host only as the keyfile (secret_file).
import base64
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

CRYPTTAB = "/etc/crypttab"
FSTAB = "/etc/fstab"


class Refused(Exception):
    pass


def run(argv, check=True):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if check and result.returncode != 0:
        raise RuntimeError("%s failed (%d): %s" % (argv[0], result.returncode, result.stderr.strip()))
    return result


def blkid(device):
    """Low-level probe of ``device`` (``blkid -p``, no cache): {} when it has no signature."""

    result = run(["blkid", "-p", "-o", "export", device], check=False)
    if result.returncode == 2:
        return {}
    if result.returncode != 0:
        raise RuntimeError("blkid -p %s failed (%d): %s" % (device, result.returncode, result.stderr.strip()))
    values = {}
    for line in result.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key] = value
    return values


def device_path(name):
    return name if name.startswith("/") else "/dev/" + name


def block_devices():
    """``lsblk -nr -p -o NAME,TYPE,PKNAME``: name -> (type, parent), parents as full paths."""

    devices = {}
    for line in run(["lsblk", "-nr", "-p", "-o", "NAME,TYPE,PKNAME"]).stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        parts += ["", ""]
        devices[parts[0]] = (parts[1], device_path(parts[2]) if parts[2] else "")
    return devices


def mounted(mount_point):
    """(source, options) mounted exactly at ``mount_point``, or None."""

    result = run(["findmnt", "-n", "-r", "-o", "SOURCE,OPTIONS", "--mountpoint", mount_point], check=False)
    if result.returncode == 1 and not result.stdout.strip():
        return None
    if result.returncode != 0:
        raise RuntimeError("findmnt %s failed (%d)" % (mount_point, result.returncode))
    lines = result.stdout.splitlines()
    if len(lines) != 1:
        raise Refused("%s has %d stacked mounts" % (mount_point, len(lines)))
    source, _, options = lines[0].partition(" ")
    return source, options


def read_text(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError:
        return None


def crypttab_update(text, line, name):
    """lineinfile with ``regexp`` "line start, <name>, whitespace": the new text, or None when unchanged.

    The last matching line is replaced; without a match the line is appended
    (after a newline when the file does not end with one); a missing file gets
    just the line.
    """

    lines = (text or "").splitlines(keepends=True)
    pattern = re.compile("^" + re.escape(name) + r"\s")
    index = -1
    for number, current in enumerate(lines):
        if pattern.search(current):
            index = number
    wanted = line + "\n"
    if index >= 0:
        if lines[index] == wanted:
            return None
        lines[index] = wanted
    else:
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines.append("\n")
        lines.append(wanted)
    return "".join(lines)


def fstab_update(text, entry):
    """ansible.posix.mount's fstab edit for ``entry``: (new text or None, matching lines).

    Lines are matched by their second field (Linux: 4 to 6 fields, comments and
    blank lines kept). A matching line that differs in source, type, options,
    dump or passno (a missing dump/passno counts as different, as there) is
    rewritten as ``src name fstype opts dump passno``; without a match the
    entry is appended. A final line without a newline gets one when the file is
    rewritten.
    """

    out = []
    matches = 0
    changed = False
    keys = ("src", "name", "fstype", "opts", "dump", "passno")
    for line in (text or "").splitlines(keepends=True):
        if not line.endswith("\n"):
            line += "\n"
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out.append(line)
            continue
        fields = line.split("#")[0].split()
        if len(fields) not in (4, 5, 6) or fields[1] != entry["name"]:
            out.append(line)
            continue
        matches += 1
        current = dict(zip(keys, fields))
        for key in ("src", "fstype", "opts", "dump", "passno"):
            if current.get(key) != entry[key]:
                changed = True
        out.append(" ".join(entry[key] for key in keys) + "\n" if changed else line)
    if not matches:
        out.append(" ".join(entry[key] for key in keys) + "\n")
        changed = True
    return ("".join(out) if changed else None), matches


def admit(cfg):
    """Read-only state; raises Refused for anything the deploy never touches."""

    device = cfg["device"]
    try:
        info = os.stat(device)
    except FileNotFoundError:
        raise Refused("device %s is missing" % device) from None
    if not stat.S_ISBLK(info.st_mode):
        raise Refused("%s is not a block device" % device)
    real = os.path.realpath(device)
    luks = blkid(real)
    if luks.get("TYPE") != "crypto_LUKS":
        raise Refused("%s is not a LUKS container" % real)
    if luks.get("UUID", "") != cfg["expected_uuid"]:
        raise Refused("LUKS UUID mismatch: expected %s, found %s" % (cfg["expected_uuid"], luks.get("UUID", "")))

    mapper = "/dev/mapper/" + cfg["mapper_name"]
    devices = block_devices()
    conflicting = sorted(
        name for name, (kind, parent) in devices.items() if kind == "crypt" and parent == real and name != mapper
    )
    if conflicting:
        raise Refused("%s is already mapped as %s" % (real, ", ".join(conflicting)))
    active = mapper in devices
    if active:
        kind, parent = devices[mapper]
        if kind != "crypt":
            raise Refused("%s exists and is not a crypt mapping" % mapper)
        if parent != real:
            raise Refused("%s is open on %s, not on %s" % (mapper, parent or "an unknown device", real))
    elif os.path.exists(mapper):
        raise Refused("%s exists but lsblk does not list it" % mapper)

    state = {"real": real, "mapper": mapper, "active": active, "pending": [], "crypttab": None, "fstab": None}
    keyfile = cfg["keyfile"]
    line = "%s %s %s %s" % (cfg["mapper_name"], real, keyfile, cfg["crypttab_options"])
    state["crypttab"] = crypttab_update(read_text(CRYPTTAB), line, cfg["mapper_name"])
    if state["crypttab"] is not None:
        state["pending"].append("crypttab")

    fstab_text = read_text(FSTAB)
    probe = {"src": "", "name": cfg["mount_point"], "fstype": "", "opts": "", "dump": "", "passno": ""}
    _, entries = fstab_update(fstab_text, probe)
    if entries > 1:
        raise Refused("%s has %d entries for %s" % (FSTAB, entries, cfg["mount_point"]))
    current = mounted(cfg["mount_point"])
    if not active:
        if current is not None:
            raise Refused("%s is mounted from %s while %s is closed" % (cfg["mount_point"], current[0], mapper))
        state["pending"] += ["open", "mount"]
        return state

    fs = blkid(mapper)
    if not fs.get("TYPE"):
        raise Refused("%s has no filesystem; this deploy never formats" % mapper)
    if fs["TYPE"] != cfg["fs_type"]:
        raise Refused("%s holds %s, the config says %s" % (mapper, fs["TYPE"], cfg["fs_type"]))
    entry = {
        "src": "UUID=" + fs["UUID"] if fs.get("UUID") else mapper,
        "name": cfg["mount_point"],
        "fstype": cfg["fs_type"],
        "opts": cfg["mount_opts"],
        "dump": cfg["dump"],
        "passno": cfg["passno"],
    }
    state["fstab"], matches = fstab_update(fstab_text, entry)
    if state["fstab"] is not None:
        state["pending"].append("fstab")
    if current is None:
        state["pending"].append("mount")
    else:
        source, options = current
        if os.path.realpath(source) != os.path.realpath(mapper):
            raise Refused("%s is mounted from %s, not %s" % (cfg["mount_point"], source, mapper))
        if "ro" in options.split(","):
            raise Refused("%s is mounted read-only" % cfg["mount_point"])
        if state["fstab"] is not None and matches:
            # A rewritten entry takes effect now; an added one records the mount as it is.
            state["pending"].append("remount")
    return state


def write_atomic(path, text, mode):
    """Replace ``path`` by a sibling temp file; keeps an existing file's owner and mode."""

    try:
        info = os.stat(path)
        mode, uid, gid = stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid
    except FileNotFoundError:
        uid = gid = 0
    directory = os.path.dirname(path)
    fd, temp = tempfile.mkstemp(prefix=".ops-deploy-" + os.path.basename(path) + ".", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            os.fchown(handle.fileno(), uid, gid)
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        if os.path.lexists(temp):
            os.unlink(temp)
        raise


def apply(cfg):
    state = admit(cfg)
    if not state["active"]:
        if not shutil.which("cryptsetup"):
            raise Refused("cryptsetup is not installed")
        keyfile = cfg["keyfile"]
        try:
            info = os.lstat(keyfile)
        except FileNotFoundError:
            raise Refused("keyfile %s is missing" % keyfile) from None
        if not stat.S_ISREG(info.st_mode):
            raise Refused("keyfile %s is not a regular file" % keyfile)
        run(["cryptsetup", "open", state["real"], cfg["mapper_name"], "--key-file", keyfile])
        if shutil.which("udevadm"):
            run(["udevadm", "settle"], check=False)
        state = admit(cfg)
        if not state["active"]:
            raise RuntimeError("%s did not appear after cryptsetup open" % state["mapper"])
    if state["crypttab"] is not None:
        write_atomic(CRYPTTAB, state["crypttab"], 0o640)
    if state["fstab"] is not None:
        write_atomic(FSTAB, state["fstab"], 0o644)
    if "mount" in state["pending"]:
        run(["mount", cfg["mount_point"]])
    elif "remount" in state["pending"]:
        # Options take effect without an unmount; a failure fails the deploy.
        run(["mount", "-o", "remount", cfg["mount_point"]])
    return admit(cfg)


def report(state):
    print("pending=" + ",".join(state["pending"]))
    print("changed=" + ("true" if state["pending"] else "false"))


def main(argv):
    if len(argv) != 3 or argv[1] not in ("check", "apply"):
        sys.stderr.write("usage: encrypted_volume_host.py check|apply <config>\n")
        return 2
    cfg = json.loads(base64.b64decode(argv[2]).decode("utf-8"))
    try:
        state = admit(cfg) if argv[1] == "check" else apply(cfg)
    except Refused as exc:
        if argv[1] == "apply":
            sys.stderr.write("refused: %s\n" % exc)
            return 1
        print("refused: %s" % exc)
        return 0
    report(state)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
