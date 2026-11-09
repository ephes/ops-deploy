"""minecraft_java_backup and minecraft_java_restore on the host; ops-library's preserver is supplied verbatim.

Run as root with one JSON payload on stdin (the RCON password of a backup
travels only there and is never printed, passed as an argument or put in an
environment). ``backup``: the archive of every world (the configured world and
each other top-level directory of the server with a ``level.dat``),
``server.properties`` and the optional player files, packed as the role's
``archive`` task packs them (paths relative to the server directory, a
world's own directory entry left out), with ``save-off``/``save-all flush``
and always ``save-on`` around it while the server runs. ``check``: the
restore's selection and every check, read only (the dry run). ``restore``:
the checks, then stop, a pre-restore copy of each world, the worlds and files
from the archive (rolled back from the copies when that fails), and a start
only when the server ran before.
"""

import grp
import gzip
import json
import os
import pwd
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time

PROPERTIES = "server.properties"
OPTIONAL_FILES = ("ops.json", "whitelist.json", "banned-ips.json", "banned-players.json")
# Backup: saves are coordinated in these states; a unit between states is refused.
RUNNING = ("active", "reloading")
TRANSITION = ("activating", "deactivating")
# Restore: the unit counts as running before the restore (it is started again after it).
WAS_RUNNING = ("active", "activating", "reloading")
STOPPED = ("inactive", "failed")
RCON_HOST = "127.0.0.1"
# RCON packet types (Source RCON protocol, as Minecraft implements it).
LOGIN, COMMAND = 3, 2
PLAN_MARKER = "MINECRAFT_RESTORE_PLAN "
# The preserver's copies (``<world>.pre-restore-<utc>-<random>``): never archived or restored as worlds.
PRE_RESTORE = ".pre-restore-"
# The owner of the backup root, the archives and the work directory (tests substitute their own account).
ROOT_UID = 0
ROOT_GID = 0


class Failure(Exception):
    """A role ``fail``/``assert``: its message ends the run."""


def preserver():
    namespace = {"__name__": "original_restore_preserve"}
    exec(compile(PRESERVE_SOURCE, "original_preserve.py", "exec"), namespace)  # noqa: F821
    return namespace


def say(message):
    print(message, flush=True)


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def identity(value, group=False):
    if value.isdecimal():
        return int(value)
    try:
        return grp.getgrnam(value).gr_gid if group else pwd.getpwnam(value).pw_uid
    except KeyError:
        raise Failure(f"{'group' if group else 'user'} {value} does not exist; deploy minecraft_java first") from None


def utc_stamp():
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


# --- shared checks -----------------------------------------------------------


def real_dir(path, what):
    """``path`` is a directory and not a link."""

    try:
        details = os.lstat(path)
    except FileNotFoundError:
        raise Failure(f"{what} not found: {path}") from None
    if not stat.S_ISDIR(details.st_mode):
        raise Failure(f"{what} is not a directory (or is a link): {path}")


def level_name(text):
    """``level-name`` of a ``server.properties`` text (Minecraft's default ``world`` without one)."""

    for line in text.splitlines():
        if line.startswith("level-name="):
            return line.split("=", 1)[1].strip()
    return "world"


def live_level_name(cfg):
    path = os.path.join(cfg["server_dir"], PROPERTIES)
    try:
        details = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(details.st_mode):
        raise Failure(f"{path} is not a regular file")
    with open(path, encoding="utf-8", errors="replace") as handle:
        return level_name(handle.read())


def require_live_world_selected(cfg):
    """The server reads the configured world: ``level-name`` of the live properties (if any) is ``world``."""

    found = live_level_name(cfg)
    if found is not None and found != cfg["world"]:
        raise Failure(
            f"{cfg['server_dir']}/{PROPERTIES} selects level-name {found!r}, not the configured world "
            f"{cfg['world']!r} (inventory pyinfra_minecraft_java_world_name); refusing to touch the wrong world"
        )
    return found


def unit_state(unit):
    """``LoadState`` and ``ActiveState``; an unreadable unit fails closed (never taken for stopped)."""

    shown = subprocess.run(
        ["systemctl", "show", "--property=LoadState", "--property=ActiveState", "--", unit],
        capture_output=True,
        text=True,
    )
    values = dict(line.partition("=")[::2] for line in shown.stdout.splitlines() if "=" in line)
    load, active = values.get("LoadState", ""), values.get("ActiveState", "")
    if not active or (shown.returncode != 0 and (load, active) != ("not-found", "inactive")):
        raise Failure(f"Cannot read the state of {unit} ({shown.stderr.strip() or 'no ActiveState'})")
    return load, active


def listening(port):
    """Whether something accepts connections on ``127.0.0.1:port``; an unclear answer fails closed."""

    try:
        with socket.create_connection((RCON_HOST, port), timeout=3):
            return True
    except ConnectionRefusedError:
        return False
    except OSError as error:
        raise Failure(f"Cannot tell whether port {port} is in use: {error}") from None


# --- RCON (stdlib client; the password stays inside this process) ------------


def _receive_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise Failure("RCON connection closed early")
        data += chunk
    return data


def _packet(conn, request, kind, body):
    payload = body.encode("utf-8")
    conn.sendall(struct.pack("<iii", len(payload) + 10, request, kind) + payload + b"\x00\x00")


def _response(conn):
    (size,) = struct.unpack("<i", _receive_exact(conn, 4))
    if size < 10 or size > 1 << 20:
        raise Failure("RCON answered with a malformed packet")
    data = _receive_exact(conn, size)
    request, kind = struct.unpack("<ii", data[:8])
    return request, kind, data[8:-2].decode("utf-8", "replace")


def rcon(cfg, password, command, timeout):
    """``command``'s answer: one authenticated connection per command."""

    try:
        with socket.create_connection((RCON_HOST, cfg["rcon_port"]), timeout=timeout) as conn:
            conn.settimeout(timeout)
            _packet(conn, 1, LOGIN, password)
            request, _kind, _body = _response(conn)
            if request == -1:
                raise Failure("RCON refused the password")
            if request != 1:
                raise Failure("RCON answered the login with an unexpected packet")
            _packet(conn, 2, COMMAND, command)
            request, _kind, body = _response(conn)
            if request != 2:
                raise Failure(f"RCON answered {command} with an unexpected packet")
            return body
    except OSError as error:
        raise Failure(f"RCON {command} failed: {error}") from None


# --- worlds ------------------------------------------------------------------


def world_like(name):
    """A top-level name that may be a world: not hidden and never a pre-restore copy."""

    return not name.startswith(".") and PRE_RESTORE not in name


def live_worlds(server_dir, world):
    """The configured world and every other top-level directory of the server with a regular ``level.dat``."""

    found = {world}
    with os.scandir(server_dir) as entries:
        for entry in entries:
            if entry.name == world or not world_like(entry.name) or not entry.is_dir(follow_symlinks=False):
                continue
            try:
                details = os.lstat(os.path.join(entry.path, "level.dat"))
            except FileNotFoundError:
                continue
            if stat.S_ISREG(details.st_mode):
                found.add(entry.name)
    return sorted(found)


# --- backup ------------------------------------------------------------------


def ensure_root(path):
    """The backup root as a real ``root:root 0700`` directory (only the root itself is created)."""

    if os.path.lexists(path):
        real_dir(path, "Backup root")
    else:
        parent = os.path.dirname(path)
        real_dir(parent, "Parent of the backup root")
        os.mkdir(path, 0o700)
    details = os.lstat(path)
    if (details.st_uid, details.st_gid) != (ROOT_UID, ROOT_GID):
        os.chown(path, ROOT_UID, ROOT_GID)
    if stat.S_IMODE(details.st_mode) != 0o700:
        os.chmod(path, 0o700)


def present_optional(server_dir):
    found = []
    for name in OPTIONAL_FILES:
        try:
            details = os.lstat(os.path.join(server_dir, name))
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(details.st_mode):
            raise Failure(f"{server_dir}/{name} is not a regular file")
        found.append(name)
    return found


def raise_error(error):
    raise error


def write_archive(cfg, worlds, optional):
    """The role's archive, with every world: each world tree (without its own entry) and the files,
    relative to the server directory. Written to a private temporary name and linked into place, so a
    failed run never leaves a partial archive and an existing archive is never replaced."""

    server_dir, archive = cfg["server_dir"], cfg["archive"]
    root = os.path.dirname(archive)
    descriptor, partial = tempfile.mkstemp(prefix="." + os.path.basename(archive) + ".", suffix=".partial", dir=root)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            with tarfile.open(fileobj=handle, mode="w|gz") as packed:
                for world in worlds:
                    top = os.path.join(server_dir, world)
                    for current, dirs, files in os.walk(top, topdown=True, onerror=raise_error):
                        for name in sorted(dirs + files):
                            full = os.path.join(current, name)
                            kind = os.lstat(full).st_mode
                            if not (stat.S_ISDIR(kind) or stat.S_ISREG(kind)):
                                # The restore refuses such members; never write an archive it cannot restore.
                                raise Failure(f"{full} is a link or special file; refusing to back up the worlds")
                            packed.add(full, os.path.relpath(full, server_dir), recursive=False)
                for name in [PROPERTIES, *optional]:
                    packed.add(os.path.join(server_dir, name), name, recursive=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(partial, ROOT_UID, ROOT_GID)
        os.chmod(partial, 0o600)
        try:
            os.link(partial, archive)
        except FileExistsError:
            raise Failure(f"{archive} already exists; nothing was replaced") from None
    finally:
        if os.path.lexists(partial):
            os.unlink(partial)


def backup(cfg):
    password = cfg.pop("rcon_password")
    server_dir, world = cfg["server_dir"], cfg["world"]
    real_dir(server_dir, "Server directory")
    real_dir(os.path.join(server_dir, world), "World directory")
    properties = os.path.join(server_dir, PROPERTIES)
    if not os.path.isfile(properties) or os.path.islink(properties):
        raise Failure(f"{properties} not found (or not a regular file)")
    require_live_world_selected(cfg)
    worlds = live_worlds(server_dir, world)
    optional = present_optional(server_dir)
    _load, active = unit_state(cfg["unit"])
    if active in TRANSITION:
        raise Failure(f"{cfg['unit']} is {active}; run the backup again once it has started or stopped")
    running = active in RUNNING
    if not running:
        for port in (cfg["port"], cfg["rcon_port"]):
            if listening(port):
                raise Failure(
                    f"{cfg['unit']} is {active} but something answers on 127.0.0.1:{port}; refusing to archive a "
                    "world a server outside the unit may be writing"
                )
    # Only after every read-only check: the root's owner and mode are its first change.
    ensure_root(cfg["root"])
    say(f"Minecraft server was running: {running}")
    disabled = False
    failure = None
    try:
        if running:
            disabled = True  # also when save-off itself fails after reaching the server
            say("save-off: " + rcon(cfg, password, "save-off", cfg["save_timeout"]))
            saved = rcon(cfg, password, "save-all flush", cfg["save_timeout"])
            say("save-all flush: " + saved)
            if "saved the game" not in saved.lower():
                raise Failure(f"save-all did not confirm completion: {saved!r}")
            time.sleep(cfg["save_wait"])
        write_archive(cfg, worlds, optional)
    except BaseException as error:
        failure = error
        raise
    finally:
        if disabled:
            try:
                say("save-on: " + rcon(cfg, password, "save-on", cfg["save_timeout"]))
            except Failure as error:
                message = (
                    f"WARNING: auto-save could not be re-enabled ({error}); run save-on over RCON or restart "
                    f"{cfg['unit']} now"
                )
                if failure is None:
                    raise Failure(message) from None
                say(message)
    size = os.lstat(cfg["archive"]).st_size
    say(
        f"Backup created: {cfg['archive']} ({size / 1048576:.2f} MB): worlds {', '.join(worlds)} (playing {world}), "
        f"{PROPERTIES}, {', '.join(optional) or 'no player files'}"
    )


# --- restore -----------------------------------------------------------------


def select_archive(cfg):
    """``latest`` (the newest ``*.tar.gz`` directly in the root by mtime, as the role picks it), a name in
    the root or an absolute path below it; a regular file, reached without links."""

    root = cfg["root"]
    real_dir(root, "Backup root")
    if cfg["archive"] == "latest":
        candidates = []
        for entry in os.scandir(root):
            if entry.name.startswith(".") or not entry.name.endswith(".tar.gz"):
                continue
            if entry.is_file(follow_symlinks=False):
                candidates.append((entry.stat(follow_symlinks=False).st_mtime, entry.name, entry.path))
        if not candidates:
            raise Failure(f"No backups found in {root}")
        selected = max(candidates)[2]
    elif cfg["archive"].startswith("/"):
        selected = cfg["archive"]
    else:
        selected = os.path.join(root, cfg["archive"])
    real_root = os.path.realpath(root)
    resolved = os.path.realpath(selected)
    if not resolved.startswith(real_root + "/") or resolved != os.path.join(real_root, os.path.relpath(selected, root)):
        raise Failure(f"Archive {selected} is not a file below {root} (links are refused)")
    try:
        details = os.lstat(selected)
    except FileNotFoundError:
        raise Failure(f"Archive not found: {selected}") from None
    if not stat.S_ISREG(details.st_mode):
        raise Failure(f"Archive is not a regular file: {selected}")
    return selected


def member_name(member):
    """The member's relative name without a leading ``./`` (``None`` for the archive's own ``.``);
    absolute or parent paths are refused."""

    name = member.name
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if name in ("", "."):
        return None
    parts = name.split("/")
    if name.startswith("/") or any(part in ("", ".", "..") for part in parts) or "\\" in name:
        raise Failure(f"Archive member {member.name!r} has an unsafe path; refusing the archive")
    return name


def wanted(name, worlds):
    """The members a restore extracts: the worlds' trees, server.properties and the player files."""

    return name is not None and (name == PROPERTIES or name in OPTIONAL_FILES or name.split("/", 1)[0] in worlds)


def inspect(cfg, selected):
    """Read the whole archive once (gzip and tar integrity), without writing anything. The worlds are the
    top-level directories with a regular ``level.dat`` (hidden names and pre-restore copies left out);
    the configured world must be one of them."""

    world = cfg["world"]
    tops = {}
    found = {"properties": None, "optional": set()}
    try:
        with gzip.open(selected, "rb") as stream:
            with tarfile.open(fileobj=stream, mode="r|") as archive:
                for member in archive:
                    name = member_name(member)
                    if name is None:
                        continue
                    if name == PROPERTIES:
                        if not member.isfile():
                            raise Failure(f"{PROPERTIES} in the archive is not a regular file")
                        found["properties"] = level_name(archive.extractfile(member).read().decode("utf-8", "replace"))
                        continue
                    if name in OPTIONAL_FILES:
                        if not member.isfile():
                            raise Failure(f"{name} in the archive is not a regular file")
                        found["optional"].add(name)
                        continue
                    top = name.split("/", 1)[0]
                    entry = tops.setdefault(top, {"entries": 0, "level_dat": False, "unsafe": None})
                    entry["entries"] += 1
                    if not (member.isdir() or member.isfile()) or (name == top and not member.isdir()):
                        entry["unsafe"] = entry["unsafe"] or member.name
                    entry["level_dat"] = entry["level_dat"] or (name == f"{top}/level.dat" and member.isfile())
            # Read to the end so gzip checks its CRC and length too.
            while stream.read(1 << 20):
                pass
    except (tarfile.TarError, EOFError, OSError, ValueError) as error:
        raise Failure(f"Archive {selected} is not a readable gzip tar: {error}") from None
    worlds = sorted(top for top, entry in tops.items() if entry["level_dat"] and world_like(top))
    if world not in worlds:
        raise Failure(f"World directory '{world}' (with level.dat) not found in archive {selected}")
    for top in worlds:
        if tops[top]["unsafe"]:
            raise Failure(f"World member {tops[top]['unsafe']!r} is a link or special file; refusing")
    if found["properties"] is not None and found["properties"] != world:
        raise Failure(
            f"The archive's {PROPERTIES} selects level-name {found['properties']!r}, not the configured world "
            f"{world!r}; refusing a restore that would switch the server to another world"
        )
    return {
        "worlds": worlds,
        "world_entries": {top: tops[top]["entries"] for top in worlds},
        "properties": found["properties"] is not None,
        "optional": sorted(found["optional"]),
        "ignored": sorted(set(tops) - set(worlds)),
    }


def checks(cfg):
    """Every check of the restore, read only; the plan."""

    selected = select_archive(cfg)
    contents = inspect(cfg, selected)
    server_dir = cfg["server_dir"]
    real_dir(server_dir, "Server directory")
    identity(cfg["user"])
    identity(cfg["group"], group=True)
    require_live_world_selected(cfg)
    present = []
    for name in contents["worlds"]:
        live = os.path.join(server_dir, name)
        if os.path.lexists(live):
            real_dir(live, f"Live world {name}")
            present.append(name)
    load, active = unit_state(cfg["unit"])
    # The role's assertion: a loaded unit, or one that is genuinely absent.
    if not (load == "loaded" or (load == "not-found" and active == "inactive")):
        raise Failure(f"{cfg['unit']} is {load}/{active}, unsafe for a restore (masked, failed to load or unknown)")
    stop = load == "loaded" and active not in STOPPED
    if not stop and listening(cfg["port"]):
        raise Failure(
            f"{cfg['unit']} is {load}/{active} but something answers on 127.0.0.1:{cfg['port']}; refusing to replace "
            "worlds a server outside the unit may be writing"
        )
    return {
        "archive": selected,
        "size_bytes": os.lstat(selected).st_size,
        "world": cfg["world"],
        "worlds": contents["worlds"],
        "world_entries": contents["world_entries"],
        "live_worlds": present,
        "server_properties": contents["properties"],
        "player_files": contents["optional"],
        "ignored_top_level": contents["ignored"],
        "server_dir": server_dir,
        "unit": f"{load}/{active}",
        "stop": stop,
        "start_after": load == "loaded" and active in WAS_RUNNING,
    }


def check(cfg):
    plan = checks(cfg)
    say(PLAN_MARKER + json.dumps(plan, sort_keys=True))
    say("DRY RUN: nothing was stopped, extracted, copied or changed")


def content(path):
    """A regular file's bytes; ``None`` when it does not exist."""

    try:
        with open(path, "rb") as handle:
            return handle.read()
    except FileNotFoundError:
        return None


def write_file(destination, data, uid, gid, mode):
    """Atomic write with owner and mode (the role's ``copy``)."""

    descriptor, partial = tempfile.mkstemp(prefix=".ops-deploy-", dir=os.path.dirname(destination))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.chown(partial, uid, gid)
        os.chmod(partial, mode)
        os.replace(partial, destination)
    finally:
        if os.path.lexists(partial):
            os.unlink(partial)


def file_state(path):
    """What a rollback needs to put a small file back: ``None`` when it does not exist."""

    try:
        details = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(details.st_mode):
        raise Failure(f"{path} is not a regular file")
    return content(path), details.st_uid, details.st_gid, stat.S_IMODE(details.st_mode)


def keep_previous(path, stamp):
    """The role's ``backup: true`` for server.properties: the replaced file stays, with its owner and mode."""

    if not os.path.isfile(path) or os.path.islink(path):
        return None
    kept = f"{path}.pre-restore-{stamp}"
    shutil.copy2(path, kept)
    details = os.lstat(path)
    os.chown(kept, details.st_uid, details.st_gid)
    return kept


def chown_tree(path, uid, gid):
    """``chown -R`` without following links (there are none: the archive's links were refused)."""

    os.lchown(path, uid, gid)
    for current, dirs, files in os.walk(path, onerror=raise_error):
        for name in dirs + files:
            os.lchown(os.path.join(current, name), uid, gid)


def empty_dir(path):
    for entry in os.listdir(path):
        full = os.path.join(path, entry)
        if os.path.isdir(full) and not os.path.islink(full):
            shutil.rmtree(full)
        else:
            os.unlink(full)


def wait_for_port(port, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if listening(port):
                return True
        except Failure:
            pass
        time.sleep(2)
    return False


def rollback(cfg, preserved, replaced):
    """Put the live state back after a failed restore: every world from its pre-restore copy (a renamed
    copy moves back, a verified copy is copied back and kept, a world that did not exist goes again)
    and every replaced file; only while the unit is stopped. Errors are collected, never raised."""

    load, active = unit_state(cfg["unit"])
    if active not in STOPPED:
        return [f"{cfg['unit']} is {load}/{active}, so nothing was rolled back"]
    errors = []
    for live, report in reversed(preserved):
        try:
            if report["method"] == "rename":
                if os.path.lexists(live):
                    shutil.rmtree(live)
                os.replace(report["path"], live)
            elif report["method"] == "copy":
                empty_dir(live)
                run(["cp", "-a", "--", report["path"] + "/.", live + "/"])
            elif os.path.lexists(live):
                shutil.rmtree(live)
            say(f"Rolled back {live}")
        except Exception as error:  # noqa: BLE001 - every item gets its attempt
            errors.append(f"{live}: {error}")
    for path, before in replaced.items():
        try:
            if before is None:
                if os.path.lexists(path):
                    os.unlink(path)
            else:
                write_file(path, *before)
            say(f"Rolled back {path}")
        except Exception as error:  # noqa: BLE001 - every item gets its attempt
            errors.append(f"{path}: {error}")
    return errors


def put_in_place(cfg, plan, work, original, uid, gid, preserved, replaced):
    """The mutation: each world through its pre-restore copy, then server.properties and the player files."""

    server_dir = cfg["server_dir"]
    for name in plan["worlds"]:
        live = os.path.join(server_dir, name)
        report = original["preserve"](live, empty=True)
        preserved.append((live, report))
        if report["method"] == "absent":
            say(f"Pre-restore copy of {name}: nothing to snapshot (no live world; a fresh installation)")
        else:
            say(f"Pre-restore copy of {name}: {json.dumps(report)}. Owner prunes copies by hand.")
        if not os.path.isdir(live):
            os.mkdir(live, 0o755)
        reference = report["path"] if report["method"] in ("rename", "copy") else None
        mode = stat.S_IMODE(os.lstat(reference).st_mode) if reference else 0o755
        run(["cp", "-a", "--", os.path.join(work, name) + "/.", live + "/"])
        os.chmod(live, mode)
        chown_tree(live, uid, gid)
    stamp = utc_stamp()
    restored = list(plan["worlds"])
    for name in (PROPERTIES, *OPTIONAL_FILES):
        data = content(os.path.join(work, name))
        if data is None:
            continue
        target = os.path.join(server_dir, name)
        before = file_state(target)
        replaced[target] = before
        note = ""
        if name == PROPERTIES:
            kept = keep_previous(target, stamp) if before is not None and before[0] != data else None
            note = f" (previous kept as {kept})" if kept else ""
            # 0640 as the pyinfra deploy writes it (it holds the RCON password); the role wrote 0644.
            write_file(target, data, uid, gid, 0o640)
        else:
            write_file(target, data, uid, gid, 0o644)
        restored.append(name + note)
    say(f"Restored from {plan['archive']}: {', '.join(restored)}")


def restore(cfg):
    plan = checks(cfg)
    say(PLAN_MARKER + json.dumps(plan, sort_keys=True))
    original = preserver()
    lives = [os.path.join(cfg["server_dir"], name) for name in plan["worlds"]]
    staging_root = cfg["staging"]
    original["check_layout"]([*lives, staging_root], [plan["archive"]])
    for live in lives:
        original["preflight"](live, empty=True)
    uid, gid = identity(cfg["user"]), identity(cfg["group"], group=True)
    if os.path.lexists(staging_root):
        real_dir(staging_root, "Restore work directory")
    else:
        os.mkdir(staging_root, 0o700)
    os.chown(staging_root, ROOT_UID, ROOT_GID)
    os.chmod(staging_root, 0o700)
    work = tempfile.mkdtemp(prefix="restore-", dir=staging_root)
    worlds = set(plan["worlds"])
    try:
        with tarfile.open(plan["archive"], "r:gz") as archive:
            members = []
            for member in archive.getmembers():
                name = member_name(member)
                if wanted(name, worlds):
                    # Checked by inspect(): regular files and directories only.
                    if not (member.isdir() or member.isfile()):
                        raise Failure(f"Archive member {member.name!r} is a link or special file; refusing")
                    member.name = name
                    members.append(member)
            options = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
            archive.extractall(work, members=members, **options)
        for name in plan["worlds"]:
            real_dir(os.path.join(work, name), f"Extracted world {name}")
        if plan["stop"]:
            say(f"Stopping {cfg['unit']}")
            run(["systemctl", "stop", "--", cfg["unit"]])
            _load, active = unit_state(cfg["unit"])
            if active not in STOPPED:
                raise Failure(f"{cfg['unit']} is still {active} after the stop; no data was touched")
        preserved, replaced = [], {}
        try:
            put_in_place(cfg, plan, work, original, uid, gid, preserved, replaced)
        except BaseException as error:
            say(f"The restore failed while replacing live data ({error}); rolling back")
            try:
                errors = rollback(cfg, preserved, replaced)
            except Exception as again:  # noqa: BLE001 - the original failure is what ends the run
                errors = [f"the rollback itself failed: {again}"]
            if errors:
                say("ROLLBACK INCOMPLETE: " + "; ".join(errors) + ". The pre-restore copies are reported above.")
            else:
                say("Rolled back: the worlds and files are as before the restore")
            say(f"{cfg['unit']} stays stopped; start it by hand once the server directory is checked")
            raise
    finally:
        shutil.rmtree(work, ignore_errors=True)
        try:
            os.rmdir(staging_root)
        except OSError:
            pass
    # The data is in place; a failed start does not roll it back (the copies stay).
    if plan["start_after"]:
        say(f"Starting {cfg['unit']} again (it was running before the restore)")
        run(["systemctl", "start", "--", cfg["unit"]])
        if not wait_for_port(cfg["port"], cfg["start_timeout"]):
            raise Failure(
                f"{cfg['unit']} started but port {cfg['port']} did not open within {cfg['start_timeout']}s; the "
                "restored worlds stay in place, the pre-restore copies are reported above"
            )
        say(f"{cfg['unit']} is running again")
    else:
        say(f"{cfg['unit']} stays stopped, as it was before the restore")


ACTIONS = {"backup": backup, "check": check, "restore": restore}


def main(action):
    os.umask(0o022)
    cfg = json.loads(sys.stdin.readline())
    try:
        ACTIONS[action](cfg)
    except Exception as error:  # noqa: BLE001 - every failure ends the run with its message
        print(f"minecraft_java {action}: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__" and len(sys.argv) == 2:
    raise SystemExit(main(sys.argv[1]))
