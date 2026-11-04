"""The MeTube, Jellyfin and Navidrome backup and restore roles on the host.

Run as root with one JSON payload on stdin; ops-library's preserver is
supplied verbatim (``PRESERVE_SOURCE``). ``backup``: the roles' directories,
archive restriction, path checks, stop/copy/start block, manifest and archive.
``retain``: the roles' pruning, after the fetch. ``restore-metube``,
``restore-jellyfin``, ``restore-navidrome``: each role's tasks in its order;
Navidrome first runs ops-control's recovery quarantine
(``playbooks/common/navidrome_restore_quarantine.yml``). Like the roles, a
failed restore stops where it failed: nothing is started again and the
staging directory stays.
"""

import fnmatch
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid

ARCHIVE_PATTERNS = ("*.tar", "*.tar.*", "*.tgz")
# Ansible's systemd module: ``stopped`` changes a running or deactivating unit;
# ``reloaded`` starts a unit that is not running.
RUNNING = ("active", "activating")
STOPPABLE = (*RUNNING, "deactivating")
# The owner of system files and of the recovery directories (tests substitute their own account).
ROOT_USER = "root"
ROOT_GROUP = "root"
TRUSTED_UID = 0


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
    return grp.getgrnam(value).gr_gid if group else pwd.getpwnam(value).pw_uid


def ensure_dir(path, owner, group, mode):
    """``file: state=directory``: owner, group and mode on ``path`` and on every directory it creates.

    Attributes that already match are left alone, as the module leaves them.
    """

    if os.path.lexists(path) and not os.path.isdir(path):
        raise Failure(f"{path} exists and is not a directory")
    attributes = identity(owner), identity(group, group=True), int(mode, 8)
    missing = []
    current = os.path.abspath(path)
    while not os.path.lexists(current):
        missing.append(current)
        current = os.path.dirname(current)
    for directory in reversed(missing):
        os.mkdir(directory, 0o700)
        set_attributes(directory, *attributes)
    set_attributes(path, *attributes)


def set_attributes(path, uid, gid, mode):
    details = os.stat(path)
    if (details.st_uid, details.st_gid) != (uid, gid):
        os.chown(path, uid, gid)
    if stat.S_IMODE(details.st_mode) != mode:
        os.chmod(path, mode)


def visible(root, kind):
    """``find`` with its defaults: direct entries, no hidden names, ``file``/``directory`` without following links."""

    try:
        entries = list(os.scandir(root))
    except FileNotFoundError:
        return []
    found = []
    for entry in entries:
        if entry.name.startswith("."):
            continue
        if (entry.is_file if kind == "file" else entry.is_dir)(follow_symlinks=False):
            found.append(entry)
    return found


def newest_first(entries):
    return sorted(entries, key=lambda entry: entry.stat(follow_symlinks=False).st_mtime, reverse=True)


def restrict_archives(root):
    for entry in visible(root, "file"):
        if any(fnmatch.fnmatch(entry.name, pattern) for pattern in ARCHIVE_PATTERNS):
            if stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode) != 0o600:
                os.chmod(entry.path, 0o600)
                say(f"Restricted {entry.path} to 0600")


def unit_state(unit):
    """``LoadState`` and ``ActiveState`` of ``unit``."""

    shown = subprocess.run(
        ["systemctl", "show", "--property=LoadState", "--property=ActiveState", unit], capture_output=True, text=True
    )
    values = dict(line.partition("=")[::2] for line in shown.stdout.splitlines() if "=" in line)
    if shown.returncode != 0 or not values.get("ActiveState"):
        # The systemd module fails closed too; never treat an unreadable unit as stopped.
        raise Failure(f"Service is in unknown state: {unit} ({shown.stderr.strip() or 'no ActiveState'})")
    return values.get("LoadState", ""), values["ActiveState"]


def active_state(unit):
    return unit_state(unit)[1]


def stop(unit):
    """``systemd: state=stopped``: fails for an unknown unit, stops a running or deactivating one.

    Returns whether it stopped the unit (the module's ``changed``).
    """

    load, active = unit_state(unit)
    if load == "not-found":
        raise Failure(f"Could not find the requested service {unit}: host")
    if active not in STOPPABLE:
        return False
    run(["systemctl", "stop", unit])
    return True


def rsync(source, destination, delete=False):
    run(["rsync", "-a", *(["--delete"] if delete else []), source + "/", destination + "/"])


def same_file(path, content, uid, gid, mode):
    try:
        details = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(details.st_mode):
        return False
    with open(path, "rb") as handle:
        current = handle.read()
    return current == content and (details.st_uid, details.st_gid, stat.S_IMODE(details.st_mode)) == (uid, gid, mode)


def copy_file(source, destination, owner, group, mode):
    """``copy: remote_src=true`` with owner, group and mode; returns whether it changed anything."""

    with open(source, "rb") as handle:
        content = handle.read()
    uid, gid, bits = identity(owner), identity(group, group=True), int(mode, 8)
    if same_file(destination, content, uid, gid, bits):
        return False
    directory = os.path.dirname(destination)
    descriptor, partial = tempfile.mkstemp(prefix=".ops-deploy-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
        os.chown(partial, uid, gid)
        os.chmod(partial, bits)
        os.replace(partial, destination)
    except BaseException:
        if os.path.lexists(partial):
            os.unlink(partial)
        raise
    return True


def write_private(path, text, owner, group, mode):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(text)
    os.chown(path, identity(owner), identity(group, group=True))
    os.chmod(path, int(mode, 8))


def write_archive(directory, destination):
    """``archive: format=gz`` of one directory: its contents below its name, as the module walks them.

    Written to a hidden name and renamed, so a failed run never leaves a
    partial archive that ``latest`` would pick.
    """

    root = os.path.dirname(directory) + "/"
    partial = os.path.join(os.path.dirname(destination), "." + os.path.basename(destination) + ".partial")
    descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle, tarfile.open(fileobj=handle, mode="w|gz") as archive:
            for current, dirs, files in os.walk(directory, topdown=True):
                for name in dirs + files:
                    full = os.path.join(current, name)
                    archive.add(full, full[len(root) :], recursive=False)
        os.chmod(partial, 0o600)
        os.replace(partial, destination)
    except BaseException:
        if os.path.lexists(partial):
            os.unlink(partial)
        raise


def version(argv):
    """The best-effort version command's stdout, trimmed (empty when it cannot run, as the roles record it)."""

    try:
        result = subprocess.run(argv, capture_output=True, text=True)
    except OSError:
        return ""
    return result.stdout.strip()


# --- backup ------------------------------------------------------------------


def backup(cfg):
    found = version(cfg["version"])
    owner, group = cfg["owner"], cfg["group"]
    for path in [cfg["root"], cfg["dir"], *(cfg["dir"] + "/" + sub for sub in cfg["subdirs"])]:
        ensure_dir(path, owner, group, cfg["dir_mode"])
    restrict_archives(cfg["root"])
    present = [os.path.exists(path) for path, _mandatory, _label in cfg["checks"]]
    for (path, mandatory, label), exists in zip(cfg["checks"], present):
        if mandatory and not exists:
            raise Failure(cfg["missing"].format(path=path, label=label))
    stopped = False
    failure = None
    try:
        if cfg["stop"]:
            stopped = True  # also when stopping fails, as the roles' ``is failed``
            stopped = stop(cfg["unit"])
        for kind, index, source, below, delete in cfg["copies"]:
            if not present[index]:
                continue
            destination = cfg["dir"] + "/" + below
            if kind == "tree":
                rsync(source, destination, delete=delete)
            else:
                copy_file(source, destination, owner, group, cfg["file_mode"])
    except BaseException as error:
        failure = error
        raise
    finally:
        if cfg["stop"] and stopped:
            try:
                run(["systemctl", "daemon-reload"])
                run(["systemctl", "start", cfg["unit"]])
            except subprocess.CalledProcessError as error:
                if failure is None:
                    raise
                # Keep the first failure; the role reports both.
                say(f"Starting {cfg['unit']} after the failed backup failed too: {error}")
    if cfg["generate_manifest"]:
        lines = [("version", found), *cfg["manifest"]]
        text = "".join(f'{key}: "{value}"\n' for key, value in lines)
        write_private(cfg["dir"] + "/manifest.yml", text, owner, group, cfg["file_mode"])
    if cfg["create_archive"]:
        write_archive(cfg["dir"], cfg["archive"])
        say(f"{cfg['label']} backup stored at {cfg['archive']}")
    else:
        say(f"{cfg['label']} backup stored at {cfg['dir']}")


def retain(cfg):
    """The roles' pruning: archives of the prefix beyond the newest ``retain``.

    Without archives MeTube and Jellyfin prune the backup directories instead;
    Navidrome's role prunes nothing then (``prune_dirs``).
    """

    if cfg["create_archive"]:
        pattern, kind = f"{cfg['prefix']}-*.{cfg['extension']}", "file"
    elif cfg["prune_dirs"]:
        pattern, kind = f"{cfg['prefix']}-*", "directory"
    else:
        return
    entries = [entry for entry in visible(cfg["root"], kind) if fnmatch.fnmatch(entry.name, pattern)]
    for entry in newest_first(entries)[cfg["retain"] :]:
        if kind == "file":
            os.unlink(entry.path)
        else:
            shutil.rmtree(entry.path)
        say(f"Removed {entry.path}")


# --- restore -----------------------------------------------------------------


def select_archive(cfg):
    """``latest`` (the newest ``*.<extension>`` file by mtime), an absolute path or a name below the root."""

    if not cfg["root"] or not cfg["archive"]:
        raise Failure(f"{cfg['service']}_restore_root and {cfg['service']}_restore_archive are required")
    if cfg["archive"] == "latest":
        candidates = [
            entry for entry in visible(cfg["root"], "file") if fnmatch.fnmatch(entry.name, "*." + cfg["extension"])
        ]
        if not candidates:
            raise Failure(f"No {cfg['label']} backup archives found in {cfg['root']}")
        selected = newest_first(candidates)[0].path
    elif cfg["archive"].startswith("/"):
        selected = cfg["archive"]
    else:
        selected = cfg["root"] + "/" + cfg["archive"]
    if not os.path.exists(selected):
        raise Failure(f"{cfg['label']} restore archive not found: {selected}")
    return selected


def unpack(cfg, selected, *, reset, mode):
    """Staging (``reset``: removed first), the archive unpacked into it, and its payload directory."""

    staging = cfg["staging"]
    if reset and os.path.lexists(staging):
        if os.path.isdir(staging) and not os.path.islink(staging):
            shutil.rmtree(staging)
        else:
            os.unlink(staging)
    ensure_dir(staging, ROOT_USER, ROOT_GROUP, mode)
    run(["tar", "--extract", "-C", staging, "-z", "-f", selected])
    payloads = sorted(entry.path for entry in visible(staging, "directory"))
    if not payloads:
        raise Failure(cfg["no_payload"])
    if len(payloads) > 1:
        raise Failure(f"More than one payload directory under {staging}: {', '.join(payloads)}; nothing restored")
    return payloads[0]


def preserve(original, path):
    report = original["preserve"](path, empty=True)
    say(f"Pre-restore copy: {json.dumps(report)}. Owner prunes copies by hand.")
    return report


def reload_traefik():
    """``service: traefik state=reloaded`` with ``failed_when: false``: start it when not running, else reload.

    A failure is tolerated. Jellyfin's "Restart Traefik when reload is not
    supported" never runs: a failing service task registers no ``rc``.
    """

    try:
        action = "reload" if active_state("traefik") in RUNNING else "start"
    except Failure as error:
        say(f"{error} (tolerated, as in the role)")
        return
    if subprocess.run(["systemctl", action, "traefik"]).returncode != 0:
        say(f"systemctl {action} traefik failed (tolerated, as in the role)")


def write_route(cfg, source):
    """The route copy; inside Traefik's dynamic directory only while no transaction holds its lock."""

    if cfg["route_guard"]:
        run(cfg["route_guard"])
    return copy_file(source, cfg["traefik_config_path"], ROOT_USER, ROOT_GROUP, "0644")


def start(unit, *, restart, enabled, daemon_reload):
    if daemon_reload:
        run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable" if enabled else "disable", unit])
    run(["systemctl", "restart" if restart else "start", unit])


def cleanup(cfg):
    if cfg["cleanup"] and os.path.lexists(cfg["staging"]):
        shutil.rmtree(cfg["staging"])


def restore_metube(cfg):
    original = preserver()
    selected = select_archive(cfg)
    original["check_layout"]([cfg["state_dir"], cfg["staging"]], [selected])
    payload = unpack(cfg, selected, reset=False, mode="0755")
    pieces = {
        "state": payload + "/state",
        "config": payload + "/config/" + os.path.basename(cfg["env_file"]),
        "unit": payload + "/systemd/" + os.path.basename(cfg["service_unit"]),
        "traefik": payload + "/traefik/" + os.path.basename(cfg["traefik_config_path"]),
    }
    present = {name: os.path.exists(path) for name, path in pieces.items()}
    if not present["state"]:
        raise Failure(f"MeTube state directory missing inside archive: {pieces['state']}")
    if cfg["stop_service"]:
        stop(cfg["unit"])
    report = preserve(original, cfg["state_dir"])
    ensure_dir(cfg["state_dir"], cfg["user"], cfg["group"], "0755")
    ensure_dir(cfg["env_dir"], ROOT_USER, ROOT_GROUP, "0755")
    ensure_dir(os.path.dirname(cfg["traefik_config_path"]), ROOT_USER, ROOT_GROUP, "0755")
    rsync(pieces["state"], cfg["state_dir"])
    if present["config"]:
        copy_file(pieces["config"], cfg["env_file"], ROOT_USER, ROOT_GROUP, "0644")
    unit_changed = present["unit"] and copy_file(pieces["unit"], cfg["service_unit"], ROOT_USER, ROOT_GROUP, "0644")
    route_changed = present["traefik"] and write_route(cfg, pieces["traefik"])
    if unit_changed:
        run(["systemctl", "daemon-reload"])
    if route_changed:
        reload_traefik()
    start(cfg["unit"], restart=cfg["restart"], enabled=cfg["enabled"], daemon_reload=False)
    cleanup(cfg)
    say(f"Retained copy: {json.dumps(report)}. Owner prunes by hand.")


def restore_jellyfin(cfg):
    original = preserver()
    selected = select_archive(cfg)
    original["check_layout"]([cfg["data_dir"], cfg["config_dir"], cfg["staging"]], [selected])
    payload = unpack(cfg, selected, reset=True, mode="0700")
    pieces = {
        "data": payload + "/data",
        "config": payload + "/config",
        "unit": payload + "/systemd/" + os.path.basename(cfg["service_unit"]),
        "traefik": payload + "/traefik/" + os.path.basename(cfg["traefik_config_path"]),
        "logs": payload + "/logs",
    }
    present = {name: os.path.exists(path) for name, path in pieces.items()}
    if not present["data"]:
        raise Failure(f"Jellyfin data directory missing inside archive: {pieces['data']}")
    if cfg["stop_service"]:
        stop(cfg["unit"])
    report = preserve(original, cfg["data_dir"])
    config_report = preserve(original, cfg["config_dir"]) if present["config"] else None
    for path in (cfg["data_dir"], cfg["log_dir"], cfg["config_dir"]):
        ensure_dir(path, cfg["user"], cfg["group"], "0750")
    ensure_dir(os.path.dirname(cfg["traefik_config_path"]), ROOT_USER, ROOT_GROUP, "0755")
    rsync(pieces["data"], cfg["data_dir"])
    if present["config"]:
        rsync(pieces["config"], cfg["config_dir"])
    unit_changed = present["unit"] and copy_file(pieces["unit"], cfg["service_unit"], ROOT_USER, ROOT_GROUP, "0644")
    route_changed = present["traefik"] and write_route(cfg, pieces["traefik"])
    if present["logs"]:
        rsync(pieces["logs"], cfg["log_dir"])
    if unit_changed:
        run(["systemctl", "daemon-reload"])
    for path in (cfg["data_dir"], cfg["log_dir"], cfg["config_dir"]):
        run(["chown", "-R", f"{cfg['user']}:{cfg['group']}", path])
    start(cfg["unit"], restart=cfg["restart"], enabled=True, daemon_reload=True)
    if route_changed:
        reload_traefik()
    cleanup(cfg)
    say(f"Retained copy: {json.dumps(report)}. Owner prunes by hand.")
    if config_report is not None:
        say(f"Retained Jellyfin config copy: {json.dumps(config_report)}")


# --- Navidrome recovery quarantine (ops-control navidrome_restore_quarantine.yml) ---------


def safe_mode(details):
    """No group or other write bit (the playbook's ``mode[-2:]`` in ``[0145][0145]``)."""

    return stat.S_IMODE(details.st_mode) & 0o022 == 0


def recovery_ancestors(base):
    """``base`` and its ancestors below ``/`` (``/var``, ``/var/lib``, ``/var/lib/ops-deploy``, ``base``)."""

    return [str(parent) for parent in reversed(Path(base).parents) if str(parent) != "/"] + [base]


def quarantine(cfg):
    """Refuse unsafe recovery state, then keep the current canonical files under a fresh attempt directory."""

    base = cfg["state_root"]
    restored = base + "/restored"
    attempt = f"{restored}/restore-{uuid.uuid4().hex}"
    for path in recovery_ancestors(base):
        try:
            details = os.lstat(path)
        except FileNotFoundError:
            details = None
        if (
            details is None
            or not stat.S_ISDIR(details.st_mode)
            or details.st_uid != TRUSTED_UID
            or not safe_mode(details)
        ):
            raise Failure(
                "Recovery ancestors must be existing root-owned directories without links or "
                "writable group/other permissions."
            )
    for path in (base + "/pending", base + "/restart", cfg["staging"], attempt):
        if os.path.lexists(path):
            raise Failure(
                "Native pending/restart work, existing staging or recovery output requires separate "
                "handling; nothing was removed."
            )
    if os.path.lexists(restored):
        details = os.lstat(restored)
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != TRUSTED_UID or stat.S_IMODE(details.st_mode) != 0o700:
            raise Failure("An existing recovery parent must be a real root-owned 0700 directory.")
    current = (cfg["config_path"], cfg["service_unit"], cfg["traefik_config_path"])
    for path in current:
        try:
            details = os.lstat(path)
        except FileNotFoundError:
            details = None
        if (
            details is None
            or not stat.S_ISREG(details.st_mode)
            or details.st_uid != TRUSTED_UID
            or not safe_mode(details)
        ):
            raise Failure(
                "Current canonical files must exist as safe root-owned regular files; no partial capture is accepted."
            )
    for path in (
        restored,
        attempt,
        attempt + "/current",
        attempt + "/archived",
        attempt + "/archived/config",
        attempt + "/archived/systemd",
        attempt + "/archived/traefik",
    ):
        ensure_dir(path, ROOT_USER, ROOT_GROUP, "0700")
    for path in current:
        copy_file(path, attempt + "/current/" + os.path.basename(path), ROOT_USER, ROOT_GROUP, "0600")
    say(
        f"Current canonical system files are captured under {attempt}/current before the restore role runs. "
        f"Retain this attempt path if recovery fails. Archived system files will stay under {attempt}/archived; "
        "no attempt is pruned."
    )
    return attempt


def restore_navidrome(cfg):
    attempt = quarantine(cfg)
    # The role's system-file destinations, pinned outside their live locations.
    config_path = attempt + "/archived/config/" + os.path.basename(cfg["config_path"])
    service_unit = attempt + "/archived/systemd/" + os.path.basename(cfg["service_unit"])
    traefik_config_path = attempt + "/archived/traefik/" + os.path.basename(cfg["traefik_config_path"])
    original = preserver()
    selected = select_archive(cfg)
    original["check_layout"]([cfg["data_dir"], cfg["staging"]], [selected])
    payload = unpack(cfg, selected, reset=True, mode="0700")
    pieces = {
        "data": payload + "/data",
        "config": payload + "/config/" + os.path.basename(config_path),
        "unit": payload + "/systemd/" + os.path.basename(service_unit),
        "traefik": payload + "/traefik/" + os.path.basename(traefik_config_path),
        "logs": payload + "/logs",
    }
    present = {name: os.path.exists(path) for name, path in pieces.items()}
    if not present["data"]:
        raise Failure(f"Navidrome data directory missing inside archive: {pieces['data']}")
    stop(cfg["unit"])
    report = preserve(original, cfg["data_dir"])
    for path in (cfg["data_dir"], cfg["cache_dir"], cfg["log_dir"]):
        ensure_dir(path, cfg["user"], cfg["group"], "0750")
    ensure_dir(os.path.dirname(config_path), ROOT_USER, ROOT_GROUP, "0755")
    ensure_dir(os.path.dirname(traefik_config_path), ROOT_USER, ROOT_GROUP, "0755")
    rsync(pieces["data"], cfg["data_dir"])
    if present["config"]:
        copy_file(pieces["config"], config_path, ROOT_USER, ROOT_GROUP, "0644")
    unit_changed = present["unit"] and copy_file(pieces["unit"], service_unit, ROOT_USER, ROOT_GROUP, "0644")
    if present["traefik"]:
        copy_file(pieces["traefik"], traefik_config_path, ROOT_USER, ROOT_GROUP, "0644")
    if present["logs"]:
        rsync(pieces["logs"], cfg["log_dir"])
    if unit_changed:
        run(["systemctl", "daemon-reload"])
    for path in (cfg["data_dir"], cfg["cache_dir"], cfg["log_dir"]):
        run(["chown", "-R", f"{cfg['user']}:{cfg['group']}", path])
    start(cfg["unit"], restart=cfg["restart"], enabled=True, daemon_reload=True)
    cleanup(cfg)
    say(f"Retained copy: {json.dumps(report)}. Owner prunes by hand.")
    say(
        f"Current canonical system files and archived system files are retained separately under {attempt}. "
        f"The role retained the quiesced pre-restore data copy at {json.dumps(report)}. The canonical route "
        "stayed live. Verify Navidrome health and expected library/user state, then run "
        "just deploy-one navidrome macmini."
    )


ACTIONS = {
    "backup": backup,
    "retain": retain,
    "restore-metube": restore_metube,
    "restore-jellyfin": restore_jellyfin,
    "restore-navidrome": restore_navidrome,
}


def main(action):
    os.umask(0o022)
    cfg = json.loads(sys.stdin.readline())
    try:
        ACTIONS[action](cfg)
    except (Failure, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"{cfg.get('service', 'media')} {action}: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__" and len(sys.argv) == 2:
    raise SystemExit(main(sys.argv[1]))
