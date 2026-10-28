"""Managed identity backup/manual restore; credentials stay target-local.

Plan inspects declared metadata and restore archive structure/integrity, never
changes a service or state. Apply may copy identity material, always privately.
This is not the ordinary Tailscale deploy route and does not make Tailnet
transport safe for restore. No state/archive body reaches stdout/stderr.
"""

import fnmatch
import grp
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile


class Refused(Exception):
    pass


def admit(path, kind, optional=True):
    path = Path(path)
    for parent in reversed(path.parents):
        if parent.is_symlink():
            raise Refused("linked lifecycle ancestor")
    try:
        info = path.lstat()
    except FileNotFoundError:
        if optional:
            return None
        raise Refused("required lifecycle input absent") from None
    if kind == "directory" and not stat.S_ISDIR(info.st_mode):
        raise Refused("lifecycle path is not an ordinary directory")
    if kind == "file" and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise Refused("lifecycle file is not an ordinary single-link file")
    return info


def run(argv):
    try:
        result = subprocess.run(argv, capture_output=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Refused("native lifecycle command unavailable or timed out") from error
    if result.returncode:
        raise Refused("native lifecycle command failed; partial state preserved")


def copy(source, target):
    run(["rsync", "-a", str(source).rstrip("/") + "/", str(target).rstrip("/") + "/"])


def private_dir(path, uid, gid):
    path = Path(path)
    admit(path, "directory")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        os.fchmod(descriptor, 0o700)
        os.fchown(descriptor, uid, gid)
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise Refused("private lifecycle directory changed during admission")
    finally:
        os.close(descriptor)


def staging_admission(path):
    # Root-owned, non-writable ancestors or root-owned sticky /tmp prevent an
    # unprivileged rename/replacement of the root-owned staging entry. Nothing
    # is chmod/chowned during this read-only admission.
    path = Path(path)
    for part in [*reversed(path.parents), path]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            raise Refused("restore staging must have existing root-owned directory ancestors")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise Refused("restore staging ancestor permits unprivileged replacement")
    return path


def stage_directory(path):
    path = staging_admission(path)
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, name in enumerate(path.parts[1:]):
            try:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(name, mode=0o700, dir_fd=descriptor)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            info = os.fstat(child)
            if info.st_uid != 0 or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                os.close(child)
                raise Refused("restore staging directory changed or is untrusted")
            os.close(descriptor)
            descriptor = child
        os.fchmod(descriptor, 0o700)
        os.fchown(descriptor, 0, 0)
    finally:
        os.close(descriptor)


def require_rsync():
    if shutil.which("rsync") is None:
        raise Refused("native rsync prerequisite unavailable; no lifecycle write or stop")


def backup_plan(cfg):
    require_rsync()
    admit(cfg["root"], "directory")
    admit(cfg["state_dir"], "directory", optional=False)
    if cfg["include_sysconfig"]:
        admit(cfg["sysconfig_path"], "file")
    if cfg["include_dropins"]:
        admit(cfg["systemd_dropin_dir"], "directory")
    for path in (Path(cfg["root"]) / cfg["name"], Path(cfg["root"]) / (cfg["name"] + ".tar.gz")):
        if path.exists() or path.is_symlink():
            raise Refused("backup name collision; existing backup preserved")
    if cfg["create_archive"]:
        link = Path(cfg["root"]) / (cfg["prefix"] + "-latest.tar.gz")
        if link.exists() and not link.is_symlink():
            raise Refused("latest archive link is an ordinary file; existing data preserved")
    pwd.getpwnam(cfg["owner"])
    grp.getgrnam(cfg["group"])


def backup(cfg):
    backup_plan(cfg)
    root = Path(cfg["root"])
    uid, gid = pwd.getpwnam(cfg["owner"]).pw_uid, grp.getgrnam(cfg["group"]).gr_gid
    private_dir(root, uid, gid)
    # Original shallow archive-mode repair, no recursive backup pruning.
    for path in root.iterdir():
        if any(fnmatch.fnmatchcase(path.name, pattern) for pattern in ("*.tar", "*.tar.*", "*.tgz")):
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise Refused("shared archive inode refused")
                if stat.S_IMODE(info.st_mode) != 0o600:
                    path.chmod(0o600)
    target = root / cfg["name"]
    for path in (target, target / "state", target / "config", target / "systemd"):
        private_dir(path, uid, gid)
    copy(cfg["state_dir"], target / "state")
    if cfg["include_sysconfig"] and admit(cfg["sysconfig_path"], "file") is not None:
        dest = target / "config" / Path(cfg["sysconfig_path"]).name
        shutil.copyfile(cfg["sysconfig_path"], dest)
        dest.chmod(0o600)
        os.chown(dest, uid, gid)
    if cfg["include_dropins"] and admit(cfg["systemd_dropin_dir"], "directory") is not None:
        copy(cfg["systemd_dropin_dir"], target / "systemd")
    if cfg["create_archive"]:
        archive = root / (cfg["name"] + ".tar.gz")
        descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                with tarfile.open(fileobj=stream, mode="w:gz") as bundle:
                    bundle.add(target, arcname=cfg["name"])
        except BaseException:
            archive.unlink(missing_ok=True)
            raise
        os.chown(archive, uid, gid)
        link = root / (cfg["prefix"] + "-latest.tar.gz")
        if link.exists() and not link.is_symlink():
            raise Refused("latest archive link target is an ordinary file; not replaced")
        temporary = root / ("." + cfg["name"] + "-latest")
        temporary.symlink_to(archive)
        os.replace(temporary, link)


def selected_archive(cfg):
    root = Path(cfg["root"])
    admit(root, "directory", optional=False)
    if cfg["archive"] == "latest":
        candidates = []
        for path in root.iterdir():
            if path.name.endswith(".tar.gz") and not path.is_symlink() and admit(path, "file"):
                candidates.append(path)
        if not candidates:
            raise Refused("no original restore archive candidate")
        path = max(candidates, key=lambda value: value.stat().st_mtime_ns)
    else:
        path = Path(cfg["archive"])
        if not path.is_absolute():
            path = root / path
    admit(path, "file", optional=False)
    if not path.name.startswith(cfg["inventory_name"] + "-") or not path.name.endswith(".tar.gz"):
        raise Refused("restore archive host prefix or format does not match")
    return path


def restore_plan(cfg):
    require_rsync()
    staging_admission(cfg["staging_dir"])
    path = selected_archive(cfg)
    for key, kind in [
        ("state_dir", "directory"),
        ("sysconfig_path", "file"),
        ("systemd_dropin_dir", "directory"),
        ("staging_dir", "directory"),
    ]:
        admit(cfg[key], kind)
    payload = path.name[:-7]
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if not members:
            raise Refused("empty restore archive")
        names = set()
        for member in members:
            normalized = str(PurePosixPath(member.name))
            if normalized in names:
                raise Refused("duplicate archive member")
            names.add(normalized)
            name = PurePosixPath(member.name)
            if (
                name.is_absolute()
                or ".." in name.parts
                or not name.parts
                or name.parts[0] != payload
                or member.isdev()
                or member.isfifo()
            ):
                raise Refused("unsafe or foreign archive member")
            # Python's native data filter validates link destinations before
            # any extraction or daemon stop, without exporting member names.
            tarfile.data_filter(member, str(Path(cfg["staging_dir"]) / "validation"))
        if not any(member.name.rstrip("/") == payload + "/state" and member.isdir() for member in members):
            raise Refused("archive lacks original state payload")
    # Native tar fully validates the gzip stream before any daemon stop/write.
    run(["tar", "-tzf", str(path)])
    return path, payload


def atomic_copy(source, target, mode):
    target = Path(target)
    admit(target, "file")
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="." + target.name + ".restore-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream, Path(source).open("rb") as source_stream:
            shutil.copyfileobj(source_stream, stream)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), 0, 0)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def restore(cfg):
    path, payload = restore_plan(cfg)
    base = Path(cfg["staging_dir"])
    created = not base.exists()
    stage_directory(base)
    directory = Path(tempfile.mkdtemp(prefix="owned-restore-", dir=base))
    try:
        with tarfile.open(path, "r:gz") as archive:
            archive.extractall(directory, filter="data")
        source = directory / payload
        # Admission and full validation/extraction precede disruption. Once
        # stopped, preserve partial state on failure; never silently repair or
        # restart a half-restored identity after an exception.
        admit(source / "state", "directory", optional=False)
        sysconfig = source / "config" / Path(cfg["sysconfig_path"]).name
        if sysconfig.exists() or sysconfig.is_symlink():
            admit(sysconfig, "file", optional=False)
        if cfg["include_dropins"]:
            admit(source / "systemd", "directory")
        run(["systemctl", "stop", cfg["service_name"]])
        private_dir(cfg["state_dir"], 0, 0)
        copy(source / "state", cfg["state_dir"])
        sysconfig = source / "config" / Path(cfg["sysconfig_path"]).name
        if sysconfig.exists():
            admit(sysconfig, "file", optional=False)
            dest = Path(cfg["sysconfig_path"])
            atomic_copy(sysconfig, dest, 0o644)
        if cfg["include_dropins"] and (source / "systemd").is_dir():
            private_dir(cfg["systemd_dropin_dir"], 0, 0)
            copy(source / "systemd", cfg["systemd_dropin_dir"])
            run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", cfg["service_name"]])
        run(["systemctl", "restart" if cfg["restart_service"] else "start", cfg["service_name"]])
    finally:
        if cfg["cleanup"]:
            shutil.rmtree(directory)
            if created:
                base.rmdir()


def main():
    if os.geteuid() != 0:
        raise Refused("identity lifecycle requires existing root authority")
    cfg = json.load(sys.stdin)
    action = sys.argv[1]
    if action == "backup-plan":
        backup_plan(cfg)
    elif action == "restore-plan":
        restore_plan(cfg)
    elif action == "backup":
        backup(cfg)
    elif action == "restore":
        restore(cfg)
    else:
        raise Refused("unknown identity lifecycle action")
    print("pending" if action.endswith("-plan") else "current")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Tailscale identity lifecycle failed; all archive/state bodies suppressed", file=sys.stderr)
        raise SystemExit(2) from None
