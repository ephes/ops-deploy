"""Certbot role orchestration; original validator and preserver supplied verbatim."""

import datetime
import fnmatch
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile


def originals():
    validator = {"__name__": "original_certbot_archive_validator"}
    preserver = {"__name__": "original_certbot_tree_preserver"}
    exec(compile(ARCHIVE_MEMBERS_SOURCE, "original_archive_members.py", "exec"), validator)
    exec(compile(PRESERVE_SOURCE, "original_preserve.py", "exec"), preserver)
    return validator, preserver


def identity(value, group=False):
    if value.isdecimal():
        return int(value)
    return grp.getgrnam(value).gr_gid if group else pwd.getpwnam(value).pw_uid


def exists(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def real_directory(path, missing_ok=False):
    details = exists(path)
    if details is None and missing_ok:
        return None
    if details is None or not stat.S_ISDIR(details.st_mode):
        raise ValueError("Certbot directory must be a real directory")
    return details


def walk_error(error):
    raise error


def backup_plan(cfg):
    source = Path(cfg["src"])
    root = Path(cfg["root"])
    real_directory(source)
    root_state = real_directory(root, missing_ok=True)
    resolved_source, resolved_root = source.resolve(), root.resolve()
    if (resolved_source == resolved_root or resolved_source in resolved_root.parents
            or resolved_root in resolved_source.parents):
        raise ValueError("Certbot backup source and root must be disjoint")
    uid, gid = identity(cfg["owner"]), identity(cfg["group"], group=True)
    root_wrong = (root_state is None or root_state.st_uid != uid or root_state.st_gid != gid
        or stat.S_IMODE(root_state.st_mode) != int(cfg["dir_mode"], 8))
    restrict = []
    if root_state is not None:
        for entry in os.scandir(root):
            if entry.name.startswith(".") or not any(fnmatch.fnmatchcase(entry.name, pattern)
                for pattern in ("*.tar", "*.tar.*", "*.tgz")):
                continue
            details = entry.stat(follow_symlinks=False)
            if stat.S_ISREG(details.st_mode) and stat.S_IMODE(details.st_mode) != 0o600:
                restrict.append(str(root / entry.name))
    stamp = cfg.get("_timestamp") or datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    if not re.fullmatch(r"[0-9]{8}T[0-9]{6}", stamp):
        raise ValueError("Invalid Certbot backup timestamp")
    archive = root / (cfg["prefix"] + "-" + stamp + "." + cfg["archive_extension"])
    archive_state = exists(archive)
    if cfg["create_archive"] and archive_state is not None and (
            not stat.S_ISREG(archive_state.st_mode) or archive_state.st_nlink != 1):
        raise ValueError("Certbot archive destination must be a regular singly-linked file")
    return {"valid": True, "timestamp": stamp, "archive": str(archive),
        "managed": bool(root_wrong or restrict or cfg["create_archive"]), "restrict": restrict}


def create_archive(source, destination, kind):
    # community.general.archive.add_targets walks each directory's entries and
    # adds them non-recursively, relative to the source's parent. Do not insert
    # an extra root entry or follow directory links during that walk.
    if kind == "zip":
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for root, directories, filenames in os.walk(source, onerror=walk_error):
                for name in directories + filenames:
                    path = Path(root) / name
                    archive.write(path, arcname=str(Path(source.name) / path.relative_to(source)))
    else:
        mode = {"tar": "w", "gz": "w:gz", "bz2": "w:bz2", "xz": "w:xz"}[kind]
        with tarfile.open(destination, mode=mode, dereference=False) as archive:
            for root, directories, filenames in os.walk(source, onerror=walk_error):
                for name in directories + filenames:
                    path = Path(root) / name
                    archive.add(path, arcname=str(Path(source.name) / path.relative_to(source)), recursive=False)


def backup_apply(cfg):
    plan = backup_plan(cfg)
    root = Path(cfg["root"])
    root.mkdir(parents=True, mode=int(cfg["dir_mode"], 8), exist_ok=True)
    details = os.lstat(root)
    uid, gid = identity(cfg["owner"]), identity(cfg["group"], group=True)
    if details.st_uid != uid or details.st_gid != gid:
        os.chown(root, uid, gid)
    if stat.S_IMODE(details.st_mode) != int(cfg["dir_mode"], 8):
        os.chmod(root, int(cfg["dir_mode"], 8))
    for path in plan["restrict"]:
        os.chmod(path, 0o600)
    if cfg["create_archive"]:
        old_umask = os.umask(0o077)
        temporary = None
        try:
            descriptor, temporary = tempfile.mkstemp(prefix=".certbot-archive-", dir=root)
            os.close(descriptor)
            create_archive(Path(cfg["src"]), temporary, cfg["archive_format"])
            os.chmod(temporary, 0o600)
            os.replace(temporary, plan["archive"])
        finally:
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)
            os.umask(old_umask)
    return {"valid": True, "archive": plan["archive"]}


def selected_archive(cfg):
    root = Path(cfg["root"])
    if cfg["archive"] == "latest":
        real_directory(root)
        candidates = []
        for entry in os.scandir(root):
            if (not entry.name.startswith(".") and entry.name.endswith("." + cfg["archive_extension"])
                    and entry.is_file(follow_symlinks=False)):
                candidates.append(Path(entry.path))
        if not candidates:
            raise ValueError("No Certbot backup archives found")
        return max(candidates, key=lambda path: path.stat().st_mtime)
    archive = Path(cfg["archive"])
    return archive if archive.is_absolute() else root / archive


def restore_validate(cfg):
    archive = selected_archive(cfg)
    if not archive.is_file():
        raise ValueError("Certbot archive not found")
    live = Path(cfg["directory"])
    validator, preserver = originals()
    tops = validator["validate"](str(archive), {live.name})
    preserver["preflight"](str(live), empty=True)
    # Named identity errors must be known before publication.
    identity(cfg["owner"])
    identity(cfg["group"], group=True)
    return {"valid": True, "archive": str(archive), "tops": tops}


def ownership_tree(live, uid, gid):
    details = os.lstat(live)
    if details.st_uid != uid or details.st_gid != gid:
        os.chown(live, uid, gid, follow_symlinks=False)
    for root, directories, filenames in os.walk(live, followlinks=False, onerror=walk_error):
        for name in directories + filenames:
            path = Path(root) / name
            details = os.lstat(path)
            if details.st_uid != uid or details.st_gid != gid:
                os.chown(path, uid, gid, follow_symlinks=False)


def restore_apply(cfg):
    if cfg["dry_run"]:
        return restore_validate(cfg)
    checked = restore_validate(cfg)
    live = Path(cfg["directory"])
    validator, preserver = originals()
    stage = Path(tempfile.mkdtemp(prefix=".restore-staging-", dir=live.parent))
    report = None
    try:
        with tarfile.open(checked["archive"], "r:*") as archive:
            # The exact original graph validator runs before this extraction.
            archive.extractall(stage, filter="fully_trusted")
        for top in checked["tops"]:
            target = stage / top
            details = os.lstat(target)
            if not stat.S_ISDIR(details.st_mode):
                raise ValueError("Staged Certbot top is not a directory")
        report = preserver["preserve"](str(live), empty=True)
        live.mkdir(mode=0o700, exist_ok=True)
        if any(live.iterdir()):
            raise ValueError("Certbot live directory is not empty after preservation")
        reference = Path(report["path"]) if report["path"] else stage / live.name
        details = reference.stat()
        os.chown(live, details.st_uid, details.st_gid)
        os.chmod(live, stat.S_IMODE(details.st_mode))
        for child in (stage / live.name).iterdir():
            subprocess.run(["mv", "-t", str(live), "--", str(child)], check=True)
    finally:
        shutil.rmtree(stage)
    uid, gid = identity(cfg["owner"]), identity(cfg["group"], group=True)
    ownership_tree(live, uid, gid)
    if stat.S_IMODE(os.lstat(live).st_mode) != int(cfg["dir_mode"], 8):
        os.chmod(live, int(cfg["dir_mode"], 8))
    for path in dict.fromkeys([cfg["credentials_file"], cfg["rfc2136_credentials_file"]]):
        if path and os.path.lexists(path):
            details = os.stat(path)
            if not stat.S_ISREG(details.st_mode):
                raise ValueError("Declared Certbot credential entry must be a file")
            if details.st_uid != uid or details.st_gid != gid:
                os.chown(path, uid, gid)
            if stat.S_IMODE(details.st_mode) != int(cfg["credentials_mode"], 8):
                os.chmod(path, int(cfg["credentials_mode"], 8))
    if cfg["run_dry_renew"]:
        # Original argv has no --config-dir and can contact ACME/write state.
        subprocess.run(["certbot", "renew", "--dry-run"], check=True)
    if cfg["reload_postfix"]:
        subprocess.run(["systemctl", "reload", "postfix"], check=True)
    return {"valid": True, "archive": checked["archive"], "preserved": report}


if __name__ == "__main__":
    request = json.load(sys.stdin)
    action = sys.argv[1]
    actions = {"backup-plan": backup_plan, "backup-apply": backup_apply,
        "restore-validate": restore_validate, "restore-apply": restore_apply}
    if action not in actions:
        raise ValueError("Unknown Certbot lifecycle action")
    print(json.dumps(actions[action](request)), flush=True)
