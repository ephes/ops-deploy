"""ACME-only Traefik restore; validate before staging, keep private bodies on host."""

from __future__ import annotations

import grp
import json
import os
import pwd
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


def selected(request):
    value = request["archive"]
    root = Path(request["root"])
    if value == "latest":
        candidates = []
        for path in root.iterdir():
            details = path.lstat()
            if path.name.endswith("." + request["archive_extension"]) and stat.S_ISREG(details.st_mode):
                candidates.append((details.st_mtime_ns, path.name, path))
        if not candidates:
            raise FileNotFoundError("No Traefik backup archive")
        return max(candidates)[2]
    return Path(value) if value.startswith("/") else root / value


def identity(details):
    return details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns, details.st_ctime_ns


def paths(request, archive):
    staging = Path(request["staging_dir"])
    if ".." in staging.parts or str(staging) in {"/", "/tmp", "/etc", "/var", "/var/lib"}:
        raise ValueError("Invalid restore staging path")
    physical = staging.parent.resolve() / staging.name
    targets = [archive.resolve()]
    if request["include_acme"]:
        destination = Path(request["acme_path"]).resolve()
        if archive.resolve() == destination:
            raise ValueError("Archive and publication must differ")
        targets.extend([destination, Path(request["acme_dir"] or str(destination.parent)).resolve()])
    for target in targets:
        if target == physical or target.is_relative_to(physical) or physical.is_relative_to(target):
            raise ValueError("Restore staging overlaps archive/publication")
    return staging


def directory(member):
    return member.is_dir() if isinstance(member, zipfile.ZipInfo) else member.isdir()


def member_name(member):
    return member.filename if isinstance(member, zipfile.ZipInfo) else member.name


def contents(handle, member):
    return handle.open(member) if isinstance(handle, zipfile.ZipFile) else handle.extractfile(member)


def archive_reader(source):
    zipped = zipfile.is_zipfile(source)
    source.seek(0)
    return zipfile.ZipFile(source) if zipped else tarfile.open(fileobj=source, mode="r:*")


def members(handle, request):
    entries = []
    seen = set()
    roots = set()
    raw_members = handle.infolist() if isinstance(handle, zipfile.ZipFile) else handle.getmembers()
    for member in raw_members:
        path = PurePosixPath(member_name(member))
        if isinstance(member, zipfile.ZipInfo):
            kind = stat.S_IFMT(member.external_attr >> 16)
            regular = kind in {0, stat.S_IFREG, stat.S_IFDIR} and not member.flag_bits & 1
            if (kind == stat.S_IFDIR and not member.is_dir()) or (kind == stat.S_IFREG and member.is_dir()):
                regular = False
        else:
            regular = member.isdir() or member.isfile()
        if path.is_absolute() or ".." in path.parts or not path.parts or not regular:
            raise ValueError("Unsupported archive member")
        canonical = path.as_posix()
        if canonical in seen:
            raise ValueError("Duplicate archive member")
        seen.add(canonical)
        roots.add(path.parts[0])
        entries.append((member, path))
    if len(roots) != 1:
        raise ValueError("Ambiguous restore payload")
    kinds = {path: directory(member) for member, path in entries}
    for _, path in entries:
        if any(parent in kinds and not kinds[parent] for parent in path.parents):
            raise ValueError("Archive parent is not a directory")
    root = next(iter(roots))
    if any(path.as_posix() == root and not directory(member) for member, path in entries):
        raise ValueError("Restore payload must be a directory")
    wanted = PurePosixPath(root) / "acme" / Path(request["acme_path"]).name
    if request["include_acme"] and not any(path == wanted and not directory(member) for member, path in entries):
        raise ValueError("ACME state absent from payload")
    # Verify every stored regular payload without exporting or retaining its
    # contents. Corrupt compression/ZIP CRC fails before staging mutation.
    for member, _ in entries:
        if not directory(member):
            with contents(handle, member) as stream:
                while stream.read(1024 * 1024):
                    pass
    if not isinstance(handle, zipfile.ZipFile):
        # Tar's end-of-members can precede compression footer/CRC validation.
        while handle.fileobj.read(1024 * 1024):
            pass
    return entries, wanted


def ensure_parent(path):
    # Parent symlinks could redirect publication; callers may use arbitrary real
    # custom directories, but cannot publish through a substituted link.
    for parent in reversed(path.parents):
        if parent.is_symlink():
            raise ValueError("Publication parent is a symlink")


def publication_policy(request):
    destination = Path(request["acme_path"])
    directory = Path(request["acme_dir"] or str(destination.parent))
    ensure_parent(destination)
    ensure_parent(directory / ".entry")
    if directory.exists() and not directory.is_dir():
        raise ValueError("ACME directory is not a directory")
    if destination.exists() or destination.is_symlink():
        details = destination.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise ValueError("ACME destination is not a single regular file")
    uid = (
        int(request["acme_owner"])
        if str(request["acme_owner"]).isdigit()
        else pwd.getpwnam(request["acme_owner"]).pw_uid
    )
    gid = (
        int(request["acme_group"])
        if str(request["acme_group"]).isdigit()
        else grp.getgrnam(request["acme_group"]).gr_gid
    )
    mode = int(request["acme_mode"], 8)
    if directory != destination.parent and not destination.parent.is_dir():
        raise ValueError("Publication parent is missing")
    return destination, directory, uid, gid, mode


def publish(source, request):
    destination, directory, uid, gid, mode = publication_policy(request)
    directory.mkdir(parents=True, exist_ok=True, mode=int(request["acme_dir_mode"], 8))
    details = directory.stat()
    if details.st_uid != uid or details.st_gid != gid:
        os.chown(directory, uid, gid)
    if stat.S_IMODE(details.st_mode) != int(request["acme_dir_mode"], 8):
        directory.chmod(int(request["acme_dir_mode"], 8))
    body = source.read_bytes()
    if destination.exists():
        details = destination.stat()
        if destination.read_bytes() == body:
            if details.st_uid != uid or details.st_gid != gid:
                os.chown(destination, uid, gid)
            if stat.S_IMODE(details.st_mode) != mode:
                destination.chmod(mode)
            return
    descriptor, temporary = tempfile.mkstemp(prefix=".ops-traefik-acme-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def restore(request, action):
    archive = selected(request)
    staging = paths(request, archive)
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        initial = os.fstat(source.fileno())
        if not stat.S_ISREG(initial.st_mode):
            raise ValueError("Archive is not a regular file")
        with archive_reader(source) as handle:
            entries, acme = members(handle, request)
            if request["include_acme"]:
                publication_policy(request)
            if identity(os.fstat(source.fileno())) != identity(initial):
                raise ValueError("Archive changed during validation")
            if action == "validate":
                return {"valid": True, "archive": str(archive)}
            if action != "apply":
                raise ValueError("Unknown restore action")
            # All archive/path/type checks precede the first staging mutation.
            if staging.is_symlink() or staging.is_file():
                staging.unlink()
            elif staging.exists():
                shutil.rmtree(staging)
            staging.mkdir(parents=True, mode=int(request["staging_mode"], 8))
            staging.chmod(int(request["staging_mode"], 8))
            try:
                for member, path in entries:
                    target = staging.joinpath(*path.parts)
                    if directory(member):
                        target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        # No archive symlinks, hardlinks, special members or
                        # duplicate paths can redirect this exclusive creation.
                        output = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        with os.fdopen(output, "wb") as stream, contents(handle, member) as archive_contents:
                            shutil.copyfileobj(archive_contents, stream)
                if identity(os.fstat(source.fileno())) != identity(initial):
                    raise ValueError("Archive changed before publication")
                if request["include_acme"]:
                    publish(staging.joinpath(*acme.parts), request)
            finally:
                shutil.rmtree(staging)
    return {"staged": True, "acme_published": request["include_acme"]}


def main():
    result = restore(json.load(sys.stdin), sys.argv[1])
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Paths may contain operator archive names; no members, private bodies,
        # command output, fingerprints or exception text leave this process.
        print("Traefik restore failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1) from None
