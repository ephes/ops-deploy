"""Owned Paperless release staging and legacy current-path convergence.

Run as the Paperless service account. Only the fixed version/archive/current/
staging paths below its declared site root are eligible for changes. A broken
version directory or legacy current directory is removed only after the pinned
archive has been verified and its replacement extracted and validated.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tomllib

VERSION = "3.2.1"
ARCHIVE_SHA256 = "7391e75706d9dafe84dd2235df12c932c0034a4f453725437d07918eee7a35b8"


class Refusal(ValueError):
    pass


def open_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refusal("release input must be a regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def layout(settings):
    if not isinstance(settings, dict) or set(settings) != {"site_root", "apply"}:
        raise Refusal("invalid release payload")
    value = settings["site_root"]
    if not isinstance(value, str) or not re.fullmatch(r"(?:/[A-Za-z0-9_.+-]+)+", value):
        raise Refusal("invalid release root")
    if any(part in {".", ".."} for part in value.split("/")[1:]) or type(settings["apply"]) is not bool:
        raise Refusal("invalid release settings")
    root = Path(value)
    if root.is_symlink():
        raise Refusal("release site root must not be a symlink")
    return root, root / f"paperless-ngx-v{VERSION}", root / "paperless-ngx", root / f".paperless-ngx-v{VERSION}-extract"


def complete(directory):
    if directory.is_symlink():
        raise Refusal("versioned release must not be a symlink")
    if not directory.exists():
        return False
    if not directory.is_dir():
        raise Refusal("versioned release must be a directory")
    project = directory / "pyproject.toml"
    if project.is_symlink():
        raise Refusal("release project metadata must not be a symlink")
    try:
        with open_regular(project) as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            return False
        values = tomllib.loads(data.decode())
    except FileNotFoundError:
        return False
    except (tomllib.TOMLDecodeError, UnicodeError):
        return False
    project_values = values.get("project")
    return (
        isinstance(project_values, dict)
        and project_values.get("name") == "paperless-ngx"
        and project_values.get("version") == VERSION
        and (directory / "src/manage.py").is_file()
        and (directory / "src/paperless/__init__.py").is_file()
    )


def remove_owned(path):
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        if not path.is_dir():
            raise Refusal("owned release path has an unsupported file type")
        shutil.rmtree(path)


def reconcile(settings):
    root, release, current, staging = layout(settings)
    needs_release = not complete(release)
    needs_current = not current.is_symlink() or current.resolve() != release.resolve()
    if not settings["apply"]:
        return {"release": needs_release, "current": needs_current}
    if needs_release:
        archive = root / f"paperless-ngx-v{VERSION}.tar.xz"
        if archive.is_symlink():
            raise Refusal("release archive must not be a symlink")
        with open_regular(archive) as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != ARCHIVE_SHA256:
                raise Refusal("release archive checksum mismatch")
            # Keep this verified descriptor open through extraction; replacing
            # the archive path cannot substitute another archive afterwards.
            stream.seek(0)
            remove_owned(staging)
            staging.mkdir(mode=0o755)
            try:
                with tarfile.open(fileobj=stream, mode="r:xz") as source:
                    source.extractall(staging, filter="data")
                extracted = staging / "paperless-ngx"
                if not complete(extracted):
                    raise Refusal("extracted Paperless release is incomplete")
                remove_owned(release)
                extracted.rename(release)
            finally:
                remove_owned(staging)
    if needs_current:
        # This matches the original declared legacy current-directory migration.
        # The successfully checked new release exists before any old path goes.
        remove_owned(current)
        current.symlink_to(release, target_is_directory=True)
    return {"release_changed": needs_release, "current_changed": needs_current}


def main():
    try:
        body = sys.stdin.buffer.read(65537)
        if len(body) > 65536:
            raise Refusal("release payload exceeds size limit")
        result = reconcile(json.loads(body))
    except (ValueError, OSError, tarfile.TarError, RecursionError):
        print("Paperless release inspection/convergence failed", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
