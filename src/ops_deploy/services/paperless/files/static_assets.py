"""Django-shell static program-asset inspection/convergence, not document data.

Only standard Django static finders inside the declared release/venv are used.
The prebuilt release frontend overrides app-finder placeholders, exactly as the
original role's collectstatic then frontend-copy sequence. Paths/content remain
host-local; the controller receives a boolean only. No search backend is opened.
"""

import hashlib
import os
from pathlib import Path
import shutil
import stat


class Refusal(ValueError):
    pass


def roots(settings):
    release = Path(settings["release_dir"]).resolve()
    venv = Path(settings["venv"]).resolve()
    target = Path(settings["static_root"])
    if target.is_symlink():
        raise Refusal("static root must not be a symlink")
    frontend = release / "static/frontend"
    if not frontend.is_dir():
        frontend = release / "src/documents/static/frontend"
    if not frontend.is_dir() or frontend.is_symlink():
        raise Refusal("release frontend program assets are missing or unsafe")
    return release, venv, target, frontend


def digest(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 32 * 1024 * 1024:
            raise Refusal("static program asset must be a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return hashlib.file_digest(stream, "sha256").digest()
    finally:
        os.close(fd)


def expected_files(settings):
    from django.apps import apps
    from django.contrib.staticfiles.finders import get_finders

    release, venv, target, frontend = roots(settings)
    expected = {}
    for finder in get_finders():
        if (type(finder).__module__, type(finder).__name__) not in {
            ("django.contrib.staticfiles.finders", "FileSystemFinder"),
            ("django.contrib.staticfiles.finders", "AppDirectoriesFinder"),
        }:
            raise Refusal("unexpected Paperless static finder")
        for relative, storage in finder.list(apps.get_app_config("staticfiles").ignore_patterns):
            source = Path(storage.path(relative)).resolve()
            if not (source.is_relative_to(release) or source.is_relative_to(venv)):
                raise Refusal("static finder escaped declared program roots")
            name = Path(relative)
            if name.is_absolute() or ".." in name.parts:
                raise Refusal("unsafe static finder relative path")
            expected.setdefault(name, (source, False))
            if len(expected) > 50000:
                raise Refusal("static program asset count exceeds limit")
    for source in frontend.rglob("*"):
        if source.is_symlink():
            raise Refusal("frontend program asset must not be a symlink")
        if source.is_file():
            expected[Path("frontend") / source.relative_to(frontend)] = (source, True)
        if len(expected) > 50000:
            raise Refusal("static program asset count exceeds limit")
    return target, expected


def inspect_static(settings):
    target, expected = expected_files(settings)
    for relative, (source, frontend) in expected.items():
        destination = target / relative
        # Parent symlinks could redirect a fixed static path into user data.
        parents = [target.joinpath(*relative.parts[:index]) for index in range(1, len(relative.parts))]
        if any(parent.is_symlink() for parent in parents):
            raise Refusal("static destination contains a symlink parent")
        try:
            if digest(destination) != digest(source):
                return {"pending": True}
            if frontend and stat.S_IMODE(destination.stat().st_mode) != 0o755:
                return {"pending": True}
        except FileNotFoundError:
            return {"pending": True}
    return {"pending": False}


def apply_static(settings):
    from django.core.management import call_command

    _, _, target, frontend = roots(settings)
    expected_files(settings)  # Validate every source before clearing any output.
    count = 0
    if target.exists():
        for directory, children, names in os.walk(target, followlinks=False):
            for name in children + names:
                count += 1
                if count > 50000 or (Path(directory) / name).is_symlink():
                    raise Refusal("static output tree is oversized or contains a symlink")
    call_command("collectstatic", interactive=False, clear=True, verbosity=0)
    destination = target / "frontend"
    destination.mkdir(parents=True, exist_ok=True)
    os.chmod(destination, 0o755)
    for source in frontend.rglob("*"):
        relative = source.relative_to(frontend)
        output = destination / relative
        if source.is_symlink():
            raise Refusal("frontend program asset must not be a symlink")
        if source.is_dir():
            output.mkdir(parents=True, exist_ok=True)
            os.chmod(output, 0o755)
        elif source.is_file():
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, output, follow_symlinks=False)
            os.chmod(output, 0o755)
    if inspect_static(settings)["pending"]:
        raise Refusal("static program assets remain pending after collection")
    return {"collected": True}
