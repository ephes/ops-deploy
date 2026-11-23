"""Inspect owned venv distribution metadata without importing Paperless/Django."""

import importlib.metadata
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


GUNICORN_MIN_MAJOR = 23


# A PEP 440 version (packaging's VERSION_PATTERN, without importing packaging).
_PEP440 = re.compile(
    r"v?(?:(?P<epoch>[0-9]+)!)?(?P<major>[0-9]+)(?:\.[0-9]+)*"
    r"(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?"
    r"(?:-[0-9]+|[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?"
    r"(?:[-_.]?dev[-_.]?[0-9]*)?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?",
    re.IGNORECASE | re.ASCII,
)


def _valid_version(version):
    # Missing Version metadata reads as None (Python 3.14).
    return _PEP440.fullmatch(version.strip()) if isinstance(version, str) else None


def _major_at_least(version, minimum):
    match = _valid_version(version)
    return bool(match) and int(match["epoch"] or 0) == 0 and int(match["major"]) >= minimum


def inspect_runtime(release_dir):
    if not isinstance(release_dir, str) or not release_dir.startswith("/"):
        raise ValueError("expected an absolute release directory")
    application = False
    try:
        package = importlib.metadata.distribution("paperless-ngx")
    except importlib.metadata.PackageNotFoundError:
        package = None
    if package is not None:
        raw = package.read_text("direct_url.json")
        if raw is not None:
            try:
                direct = json.loads(raw)
            except (ValueError, RecursionError):
                direct = None
            if isinstance(direct, dict) and isinstance(direct.get("url"), str):
                url = urlsplit(direct["url"])
                editable = direct.get("dir_info")
                application = (
                    package.version == "3.5.1" and url.scheme == "file" and not url.netloc
                    and not url.query and not url.fragment and unquote(url.path) == release_dir
                    and isinstance(editable, dict) and editable.get("editable") is True
                    and (Path(release_dir) / "src/paperless/__init__.py").is_file()
                    and (Path(release_dir) / "src/manage.py").is_file()
                )
    supporting = True
    # uv pip check does not select optional extras. The original editable
    # installation explicitly selects postgres, so inspect those distributions
    # too without importing a database driver or opening a connection.
    for name, expected in (("psycopg", "3.3.4"), ("psycopg-c", "3.3.4"), ("psycopg-pool", "3.3.3")):
        try:
            if importlib.metadata.version(name) != expected:
                application = False
        except importlib.metadata.PackageNotFoundError:
            application = False
    gunicorn_repair = False
    for name in ("gunicorn", "whitenoise", "setproctitle", "fido2"):
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            supporting = False
            continue
        if name == "fido2" and installed != "1.1.3":
            supporting = False
        # The unit passes --forwarder-headers=, which gunicorn 22 and older refuse.
        if name == "gunicorn" and not _major_at_least(installed, GUNICORN_MIN_MAJOR):
            supporting = False
            # Missing or malformed (not PEP 440) version metadata: only a
            # targeted reinstall replaces it (python_runtime.install_commands);
            # a valid older release takes the normal upgrade.
            gunicorn_repair = _valid_version(installed) is None
    return {
        "python": sys.version_info[:2] == (3, 14),
        "application": application,
        "supporting": supporting,
        "gunicorn_repair": gunicorn_repair,
    }


def main():
    try:
        body = sys.stdin.buffer.read(65537)
        if len(body) > 65536:
            raise ValueError("runtime payload exceeds size limit")
        settings = json.loads(body)
        if not isinstance(settings, dict) or set(settings) != {"release_dir"}:
            raise ValueError("invalid runtime payload")
        result = inspect_runtime(settings["release_dir"])
    except (ValueError, OSError, RecursionError):
        print("Paperless runtime metadata inspection refused", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
