"""Inspect owned venv distribution metadata without importing Paperless/Django."""

import importlib.metadata
import json
from pathlib import Path
import sys
from urllib.parse import unquote, urlsplit


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
                    package.version == "3.2.1" and url.scheme == "file" and not url.netloc
                    and not url.query and not url.fragment and unquote(url.path) == release_dir
                    and isinstance(editable, dict) and editable.get("editable") is True
                    and (Path(release_dir) / "src/paperless/__init__.py").is_file()
                    and (Path(release_dir) / "src/manage.py").is_file()
                )
    supporting = True
    # uv pip check does not select optional extras. The original editable
    # installation explicitly selects postgres, so inspect those distributions
    # too without importing a database driver or opening a connection.
    for name, expected in (("psycopg", "3.3.4"), ("psycopg-c", "3.3.4"), ("psycopg-pool", "3.3.1")):
        try:
            if importlib.metadata.version(name) != expected:
                application = False
        except importlib.metadata.PackageNotFoundError:
            application = False
    for name in ("gunicorn", "whitenoise", "setproctitle", "fido2"):
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            supporting = False
            continue
        if name == "fido2" and installed != "1.1.3":
            supporting = False
    return {"python": sys.version_info[:2] == (3, 14), "application": application, "supporting": supporting}


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
