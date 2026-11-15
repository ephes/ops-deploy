"""Stub executables that pay macOS's first-exec cost once per run, not once per test.

On macOS the first ``exec`` of a freshly written file costs 0.2-0.6 s (the
kernel and its security policy look at every new executable vnode once); a
second exec of the same inode, or of a hard link to it, costs a few
milliseconds. Many tests put stand-ins for ``systemctl``, ``pg_dump`` and the
like on ``PATH`` and write them anew for every test, so that cost adds up to
minutes.

:func:`install` writes each distinct (content, mode) once per test run into a
cache directory under pytest's base temp directory (shared by all xdist
workers of the run) and gives the test a **hard link** to it at the path it
asked for. The test sees a regular file with the content and mode it wrote:
same path, same ``$0``/``sys.argv[0]``, same directory listing, so the stub
behaves exactly as before. The one visible difference is the link count.

A stub must not be changed in place through its path after :func:`install`
(that would change the shared copy): write a new one with :func:`install`, or
unlink it first. :func:`install` re-checks the cached content on every reuse
and fails loudly if a test did change it.

Outside a pytest session (no cache directory), or across filesystems, it
falls back to writing the file.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

_cache: Path | None = None


def use_cache_dir(directory: Path | None) -> None:
    """Set (``conftest.py``, once per session) or clear the cache directory."""

    global _cache
    if directory is not None:
        directory.mkdir(parents=True, exist_ok=True)
    _cache = directory


def _cached(data: bytes, mode: int) -> Path | None:
    if _cache is None:
        return None
    key = hashlib.sha256(data + b"\0" + oct(mode).encode()).hexdigest()[:40]
    cached = _cache / key
    if cached.exists():
        if cached.read_bytes() != data or cached.stat().st_mode & 0o7777 != mode:
            raise RuntimeError(f"cached stub {cached} was changed in place through a hard link to it")
        return cached
    # Written under a unique name and linked into place: other workers see the whole file or none.
    scratch = _cache / f".{key}.{os.getpid()}.{uuid.uuid4().hex}"
    scratch.write_bytes(data)
    scratch.chmod(mode)
    try:
        os.link(scratch, cached)
    except FileExistsError:
        pass
    finally:
        scratch.unlink()
    return cached


def install(path: Path, content: str | bytes, *, mode: int = 0o755) -> Path:
    """Put an executable with ``content`` at ``path`` (replacing a file there) and return ``path``."""

    data = content.encode() if isinstance(content, str) else content
    cached = _cached(data, mode)
    if cached is not None:
        link = path.with_name(f".{path.name}.{uuid.uuid4().hex}.stub")
        try:
            os.link(cached, link)
        except OSError:  # another filesystem: fall back to a plain write
            pass
        else:
            os.replace(link, path)
            return path
    path.write_bytes(data)
    path.chmod(mode)
    return path
