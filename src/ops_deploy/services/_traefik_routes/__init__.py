"""Writes and removals of Traefik dynamic files that services make outside ``traefik_route``.

Both refuse, through :func:`ops_deploy.helpers.traefik.guarded`, while a Traefik
transaction holds its host lock, and run the guard only when they change something
(an unchanged deploy stays free of changes). The files are root's, ``0644`` unless
``mode`` says otherwise. Lives outside the size-capped shared layer.
"""

from __future__ import annotations

from collections.abc import Generator
from io import StringIO
from typing import Any

from pyinfra.api import operation
from pyinfra.operations import files

from ops_deploy.helpers.traefik import guarded


@operation()
def route_put(src: str, dest: str, mode: str = "0644", create_remote_dir: bool = True) -> Generator[Any, None, None]:
    """``files.put`` of the text ``src`` to the dynamic file ``dest``, refused while a transaction holds the lock."""

    yield from guarded(
        files.put._inner(
            src=StringIO(src), dest=dest, user="root", group="root", mode=mode, create_remote_dir=create_remote_dir
        )
    )


@operation()
def route_absent(path: str) -> Generator[Any, None, None]:
    """Remove the dynamic file ``path`` if present, refused while a transaction holds the lock."""

    yield from guarded(files.file._inner(path=path, present=False))
