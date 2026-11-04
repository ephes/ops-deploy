"""Path and name types shared by the backup and restore ports.

The host scripts create, copy, chown and remove below these paths, so a path
must be spelled canonically: no ``/./``, ``/../``, ``//`` or trailing ``/``
that resolves somewhere else, and never ``/`` itself.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated

from pydantic import AfterValidator, Field


def _canonical(value: str) -> str:
    path = PurePosixPath(value)
    if value != str(path) or value.startswith("//") or ".." in path.parts or len(path.parts) < 2:
        raise ValueError(f"{value!r} must be a canonical absolute path other than /")
    return value


CanonicalPath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/+-]*$"), AfterValidator(_canonical)]
Prefix = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
Hostname = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
FileMode = Annotated[str, Field(pattern=r"^0?[0-7]{3}$")]
# ``latest``, or an archive name directly below the search root.
ArchiveName = Annotated[str, Field(pattern=r"^(latest|[A-Za-z0-9._+-]+\.tar\.gz)$")]
Url = Annotated[str, Field(pattern=r"^https?://[A-Za-z0-9.:/_-]+$")]
# ops-library's galaxy version (``unknown`` when the controller has none).
LibraryVersion = Annotated[str, Field(pattern=r"^[A-Za-z0-9._+-]+$")]

__all__ = ["ArchiveName", "CanonicalPath", "FileMode", "Hostname", "LibraryVersion", "Prefix", "Url"]
