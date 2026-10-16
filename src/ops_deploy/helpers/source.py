"""Record which commit a deploy shipped.

A deploy from a git source (:mod:`ops_deploy.core.git_source`) writes the
commit to a file on the host; a deploy from a local working tree, which no
commit describes, removes it. Rewriting the same commit is no change, so a
re-run of the same ref stays a no-op.
"""

from __future__ import annotations

import re
from io import StringIO
from pathlib import PurePosixPath

from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files

from ops_deploy.core.git_source import COMMIT_PATTERN

# Inside the site: ``sync_tree`` never transfers or deletes ``.ops-deploy-*``.
SOURCE_RECORD = ".ops-deploy-source"


def record_source(site_path: PurePosixPath, commit: str | None, *, user: str, group: str) -> OperationMeta:
    """Write ``commit`` to ``site_path/.ops-deploy-source``, or remove the file when ``None``."""

    path = str(site_path / SOURCE_RECORD)
    if commit is None:
        return files.file(name="Forget the deployed commit (local source)", path=path, present=False)
    if not re.match(COMMIT_PATTERN, commit):
        raise ValueError("commit must be a full 40-character commit id")
    return files.put(
        name="Record the deployed commit",
        src=StringIO(f"{commit}\n"),
        dest=path,
        user=user,
        group=group,
        mode="0644",
    )
