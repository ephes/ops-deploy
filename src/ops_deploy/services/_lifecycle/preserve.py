"""ops-library's ``restore_preserve_internal`` helper for the restore ports.

``files/preserve.py`` is the role's ``files/preserve.py`` byte for byte
(``tests/test_ops_library_drift.py`` checks it). Host scripts run it as
``python3 -I -c "$PRESERVE_PY" <args>`` (``-I``: nothing from the
working directory or the environment is imported):

- ``--validate-layout <live>... --source <src>``: refuse overlapping live,
  staging and source paths and any pre-restore copy;
- ``<live> --preflight [--keep-live]``: mounts and free space, before the
  writers stop;
- ``<live> [--keep-live]``: keep the live directory as a sibling
  ``<name>.pre-restore-<utc>-<random>`` (rename, or a verified copy across
  filesystems), print ``RESTORE_PRESERVED <json>`` and leave the live
  directory empty unless ``--keep-live``. No path removes a copy.
"""

from __future__ import annotations

from pathlib import Path

PRESERVE_PY = (Path(__file__).parent / "files" / "preserve.py").read_text()

__all__ = ["PRESERVE_PY"]
