"""Photos-only main-ref bundle inside the existing controller run lifetime.

The shared resolver remains the sole Main/FF authority. Its already-bound
bundle has a remote-tracking ref; the original Photos role consumes a local
main ref. This derived bundle changes only that representation and remains
alive through operation execution. No owner checkout or shared mirror changes.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class PhotosBundleError(RuntimeError):
    pass


@contextmanager
def photos_main_bundle(source_bundle: Path, revision: str, work_root: Path) -> Iterator[Path]:
    """Repackage only the exact single Main ref supplied by the normal resolver."""
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise PhotosBundleError("photos_bundle_revision_invalid")
    if not source_bundle.is_absolute() or not work_root.is_absolute():
        raise PhotosBundleError("photos_bundle_paths_must_be_absolute")
    info = work_root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise PhotosBundleError("photos_bundle_needs_private_run_directory")
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    with tempfile.TemporaryDirectory(prefix="photos-main-", dir=work_root) as directory:
        root = Path(directory)

        def git(*args: str) -> str:
            try:
                result = subprocess.run(
                    ["/usr/bin/git", "-C", str(root), "-c", "core.hooksPath=/dev/null", *args],
                    env=env,
                    capture_output=True,
                    timeout=120,
                )
            except (OSError, subprocess.TimeoutExpired):
                raise PhotosBundleError("photos_bundle_git_unavailable") from None
            if result.returncode:
                raise PhotosBundleError("photos_bundle_git_failed")
            try:
                return result.stdout.decode("ascii").strip()
            except UnicodeDecodeError:
                raise PhotosBundleError("photos_bundle_ref_unavailable") from None

        expected = revision + " refs/remotes/origin/main"
        if git("bundle", "list-heads", str(source_bundle)) != expected:
            raise PhotosBundleError("photos_bundle_source_ref_mismatch")
        git("init", "--bare", "--quiet", "--template=")
        git("fetch", "--quiet", "--no-tags", str(source_bundle), "refs/remotes/origin/main")
        if git("rev-parse", "--verify", "FETCH_HEAD^{commit}") != revision:
            raise PhotosBundleError("photos_bundle_source_revision_mismatch")
        git("update-ref", "refs/heads/main", revision, "0" * 40)
        destination = root / "source.bundle"
        git("bundle", "create", str(destination), "refs/heads/main")
        git("bundle", "verify", str(destination))
        if git("bundle", "list-heads", str(destination)) != revision + " refs/heads/main":
            raise PhotosBundleError("photos_bundle_derived_ref_mismatch")
        yield destination
