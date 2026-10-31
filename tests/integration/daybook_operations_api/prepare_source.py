"""Validate the private fixture checkout locally, without fetching or printing it."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

DAYBOOK = "45ac5a62fafef66e8c8fb16222362f075b326f7d"
OLD = "ec46a28fbeb33bc4fee924f68e5909832beca28e"


def validate_source(path: Path, revision: str = DAYBOOK, old: str = OLD) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir() or "," in str(path):
        raise ValueError("fixture_source_path")
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or not re.fullmatch(r"[0-9a-f]{40}", old):
        raise ValueError("fixture_source_revision")
    if not (path / ".git").is_dir() or (path / ".git").is_symlink():
        raise ValueError("fixture_source_repository")
    if (path / ".git/objects/info/alternates").exists():
        raise ValueError("fixture_source_alternates")
    env = {"PATH": os.environ["PATH"], "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}

    def git(*args: str, optional: bool = False) -> bytes:
        result = subprocess.run(
            ["git", "-c", "safe.directory=" + str(path), "-C", str(path), *args],
            capture_output=True,
            timeout=15,
            env=env,
        )
        if result.returncode and not (optional and result.returncode == 1):
            raise ValueError("fixture_source_git_refused")
        if len(result.stdout) > 1048576:
            raise ValueError("fixture_source_output_bound")
        return result.stdout.strip()

    if git("rev-parse", "HEAD").decode() != revision or git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("fixture_source_not_exact_clean")
    git("cat-file", "-e", old + ":src/daybook/operations_protocol.py")
    if git("config", "--local", "--get-regexp", r"(extraheader|credential|sshcommand|include)", optional=True):
        raise ValueError("fixture_source_authorization")
    if git("remote", "get-url", "origin") not in (
        b"https://github.com/ephes/daybook",
        b"https://github.com/ephes/daybook.git",
    ):
        raise ValueError("fixture_source_origin")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("fixture_source_argument")
        validate_source(Path(sys.argv[1]))
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit("fixed private source preflight refused") from None
    print("Fixed private source identity and credential-free checkout verified")
