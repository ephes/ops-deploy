"""Real owned Git admission; simulated root ownership/ACL metadata only."""

from __future__ import annotations

import os
import runpy
import subprocess
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

MODULE = runpy.run_path(str(files("ops_deploy.services.daybook_photos_offload").joinpath("files/photos_source.py")))


def git(path: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(path), *args],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
    ).stdout.strip()


def as_root(info: Any) -> Any:
    if info is None:
        return None
    return SimpleNamespace(
        **{
            name: (0 if name == "st_uid" else getattr(info, name))
            for name in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid")
        }
    )


BaseProbes: Any = MODULE["PhotosProbes"]


class Probes(BaseProbes):  # type: ignore[misc]
    def __init__(self, data: Any) -> None:
        self.data = data
        self.contexts: list[tuple[list[str], bool]] = []
        self.acls: set[str] = set()

    def info(self, path: Any) -> Any:
        return as_root(MODULE["metadata"](path))

    def fstat(self, descriptor: int) -> Any:
        return as_root(os.fstat(descriptor))

    def acl_free(self, path: Any) -> bool:
        return str(path) not in self.acls

    def run(self, argv: list[str], *, user: bool = False, managed: bool = False) -> Any:
        self.contexts.append((argv, user))
        return subprocess.run(
            argv,
            capture_output=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
        )


@pytest.fixture
def checkout(tmp_path: Path) -> Any:
    root = tmp_path / "daybook"
    root.mkdir()
    git(root, "init", "--quiet", "--template=", "-b", "main")
    (root / "source.py").write_text("# owned synthetic code; never imported\n")
    (root / ".gitignore").write_text(".venv/\n")
    git(root, "add", ".")
    git(root, "-c", "user.name=Owned", "-c", "user.email=owned@example.test", "commit", "-qm", "owned")
    bundle = tmp_path / "source.bundle"
    git(root, "remote", "add", "origin", str(bundle))
    attestation = tmp_path / "managed-v1"
    attestation.write_bytes(MODULE["ATTESTATION"])
    attestation.chmod(0o600)
    data = {
        "checkout": str(root),
        "attestation": str(attestation),
        "bundle": str(bundle),
        "revision": git(root, "rev-parse", "HEAD"),
    }
    return SimpleNamespace(root=root, attestation=attestation, data=data, probes=Probes(data))


def test_real_git_exact_current_and_clean_old_revision_are_distinct(checkout: Any) -> None:
    c = checkout
    assert MODULE["check_checkout"](c.data, c.probes) is True
    c.data["revision"] = "a" * 40
    assert MODULE["check_checkout"](c.data, c.probes) is False
    assert any(user and "--porcelain=v1" in argv for argv, user in c.probes.contexts)
    assert any(user and "get-url" in argv for argv, user in c.probes.contexts)


@pytest.mark.parametrize(
    "fault",
    [
        "missing-attestation",
        "attestation-bytes",
        "attestation-mode",
        "attestation-link",
        "dirty",
        "config",
        "index",
        "origin",
        "ignored",
        "hardlink",
        "acl",
        "venv-link",
    ],
)
def test_original_fail_closed_preexisting_admission_faults(checkout: Any, fault: str) -> None:
    c = checkout
    if fault == "missing-attestation":
        c.attestation.unlink()
    elif fault == "attestation-bytes":
        c.attestation.write_text("wrong existing attestation\n")
    elif fault == "attestation-mode":
        c.attestation.chmod(0o644)
    elif fault == "attestation-link":
        c.attestation.unlink()
        c.attestation.symlink_to(c.root / "source.py")
    elif fault == "dirty":
        (c.root / "source.py").write_text("# changed\n")
    elif fault == "config":
        git(c.root, "config", "core.fsmonitor", "/owned/untrusted")
    elif fault == "index":
        git(c.root, "update-index", "--skip-worktree", "source.py")
    elif fault == "origin":
        git(c.root, "remote", "set-url", "origin", "/wrong/bundle")
    elif fault == "ignored":
        (c.root / ".git/info").mkdir(exist_ok=True)
        (c.root / ".git/info/exclude").write_text("other/\n")
        (c.root / "other").mkdir()
        (c.root / "other/private").write_text("owned fixture")
    elif fault == "hardlink":
        os.link(c.root / "source.py", c.root.parent / "source-hardlink")
    elif fault == "acl":
        c.probes.acls.add(str(c.root / "source.py"))
    elif fault == "venv-link":
        (c.root / ".venv").symlink_to(c.root.parent)
    with pytest.raises(MODULE["PhotosSourceError"]):
        MODULE["check_checkout"](c.data, c.probes)


def test_privileged_walk_never_descends_into_gui_owned_environment(checkout: Any) -> None:
    c = checkout
    env = c.root / ".venv"
    env.mkdir()
    (env / "untrusted-user-file").write_text("owned environment fixture")
    # Unsafe mode/ACL is deliberately confined to environment contents, which
    # the original role excludes from every privileged tree walk.
    (env / "untrusted-user-file").chmod(0o666)
    c.probes.acls.add(str(env / "untrusted-user-file"))
    assert MODULE["check_checkout"](c.data, c.probes) is True
