"""Protected Inbox source proof helpers, before managed checkout replacement.

Inputs are bound controller source declarations. Git diagnostics and source
names stay internal; no importer, Journal, audio or runtime record is opened.
"""

import hashlib
import os
import pathlib
import re
import stat
import subprocess


class InboxSourceError(RuntimeError):
    pass


def git(directory, *arguments, timeout=120):
    environment = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        result = subprocess.run([
            "/usr/bin/git", "--no-optional-locks", "-c", "core.hooksPath=/dev/null",
            "-c", "core.fsmonitor=false", "-C", str(directory), *arguments,
        ], capture_output=True, env=environment, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise InboxSourceError("inbox_source_git_unavailable") from None
    return result


def installed_revision(checkout):
    checkout = pathlib.Path(checkout)
    info = checkout.lstat() if checkout.exists() or checkout.is_symlink() else None
    if info is None:
        return None
    if not stat.S_ISDIR(info.st_mode):
        raise InboxSourceError("inbox_source_checkout_unsafe")
    marker = checkout / ".git"
    if not marker.exists() and not marker.is_symlink():
        return None
    result = git(checkout, "rev-parse", "HEAD")
    revision = result.stdout.decode("ascii", "replace").strip()
    if result.returncode or not re.fullmatch(r"[0-9a-f]{40}", revision):
        # Original refuses unreadable HEAD before deleting the protected FDA
        # interpreter. No replacement/repair occurs inside this probe.
        raise InboxSourceError("inbox_source_installed_revision_unreadable")
    return revision


def require_valid_bundle(bundle, revision, checkout):
    path = pathlib.Path(bundle)
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise InboxSourceError("inbox_source_bundle_unavailable") from None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise InboxSourceError("inbox_source_bundle_unsafe")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise InboxSourceError("inbox_source_revision_invalid")
    directory = pathlib.Path(checkout)
    # list-heads works outside a repository. An existing checkout also requires
    # original object/prerequisite validation before its protected tree changes.
    context = directory if (directory / ".git").exists() else path.parent
    heads = git(context, "bundle", "list-heads", str(path))
    if heads.returncode or not any(line.startswith(revision.encode() + b" refs/") for line in heads.stdout.splitlines()):
        raise InboxSourceError("inbox_source_bundle_wrong_revision")
    if (directory / ".git").exists() and git(directory, "bundle", "verify", str(path)).returncode:
        raise InboxSourceError("inbox_source_bundle_invalid")


def require_clean_checkout(checkout):
    checked = git(checkout, "status", "--porcelain", "--untracked-files=all")
    if checked.returncode or checked.stdout.strip():
        raise InboxSourceError("inbox_source_checkout_modified")


def code_matches(checkout, expected):
    """Read only declared code/lock files, not arbitrary checkout contents."""
    root = pathlib.Path(checkout)
    if not expected or not {"pyproject.toml", "uv.lock"}.issubset(expected):
        raise InboxSourceError("inbox_source_manifest_incomplete")
    for name, digest in expected.items():
        path = pathlib.PurePosixPath(name)
        if (path.is_absolute() or ".." in path.parts
                or not (name.startswith("src/daybook/") and name.endswith(".py")
                        or name in {"pyproject.toml", "uv.lock", ".python-version"})
                or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise InboxSourceError("inbox_source_manifest_invalid")
    for name, digest in expected.items():
        target = root / pathlib.PurePosixPath(name)
        if any(parent.is_symlink() for parent in (target, *target.parents)):
            raise InboxSourceError("inbox_source_code_linked")
        try:
            fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return False
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 8 * 1024 * 1024:
                raise InboxSourceError("inbox_source_code_unsafe")
            hashed = hashlib.sha256()
            remaining = 8 * 1024 * 1024 + 1
            while remaining:
                body = os.read(fd, min(65536, remaining))
                if not body:
                    break
                hashed.update(body)
                remaining -= len(body)
            if remaining == 0 or hashed.hexdigest() != digest:
                return False
        finally:
            os.close(fd)
    return True


def require_git(directory, *arguments):
    result = git(directory, *arguments, timeout=None)
    if result.returncode:
        raise InboxSourceError("inbox_source_git_failed")
    return result.stdout


def converge_checkout(data, probes):
    """Original bundle proof -> drifted checkout replacement -> exact source.

    Explicit managed work. The full host entrypoint binds the original layout
    and private transfer before calling this function. It never runs in a fact.
    """
    import shutil
    from ops_inbox_controls import require_inbox_quiescent

    require_inbox_quiescent(data, probes)
    checkout = pathlib.Path(data["checkout"])
    bundle = pathlib.Path(data["bundle"])
    revision = data["revision"]
    previous = installed_revision(checkout)
    # Both proofs precede deleting a drifted protected interpreter. Preserve
    # the original limitation: bundle pack corruption is detected on fetch,
    # after replacement; this is not a transactional rollback promise.
    require_valid_bundle(bundle, revision, checkout)
    if previous is not None and previous != revision:
        shutil.rmtree(checkout)
    if not (checkout / ".git").exists():
        require_git(checkout.parent, "init", "--quiet", "--template=", str(checkout))
    require_git(checkout, "fetch", "--quiet", "--no-tags", str(bundle), "+refs/*:refs/bundle/*")
    require_git(checkout, "checkout", "--detach", revision)
    require_clean_checkout(checkout)
    if installed_revision(checkout) != revision:
        raise InboxSourceError("inbox_source_installed_revision_mismatch")
