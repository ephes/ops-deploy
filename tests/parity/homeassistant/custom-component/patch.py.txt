"""Exact public Custom Conversation 1.7.0 ignored-intent compatibility patch.

The upstream selector rejects its own default when an excluded intent is not
currently registered. Exclusion names must remain valid for future integrations.
Only the qualified archive pair is patched; every other source is unchanged.
"""

# Keep this shared original/typed helper byte-identical across formatters.
# fmt: off
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tarfile
import tempfile
from pathlib import Path

VERSION = "1.7.0"
ARCHIVE_SHA256 = "a81433682ab0da8439dddb3eb549ca57c4e5b20d64b6797b2568b524903a0d52"  # pragma: allowlist secret
SOURCE_SHA256 = "72fecc19115c7378d29af7e0c269f4587fbe466a05286ed0a2e739350df02293"  # pragma: allowlist secret
PATCHED_SHA256 = "dd7d7c73a8288dd3db33bec6074dd6f00ca4e21b74b37c66e54e48a34a502de8"  # pragma: allowlist secret
PATCH_ID = "ignored-intent-names-v1"
BEFORE = b"options=intents, multiple=True, sort=True"
AFTER = BEFORE + b", custom_value=True"


def selected(version: str, checksum: str) -> bool:
    return version == VERSION and checksum == ARCHIVE_SHA256


def expected_stamp(version: str, checksum: str) -> str:
    base = version + " " + checksum
    if selected(version, checksum):
        return base + " " + PATCH_ID + " " + PATCHED_SHA256
    return base


def needs_patch(component: str, version: str, checksum: str) -> bool:
    if not selected(version, checksum):
        return False
    path = Path(component) / "config_flow.py"
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            return True
        return hashlib.sha256(path.read_bytes()).hexdigest() != PATCHED_SHA256
    except OSError:
        return True


def prepare(archive: str, version: str, checksum: str) -> bytes | None:
    """Verify the immutable candidate before any managed tree is replaced."""
    if not selected(version, checksum):
        return None
    with open(archive, "rb") as handle:
        if hashlib.file_digest(handle, "sha256").hexdigest() != ARCHIVE_SHA256:
            raise ValueError("Custom Conversation candidate archive mismatch")
    member_name = (
        "custom-conversation-1.7.0/custom_components/custom_conversation/config_flow.py"
    )
    with tarfile.open(archive, "r:gz") as source:
        member = source.getmember(member_name)
        if not member.isfile():
            raise ValueError("Custom Conversation candidate source is not a file")
        content = source.extractfile(member)
        assert content is not None
        with content:
            body = content.read()
    if hashlib.sha256(body).hexdigest() != SOURCE_SHA256 or body.count(BEFORE) != 1:
        raise ValueError("Custom Conversation candidate source mismatch")
    desired = body.replace(BEFORE, AFTER)
    if hashlib.sha256(desired).hexdigest() != PATCHED_SHA256:
        raise ValueError("Custom Conversation candidate patch mismatch")
    return desired


def apply(component: str, desired: bytes | None) -> bool:
    """Replace the managed file from the verified candidate, preserving metadata."""
    if desired is None:
        return False
    path = Path(component) / "config_flow.py"
    if path.is_file() and not path.is_symlink() and path.read_bytes() == desired:
        return False
    current = path.lstat()
    if not stat.S_ISREG(current.st_mode):
        # Callers reconcile a drifted installed tree through their original
        # remove/extract operation first. This is the freshly extracted path.
        raise ValueError("Custom Conversation extracted source is not a file")
    descriptor, temporary = tempfile.mkstemp(prefix=".ops-cc-patch-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(desired)
            os.fchmod(output.fileno(), stat.S_IMODE(current.st_mode))
            info = os.fstat(output.fileno())
            if (info.st_uid, info.st_gid) != (current.st_uid, current.st_gid):
                os.fchown(output.fileno(), current.st_uid, current.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("check", "prepare", "apply"))
    for name in ("archive", "component", "stamp", "version", "checksum"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    wanted = expected_stamp(args.version, args.checksum)
    try:
        observed = Path(args.stamp).read_text().strip()
    except (OSError, UnicodeError):
        observed = None
    needed = observed != wanted or needs_patch(
        args.component, args.version, args.checksum
    )
    desired = (
        prepare(args.archive, args.version, args.checksum)
        if needed and args.action != "check"
        else None
    )
    changed = apply(args.component, desired) if args.action == "apply" else False
    print(
        json.dumps(
            {"needs_install": needed, "expected_stamp": wanted, "changed": changed}
        )
    )


if __name__ == "__main__":
    main()

# fmt: on
