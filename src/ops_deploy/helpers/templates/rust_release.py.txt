"""Decisions of the ``rust_release_binary`` role (pin moves and prune plans).

The role keeps pinned Rust release binaries in ``<install_root>/<version>/``
(``rust/PLAN-foundation.md`` 6.1). The decisions that must never delete a
version still in use live here as plain functions, so they are unit-tested
directly and the pyinfra helper of ops-deploy (F4) can make the same decisions
on the same on-host files.

Everything fails closed: input this module cannot interpret yields an
``unknown`` reason, and a prune plan with an unknown reason removes nothing.
"""

from __future__ import annotations

import base64
import binascii
import posixpath
import re
from typing import Any

try:  # Ansible is not needed for the unit tests of the pure functions.
    from ansible.errors import AnsibleFilterError
except ImportError:  # pragma: no cover - exercised only without ansible-core
    AnsibleFilterError = ValueError  # type: ignore[misc,assignment]

# A release version as it appears in a tag (`<crate>-v<version>`) and as the
# name of its directory: semver core plus an optional pre-release, no build
# metadata. Directories with other names are never pruned.
VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)"
    r"(-[0-9A-Za-z-]+([.][0-9A-Za-z-]+)*)?$"
)
# A consumer name: the pin file name. No dot, so `<consumer>.previous` (the
# rollback pin) can never collide with another consumer's current pin.
CONSUMER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
# A crate name (= binary name = tag prefix).
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# An install root: a normalised absolute path other than "/", plain characters.
ROOT_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._@+-]+$")
PREVIOUS_SUFFIX = ".previous"
DELETED_SUFFIX = " (deleted)"


def rust_release_version_ok(value: Any) -> bool:
    """True when ``value`` is a release version string (a directory name)."""

    return isinstance(value, str) and VERSION_RE.fullmatch(value) is not None


def rust_release_name_ok(value: Any) -> bool:
    """True when ``value`` is a crate name."""

    return isinstance(value, str) and NAME_RE.fullmatch(value) is not None


def rust_release_sha256_ok(value: Any) -> bool:
    """True when ``value`` is a sha256 in 64 lowercase hex digits."""

    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def rust_release_root_ok(value: Any) -> bool:
    """True when ``value`` is a normalised absolute path other than ``/``."""

    if not isinstance(value, str) or not value.startswith("/"):
        return False
    parts = value.split("/")[1:]
    return all(ROOT_COMPONENT_RE.fullmatch(p) and p not in (".", "..") for p in parts)


def rust_release_consumer_ok(value: Any) -> bool:
    """True when ``value`` is a valid consumer (pin file) name."""

    return isinstance(value, str) and CONSUMER_RE.fullmatch(value) is not None


def _parse_pin(content: Any) -> str | None:
    """The version of a pin file's text, or None when it is not exactly one."""

    if not isinstance(content, str):
        return None
    text = content[:-1] if content.endswith("\n") else content
    return text if rust_release_version_ok(text) else None


def rust_release_pin_content(version: str) -> str:
    """The exact bytes of a pin file (and of nothing else): ``<version>\\n``."""

    if not rust_release_version_ok(version):
        raise AnsibleFilterError(f"not a release version: {version!r}")
    return version + "\n"


def rust_release_pin_plan(
    current: Any,
    previous: Any,
    state: str,
    version: str = "",
    previous_override: str = "",
    keep_previous: bool = True,
) -> dict[str, Any]:
    """Where the current and the previous (rollback) pin of one consumer go.

    ``current`` and ``previous`` are the texts of the existing pin files, or
    None when the file does not exist. Returns ``{"current": <version or None>,
    "previous": <version or None>, "error": <reason or "">}``; on an error the
    caller changes nothing.

    - ``present``: the current pin becomes ``version``. If the current pin
      named another version, that version becomes the previous pin, so the
      previous pin always names the version the consumer ran (and verified)
      before the current one. Pinning the version that is already current
      moves nothing.
    - ``absent``: the current pin is removed; with ``keep_previous`` its
      version becomes the previous pin (the last version verified live stays
      installed for a quick switch back), without it both pins go.
    - ``previous_override`` (a version, optional) replaces the automatic
      choice, for a consumer that knows the live version from elsewhere (no
      current pin yet). It is ignored when it equals the new current version.
    """

    if state not in ("present", "absent"):
        return {"current": None, "previous": None, "error": f"state must be present or absent, not {state!r}"}
    if state == "present" and not rust_release_version_ok(version):
        return {"current": None, "previous": None, "error": f"version {version!r} is not a release version"}
    if previous_override and not rust_release_version_ok(previous_override):
        return {
            "current": None,
            "previous": None,
            "error": f"previous {previous_override!r} is not a release version",
        }
    old_current = None
    if current is not None:
        old_current = _parse_pin(current)
        if old_current is None:
            return {"current": None, "previous": None, "error": f"current pin holds {current!r}, not one version"}
    old_previous = None
    if previous is not None:
        old_previous = _parse_pin(previous)
        if old_previous is None:
            return {"current": None, "previous": None, "error": f"previous pin holds {previous!r}, not one version"}

    new_current: str | None
    new_previous: str | None
    if state == "present":
        new_current = version
        if previous_override and previous_override != version:
            new_previous = previous_override
        elif old_current is not None and old_current != version:
            new_previous = old_current
        else:
            new_previous = old_previous
    else:
        new_current = None
        if not keep_previous:
            new_previous = None
        elif previous_override:
            new_previous = previous_override
        elif old_current is not None:
            new_previous = old_current
        else:
            new_previous = old_previous
    return {"current": new_current, "previous": new_previous, "error": ""}


def _protected_version(entry: Any, roots: list[str], name: str) -> tuple[str | None, str]:
    """(version or None, unknown reason or "") for one ``protect`` entry."""

    if not isinstance(entry, str) or not entry:
        return None, f"protect entry {entry!r} is neither a version nor an absolute path"
    if rust_release_version_ok(entry):
        return entry, ""
    if not entry.startswith("/"):
        return None, f"protect entry {entry!r} is neither a version nor an absolute path"
    path = entry[: -len(DELETED_SUFFIX)] if entry.endswith(DELETED_SUFFIX) else entry
    parts = path.split("/")[1:]
    if any(part in ("", ".", "..") for part in parts) or "\n" in path:
        return None, f"protect path {entry!r} is not a normalised absolute path"
    for root in roots:
        prefix = root.rstrip("/") + "/"
        if path.startswith(prefix):
            rest = path[len(prefix):].split("/")
            if len(rest) == 2 and rust_release_version_ok(rest[0]) and not rest[1].startswith("."):
                return rest[0], ""
            return None, f"protect path {entry!r} lies under {root} but not in a version directory"
    if posixpath.basename(path) == name:
        # The binary's name outside every spelling of the install root: an
        # alias (symlink) of the root this play cannot map to a version.
        return None, f"protect path {entry!r} names {name} outside {', '.join(roots)}"
    return None, ""


def rust_release_prune_plan(
    entries: Any,
    pins: Any,
    protect: Any,
    keep_versions: Any,
    roots: Any,
    name: str,
) -> dict[str, Any]:
    """Which version directories a prune keeps and removes.

    - ``entries``: the ``files`` of ``ansible.builtin.find`` over the install
      root (non-recursive, without hidden entries): dicts with ``path``,
      ``mtime``, ``isdir`` and ``islnk``. Only real directories named like a
      version are candidates; everything else is left alone.
    - ``pins``: one dict per entry of ``<root>/.pins`` with ``path``,
      ``isreg`` and ``content`` (the text, or None when unreadable). Every pin
      file counts, the current pins and the ``.previous`` rollback pins alike.
    - ``protect``: versions, or absolute executable paths as
      ``readlink /proc/<pid>/exe`` prints them (a `` (deleted)`` suffix is
      allowed), that the consumer read from the live state.
    - ``roots``: the install root and its resolved spelling.

    Kept: the ``keep_versions`` newest directories by mtime (ties by version
    name, descending), every pinned and every protected version. Any pin or
    protect entry that cannot be interpreted makes the plan ``unknown`` and
    the plan removes nothing.
    """

    if isinstance(keep_versions, bool) or not isinstance(keep_versions, int) or keep_versions < 1:
        raise AnsibleFilterError(f"keep_versions must be an integer >= 1, not {keep_versions!r}")
    if not isinstance(roots, list) or not roots or not all(isinstance(r, str) and r.startswith("/") for r in roots):
        raise AnsibleFilterError(f"roots must be a list of absolute paths, not {roots!r}")
    unknown: list[str] = []

    pinned: set[str] = set()
    for pin in pins if isinstance(pins, list) else [None]:
        if not isinstance(pin, dict):
            unknown.append(f"pin entry {pin!r} is not a file record")
            continue
        label = pin.get("path", "?")
        if not pin.get("isreg"):
            unknown.append(f"pin {label} is not a regular file")
            continue
        version = _parse_pin(pin.get("content"))
        if version is None:
            unknown.append(f"pin {label} does not hold exactly one version")
            continue
        pinned.add(version)

    protected: set[str] = set()
    for entry in protect if isinstance(protect, list) else [protect]:
        version, reason = _protected_version(entry, roots, name)
        if reason:
            unknown.append(reason)
        elif version is not None:
            protected.add(version)

    candidates = []
    for item in entries if isinstance(entries, list) else []:
        if not isinstance(item, dict) or not item.get("isdir") or item.get("islnk"):
            continue
        version = posixpath.basename(str(item.get("path", "")))
        if rust_release_version_ok(version):
            candidates.append((float(item.get("mtime", 0)), version))
    if not isinstance(entries, list):
        unknown.append(f"version listing {entries!r} is not a list")
    # Newest first; equal mtimes by version name, descending, so the plan is
    # deterministic.
    candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)
    versions = [v for _, v in candidates]
    newest = versions[:keep_versions]
    if unknown:
        keep, remove = list(versions), []
    else:
        keep = [v for v in versions if v in newest or v in pinned or v in protected]
        remove = [v for v in versions if v not in keep]
    return {
        "versions": versions,
        "newest": newest,
        "pinned": sorted(pinned),
        "protected": sorted(protected),
        "keep": keep,
        "remove": remove,
        "unknown": unknown,
    }


def rust_release_pin_records(results: Any) -> list[dict[str, Any]]:
    """Pin records for ``rust_release_prune_plan`` from Ansible results.

    ``results`` are the ``results`` of an ``ansible.builtin.slurp`` loop over
    the ``files`` of an ``ansible.builtin.find`` of ``<root>/.pins`` (every
    entry, hidden ones included; the slurp runs only for regular files and
    may fail). A record's ``content`` is None when the file was not read.
    """

    records = []
    for result in results if isinstance(results, list) else []:
        entry = result.get("item", {}) if isinstance(result, dict) else {}
        content = None
        if isinstance(result, dict) and isinstance(result.get("content"), str) and not result.get("failed"):
            try:
                content = base64.b64decode(result["content"], validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                content = None
        records.append(
            {
                "path": entry.get("path", "?") if isinstance(entry, dict) else "?",
                "isreg": bool(entry.get("isreg")) and not entry.get("islnk") if isinstance(entry, dict) else False,
                "content": content,
            }
        )
    if not isinstance(results, list):
        records.append({"path": repr(results), "isreg": False, "content": None})
    return records


class FilterModule:
    """Expose the rust_release_binary decisions to Ansible."""

    def filters(self) -> dict[str, Any]:
        return {
            "rust_release_version_ok": rust_release_version_ok,
            "rust_release_consumer_ok": rust_release_consumer_ok,
            "rust_release_name_ok": rust_release_name_ok,
            "rust_release_root_ok": rust_release_root_ok,
            "rust_release_sha256_ok": rust_release_sha256_ok,
            "rust_release_pin_content": rust_release_pin_content,
            "rust_release_pin_plan": rust_release_pin_plan,
            "rust_release_pin_records": rust_release_pin_records,
            "rust_release_prune_plan": rust_release_prune_plan,
        }
