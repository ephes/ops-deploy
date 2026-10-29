#!/usr/bin/env python3
"""Validate restore archive members before anything is extracted.

Every member must sit below one of the allowed top-level directories, use a
relative path without "..", appear only once, and be a regular file, directory, symlink or
hardlink; a top-level entry itself must be a directory. Symlink and hardlink
targets, resolved through all symlinks in the archive, must stay inside the
member's own top-level directory, no hardlink may point (directly or through
other hardlinks) at a symlink, and no member may be stored below a symlink
member.
Prints ``ARCHIVE_TOPS <json list>`` with the top-level directories present.
"""
import argparse
import json
import posixpath
import sys
import tarfile


def clean(name):
    if name.startswith("/") or "\\" in name:
        raise ValueError(f"absolute or non-POSIX member path: {name!r}")
    parts = [part for part in name.split("/") if part not in ("", ".")]
    if not parts or ".." in parts:
        raise ValueError(f"member path escapes the archive root: {name!r}")
    return parts


def inside(target, top):
    return target is not None and (target == top or target.startswith(top + "/"))


def resolve(name, links, depth=0):
    """Resolve a member path through the archive's own symlinks, like realpath.

    Returns None when the path climbs above the extraction directory.
    """
    if depth > 40:
        raise ValueError(f"symlink loop at {name!r}")
    resolved = []
    for part in name.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                return None
            resolved.pop()
            continue
        resolved.append(part)
        current = "/".join(resolved)
        if current in links:
            target = resolve(
                posixpath.join(posixpath.dirname(current), links[current]),
                links,
                depth + 1,
            )
            if target is None:
                return None
            resolved = [part for part in target.split("/") if part]
    return "/".join(resolved)


def validate(path, allowed):
    tops = []
    links = {}
    hardlinks = []
    names = set()
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            parts = clean(member.name)
            top = parts[0]
            if top not in allowed:
                raise ValueError(
                    f"member {member.name!r} is outside the allowed directories "
                    f"{sorted(allowed)}"
                )
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError(f"unsupported member type: {member.name!r}")
            if len(parts) == 1 and not member.isdir():
                raise ValueError(f"top-level member is not a directory: {member.name!r}")
            name = "/".join(parts)
            # A repeated name makes the later member replace the earlier one
            # on extraction, so checks keyed by name would see the wrong one.
            if name in names:
                raise ValueError(f"duplicate member: {member.name!r}")
            if member.issym():
                if member.linkname.startswith("/"):
                    raise ValueError(f"absolute symlink target: {member.name!r}")
                links[name] = member.linkname
            elif member.islnk():
                hardlinks.append((name, "/".join(clean(member.linkname))))
            names.add(name)
            if top not in tops:
                tops.append(top)
    for name in names:
        parts = name.split("/")
        for depth in range(1, len(parts)):
            if "/".join(parts[:depth]) in links:
                raise ValueError(f"member stored below a symlink: {name!r}")
    for name in links:
        top = name.split("/")[0]
        # Resolve through every symlink in the archive, so a chain of links
        # cannot leave the tree even when each link looks harmless alone.
        if not inside(resolve(name, links), top):
            raise ValueError(f"symlink leaves {top}/: {name!r}")
    hardlink_targets = dict(hardlinks)
    for name, target in hardlinks:
        top = name.split("/")[0]
        if not inside(resolve(target, links), top):
            raise ValueError(f"hardlink leaves {top}/: {name!r}")
        # A hardlink to a symlink extracts as a copy of that symlink at the
        # hardlink's own location, where its relative target means something
        # else. Follow hardlink chains and refuse any that ends at a symlink.
        seen = {name}
        while target in hardlink_targets and target not in seen:
            seen.add(target)
            target = hardlink_targets[target]
        if target in links:
            raise ValueError(f"hardlink to a symlink: {name!r}")
    if not tops:
        raise ValueError("archive has no members")
    return tops


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument("--allow-top", action="append", required=True)
    args = parser.parse_args()
    try:
        tops = validate(args.archive, set(args.allow_top))
    except (OSError, tarfile.TarError, ValueError) as error:
        print(f"archive validation failed: {error}", file=sys.stderr)
        return 1
    print("ARCHIVE_TOPS " + json.dumps(tops))
    return 0


if __name__ == "__main__":
    sys.exit(main())
