#!/usr/bin/env python3
"""Decide which listed stray certbot config trees may be removed.

Input (JSON in CERTBOT_STRAY_INPUT): {"stray": [...], "protected": [...],
"config_dir": "..."}. Output (JSON on stdout): {"remove": [...], "skipped": [...],
"refused": [...]}. Nothing is deleted here. Any unexpected error exits non-zero.

Instead of tracing how a live tree could depend on a listed path, the guard
only accepts live trees in which every path is literal, so that plain string
containment is exact:

- a listed path, as given or resolved, must not be equal to, inside or above a
  protected dir (as given or resolved);
- it must be a real directory with a real renewal/ directory;
- each existing protected dir must be its own real path (no symlink in it or
  above it);
- the only symlinks allowed in a protected tree are certbot's lineage links,
  `<root>/live/<name>/{cert,chain,fullchain,privkey}.pem` pointing exactly at
  `../../archive/<name>/<same>N.pem`;
- in every protected tree's renewal/*.conf, each value containing `/` must be
  an `https://` URL or a literal absolute path of [A-Za-z0-9._/-] without `.` or
  `..` segments, inside the protected dirs.

Anything else, or an unreadable file or tree, refuses every listed path.
"""

import json
import os
import re
import sys

LINK_NAMES = ("cert", "chain", "fullchain", "privkey")
SAFE_PATH = re.compile(r"/[A-Za-z0-9._/-]+\Z")
URL = re.compile(r"https://\S+\Z")


def overlaps(a, b):
    """True when a and b are equal or one contains the other."""
    if a == b or a == "/" or b == "/":
        return True
    return a.startswith(b.rstrip("/") + "/") or b.startswith(a.rstrip("/") + "/")


def inside(path, roots):
    return any(path == root or path.startswith(root + "/") for root in roots)


def literal_path(value):
    if not SAFE_PATH.match(value) or value.endswith("/"):
        return False
    return not any(part in (".", "..") for part in value.split("/")[1:])


def allowed_link(root, entry):
    relative = os.path.relpath(entry, root).split(os.sep)
    if len(relative) != 3 or relative[0] != "live":
        return False
    lineage, name = relative[1], relative[2]
    stem = name[: -len(".pem")] if name.endswith(".pem") else ""
    if stem not in LINK_NAMES:
        return False
    pattern = re.escape(f"../../archive/{lineage}/{stem}") + r"[0-9]+\.pem\Z"
    return re.match(pattern, os.readlink(entry)) is not None


def check_live_trees(roots, problems):
    for root in roots:
        if not os.path.lexists(root):
            continue
        if os.path.realpath(root) != root:
            problems.append(f"live certbot dir {root} is not its own real path")
            continue

        def onerror(error, root=root):
            problems.append(f"cannot read {root}: {error}")

        for current, dirs, files in os.walk(root, onerror=onerror, followlinks=False):
            for name in dirs + files:
                entry = os.path.join(current, name)
                if not os.path.islink(entry):
                    continue
                try:
                    if not allowed_link(root, entry):
                        problems.append(
                            f"unexpected symlink {entry} in a live certbot dir"
                        )
                except OSError as error:
                    problems.append(f"cannot read link {entry}: {error}")


def check_renewal_configs(roots, config_dir, problems):
    for root in roots:
        renewal = os.path.join(root, "renewal")
        if not os.path.lexists(renewal) and root != config_dir:
            continue
        try:
            names = sorted(n for n in os.listdir(renewal) if n.endswith(".conf"))
        except OSError as error:
            problems.append(f"cannot list {renewal}: {error}")
            continue
        if root == config_dir and not names:
            problems.append(f"no renewal configuration in {renewal}")
        for name in names:
            conf = os.path.join(renewal, name)
            try:
                with open(conf, encoding="utf-8") as handle:
                    lines = handle.read().splitlines()
            except (OSError, UnicodeDecodeError) as error:
                problems.append(f"cannot read {conf}: {error}")
                continue
            for line in lines:
                text = line.strip()
                if not text or text.startswith("#") or "/" not in text:
                    continue
                value = text.split("=", 1)[1].strip() if "=" in text else text
                if URL.match(value):
                    continue
                if not (literal_path(value) and inside(value, roots)):
                    problems.append(
                        f"{conf} has a value that is not a literal live path: {line!r}"
                    )


def main():
    data = json.loads(os.environ["CERTBOT_STRAY_INPUT"])
    stray = data["stray"]
    protected = data["protected"]
    config_dir = data["config_dir"]

    problems = []
    check_live_trees(protected, problems)
    check_renewal_configs(protected, config_dir, problems)

    result = {"remove": [], "skipped": [], "refused": []}
    for path in stray:
        reasons = []
        resolved = os.path.realpath(path)
        for root in protected:
            for given, other in ((path, root), (resolved, os.path.realpath(root))):
                if overlaps(given, other):
                    reasons.append(f"overlaps live certbot dir {root}")
        if not os.path.lexists(path) and not reasons:
            result["skipped"].append(path)
            continue
        if os.path.islink(path) or not os.path.isdir(path):
            reasons.append("not a real directory")
        renewal = os.path.join(path, "renewal")
        if os.path.islink(renewal) or not os.path.isdir(renewal):
            reasons.append("has no real renewal/ directory")
        reasons.extend(problems)
        if reasons:
            result["refused"].append({"path": path, "reasons": sorted(set(reasons))})
        else:
            result["remove"].append(path)
    json.dump(result, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
