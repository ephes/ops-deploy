"""Read-only planning probe: do the installed packages already satisfy the extra specs?

Runs as the service user with the Home Assistant virtualenv's Python. Reads
package metadata and the constraint files only; never installs, never runs uv
and prints only a fixed status. ``current`` is true only when every spec, every
dependency it pulls in (with markers and extras) and every applicable
constraint is satisfied by an installed distribution, which is when
``uv pip install`` leaves the environment unchanged. Anything it cannot decide
reports ``current: false``, so the dry run lists the install as a change.
"""

import json
import sys


def satisfied(specs, constraint_files):
    try:
        from importlib import metadata

        from packaging.requirements import Requirement
        from packaging.utils import canonicalize_name
        from packaging.version import Version
    except ImportError:
        return False
    installed = {}
    for dist in metadata.distributions():
        name = dist.metadata["Name"]
        if name:
            key = canonicalize_name(name)
            if key in installed:
                return False  # Duplicate metadata: UV would reinstall it.
            installed[key] = dist
    constraints = {}
    for path in constraint_files:
        with open(path, encoding="utf-8") as stream:
            for raw in stream:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                requirement = Requirement(line)
                if line.startswith("-") or requirement.url:
                    return False
                constraints.setdefault(canonicalize_name(requirement.name), []).append(requirement)
    queue = []
    for spec in specs:
        if spec.startswith("-"):
            return False
        requirement = Requirement(spec)
        if requirement.url:
            return False
        if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
            queue.append(requirement)
    seen = set()
    while queue:
        requirement = queue.pop()
        name = canonicalize_name(requirement.name)
        dist = installed.get(name)
        if dist is None:
            return False
        version = Version(dist.version)
        if not requirement.specifier.contains(version, prereleases=True):
            return False
        for constraint in constraints.get(name, ()):
            if constraint.marker is not None and not constraint.marker.evaluate({"extra": ""}):
                continue
            if not constraint.specifier.contains(version, prereleases=True):
                return False
        for extra in sorted({""} | {canonicalize_name(item) for item in requirement.extras}):
            if (name, extra) in seen:
                continue
            seen.add((name, extra))
            for line in dist.requires or ():
                dependency = Requirement(line)
                if dependency.url:
                    return False
                if dependency.marker is None or dependency.marker.evaluate({"extra": extra}):
                    queue.append(dependency)
    return True


def main():
    try:
        payload = json.load(sys.stdin)
        specs, constraint_files = payload["specs"], payload["constraints"]
        if not all(isinstance(item, str) for item in [*specs, *constraint_files]):
            raise ValueError
        current = satisfied(specs, constraint_files)
    except Exception:
        print(json.dumps({"success": False}))
        raise SystemExit(1) from None
    print(json.dumps({"success": True, "current": bool(current)}))


if __name__ == "__main__":
    main()
