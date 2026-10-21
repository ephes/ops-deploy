"""Print the `--exclude <crate>` arguments of the default Rust CI job.

PLAN-foundation.md section 3: a workspace member that needs system build
dependencies the CI runner image does not have is listed in
`[workspace.metadata.ci] exclude` of `rust/Cargo.toml` and left out of the
default `rust` job (and `just rust-check`) with `--workspace --exclude
<crate>`. This script reads the JSON of `cargo metadata --format-version 1
--no-deps` (a file argument, or stdin) and prints the arguments on one line,
separated by single spaces (an empty line when nothing is excluded). Every
entry must name a workspace member, so a typo cannot silently put a crate
back into the default job; package names only consist of ASCII letters,
digits, `-` and `_`, so the line is safe to word-split in a shell.

Standard library only (Python 3.10, the runner's python3).
"""

from __future__ import annotations

import json
import sys


class ExcludeError(Exception):
    pass


def workspace_members(metadata: dict) -> set[str]:
    member_ids = set(metadata.get("workspace_members") or [])
    return {
        package["name"]
        for package in metadata.get("packages") or []
        if package.get("id") in member_ids
    }


def excludes(metadata: dict) -> list[str]:
    workspace = metadata.get("metadata")
    if workspace is None:
        return []
    if not isinstance(workspace, dict):
        raise ExcludeError("workspace metadata is not a table")
    ci = workspace.get("ci")
    if ci is None:
        return []
    if not isinstance(ci, dict):
        raise ExcludeError("[workspace.metadata.ci] is not a table")
    names = ci.get("exclude", [])
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise ExcludeError(
            "[workspace.metadata.ci] exclude must be a list of crate names"
        )
    members = workspace_members(metadata)
    unknown = sorted(name for name in names if name not in members)
    if unknown:
        raise ExcludeError(
            f"[workspace.metadata.ci] exclude names non-members: {', '.join(unknown)}"
        )
    if len(set(names)) != len(names):
        raise ExcludeError("[workspace.metadata.ci] exclude lists a crate twice")
    if names and set(names) == members:
        raise ExcludeError(
            "[workspace.metadata.ci] exclude leaves no member in the default job"
        )
    return names


def arguments(metadata: dict) -> str:
    return " ".join(f"--exclude {name}" for name in excludes(metadata))


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        print("usage: ci_excludes.py [cargo-metadata.json]", file=sys.stderr)
        return 2
    try:
        if argv:
            with open(argv[0], encoding="utf-8") as handle:
                metadata = json.load(handle)
        else:
            metadata = json.load(sys.stdin)
        if not isinstance(metadata, dict):
            raise ExcludeError("cargo metadata is not a JSON object")
        print(arguments(metadata))
    except (OSError, ValueError, ExcludeError) as error:
        print(f"ci_excludes.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
