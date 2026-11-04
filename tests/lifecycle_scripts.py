"""Helpers for the backup/restore port tests: planned settings and the host scripts run locally.

The script tests run a planned ``backup.sh``/``restore.sh`` with bash in a
temporary tree. Commands that need root or a service manager are recording
stubs inserted between the shared helpers and the script body. They need GNU
find, sha256sum, stat and rsync, as on the Linux targets.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest


def _gnu() -> bool:
    if shutil.which("rsync") is None or shutil.which("sqlite3") is None:
        return False
    probe = subprocess.run(["find", ".", "-maxdepth", "0", "-printf", "%p"], capture_output=True, text=True)
    return probe.returncode == 0 and probe.stdout == "."


needs_gnu = pytest.mark.skipif(not _gnu(), reason="needs GNU find, rsync and sqlite3, as on the Linux targets")

# Root-only helpers and service commands, recorded in $LOG.
STUBS = r"""
ensure_dir() { mkdir -p "$4"; chmod "$3" "$4"; }
set_attrs() { chmod "$3" "$4"; }
copy_file() { local dest=$5; [ -d "$dest" ] && dest="$dest/$(basename "$4")"; cp "$4" "$dest"; chmod "$3" "$dest"; }
chown_tree() { printf 'chown_tree %s\n' "$*" >>"$LOG"; }
chown() { printf 'chown %s\n' "$*" >>"$LOG"; }
systemctl() {
    printf 'systemctl %s\n' "$*" >>"$LOG"
    case $1 in
        stop) [ -z "${SYSTEMCTL_STOP_FAILS:-}" ] ;;
        is-active) printf 'active\n' ;;
        *) return 0 ;;
    esac
}
curl() {
    printf 'curl %s\n' "$*" >>"$LOG"
    local out=""
    while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done
    [ -z "$out" ] || printf '%s' "${CURL_BODY:-}" >"$out"
    printf '%s' "${CURL_CODE:-200}"
}
runuser() { printf 'runuser %s\n' "$*" >>"$LOG"; shift 3; [ -z "${RUNUSER_FAILS:-}" ] || return 1; }
ROUTE_GUARD=(true)
"""


def assignments(command: str) -> dict[str, str]:
    """The ``NAME=value`` lines in front of a script body (arrays as their raw text)."""

    values = {}
    for line in command.splitlines():
        name, sep, value = line.partition("=")
        if sep and name.isidentifier() and name.isupper():
            try:
                values[name] = value if value.startswith("(") else shlex.split(value)[0] if value else ""
            except ValueError:  # the first line of a multi-line value
                continue
    return values


def run_script(
    command: str, body: Path, tmp_path: Path, *, stubs: str = "", **env: str
) -> subprocess.CompletedProcess[str]:
    """``command`` (as planned) with :data:`STUBS` and ``stubs`` between the shared helpers and ``body``."""

    text = body.read_text().rstrip()
    head, sep, tail = command.rpartition(text)
    assert sep, "script body not found"
    return subprocess.run(
        ["bash", "-c", head + STUBS + stubs + sep + tail],
        capture_output=True,
        text=True,
        # COPYFILE_DISABLE: macOS tar would add AppleDouble ``._`` entries.
        env={"PATH": os.environ["PATH"], "LOG": str(tmp_path / "calls.log"), "COPYFILE_DISABLE": "1", **env},
    )


def repack(directory: Path) -> Path:
    """Pack an edited backup directory again as ``<directory>.tar.gz`` (the only top-level entry)."""

    archive = directory.parent / f"{directory.name}.tar.gz"
    archive.unlink(missing_ok=True)
    subprocess.run(
        ["tar", "-C", str(directory.parent), "-czf", str(archive), directory.name],
        check=True,
        env={**os.environ, "COPYFILE_DISABLE": "1"},
    )
    return archive


def calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "calls.log"
    return log.read_text().splitlines() if log.exists() else []


__all__ = ["STUBS", "assignments", "calls", "needs_gnu", "repack", "run_script"]
