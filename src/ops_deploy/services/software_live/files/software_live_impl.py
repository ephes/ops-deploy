"""Decisions of the ``software_live`` role's switch between Python and Rust.

``rust/software-live/PLAN.md`` 7.3: the role reads the live state (drop-ins,
shadow units, the pins and every process of the four units) with read-only
tasks and hands the raw results to these functions, so every rule is a plain,
unit-tested function (``tests/test_software_live_impl.py``):

- ``software_live_variant``: the release variant of ``/etc/os-release``.
- ``software_live_live_state``: every release version the host runs or is
  configured to run right now (the ``protect`` list of the prune), whether
  that state is completely known, and the version last verified live.
- ``software_live_verify``: what is wrong with the running implementation
  after the switch (empty when it runs the selected one).
- ``software_live_apt_status``: the ``status`` of the APT helper's answer.

Everything fails closed: input these functions cannot interpret is reported
as ``unknown`` (and then nothing is pruned) or as a problem (and then nothing
is pinned).
"""

from __future__ import annotations

import base64
import binascii
import json
import posixpath
import re
from typing import Any

# The release variants of PLAN.md 7.2: (os-release ID, VERSION_ID) -> suffix.
VARIANTS = {("ubuntu", "24.04"): "ubuntu24.04", ("debian", "13"): "debian13"}

# The version grammar of rust_release_binary (plugins/filter/rust_release.py),
# repeated here because Ansible loads every filter file on its own.
VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)"
    r"(-[0-9A-Za-z-]+([.][0-9A-Za-z-]+)*)?$"
)
DELETED_SUFFIX = " (deleted)"
# The executables of a release (7.2): a process or a command that names one of
# them outside the release directory is an alias the role cannot map.
RELEASE_EXECUTABLES = ("software-live", "software-live-apt")

ENDPOINT = "software-live-endpoint.service"
COLLECTOR = "software-live-collector.service"
SHADOW_ENDPOINT = "software-live-shadow-endpoint.service"
SHADOW_COLLECTOR = "software-live-shadow-collector.service"
UNITS = (ENDPOINT, COLLECTOR, SHADOW_ENDPOINT, SHADOW_COLLECTOR)
# Unit states in which a process of the unit may run (7.3 step 0; systemd
# 257 adds "refreshing").
RUNNING_STATES = ("activating", "active", "deactivating", "reloading", "refreshing")

OS_RELEASE_LINE = re.compile(r"^([A-Za-z0-9_]+)=(.*)$")
OS_RELEASE_UNESCAPE = re.compile(r"\\([\\$\"'`])")
DIRECTIVE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s*=(.*)$")
EXEC_PATH = re.compile(r"\bpath=([^\s;]+)")


def _version_ok(value: Any) -> bool:
    return isinstance(value, str) and VERSION_RE.fullmatch(value) is not None


# ---------------------------------------------------------------------------
# variant
# ---------------------------------------------------------------------------


def software_live_variant(os_release: Any) -> str:
    """The release variant (``ubuntu24.04``, ``debian13``) of an os-release
    text, or ``""`` for any other system or an unreadable file.

    The text is read with the os-release rules: ``NAME=VALUE`` lines, the value
    optionally in one matching pair of quotes with ``\\\\``, ``\\$``, ``\\"``,
    ``\\'`` and ``\\``` unescaped; later lines win."""

    if not isinstance(os_release, str):
        return ""
    fields: dict[str, str] = {}
    for line in os_release.splitlines():
        match = OS_RELEASE_LINE.match(line.strip())
        if not match:
            continue
        value = match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = OS_RELEASE_UNESCAPE.sub(r"\1", value[1:-1])
        fields[match.group(1)] = value
    return VARIANTS.get((fields.get("ID", ""), fields.get("VERSION_ID", "")), "")


# ---------------------------------------------------------------------------
# live state (step 0)
# ---------------------------------------------------------------------------


def _classify(path: str, roots: list[str]) -> tuple[str | None, str]:
    """(version or None, unknown reason or "") for an executable path.

    ``<root>/<version>/<file>`` names ``<version>``; any other path below a
    root, and a release executable's name anywhere else, make the live state
    unknown; every other path (``/usr/bin/python3``) names nothing."""

    if path.endswith(DELETED_SUFFIX):
        path = path[: -len(DELETED_SUFFIX)]
    for root in roots:
        prefix = root.rstrip("/") + "/"
        if path.startswith(prefix):
            rest = path[len(prefix) :].split("/")
            if (
                len(rest) == 2
                and _version_ok(rest[0])
                and rest[1]
                and not rest[1].startswith(".")
            ):
                return rest[0], ""
            return None, f"{path!r} lies under {root} but not as <version>/<file>"
    if posixpath.basename(path) in RELEASE_EXECUTABLES:
        return None, f"{path!r} names a release executable outside {', '.join(roots)}"
    return None, ""


def _logical_lines(content: str) -> list[str]:
    """The lines of a unit file as systemd reads them: comment lines (``#``,
    ``;``) dropped, a line ending in a backslash continued by the next one."""

    lines: list[str] = []
    pending = ""
    for raw in content.splitlines():
        stripped = raw.strip()
        if stripped.startswith(("#", ";")):
            continue  # also inside a continuation, as systemd does
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        lines.append(pending + stripped)
        pending = ""
    if pending:
        lines.append(pending)
    return lines


def _path_words(value: str) -> list[str]:
    """Every word of a directive's value that may name an executable: an
    absolute path or a release executable's name, after systemd's command
    prefixes (``-``, ``@``, ``:``, ``+``, ``!``), quotes and an ``--opt=``."""

    words = []
    for word in value.split():
        word = word.strip("\"'").lstrip("-@:+!")
        if "=" in word and not word.startswith("/"):
            word = word.rsplit("=", 1)[1]
        word = word.strip("\"'")
        if word.startswith("/") or posixpath.basename(word) in RELEASE_EXECUTABLES:
            words.append(word)
    return words


def _decode(content: Any) -> str | None:
    if not isinstance(content, str):
        return None
    try:
        return base64.b64decode(content, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None


def software_live_files(stats: Any, reads: Any) -> list[dict[str, Any]]:
    """File records for ``software_live_live_state`` from Ansible results.

    ``stats`` are the ``results`` of an ``ansible.builtin.stat`` loop (with
    ``follow: false``) over the files, ``reads`` those of the
    ``ansible.builtin.slurp`` loop over ``stats`` (run only for existing
    files, allowed to fail). A record's ``content`` is None when the file
    exists but was not read."""

    contents: dict[str, str | None] = {}
    for result in reads if isinstance(reads, list) else []:
        if not isinstance(result, dict):
            continue
        item = result.get("item")
        path = item.get("item") if isinstance(item, dict) else None
        if (
            isinstance(path, str)
            and not result.get("failed")
            and not result.get("skipped")
        ):
            contents[path] = _decode(result.get("content"))
    records = []
    for result in stats if isinstance(stats, list) else []:
        path = result.get("item") if isinstance(result, dict) else None
        stat = result.get("stat") if isinstance(result, dict) else None
        if not isinstance(path, str):
            continue
        if not isinstance(stat, dict) or result.get("failed"):
            records.append(
                {"path": path, "exists": True, "isreg": False, "content": None}
            )
            continue
        records.append(
            {
                "path": path,
                "exists": bool(stat.get("exists")),
                "isreg": bool(stat.get("isreg")) and not stat.get("islnk"),
                "content": contents.get(path),
            }
        )
    return records


def _pin(record: dict[str, Any] | None, unknown: list[str]) -> str:
    """The version of a pin record ("" when absent); a pin that cannot be
    read makes the live state unknown."""

    if record is None or not record.get("exists"):
        return ""
    content = record.get("content")
    if record.get("isreg") and isinstance(content, str):
        text = content[:-1] if content.endswith("\n") else content
        if _version_ok(text):
            return text
    unknown.append(
        f"pin {record.get('path')} is not a regular file holding exactly one version"
    )
    return ""


def software_live_live_state(
    probe: Any, files: Any, roots: Any, paths: Any
) -> dict[str, Any]:
    """The live state of PLAN.md 7.3 step 0.

    - ``probe``: the registered result of the role's process probe (``rc``
      and ``stdout_lines``; line format in ``tasks/live_state.yml``).
    - ``files``: ``software_live_files`` records of the drop-ins, the shadow
      units and the two pins.
    - ``roots``: the release root as configured (its resolved spelling comes
      from the probe's ``root`` line).
    - ``paths``: ``{"dropins": [...], "units": [...], "pin": p,
      "shadow_pin": p}``: which file record is which.

    Returns ``versions`` (every release version a drop-in, a shadow unit,
    systemd's loaded command lines or a running process of the four units
    names), ``unknown`` (reasons; non-empty means prune must not delete
    anything), ``pin`` and ``shadow_pin`` (the versions of the existing pins,
    "" when absent), ``endpoint_version`` (the release the production
    endpoint's MainPID executes, "" for Python or none) and ``last_live``
    (``pin``, else ``endpoint_version``).
    """

    unknown: list[str] = []
    versions: set[str] = set()
    roots = [
        r
        for r in (roots if isinstance(roots, list) else [roots])
        if isinstance(r, str) and r.startswith("/")
    ]
    if not roots:
        unknown.append("no release root to compare the live state with")
    paths = paths if isinstance(paths, dict) else {}
    records = {
        r.get("path"): r
        for r in (files if isinstance(files, list) else [])
        if isinstance(r, dict)
    }

    def note(path: str, origin: str) -> str | None:
        version, reason = _classify(path, roots)
        if reason:
            unknown.append(f"{origin}: {reason}")
        elif version is not None:
            versions.add(version)
        return version

    # The process probe (it also prints the resolved release root).
    lines = probe.get("stdout_lines") if isinstance(probe, dict) else None
    if (
        not isinstance(probe, dict)
        or probe.get("rc") != 0
        or not isinstance(lines, list)
    ):
        rc = probe.get("rc") if isinstance(probe, dict) else None
        unknown.append(f"the process probe failed (rc {rc})")
        lines = lines if isinstance(lines, list) else []
    for line in lines:
        if isinstance(line, str) and line.startswith("root\t"):
            resolved = line[len("root\t") :]
            if resolved.startswith("/") and resolved not in roots:
                roots.append(resolved)

    # Files: the production drop-ins and the shadow units.
    for path in list(paths.get("dropins", [])) + list(paths.get("units", [])):
        record = records.get(path)
        if record is None:
            unknown.append(f"{path} was not checked")
            continue
        if not record.get("exists"):
            continue
        content = record.get("content")
        if not isinstance(content, str):
            unknown.append(f"{path} exists but cannot be read")
            continue
        # Every directive, not only ExecStart=/ExecStartPost=: whatever path
        # below the release root a drop-in or shadow unit names is kept, and
        # a release path that cannot be read as <version>/<file> anywhere in
        # it makes the live state unknown.
        for logical in _logical_lines(content):
            match = DIRECTIVE.match(logical)
            if match:
                for word in _path_words(match.group(2)):
                    note(word, path)

    pin = _pin(records.get(paths.get("pin")), unknown)
    shadow_pin = _pin(records.get(paths.get("shadow_pin")), unknown)

    seen: dict[str, dict[str, str]] = {}
    done = False
    endpoint_version = ""
    for line in lines:
        if not isinstance(line, str):
            unknown.append(f"unexpected probe output {line!r}")
            continue
        kind, _, rest = line.partition("\t")
        fields = rest.split("\t")
        if kind == "root":
            continue
        if kind == "done" and rest == "":
            done = True
        elif kind == "unit" and len(fields) == 5 and fields[0] in UNITS:
            seen[fields[0]] = {
                "state": fields[1],
                "main": fields[2],
                "control": fields[3],
                "cgroup": fields[4],
            }
        elif kind == "prop" and len(fields) >= 2 and fields[0] in UNITS:
            for path in EXEC_PATH.findall("\t".join(fields[1:])):
                note(path, f"{fields[0]} (loaded command)")
        elif (
            kind == "exe"
            and len(fields) >= 3
            and fields[0] in UNITS
            and fields[1].isdigit()
        ):
            target = "\t".join(fields[2:])
            version = note(target, f"{fields[0]} PID {fields[1]}")
            unit = seen.get(fields[0], {})
            if fields[0] == ENDPOINT and fields[1] == unit.get("main") and version:
                endpoint_version = version
        elif kind == "noexe" and len(fields) == 2 and fields[0] in UNITS:
            unknown.append(
                f"{fields[0]}: the executable of running PID {fields[1]} cannot be resolved"
            )
        elif kind == "nocgroup" and len(fields) == 1 and fields[0] in UNITS:
            unknown.append(
                f"{fields[0]} is running but its control group cannot be listed"
            )
        elif kind == "error" and len(fields) == 1 and fields[0] in UNITS:
            unknown.append(f"systemctl show {fields[0]} failed")
        else:
            unknown.append(f"unexpected probe output {line!r}")
    if lines and not done:
        unknown.append("the process probe did not finish")
    missing = [u for u in UNITS if u not in seen]
    if missing and lines:
        unknown.append(f"the process probe did not report {', '.join(missing)}")

    return {
        "versions": sorted(versions),
        "unknown": unknown,
        "pin": pin,
        "shadow_pin": shadow_pin,
        "endpoint_version": endpoint_version,
        "last_live": pin or endpoint_version,
    }


# ---------------------------------------------------------------------------
# verification (step 6)
# ---------------------------------------------------------------------------


def software_live_verify(probe: Any, expect: Any) -> list[str]:
    """What is wrong with the running implementation (empty: nothing).

    ``probe`` is the registered result of the role's verification probe (line
    format in ``tasks/verify_impl.yml``); ``expect`` is ``{"impl": "rust" |
    "python", "binary": <versioned binary>, "script": <software_live.py>,
    "shadow": bool}``.

    - endpoint: active; impl rust: ``/proc/<MainPID>/exe`` is the binary (or
      its resolved path); impl python: its command line runs ``<script>
      serve``.
    - collector: ``ExecMainStatus=0`` and systemd's loaded ``ExecStart=``
      runs the binary (rust) or ``/usr/bin/python3 <script> collect``
      (python).
    - shadow endpoint (with the shadow): active and executing the binary.
    """

    expect = expect if isinstance(expect, dict) else {}
    impl = expect.get("impl")
    binary = expect.get("binary") or ""
    script = expect.get("script") or ""
    lines = probe.get("stdout_lines") if isinstance(probe, dict) else None
    if (
        not isinstance(probe, dict)
        or probe.get("rc") != 0
        or not isinstance(lines, list)
    ):
        return [
            f"the verification probe failed (rc {probe.get('rc') if isinstance(probe, dict) else None})"
        ]

    binaries = {binary} if binary else set()
    # Per unit: the `unit` line's fields (once reported) and the other lines,
    # in whatever order the probe printed them.
    units: dict[str, dict[str, Any]] = {}
    reported: set[str] = set()
    done = False
    problems: list[str] = []

    def info(name: str) -> dict[str, Any]:
        return units.setdefault(
            name,
            {
                "state": "",
                "main": "",
                "status": "",
                "exec": [],
                "exe": None,
                "args": [],
            },
        )

    for line in lines:
        kind, _, rest = str(line).partition("\t")
        fields = rest.split("\t")
        if kind == "real" and rest.startswith("/"):
            binaries.add(rest)
        elif kind == "unit" and len(fields) == 4 and fields[0] in UNITS:
            info(fields[0]).update(state=fields[1], main=fields[2], status=fields[3])
            reported.add(fields[0])
        elif kind in ("prop", "exe", "arg") and len(fields) >= 2 and fields[0] in UNITS:
            value = "\t".join(fields[1:])
            if kind == "prop":
                info(fields[0])["exec"].append(value)
            elif kind == "exe":
                info(fields[0])["exe"] = value
            else:
                info(fields[0])["args"].append(value)
        elif kind == "done" and rest == "":
            done = True
        else:
            problems.append(f"unexpected probe output {line!r}")
    if not done:
        problems.append("the verification probe did not finish")
    units = {name: value for name, value in units.items() if name in reported}

    def endpoint(unit: str, want_impl: str) -> None:
        info = units.get(unit)
        if info is None:
            problems.append(f"{unit} was not reported")
            return
        if info["state"] != "active":
            problems.append(f"{unit} is {info['state'] or 'unknown'}, not active")
            return
        if want_impl == "rust":
            if info["exe"] not in binaries:
                problems.append(f"{unit} runs {info['exe']!r}, not {binary}")
        else:
            args = info["args"]
            if not any(
                args[i] == script and args[i + 1] == "serve"
                for i in range(len(args) - 1)
            ):
                problems.append(
                    f"{unit} does not run {script} serve (command line {args!r})"
                )

    endpoint(ENDPOINT, impl)
    collector = units.get(COLLECTOR)
    if collector is None:
        problems.append(f"{COLLECTOR} was not reported")
    else:
        if collector["status"] != "0":
            problems.append(
                f"{COLLECTOR} exited with ExecMainStatus={collector['status']}"
            )
        starts = [line for line in collector["exec"] if line.startswith("ExecStart=")]
        if impl == "rust":
            found = [p for line in starts for p in EXEC_PATH.findall(line)]
            if not found or any(p != binary for p in found):
                problems.append(f"{COLLECTOR} runs {found!r}, not {binary}")
        elif not starts or not all(
            f"argv[]=/usr/bin/python3 {script} collect " in line for line in starts
        ):
            problems.append(
                f"{COLLECTOR} does not run /usr/bin/python3 {script} collect ({starts!r})"
            )
    shadow = expect.get("shadow")
    if isinstance(shadow, str):
        shadow = shadow.strip().lower() in ("true", "yes", "1")
    if shadow is True:
        endpoint(SHADOW_ENDPOINT, "rust")
    return problems


def software_live_apt_status(stdout: Any) -> str:
    """The ``status`` of the APT helper's JSON object ("" when it is none)."""

    try:
        value = json.loads(stdout) if isinstance(stdout, str) else None
    except ValueError:
        return ""
    status = value.get("status") if isinstance(value, dict) else None
    return status if isinstance(status, str) else ""


class FilterModule:
    """Expose the software_live switch decisions to Ansible."""

    def filters(self) -> dict[str, Any]:
        return {
            "software_live_variant": software_live_variant,
            "software_live_files": software_live_files,
            "software_live_live_state": software_live_live_state,
            "software_live_verify": software_live_verify,
            "software_live_apt_status": software_live_apt_status,
        }
