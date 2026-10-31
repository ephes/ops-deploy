"""Original ``python_security_floor`` policy, with a ValueError exception alias.

They run on the controller: the role passes them a lock file's text or the
JSON report of ``inspect_python_security.py`` and asserts on the returned list
of problems. An empty list means the floors hold.
"""

from __future__ import annotations

import re
import tomllib
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

# Original filter exceptions are public ValueError here; no Ansible dependency.
AnsibleFilterError = ValueError

# The system store a distribution-unbundled certifi or pip must point at.
SYSTEM_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt",)
# Distribution packages allowed to own an unbundled module outside the environment.
DISTRO_OWNERS = {"certifi": ("python3-certifi",), "pip": ("python3-pip",)}


def _name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _version(value: Any, what: str) -> Version:
    try:
        return Version(str(value))
    except InvalidVersion as exc:
        raise AnsibleFilterError(f"{what}: invalid version {value!r}") from exc


def _floors(floors: Any) -> dict[str, Version]:
    if not isinstance(floors, dict) or not floors:
        raise AnsibleFilterError("floors must be a non-empty mapping of package to minimum version")
    return {_name(str(name)): _version(minimum, f"floor for {name}") for name, minimum in floors.items()}


def uv_lock_floor_violations(lock_text: Any, floors: Any) -> list[str]:
    """Packages the ``uv.lock`` text locks below their floor.

    Packages the lock does not contain are ignored: the guard never asks for
    a package an application does not already install.
    """

    minimums = _floors(floors)
    if not isinstance(lock_text, str):
        raise AnsibleFilterError("lock_text must be the text of a uv.lock file")
    try:
        lock = tomllib.loads(lock_text)
    except tomllib.TOMLDecodeError as exc:
        raise AnsibleFilterError(f"uv.lock is not valid TOML: {exc}") from exc
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise AnsibleFilterError("uv.lock has no [[package]] entries")
    problems = []
    for package in packages:
        name = _name(str(package.get("name", "")))
        if name not in minimums:
            continue
        if "version" not in package:
            problems.append(f"{name}: locked without a version (source: {package.get('source')})")
            continue
        locked = _version(package["version"], f"locked {name}")
        if locked < minimums[name]:
            problems.append(f"{name} {locked} is locked; {minimums[name]} or later is required")
    return problems


def python_security_constraints(floors: Any) -> str:
    """Constraint file text: one ``name>=minimum`` line per floor.

    Constraints only limit the versions of packages an install resolves; they
    never add a package.
    """

    return "".join(f"{name}>={minimum}\n" for name, minimum in sorted(_floors(floors).items()))


def _fingerprint(value: Any) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value).lower())


def _supported(name: str, requires_python: Any, python: Version) -> tuple[bool, str]:
    spec = (requires_python or {}).get(name)
    if not spec:
        return True, ""
    try:
        return python in SpecifierSet(str(spec)), str(spec)
    except InvalidSpecifier as exc:
        raise AnsibleFilterError(f"invalid Requires-Python for {name}: {spec!r}") from exc


def _deferral_problem(
    name: str,
    info: dict[str, Any],
    minimums: dict[str, Version],
    requires_python: Any,
    python: Version,
) -> str | None:
    if name not in minimums or not info.get("in_environment"):
        return None
    supported, spec = _supported(name, requires_python, python)
    if supported:
        return None
    return (
        f"{name} cannot be raised by the following install: {name} {minimums[name]} requires Python {spec}"
        f" and this environment runs {python}; it cannot be updated in place"
    )


def python_security_report_violations(
    report: Any,
    floors: Any,
    distrusted_roots: Any,
    requires_python: Any,
    deferred: Any = None,
    managed_base: Any = None,
) -> list[str]:
    """Problems in an ``inspect_python_security.py`` report.

    - A package that is not installed is fine (nothing is added).
    - A package installed in the environment must meet its floor. When the
      environment's Python is outside the floor release's ``Requires-Python``
      the package cannot be updated in place; that is reported, not bypassed.
    - A package imported from outside the environment is accepted only when a
      distribution package owns it and its bundle is the system store; any
      other location (a custom or unknown bundle) fails.
    - No effective bundle may contain a distrusted root, matched by SHA-256
      fingerprint. Names are labels only.
    - ``deferred`` names packages a following install step of the calling
      role raises to the floor itself (a preflight before that step); they
      are skipped here, unless the floor release does not support the
      environment's Python (then the step cannot raise them), and must be
      checked again after the step.
    """

    minimums = _floors(floors)
    if not isinstance(report, dict) or "packages" not in report:
        raise AnsibleFilterError("report must be the JSON object printed by inspect_python_security.py")
    bad = {}
    for root in distrusted_roots or []:
        if not isinstance(root, dict) or not root.get("sha256"):
            raise AnsibleFilterError("each distrusted root needs a sha256 fingerprint")
        bad[_fingerprint(root["sha256"])] = str(root.get("name", "distrusted root"))
    python = _version(report.get("python_version"), "environment Python")
    skipped = {_name(str(name)) for name in deferred or []}
    problems = []
    if managed_base:
        if not {"pip", "certifi"}.issubset(minimums):
            raise AnsibleFilterError("managed base verification requires pip and certifi floors")
        if not isinstance(managed_base, dict) or not re.fullmatch(
            r"[0-9]+[.][0-9]+[.][0-9]+", str(managed_base.get("python_version", ""))
        ):
            raise AnsibleFilterError("managed base verification requires an exact Python patch")
        # Explicit base-runtime mode is stricter than the default venv policy:
        # no deferrals, absent pip, external imports or distro exemptions.
        if deferred:
            problems.append("managed base runtime verification does not allow deferrals")
        expected = report.get("expected_base_prefix")
        if (
            not expected
            or expected == "/"
            or report.get("prefix") != expected
            or report.get("base_prefix") != expected
            or not str(report.get("executable", "")).startswith(expected + "/")
        ):
            problems.append("managed base runtime prefix/executable does not match the expected base")
        if report.get("python_version") != managed_base["python_version"]:
            problems.append("managed base runtime Python does not match the exact expected version")
        if not report["packages"].get("pip", {}).get("installed"):
            problems.append("managed base runtime must contain pip")
        skipped = set()
    for raw_name, info in sorted(report["packages"].items()):
        name = _name(raw_name)
        if not info.get("installed"):
            continue
        if name in skipped:
            # Deferred only while the following install can actually raise it.
            problem = _deferral_problem(name, info, minimums, requires_python, python)
            if problem:
                problems.append(problem)
            continue
        if info.get("error"):
            problems.append(f"{name}: could not be inspected: {info['error']}")
            continue
        if info.get("in_environment"):
            if name in minimums and info.get("version") is None:
                problems.append(f"{name}: installed version could not be read from its metadata")
            elif name in minimums:
                installed = _version(info.get("version"), f"installed {name}")
                if installed < minimums[name]:
                    detail = f"{name} {installed} is installed; {minimums[name]} or later is required"
                    supported, spec = _supported(name, requires_python, python)
                    if not supported:
                        detail += (
                            f" but {name} {minimums[name]} requires Python {spec} and this environment"
                            f" runs {python}; it cannot be updated in place"
                        )
                    problems.append(detail)
        elif managed_base:
            problems.append(f"{name} is imported from outside the expected managed base runtime")
        else:
            owner = info.get("distro_owner") or ""
            if owner not in DISTRO_OWNERS.get(name, ()) or info.get("bundle") not in SYSTEM_BUNDLES:
                problems.append(
                    f"{name} is imported from outside the environment ({info.get('module_file')}) with bundle"
                    f" {info.get('bundle')}; only a distribution package using the system store is accepted"
                )
        if managed_base:
            prefix = str(report.get("expected_base_prefix", "")) + "/"
            for field in ("module_file", "bundle_module_file", "bundle"):
                if not str(info.get(field, "")).startswith(prefix):
                    problems.append(f"{name}: {field} is outside the expected managed base runtime")
            origins = info.get("module_origins")
            if not origins or any(not str(path).startswith(prefix) for path in origins.values()):
                problems.append(
                    f"{name}: imported module origins are outside or missing from the expected managed base runtime"
                )
            bundled = info.get("bundle_version")
            if bundled is None or _version(bundled, f"{name} bundled certifi") < minimums["certifi"]:
                problems.append(f"{name}: bundled certifi must meet {minimums['certifi']}")
        if info.get("bundle_error"):
            problems.append(f"{name}: bundle {info.get('bundle')} could not be read: {info['bundle_error']}")
            continue
        for fingerprint in info.get("bundle_fingerprints") or []:
            label = bad.get(_fingerprint(fingerprint))
            if label:
                problems.append(f"{name}: bundle {info.get('bundle')} contains distrusted root {label}")
    return problems
