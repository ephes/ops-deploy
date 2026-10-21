"""metrics-httpd: the Python script or the pinned Rust release for one endpoint unit.

The pyinfra side of ops-library's internal role ``metrics_httpd_switch``
(``rust/metrics-httpd/PLAN.md`` 7.2 and 7.4, slice S5e), shared by the
deploys that render a metrics-httpd endpoint role: ``thermal_monitoring``,
``logyard`` (the health endpoint) and ``static_site``. Each unit keeps its
unit file and Python script exactly as before; Rust is selected by the drop-in
``/etc/systemd/system/<unit>.service.d/metrics-httpd-impl.conf``, the role's
template (``templates/metrics-httpd-impl.conf.j2``, vendored byte for byte and
rendered as Ansible's ``template`` module renders it), so Ansible and pyinfra
can take turns on a host.

:func:`select` (after the unit file, before the unit's reload and restart):

- ``python``: the drop-in is removed first, so a switch back never waits on
  a download or a check;
- with a release version set (independent of the implementation, so the
  binary can be installed ahead of the switch): ``helpers.rust_release``
  installs it under ``/opt/metrics-httpd/<version>/``, and
  ``<binary> <argv> --check-config`` runs through ``systemd-run`` as the
  unit's user and group with the unit's sandbox. For ``rust`` a failure stops
  the deploy before anything is switched; for ``python`` it only warns (an
  ignored error), as does an input only the Rust path uses;
- ``rust``: the drop-in names the versioned binary and the argv.

:func:`verify` (after the restart): the unit runs the selected implementation
and answers an unauthenticated ``GET`` as expected (``files/verify_host.py``);
only then the unit's pin moves (``rust``: the version; ``python``: removed,
its version kept as the rollback pin) and old versions are pruned, keeping
every pin, the selected binary, the one the drop-in named before this run and
the executable the unit ran while planning.

The argv, sandbox and probe-coverage rules are ops-library's
``plugins/filter/metrics_httpd.py``, vendored byte for byte as ``rules.py``
(``tests/test_ops_library_drift.py`` compares both).
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from functools import cache
from io import StringIO
from pathlib import Path
from typing import Literal

import jinja2
from pydantic import BaseModel, ConfigDict, model_validator
from pyinfra import host, logger
from pyinfra.api import DeployError
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import FileContents
from pyinfra.operations import files, server

from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe, stdin_arguments
from ops_deploy.helpers.rust_release import HOST_PYTHON, Install, install_release, pin_release, prune_releases
from ops_deploy.services._metrics_httpd import rules

NAME = "metrics-httpd"
INSTALL_ROOT = f"/opt/{NAME}"
DROPIN = "metrics-httpd-impl.conf"
SYSTEMD_DIR = "/etc/systemd/system"
KEEP_VERSIONS = 3
# The role's verify: up to about 30 s for the process, then for the answer.
VERIFY_RETRIES = 15
VERIFY_DELAY = 2
VERIFY_SCRIPT = (Path(__file__).parent / "files" / "verify_host.py").read_text()
# ops-library plugins/filter/rust_release.py: the grammar of a version, a
# sha256 and a pin consumer (tests compare them with the vendored copy).
VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-[0-9A-Za-z-]+([.][0-9A-Za-z-]+)*)?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CONSUMER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
# The probe expectations of the role's verify (metrics_httpd_switch_probe_expect).
Expect = Literal["unauthorized", "logyard-health", "static"]
Impl = Literal["python", "rust"]


class HttpdSwitchFields(BaseModel):
    """The implementation switch of a deploy's metrics-httpd endpoint (PLAN.md 7.1).

    ``httpd_impl`` is the role's ``<role>_impl``; ``httpd_rust_version`` and
    ``httpd_rust_sha256`` are the fleet pin ``metrics_httpd_rust_version`` and
    ``metrics_httpd_rust_sha256``. ``rust`` needs both; ``python`` with a
    version installs and checks the release without switching (empty: nothing
    is installed), and a malformed version or sha256 only warns there, so it
    never blocks the switch back.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True, hide_input_in_errors=True)

    httpd_impl: Impl = "python"
    httpd_rust_version: str = ""
    httpd_rust_sha256: str = ""

    @model_validator(mode="after")
    def _rust_needs_a_release(self) -> HttpdSwitchFields:
        if self.httpd_impl == "rust":
            if not VERSION_RE.fullmatch(self.httpd_rust_version):
                raise ValueError("httpd_impl rust needs httpd_rust_version, a release version such as 0.1.0")
            if not SHA256_RE.fullmatch(self.httpd_rust_sha256):
                raise ValueError("httpd_impl rust needs httpd_rust_sha256, the 64-hex sha256 of the release archive")
        return self


@dataclass(frozen=True)
class Endpoint:
    """One unit's inputs to the switch (the role's ``metrics_httpd_switch_*`` variables)."""

    service_name: str
    # The metrics-httpd command line after the binary (PLAN.md 7.3).
    argv: tuple[str, ...]
    # The unit's User= and Group=: --check-config runs as them.
    user: str
    group: str
    # systemd-run --property values mirroring the rest of the unit's sandbox.
    sandbox: tuple[str, ...]
    # With impl python the live process's command line holds this path.
    python_script: str
    probe_bind: str
    probe_port: int
    probe_path: str
    probe_expect: Expect = "unauthorized"
    probe_realm: str = ""
    # Whole seconds the probe waits for an answer.
    probe_timeout: int = 5
    # The unit's IPAddressAllow= values; ("any",): no IP filter.
    ip_address_allow: tuple[str, ...] = ("any",)

    @property
    def dropin_dir(self) -> str:
        return f"{SYSTEMD_DIR}/{self.service_name}.service.d"

    @property
    def dropin_path(self) -> str:
        return f"{self.dropin_dir}/{DROPIN}"


@dataclass(frozen=True)
class Selection:
    """What :func:`select` planned for one unit; :func:`verify` takes it from there."""

    endpoint: Endpoint
    impl: Impl
    # The release this deploy installs or validates ("" when none or malformed).
    version: str
    # The drop-in's write (rust) or removal (python): a change reloads and restarts the unit.
    dropin: OperationMeta
    install: Install | None
    # The binary the drop-in named before this run, and the executable the unit ran while planning.
    before_binary: str
    live_executable: str
    live_state_unknown: bool

    @property
    def binary(self) -> str:
        return f"{INSTALL_ROOT}/{self.version}/{NAME}" if self.version else ""


@cache
def _environment() -> jinja2.Environment:
    """The role's template with the options of Ansible's ``template`` module (no filter needed)."""

    return jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services._metrics_httpd", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def render_dropin(binary: str, argv: tuple[str, ...]) -> str:
    """``metrics-httpd-impl.conf`` as the role renders it for ``binary`` and ``argv``."""

    return (
        _environment()
        .get_template("metrics-httpd-impl.conf.j2")
        .render(metrics_httpd_impl_binary=binary, metrics_httpd_impl_argv=list(argv))
    )


def problems(endpoint: Endpoint) -> list[str]:
    """What would make the Rust path refuse ``endpoint`` (the role's select checks)."""

    found = rules.metrics_httpd_argv_problems(list(endpoint.argv))
    found += rules.metrics_httpd_sandbox_problems(list(endpoint.sandbox))
    found += [] if endpoint.user else ["validate_user must be the unit's User="]
    found += [] if endpoint.group else ["validate_group must be the unit's Group="]
    return found


def before_binary(dropin: list[str] | None) -> str:
    """The binary the last ``ExecStart=`` of an existing drop-in names (the role's regex)."""

    found = re.findall(r"(?m)^ExecStart=(\S+)", "\n".join(dropin or ()))
    return found[-1] if found else ""


def live_command(unit: str) -> str:
    """Probe printing the executable of the unit's main process (nothing when none runs)."""

    show = shlex.join(["systemctl", "show", "--property=MainPID", "--value", unit])
    return f'pid=$({show}) || exit 1; case "$pid" in ""|*[!0-9]*|0) exit 0 ;; esac; readlink "/proc/$pid/exe" || true'


def check_config_command(endpoint: Endpoint, binary: str) -> str:
    """``systemd-run`` of ``<binary> <argv> --check-config`` as the unit's user in the unit's sandbox."""

    argv = [
        "systemd-run",
        *("--wait", "--pipe", "--collect", "--quiet"),
        f"--property=User={endpoint.user}",
        f"--property=Group={endpoint.group}",
        *(f"--property={value}" for value in endpoint.sandbox),
        binary,
        *endpoint.argv,
        "--check-config",
    ]
    return shlex.join(argv)


def _release(cfg: HttpdSwitchFields, unit: str) -> str:
    """The version to install, "" when none is pinned or (impl python) the pin is malformed."""

    version, sha256 = cfg.httpd_rust_version, cfg.httpd_rust_sha256
    if not version:
        return ""
    if VERSION_RE.fullmatch(version) and SHA256_RE.fullmatch(sha256):
        return version
    # Only impl python gets here (the config refuses it for rust).
    logger.warning(
        f"{host.print_prefix}{unit} stays on Python, but its metrics-httpd release pin is not a version "
        "with a 64-hex sha256; nothing is installed or checked. Fix it before switching to Rust."
    )
    return ""


def select(endpoint: Endpoint, cfg: HttpdSwitchFields) -> Selection:
    """Select the implementation of ``endpoint``'s unit; call it after the unit file is written."""

    unit, impl = endpoint.service_name, cfg.httpd_impl
    if not CONSUMER_RE.fullmatch(unit):
        raise DeployError(f"metrics-httpd: {unit!r} is not usable as a pin consumer (lower-case, digits, - and _)")
    found = problems(endpoint)
    if found and impl == "rust":
        raise DeployError(f"metrics-httpd: impl rust for {unit} refused, nothing switched: {'; '.join(found)}")
    if found:
        logger.warning(
            f"{host.print_prefix}{unit} stays on Python, but a switch to Rust would be refused: "
            f"{'; '.join(found)}. --check-config is skipped."
        )

    before = before_binary(host.get_fact(FileContents, path=endpoint.dropin_path))
    live = probe(live_command(unit), name=f"the executable {unit} runs")
    dropin: OperationMeta | None = None
    if impl == "python":
        dropin = files.file(name=f"Select the Python HTTP server for {unit}", path=endpoint.dropin_path, present=False)

    version = _release(cfg, unit)
    install = None
    if version:
        install = install_release(
            NAME, version, sha256=cfg.httpd_rust_sha256, validate_user=endpoint.user, fail_hard=impl == "rust"
        )
    if install is not None and not found:
        checked = install
        # Binds nothing, sends nothing, prints no hash or password.
        mark_read_only(
            server.shell(
                name=f"Check the {NAME} {version} configuration of {unit}",
                commands=[check_config_command(endpoint, install.binary)],
                _if=lambda: not checked.failed(),
                # As the role: a refused configuration stops impl rust; with impl
                # python it is an ignored error and the unit stays on Python.
                _ignore_errors=impl == "python",
            )
        )
    if impl == "rust":
        files.directory(
            name=f"Ensure {endpoint.dropin_dir}", path=endpoint.dropin_dir, user="root", group="root", mode="0755"
        )
        dropin = files.put(
            name=f"Select the Rust HTTP server for {unit}",
            src=StringIO(render_dropin(f"{INSTALL_ROOT}/{version}/{NAME}", endpoint.argv)),
            dest=endpoint.dropin_path,
            user="root",
            group="root",
            mode="0644",
        )
    assert dropin is not None
    return Selection(
        endpoint=endpoint,
        impl=impl,
        version=version,
        dropin=dropin,
        install=install,
        before_binary=before,
        live_executable=(live or "").strip(),
        live_state_unknown=live is None,
    )


def verify_command(selection: Selection) -> str:
    """The host script's command line: what to expect from the unit and its endpoint."""

    endpoint = selection.endpoint
    argv = [HOST_PYTHON, "-I", "-", "--unit", endpoint.service_name, "--impl", selection.impl]
    argv += ["--binary", selection.binary] if selection.impl == "rust" else ["--python-script", endpoint.python_script]
    if rules.metrics_httpd_probe_covered(endpoint.probe_bind, list(endpoint.ip_address_allow)):
        argv += [
            *("--host", rules.metrics_httpd_probe_address(endpoint.probe_bind)),
            *("--port", str(endpoint.probe_port), "--path", endpoint.probe_path),
            *("--expect", endpoint.probe_expect, "--timeout", str(endpoint.probe_timeout)),
        ]
        argv += ["--realm", endpoint.probe_realm] if endpoint.probe_expect == "unauthorized" else []
    else:
        argv.append("--no-probe")
    argv += ["--retries", str(VERIFY_RETRIES), "--delay", str(VERIFY_DELAY)]
    return shlex.join(argv)


def _probe_skipped(endpoint: Endpoint) -> str:
    if rules.metrics_httpd_probe_covered(endpoint.probe_bind, ["any"]):
        allowed = ", ".join(endpoint.ip_address_allow)
        return (
            f"its IPAddressAllow= ({allowed}) does not cover {endpoint.probe_bind}, "
            "the source address of a probe from this host"
        )
    return f"its bind address {endpoint.probe_bind} is not an IP address, so the address to probe is unknown"


def verify(selection: Selection) -> None:
    """Prove the unit runs the selected implementation and answers; then pin and prune.

    Call it after the unit's reload and restart. A failed check stops the
    deploy before any pin moves or anything is pruned.
    """

    endpoint, impl = selection.endpoint, selection.impl
    unit = endpoint.service_name
    if not rules.metrics_httpd_probe_covered(endpoint.probe_bind, list(endpoint.ip_address_allow)):
        logger.info(f"{host.print_prefix}Skipping the HTTP probe of {unit}: {_probe_skipped(endpoint)}.")
    label = "Rust" if impl == "rust" else "Python"
    mark_read_only(
        server.shell(
            name=f"Check {unit} runs the {label} HTTP server and answers",
            commands=[verify_command(selection)],
            **stdin_arguments(VERIFY_SCRIPT),
        )
    )
    # The unit runs the selected implementation: move its pin (the version it
    # ran before stays as the rollback pin).
    pin_release(NAME, unit, selection.version if impl == "rust" else None)
    protect = [selection.binary if impl == "rust" else "", selection.before_binary, selection.live_executable]
    prune_releases(
        NAME,
        keep_versions=KEEP_VERSIONS,
        protect=list(dict.fromkeys(entry for entry in protect if entry)),
        live_state_unknown=selection.live_state_unknown,
        after=[step for step in (selection.install, selection.dropin) if step is not None],
    )


__all__ = [
    "DROPIN",
    "INSTALL_ROOT",
    "NAME",
    "Endpoint",
    "HttpdSwitchFields",
    "Selection",
    "check_config_command",
    "render_dropin",
    "select",
    "verify",
    "verify_command",
]
