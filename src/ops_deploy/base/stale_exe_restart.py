"""Restart allowlisted units that still run a replaced package binary (no ops-library role).

A reload never loads a new executable, and a package only restarts the units
it ships itself, so a unit that runs a packaged binary under its own name (an
nginx for one service, say) keeps the old, deleted image after an upgrade
until something restarts it. This deploy installs the host program
``files/stale_exe_restart.py`` as ``/usr/local/libexec/ops-deploy/stale-exe-restart``,
its allowlist ``/etc/ops-deploy/stale-exe-restart.json``, a oneshot
``stale-exe-restart.service`` with an hourly timer, and an apt
``DPkg::Post-Invoke`` hook that only queues the oneshot after each dpkg run.
The oneshot restarts an allowlisted unit at most once per installed binary and
only after its checks pass (see the program's docstring and ``docs/base.md``);
every other unit is only reported.

The deploy itself never restarts or starts a consumer unit, and never starts
the oneshot: it writes files, reloads systemd when a unit file changed and
enables the timer. While planning, the packaged program runs read-only with
the rendered allowlist (``report``), so ``--dry`` shows what the next timer run
would do, and a host that cannot run the program fails before any change.
"""

from __future__ import annotations

import base64
import json
import os
import shlex
import urllib.parse
from io import StringIO
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, StrictInt, field_validator, model_validator
from pyinfra import host, logger
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Which
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import AbsolutePath, RoleConfig, require_linux, require_systemd
from ops_deploy.helpers import mark_read_only, systemd_unit
from ops_deploy.helpers.probes import probe

HOST_SCRIPT = (Path(__file__).parent / "files" / "stale_exe_restart.py").read_text()
HOST_PYTHON = "/usr/bin/python3"
LIBEXEC_DIR = "/usr/local/libexec/ops-deploy"
SCRIPT_PATH = f"{LIBEXEC_DIR}/stale-exe-restart"
CONFIG_DIR = "/etc/ops-deploy"
CONFIG_PATH = f"{CONFIG_DIR}/stale-exe-restart.json"
STATE_PATH = "/var/lib/ops-deploy/stale-exe-restart/state.json"
SERVICE = "stale-exe-restart.service"
TIMER = "stale-exe-restart.timer"
APT_HOOK = "/etc/apt/apt.conf.d/80ops-deploy-stale-exe-restart"
SCHEMA = 1
HEADER = "Managed by ops-deploy (base.stale_exe_restart). Do not edit."
LOOPBACK = ("127.0.0.1", "::1", "localhost")

UnitName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@:-]*\.service$")]
Package = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]+$")]
# One argv element: anything but NUL and newline (systemd's ExecStart cannot hold those).
Argument = Annotated[str, Field(pattern=r"^[^\x00\n]*$")]
HeaderName = Annotated[str, Field(pattern=r"^[A-Za-z0-9-]+$")]
HeaderValue = Annotated[str, Field(pattern=r"^[^\x00-\x1f\x7f]*$")]


class StaleExeHttpProbe(RoleConfig):
    """A local HTTP request after a restart; the restart counts as failed unless it answers ``status``."""

    url: str
    headers: dict[HeaderName, HeaderValue] = Field(default_factory=dict)
    status: StrictInt = Field(default=200, ge=100, le=599)

    @field_validator("url")
    @classmethod
    def _loopback(cls, value: str) -> str:
        parts = urllib.parse.urlsplit(value)
        try:
            port = parts.port
        except ValueError:
            port = None
        if (
            parts.scheme != "http"
            or parts.hostname not in LOOPBACK
            or port is None
            or parts.fragment
            or any(ord(char) < 0x21 or ord(char) == 0x7F for char in value)
        ):
            raise ValueError("url must be http:// to 127.0.0.1, ::1 or localhost with an explicit port")
        return value


class StaleExeUnit(RoleConfig):
    """One allowlisted unit: restarted when it runs a replaced image of ``binary``."""

    unit: UnitName
    binary: AbsolutePath
    # The package that owns ``binary``; anything else (a manual or upstream binary) is refused on the host.
    package: Package
    # The configuration test: ``nginx`` runs ``<binary> -t <expected_argv[1:]>`` and each ExecStartPre.
    test: Literal["nginx"]
    # The unit's exact ExecStart argv; a unit that changed is refused, never restarted.
    expected_argv: tuple[Argument, ...] = Field(min_length=1)
    http_probe: StaleExeHttpProbe | None = None

    @model_validator(mode="after")
    def _argv_runs_the_binary(self) -> StaleExeUnit:
        if os.path.normpath(self.binary) != self.binary or self.binary == "/":
            raise ValueError("binary must be a normalized absolute file path")
        if self.expected_argv[0] != self.binary:
            raise ValueError("expected_argv must start with the binary")
        return self


class StaleExeRestartConfig(RoleConfig):
    """The allowlist; empty: the timer only reports, it restarts nothing."""

    units: tuple[StaleExeUnit, ...] = ()

    @model_validator(mode="after")
    def _unique(self) -> StaleExeRestartConfig:
        names = [entry.unit for entry in self.units]
        if len(set(names)) != len(names):
            raise ValueError("a unit is listed twice")
        return self


def render_config(cfg: StaleExeRestartConfig) -> str:
    """``/etc/ops-deploy/stale-exe-restart.json``: what the host program's ``parse_config`` reads."""

    units: list[dict[str, Any]] = []
    for entry in cfg.units:
        item: dict[str, Any] = {
            "unit": entry.unit,
            "binary": entry.binary,
            "package": entry.package,
            "test": entry.test,
            "expected_argv": list(entry.expected_argv),
        }
        if entry.http_probe is not None:
            item["http_probe"] = {
                "url": entry.http_probe.url,
                "headers": dict(entry.http_probe.headers),
                "status": entry.http_probe.status,
            }
        units.append(item)
    return json.dumps({"schema": SCHEMA, "units": units}, indent=2, sort_keys=True) + "\n"


def render_service() -> str:
    return (
        f"# {HEADER}\n"
        "[Unit]\n"
        "Description=Restart allowlisted units still running a replaced package binary\n"
        f"ConditionPathExists={CONFIG_PATH}\n"
        # The apt hook may queue it after every dpkg run; no start may be dropped (it has no Restart=).
        "StartLimitIntervalSec=0\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={HOST_PYTHON} -I {SCRIPT_PATH} run\n"
        "StateDirectory=ops-deploy/stale-exe-restart\n"
        "StateDirectoryMode=0755\n"
        # Up to 30 minutes waiting for dpkg, then tests, a restart and its checks.
        "TimeoutStartSec=50min\n"
    )


def render_timer() -> str:
    return (
        f"# {HEADER}\n"
        "[Unit]\n"
        "Description=Hourly check for allowlisted units still running a replaced package binary\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=hourly\n"
        "RandomizedDelaySec=5min\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def render_apt_hook() -> str:
    command = (
        f"if [ -d /run/systemd/system ] && [ -e /etc/systemd/system/{SERVICE} ]; "
        f"then systemctl --no-block start {SERVICE} || true; fi"
    )
    return (
        f"// {HEADER}\n"
        f"// After each dpkg run, queue {SERVICE}: it waits until dpkg is idle,\n"
        "// so a restart never happens inside dpkg, and it never fails apt.\n"
        f'DPkg::Post-Invoke {{ "{command}"; }};\n'
    )


def report_command(cfg: StaleExeRestartConfig) -> str:
    """The packaged program, read from stdin, in read-only ``report`` mode with the rendered allowlist."""

    encoded = base64.b64encode(render_config(cfg).encode()).decode()
    return shlex.join([HOST_PYTHON, "-I", "-", "report", "--config-b64", encoded, "--state", STATE_PATH])


def report_lines(answer: str | None) -> list[str]:
    """Human lines from the ``report`` JSON; a failed or unreadable report fails the deploy.

    So does an allowlist that does not fit the host: a unit that is not loaded, or one the
    program would refuse to restart (other package owner, modified binary, another
    ExecStart, a pending unit edit, ...), is refused before any change.
    """

    if answer is None:
        raise DeployError("stale_exe_restart: the read-only report failed on the host (see the probe warning)")
    try:
        report = json.loads(answer)
        rows = report["units"]
        others = report["report_only"]
        foreign = int(report["foreign_namespace_pids"])
        unreadable = int(report["unreadable_pids"])
        lines = []
        for row in rows:
            text = f"{row['unit']}: {row['status']}"
            if row.get("reason"):
                text += f" ({row['reason']})"
            if row.get("action") == "test_and_restart":
                text += "; the next timer run tests and restarts it"
            lines.append(text)
        stale = [row["unit"] for row in others if row["stale_exe"]]
        libs = [row["unit"] for row in others if row["deleted_libs"]]
        unfit = [
            f"{row['unit']}: {row['status']}" + (f" ({row['reason']})" if row.get("reason") else "")
            for row in rows
            if row["status"] in ("not_loaded", "refused", "error") or row.get("ready") is False
        ]
    except (ValueError, KeyError, TypeError) as exc:
        raise DeployError(f"stale_exe_restart: unreadable report from the host ({type(exc).__name__})") from None
    if unfit:
        raise DeployError(f"stale_exe_restart: the allowlist does not fit the host: {'; '.join(unfit)}")
    if report.get("state_error"):
        raise DeployError(f"stale_exe_restart: {report['state_error']}; check it, then repair or remove it")
    lines.append(
        f"report only (never restarted): {len(stale)} unit(s) with a replaced executable"
        + (f" ({', '.join(stale)})" if stale else "")
        + f", {len(libs)} with deleted libraries"
        + (f" ({', '.join(libs)})" if libs else "")
        + f"; {foreign} process(es) in other mount namespaces (path comparison skipped)"
        + (f"; {unreadable} process(es) NOT READABLE" if unreadable else "")
    )
    return lines


@deploy("Stale binary restart")
def deploy_stale_exe_restart(cfg: StaleExeRestartConfig) -> None:
    require_linux("stale_exe_restart")
    require_systemd("stale_exe_restart")
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("stale_exe_restart hooks into apt; a Debian-family host is required")

    # Read-only, while planning: what the timer would do with this allowlist.
    answer = probe(report_command(cfg), name="stale-exe-restart report", stdin=HOST_SCRIPT)
    for line in report_lines(answer):
        logger.info(f"{host.print_prefix}stale_exe_restart: {line}")

    files.directory(name=f"Ensure {LIBEXEC_DIR}", path=LIBEXEC_DIR, user="root", group="root", mode="0755")
    files.put(
        name=f"Install {SCRIPT_PATH}",
        src=StringIO(HOST_SCRIPT),
        dest=SCRIPT_PATH,
        user="root",
        group="root",
        mode="0755",
    )
    files.directory(name=f"Ensure {CONFIG_DIR}", path=CONFIG_DIR, user="root", group="root", mode="0755")
    files.put(
        name=f"Write {CONFIG_PATH}",
        src=StringIO(render_config(cfg)),
        dest=CONFIG_PATH,
        user="root",
        group="root",
        mode="0644",
    )
    units = [systemd_unit(SERVICE, render_service()), systemd_unit(TIMER, render_timer())]
    systemd.daemon_reload(name="Reload systemd for the stale-exe-restart units", _if=any_changed(*units))
    # The timer only; the oneshot runs from the timer and the apt hook, never from the deploy.
    systemd.service(name=f"Enable and start {TIMER}", service=TIMER, running=True, enabled=True)
    # Last: the hook may queue the oneshot only once everything it runs is in place.
    files.put(
        name=f"Write {APT_HOOK}",
        src=StringIO(render_apt_hook()),
        dest=APT_HOOK,
        user="root",
        group="root",
        mode="0644",
    )
    mark_read_only(
        server.shell(
            name="Check the installed stale-exe-restart",
            commands=[f"{HOST_PYTHON} -I {SCRIPT_PATH} report >/dev/null"],
        )
    )
