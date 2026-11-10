"""The Linux role ``software_estate_publisher_linux`` as pyinfra operations (root connection)."""

from __future__ import annotations

import shlex
from io import StringIO

from pyinfra import host
from pyinfra.api import DeployError
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File
from pyinfra.facts.server import Command, Hostname, Kernel, Users
from pyinfra.operations import files, server, systemd

from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.ops import secret_file

from .config import (
    LINUX_ACCOUNT,
    LINUX_CONFIG_DIR,
    LINUX_ENTRY,
    LINUX_PROGRAM,
    LINUX_STATE_DIR,
    LINUX_UNIT_DIR,
    LINUX_UNITS,
    SoftwareEstatePublisherConfig,
)
from .render import PROGRAMS, config_json, program, release_path, render

TIMER, SERVICE = LINUX_UNITS
PATH_CHECK = program("linux_paths.py")
# systemd ActiveState values of a unit that still runs or is scheduled.
ACTIVE_STATES = ("active", "activating", "deactivating", "reloading", "refreshing")


def _paths_ok(mode: str, *arguments: str) -> None:
    command = shlex.join(["python3", "-I", "-c", PATH_CHECK, mode, *arguments])
    if host.get_fact(Command, command=command) != "ok":
        raise DeployError("software-estate-publisher path check did not answer ok")


def _require_host(cfg: SoftwareEstatePublisherConfig) -> None:
    if host.get_fact(Kernel) != "Linux":
        raise DeployError("the Linux publisher needs a Linux host")
    if host.get_fact(Command, command="id -u") != "0":
        raise DeployError("the Linux publisher is managed as root")
    if host.get_fact(Command, command="test -d /run/systemd/system && echo systemd || echo none") != "systemd":
        raise DeployError("the Linux publisher needs systemd")
    name = str(host.get_fact(Hostname) or "").split(".")[0].lower()
    if name not in cfg.hostnames:
        raise DeployError(f"host name {name!r} is not one of the publisher's hostnames")


def _put(path: str, content: str, *, user: str = "root", mode: str = "0644", name: str | None = None) -> OperationMeta:
    return files.put(name=name or f"Install {path}", src=StringIO(content), dest=path, user=user, group=user, mode=mode)


def _show(unit: str) -> str:
    return shlex.join(["systemctl", "show", "-p", "LoadState", "-p", "ActiveState", unit])


def _unit_state(unit: str) -> dict[str, str]:
    """systemd's ``LoadState`` and ``ActiveState`` of ``unit``, whether or not its file exists."""

    output = str(host.get_fact(Command, command=_show(unit)) or "")
    state = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    return {"LoadState": state.get("LoadState", ""), "ActiveState": state.get("ActiveState", "")}


def _verify_removed() -> None:
    """Fail unless neither unit is loaded or active any more (read-only)."""

    active = "|".join(f"*ActiveState={value}*" for value in ACTIVE_STATES)
    checks = [
        f's=$({_show(unit)}) || exit 1; case "$s" in *LoadState=loaded*|{active}) '
        f'echo "{unit} is still loaded or active" >&2; exit 1;; esac'
        for unit in (TIMER, SERVICE)
    ]
    mark_read_only(server.shell(name="Verify the publisher units are unloaded", commands=["; ".join(checks)]))


def _remove() -> None:
    # systemd keeps a unit loaded, and a running timer scheduled, after its
    # file is deleted, so the units' state is read independently of the files.
    reload_needed = False
    timer_file = True
    for unit in LINUX_UNITS:
        exists = bool(host.get_fact(File, path=str(LINUX_UNIT_DIR / unit)))
        state = _unit_state(unit)
        if state["ActiveState"] in ACTIVE_STATES:
            server.shell(name=f"Stop {unit}", commands=[shlex.join(["systemctl", "stop", unit])])
        if exists:
            systemd.service(name=f"Disable {unit}", service=unit, enabled=False)
        elif state["LoadState"] == "loaded":
            reload_needed = True
        if unit == TIMER:
            timer_file = exists
    changes = [
        files.file(name=f"Remove {unit}", path=str(LINUX_UNIT_DIR / unit), present=False) for unit in (TIMER, SERVICE)
    ]
    if not timer_file:
        # Without its file, `systemctl disable` cannot read the timer's
        # [Install] section: remove its timers.target enablement link directly.
        changes.append(
            files.link(
                name=f"Remove the enablement link of {TIMER}",
                path=str(LINUX_UNIT_DIR / "timers.target.wants" / TIMER),
                present=False,
            )
        )
    systemd.daemon_reload(
        name="Reload systemd after removing the publisher units",
        _if=lambda: reload_needed or any(op.did_change() for op in changes),
    )
    _verify_removed()


def _account() -> None:
    server.group(name=f"Ensure group {LINUX_ACCOUNT}", group=LINUX_ACCOUNT, system=True)
    existing = host.get_fact(Users).get(LINUX_ACCOUNT)
    if existing is not None and str(existing.get("uid")) == "0":
        raise DeployError(f"{LINUX_ACCOUNT} must not be root")
    server.user(
        name=f"Ensure user {LINUX_ACCOUNT}",
        user=LINUX_ACCOUNT,
        group=LINUX_ACCOUNT,
        home="/nonexistent",
        shell="/usr/sbin/nologin",
        system=True,
        create_home=False,
        ensure_home=False,
    )
    if existing is not None and existing.get("groups"):
        # The role's ``groups: []``: no supplementary groups.
        server.shell(
            name=f"Remove {LINUX_ACCOUNT} from supplementary groups",
            commands=[shlex.join(["usermod", "-G", "", LINUX_ACCOUNT])],
        )


def _validate_as_publisher(cfg: SoftwareEstatePublisherConfig) -> None:
    check = shlex.join(
        [
            "/usr/sbin/runuser",
            "-u",
            LINUX_ACCOUNT,
            "--",
            str(cfg.python),
            f"{release_path(cfg)}/publish.py",
            "--config",
            str(cfg.config_path),
            "--check",
        ]
    )
    # Exit 75 is the publisher's busy lock: retried every 5 s, 60 times.
    script = (
        f"n=0; while :; do {check}; rc=$?; [ $rc -ne 75 ] && exit $rc; "
        "n=$((n+1)); [ $n -gt 60 ] && exit 75; sleep 5; done"
    )
    mark_read_only(server.shell(name="Validate the configuration as the publisher account", commands=[script]))


def deploy_linux(cfg: SoftwareEstatePublisherConfig, writer: str | None) -> None:
    _require_host(cfg)
    target = release_path(cfg)
    _paths_ok(
        "root",
        "/usr",
        "/usr/local",
        "/usr/local/bin",
        "/usr/local/lib",
        "/etc",
        "/etc/systemd",
        str(LINUX_UNIT_DIR),
        "/var",
        "/var/lib",
        str(LINUX_PROGRAM),
        target,
        *(f"{target}/{name}" for name in PROGRAMS),
        str(LINUX_ENTRY),
        *(str(LINUX_UNIT_DIR / unit) for unit in (SERVICE, TIMER)),
    )
    if cfg.state == "absent":
        _remove()
        return
    _account()
    _paths_ok(
        "private",
        LINUX_ACCOUNT,
        str(LINUX_CONFIG_DIR),
        str(LINUX_CONFIG_DIR / "config.json"),
        str(LINUX_CONFIG_DIR / "writer"),
        str(LINUX_STATE_DIR),
        str(LINUX_STATE_DIR / "outbox"),
    )
    for path in (LINUX_CONFIG_DIR, LINUX_STATE_DIR, LINUX_STATE_DIR / "outbox"):
        files.directory(
            name=f"Ensure private directory {path}",
            path=str(path),
            user=LINUX_ACCOUNT,
            group=LINUX_ACCOUNT,
            mode="0700",
        )
    for path_text in (str(LINUX_PROGRAM), target):
        files.directory(
            name=f"Ensure program directory {path_text}", path=path_text, user="root", group="root", mode="0755"
        )
    for name in PROGRAMS:
        _put(f"{target}/{name}", program(name))
    if writer:
        secret_file(
            name="Install the host-bound writer",
            path=str(LINUX_CONFIG_DIR / "writer"),
            content=SecretContent(writer.strip() + "\n"),
            user=LINUX_ACCOUNT,
            group=LINUX_ACCOUNT,
            mode="0600",
        )
    _put(str(cfg.config_path), config_json(cfg), user=LINUX_ACCOUNT, mode="0600")
    _validate_as_publisher(cfg)
    _put(str(LINUX_ENTRY), render(cfg, "run.j2"), mode="0755")
    units = [
        _put(str(LINUX_UNIT_DIR / unit), render(cfg, template))
        for unit, template in (
            (SERVICE, "publisher.service.j2"),
            (TIMER, "publisher.timer.j2"),
        )
    ]

    def units_changed() -> bool:
        return any(op.did_change() for op in units)

    systemd.daemon_reload(name="Reload the publisher units", _if=units_changed)
    systemd.service(name=f"Restart {TIMER}", service=TIMER, running=None, restarted=True, _if=units_changed)
    systemd.service(name=f"Enable and start {TIMER}", service=TIMER, running=True, enabled=True)
    server.shell(
        name="Start one immediate cadence and delivery check",
        commands=[f"systemctl start --no-block {SERVICE}"],
        _if=units_changed,
    )
